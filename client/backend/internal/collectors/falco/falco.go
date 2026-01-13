package falco

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/natsumezjr/attack-trace-analyzer/client/backend/internal/config"
	"github.com/natsumezjr/attack-trace-analyzer/client/backend/internal/normalize"
	"github.com/natsumezjr/attack-trace-analyzer/client/backend/internal/storage"
)

func NormalizeLine(cfg config.Config, line []byte) (storage.Event, error) {
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		return storage.Event{}, err
	}

	ts := time.Now().UTC()
	if tsStr := getString(m, "time"); tsStr != "" {
		if t, err := normalize.ParseTimeFlexible(tsStr); err == nil {
			ts = t.UTC()
		}
	}

	ruleName := getString(m, "rule")
	if strings.TrimSpace(ruleName) == "" {
		return storage.Event{}, errors.New("falco: missing rule")
	}

	priority := strings.TrimSpace(getString(m, "priority"))
	severity100 := mapFalcoPriority(priority)

	output := getString(m, "output")
	outputFields, _ := m["output_fields"].(map[string]any)

	ruleID := "falco-" + normalize.SHA1Hex(ruleName)[:16]
	eventID := "alrt-" + normalize.SHA1Hex(fmt.Sprintf("falco|%s|%s|%s", ruleID, ts.Format(time.RFC3339Nano), output))

	now := time.Now().UTC()
	eventObj := map[string]any{
		"id":       eventID,
		"kind":     "alert",
		"created":  now.Format(time.RFC3339Nano),
		"ingested": now.Format(time.RFC3339Nano),
		"category": []string{"process"},
		"type":     []string{"info"},
		"action":   "falco_alert",
		"dataset":  "finding.raw",
		"severity": severity100,
		"original": string(line),
	}

	doc := map[string]any{
		"ecs":        map[string]any{"version": normalize.ECSVersion},
		"@timestamp": ts.Format(time.RFC3339Nano),
		"event":      eventObj,
		"host":       map[string]any{"id": cfg.HostID, "name": cfg.HostName},
		"agent":      map[string]any{"name": "falco", "version": "unknown"},
		"rule": map[string]any{
			"id":      ruleID,
			"name":    ruleName,
			"ruleset": "falco",
		},
		"threat": map[string]any{
			"framework": "MITRE ATT&CK",
			"tactic":    map[string]any{"id": "TA0000", "name": "Unknown"},
			"technique": map[string]any{"id": "T0000", "name": "Unknown"},
		},
		"custom": map[string]any{
			"finding": map[string]any{
				"stage":     "raw",
				"providers": []string{"falco"},
				"fingerprint": "fp-" + normalize.SHA1Hex(fmt.Sprintf("%s|%s|%d",
					ruleID, cfg.HostID, ts.Unix()/300,
				)),
			},
		},
	}

	if strings.TrimSpace(output) != "" {
		doc["message"] = output
	}

	if outputFields != nil {
		addProcessFields(doc, cfg, ts, outputFields)
		addFileFields(doc, outputFields)
		addNetworkFields(doc, outputFields)
		addUserFields(doc, outputFields)
	}

	j, err := json.Marshal(doc)
	if err != nil {
		return storage.Event{}, err
	}

	return storage.Event{
		EventID:      eventID,
		EventKind:    "alert",
		EventDataset: "finding.raw",
		Timestamp:    ts,
		DocJSON:      j,
	}, nil
}

func mapFalcoPriority(p string) int64 {
	switch strings.ToLower(p) {
	case "emergency":
		return 100
	case "alert":
		return 90
	case "critical":
		return 80
	case "error":
		return 70
	case "warning":
		return 60
	case "notice":
		return 40
	case "informational", "info":
		return 20
	case "debug":
		return 10
	default:
		return 30
	}
}

func addProcessFields(doc map[string]any, cfg config.Config, ts time.Time, f map[string]any) {
	pid := getInt64(f, "proc.pid")
	ppid := getInt64(f, "proc.ppid")
	exe := getString(f, "proc.exe")
	name := getString(f, "proc.name")
	cmd := getString(f, "proc.cmdline")

	if pid == 0 && name == "" && exe == "" {
		return
	}

	proc := map[string]any{}
	if pid != 0 {
		proc["pid"] = pid
	}
	if name != "" {
		proc["name"] = name
	}
	if exe != "" {
		proc["executable"] = exe
	}
	if cmd != "" {
		proc["command_line"] = cmd
	}
	if ppid != 0 {
		proc["parent"] = map[string]any{"pid": ppid}
	}

	if pid != 0 && exe != "" {
		proc["entity_id"] = "p-" + normalize.SHA1Hex(fmt.Sprintf("%s|%d|%s|%s", cfg.HostID, pid, ts.Format(time.RFC3339Nano), exe))[:32]
	}

	doc["process"] = proc
}

func addFileFields(doc map[string]any, f map[string]any) {
	path := getString(f, "fd.name")
	if path == "" {
		path = getString(f, "file.path")
	}
	if path == "" {
		return
	}
	doc["file"] = map[string]any{"path": path}
}

func addUserFields(doc map[string]any, f map[string]any) {
	user := getString(f, "user.name")
	if user == "" {
		user = getString(f, "user")
	}
	if user == "" {
		return
	}
	doc["user"] = map[string]any{"name": user}
}

func addNetworkFields(doc map[string]any, f map[string]any) {
	// Falco socket fields can vary; best-effort mapping.
	srcIP := getString(f, "fd.sip")
	dstIP := getString(f, "fd.cip")
	dstPort := getInt64(f, "fd.cport")
	if srcIP == "" && dstIP == "" && dstPort == 0 {
		return
	}

	if srcIP != "" {
		doc["source"] = map[string]any{"ip": srcIP}
	}
	if dstIP != "" || dstPort != 0 {
		dst := map[string]any{}
		if dstIP != "" {
			dst["ip"] = dstIP
		}
		if dstPort != 0 {
			dst["port"] = dstPort
		}
		doc["destination"] = dst
	}
}

func getString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}

func getInt64(m map[string]any, key string) int64 {
	if m == nil {
		return 0
	}
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch t := v.(type) {
	case int64:
		return t
	case float64:
		return int64(t)
	case json.Number:
		i, _ := t.Int64()
		return i
	case string:
		i, _ := strconv.ParseInt(t, 10, 64)
		return i
	default:
		return 0
	}
}
