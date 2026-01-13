package wazuh

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

func NormalizeAlertLine(cfg config.Config, line []byte) (storage.Event, error) {
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		return storage.Event{}, err
	}

	ts := extractTimestamp(m)
	now := time.Now().UTC()

	ruleObj, _ := m["rule"].(map[string]any)
	ruleIDRaw := getString(ruleObj, "id")
	ruleDesc := getString(ruleObj, "description")
	level := getInt64(ruleObj, "level")

	if ruleIDRaw == "" && ruleDesc == "" {
		return storage.Event{}, errors.New("wazuh alert: missing rule")
	}

	severity := int64(30)
	if level > 0 {
		// Wazuh levels are commonly 0-15.
		if level > 15 {
			level = 15
		}
		severity = level * 100 / 15
		if severity < 1 {
			severity = 1
		}
	}

	ruleID := "wazuh-" + strings.TrimSpace(ruleIDRaw)
	if ruleIDRaw == "" {
		ruleID = "wazuh-" + normalize.SHA1Hex(ruleDesc)[:12]
	}

	eventID := "alrt-" + normalize.SHA1Hex(fmt.Sprintf("wazuh|alert|%s|%s|%s", ruleID, ts.Format(time.RFC3339Nano), ruleDesc))

	category := []string{"host"}
	if groups := getStringSlice(ruleObj, "groups"); len(groups) > 0 {
		for _, g := range groups {
			if strings.Contains(strings.ToLower(g), "authentication") {
				category = []string{"authentication"}
				break
			}
		}
	}

	eventObj := map[string]any{
		"id":       eventID,
		"kind":     "alert",
		"created":  now.Format(time.RFC3339Nano),
		"ingested": now.Format(time.RFC3339Nano),
		"category": category,
		"type":     []string{"info"},
		"action":   "wazuh_alert",
		"dataset":  "finding.raw",
		"severity": severity,
		"original": string(line),
	}

	doc := map[string]any{
		"ecs":        map[string]any{"version": normalize.ECSVersion},
		"@timestamp": ts.Format(time.RFC3339Nano),
		"event":      eventObj,
		"host":       map[string]any{"id": cfg.HostID, "name": cfg.HostName},
		"agent":      map[string]any{"name": "wazuh-agent", "version": "unknown"},
		"rule": map[string]any{
			"id":      ruleID,
			"name":    ruleDesc,
			"ruleset": "wazuh",
		},
		"threat": map[string]any{
			"framework": "MITRE ATT&CK",
			"tactic":    map[string]any{"id": "TA0000", "name": "Unknown"},
			"technique": map[string]any{"id": "T0000", "name": "Unknown"},
		},
		"custom": map[string]any{
			"finding": map[string]any{
				"stage":     "raw",
				"providers": []string{"wazuh"},
				"fingerprint": "fp-" + normalize.SHA1Hex(fmt.Sprintf("%s|%s|%d",
					ruleID, cfg.HostID, ts.Unix()/300,
				)),
			},
		},
	}

	// Best-effort entity extraction from `data.*`
	if data, ok := m["data"].(map[string]any); ok {
		if user := getString(data, "user"); user != "" {
			doc["user"] = map[string]any{"name": user}
		} else if user := getString(data, "dstuser"); user != "" {
			doc["user"] = map[string]any{"name": user}
		}
		if src := getString(data, "srcip"); src != "" {
			doc["source"] = map[string]any{"ip": src}
		}
	}

	// MITRE fields: Wazuh may already include them under rule.mitre.*
	applyMitre(ruleObj, doc)

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

func NormalizeArchiveLine(cfg config.Config, line []byte) (storage.Event, error) {
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		return storage.Event{}, err
	}

	ts := extractTimestamp(m)
	now := time.Now().UTC()

	location := strings.ToLower(getString(m, "location"))
	decoderObj, _ := m["decoder"].(map[string]any)
	decoderName := strings.ToLower(getString(decoderObj, "name"))
	fullLog := getString(m, "full_log")

	dataset := "hostlog.process"
	category := []string{"process"}
	action := "hostlog_event"
	if strings.Contains(location, "auth") || strings.Contains(decoderName, "sshd") || strings.Contains(fullLog, "sshd") {
		dataset = "hostlog.auth"
		category = []string{"authentication"}
		action = "auth_event"
	}

	eventID := "evt-" + normalize.SHA1Hex(fmt.Sprintf("wazuh|archive|%s|%s|%s", dataset, ts.Format(time.RFC3339Nano), fullLog))

	eventObj := map[string]any{
		"id":       eventID,
		"kind":     "event",
		"created":  now.Format(time.RFC3339Nano),
		"ingested": now.Format(time.RFC3339Nano),
		"category": category,
		"type":     []string{"info"},
		"action":   action,
		"dataset":  dataset,
		"original": string(line),
	}

	doc := map[string]any{
		"ecs":        map[string]any{"version": normalize.ECSVersion},
		"@timestamp": ts.Format(time.RFC3339Nano),
		"event":      eventObj,
		"host":       map[string]any{"id": cfg.HostID, "name": cfg.HostName},
		"agent":      map[string]any{"name": "wazuh-agent", "version": "unknown"},
	}

	// Wazuh archives often include parsed fields under `data.*`
	if data, ok := m["data"].(map[string]any); ok {
		if dataset == "hostlog.auth" {
			user := firstNonEmpty(getString(data, "user"), getString(data, "dstuser"))
			srcIP := getString(data, "srcip")
			if user != "" {
				doc["user"] = map[string]any{"name": user}
			}
			if srcIP != "" {
				doc["source"] = map[string]any{"ip": srcIP}
			}
			if user != "" && srcIP != "" {
				doc["session"] = map[string]any{
					"id": "sess-" + normalize.SHA1Hex(cfg.HostID + "|" + user + "|" + srcIP + "|" + strconv.FormatInt(ts.Unix()/600, 10))[:32],
				}
			}
		}
	}

	if fullLog != "" {
		doc["message"] = fullLog
	}

	j, err := json.Marshal(doc)
	if err != nil {
		return storage.Event{}, err
	}

	return storage.Event{
		EventID:      eventID,
		EventKind:    "event",
		EventDataset: dataset,
		Timestamp:    ts,
		DocJSON:      j,
	}, nil
}

func extractTimestamp(m map[string]any) time.Time {
	// Wazuh commonly uses `timestamp`.
	if tsStr := getString(m, "timestamp"); tsStr != "" {
		if t, err := normalize.ParseTimeFlexible(tsStr); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

func applyMitre(ruleObj map[string]any, doc map[string]any) {
	if ruleObj == nil {
		return
	}
	mitreObj, _ := ruleObj["mitre"].(map[string]any)
	if mitreObj == nil {
		// Wazuh sometimes nests under rule.mitre
		mitreObj, _ = ruleObj["mitre"].(map[string]any)
	}

	var techniqueID string
	var tacticID string
	var tacticName string
	var techniqueName string

	// Technique IDs could be array or string.
	if ids := getAnySlice(mitreObj, "id"); len(ids) > 0 {
		techniqueID, _ = ids[0].(string)
	} else if id := getString(mitreObj, "id"); id != "" {
		techniqueID = id
	}
	if names := getAnySlice(mitreObj, "technique"); len(names) > 0 {
		techniqueName, _ = names[0].(string)
	} else if name := getString(mitreObj, "technique"); name != "" {
		techniqueName = name
	}

	if tactics := getAnySlice(mitreObj, "tactic"); len(tactics) > 0 {
		tacticName, _ = tactics[0].(string)
	} else if tactic := getString(mitreObj, "tactic"); tactic != "" {
		tacticName = tactic
	}
	if tid := getString(mitreObj, "tactic_id"); tid != "" {
		tacticID = tid
	}

	if techniqueID == "" {
		return
	}

	threat, ok := doc["threat"].(map[string]any)
	if !ok {
		return
	}
	threat["framework"] = "MITRE ATT&CK"
	threat["technique"] = map[string]any{"id": techniqueID, "name": firstNonEmpty(techniqueName, "Unknown")}
	threat["tactic"] = map[string]any{"id": firstNonEmpty(tacticID, "TA0000"), "name": firstNonEmpty(tacticName, "Unknown")}
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

func getAnySlice(m map[string]any, key string) []any {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok {
		return nil
	}
	if a, ok := v.([]any); ok {
		return a
	}
	return nil
}

func getStringSlice(m map[string]any, key string) []string {
	a := getAnySlice(m, key)
	if len(a) == 0 {
		return nil
	}
	out := make([]string, 0, len(a))
	for _, v := range a {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
