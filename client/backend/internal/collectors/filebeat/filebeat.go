package filebeat

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
	var doc map[string]any
	if err := json.Unmarshal(line, &doc); err != nil {
		return storage.Event{}, err
	}
	if doc == nil {
		return storage.Event{}, errors.New("filebeat: empty json object")
	}

	ts := time.Now().UTC()
	if tsStr := getString(doc, "@timestamp"); tsStr != "" {
		if t, err := normalize.ParseTimeFlexible(tsStr); err == nil {
			ts = t.UTC()
		}
	}
	doc["@timestamp"] = ts.Format(time.RFC3339Nano)

	now := time.Now().UTC().Format(time.RFC3339Nano)

	ecs := ensureMap(doc, "ecs")
	ecs["version"] = normalize.ECSVersion

	host := ensureMap(doc, "host")
	if getString(host, "id") == "" {
		host["id"] = cfg.HostID
	}
	if getString(host, "name") == "" {
		host["name"] = cfg.HostName
	}

	agent := ensureMap(doc, "agent")
	if getString(agent, "name") == "" {
		agent["name"] = "filebeat"
	}
	if getString(agent, "version") == "" {
		agent["version"] = "unknown"
	}

	eventObj := ensureMap(doc, "event")
	if getString(eventObj, "created") == "" {
		eventObj["created"] = now
	}
	if getString(eventObj, "ingested") == "" {
		eventObj["ingested"] = now
	}
	if getString(eventObj, "original") == "" {
		eventObj["original"] = string(line)
	}

	kind := strings.ToLower(strings.TrimSpace(firstNonEmpty(
		getString(eventObj, "kind"),
		getString(doc, "event.kind"),
	)))
	if kind == "" {
		if isLikelyAlert(doc) {
			kind = "alert"
		} else {
			kind = "event"
		}
	}
	if kind != "event" && kind != "alert" {
		kind = "event"
	}
	eventObj["kind"] = kind

	dataset := strings.TrimSpace(firstNonEmpty(
		getString(eventObj, "dataset"),
		getString(doc, "event.dataset"),
	))
	if dataset == "" {
		if kind == "alert" {
			dataset = "finding.raw"
		} else {
			dataset = inferHostlogDataset(doc)
		}
		eventObj["dataset"] = dataset
	}
	if dataset == "" {
		return storage.Event{}, errors.New("filebeat: missing event.dataset")
	}

	eventID := strings.TrimSpace(firstNonEmpty(
		getString(eventObj, "id"),
		getString(doc, "event.id"),
	))
	if eventID == "" {
		prefix := "evt-"
		if kind == "alert" {
			prefix = "alrt-"
		}
		eventID = prefix + normalize.SHA1Hex(fmt.Sprintf(
			"filebeat|%s|%s|%s|%s",
			cfg.HostID,
			ts.Format(time.RFC3339Nano),
			dataset,
			string(line),
		))[:16]
		eventObj["id"] = eventID
	}

	j, err := json.Marshal(doc)
	if err != nil {
		return storage.Event{}, err
	}

	return storage.Event{
		EventID:      eventID,
		EventKind:    kind,
		EventDataset: dataset,
		Timestamp:    ts,
		DocJSON:      j,
	}, nil
}

func ensureMap(m map[string]any, key string) map[string]any {
	v, ok := m[key]
	if ok {
		if mm, ok := v.(map[string]any); ok && mm != nil {
			return mm
		}
	}
	mm := map[string]any{}
	m[key] = mm
	return mm
}

func inferHostlogDataset(doc map[string]any) string {
	// Prefer explicit hint from filebeat configuration (fields.log_type).
	switch strings.ToLower(strings.TrimSpace(getString(doc, "log_type"))) {
	case "auth":
		return "hostlog.auth"
	case "syslog":
		return "hostlog.process"
	case "kernel":
		// Docs only define auth/process/file_registry for v1.
		return "hostlog.process"
	}

	// Fallback: infer from log origin path if present.
	path := firstNonEmpty(
		getNestedString(doc, "log", "origin", "file", "path"),
		getNestedString(doc, "log", "file", "path"),
		getString(doc, "log.origin.file.path"),
		getString(doc, "log.file.path"),
	)
	pathLower := strings.ToLower(path)
	if strings.Contains(pathLower, "auth.log") {
		return "hostlog.auth"
	}
	return "hostlog.process"
}

func isLikelyAlert(doc map[string]any) bool {
	if a, ok := doc["anomaly"].(map[string]any); ok {
		if b, ok := a["detected"].(bool); ok && b {
			return true
		}
	}
	if custom, ok := doc["custom"].(map[string]any); ok {
		if finding, ok := custom["finding"].(map[string]any); ok && len(finding) > 0 {
			return true
		}
	}
	if _, ok := doc["rule"].(map[string]any); ok {
		// Sigma detections commonly add rule.*; treat as alert if not specified.
		return true
	}
	return false
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
	case int64:
		return strconv.FormatInt(t, 10)
	default:
		return ""
	}
}

func getNestedString(m map[string]any, keys ...string) string {
	cur := any(m)
	for _, k := range keys {
		obj, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = obj[k]
	}
	switch t := cur.(type) {
	case string:
		return t
	default:
		return ""
	}
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
