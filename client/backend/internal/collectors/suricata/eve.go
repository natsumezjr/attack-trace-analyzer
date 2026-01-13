package suricata

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

func NormalizeEveLine(cfg config.Config, line []byte) (storage.Event, error) {
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		return storage.Event{}, err
	}

	eventType := strings.ToLower(getString(m, "event_type"))
	if eventType == "" {
		return storage.Event{}, errors.New("suricata: missing event_type")
	}

	ts := time.Now().UTC()
	if tsStr := getString(m, "timestamp"); tsStr != "" {
		if t, err := normalize.ParseTimeFlexible(tsStr); err == nil {
			ts = t.UTC()
		}
	}

	agentVersion := "unknown"
	if v := getNestedString(m, "suricata", "version"); v != "" {
		agentVersion = v
	}

	switch eventType {
	case "alert":
		return normalizeAlert(cfg, agentVersion, ts, line, m)
	case "dns":
		return normalizeDNS(cfg, agentVersion, ts, line, m)
	case "http":
		return normalizeHTTP(cfg, agentVersion, ts, line, m)
	case "icmp":
		return normalizeICMP(cfg, agentVersion, ts, line, m)
	case "flow", "tls":
		return normalizeFlow(cfg, agentVersion, ts, line, m, eventType)
	default:
		// Keep unknown types as generic flow telemetry to not drop data.
		return normalizeFlow(cfg, agentVersion, ts, line, m, eventType)
	}
}

func normalizeFlow(cfg config.Config, agentVersion string, ts time.Time, raw []byte, m map[string]any, eventType string) (storage.Event, error) {
	now := time.Now().UTC()

	srcIP := getString(m, "src_ip")
	dstIP := getString(m, "dest_ip")
	srcPort := getInt64(m, "src_port")
	dstPort := getInt64(m, "dest_port")
	transport := strings.ToLower(getString(m, "proto"))
	if transport == "" {
		transport = "unknown"
	}
	appProto := strings.ToLower(getString(m, "app_proto"))
	if appProto == "" {
		appProto = strings.ToLower(eventType)
	}
	if appProto == "" {
		appProto = "unknown"
	}

	flowID := getInt64(m, "flow_id")
	flowIDStr := "unknown"
	if flowID != 0 {
		flowIDStr = fmt.Sprintf("flow-%d", flowID)
	}

	eventID := "evt-" + normalize.SHA1Hex(fmt.Sprintf("suricata|%s|%s|%s|%d|%s|%s|%d|%d",
		eventType, ts.Format(time.RFC3339Nano), transport, flowID, srcIP, dstIP, srcPort, dstPort,
	))

	eventObj := map[string]any{
		"id":       eventID,
		"kind":     "event",
		"created":  now.Format(time.RFC3339Nano),
		"ingested": now.Format(time.RFC3339Nano),
		"category": []string{"network"},
		"type":     []string{"connection"},
		"action":   "flow_event",
		"dataset":  "netflow.flow",
		"original": string(raw),
	}

	doc := map[string]any{
		"ecs":        map[string]any{"version": normalize.ECSVersion},
		"@timestamp": ts.Format(time.RFC3339Nano),
		"event":      eventObj,
		"host":       map[string]any{"id": cfg.HostID, "name": cfg.HostName},
		"agent":      map[string]any{"name": "suricata", "version": agentVersion},
		"network": map[string]any{
			"transport": transport,
			"protocol":  appProto,
		},
		"source":      map[string]any{"ip": srcIP, "port": srcPort},
		"destination": map[string]any{"ip": dstIP, "port": dstPort},
		"flow":        map[string]any{"id": flowIDStr},
	}

	if cid := getString(m, "community_id"); cid != "" {
		network := doc["network"].(map[string]any)
		network["community_id"] = cid
	}

	// Flow stats are commonly under `flow.*`.
	if flow, ok := m["flow"].(map[string]any); ok {
		bytesToClient := getInt64(flow, "bytes_toclient")
		bytesToServer := getInt64(flow, "bytes_toserver")
		pktsToClient := getInt64(flow, "pkts_toclient")
		pktsToServer := getInt64(flow, "pkts_toserver")

		network := doc["network"].(map[string]any)
		if bytesToClient != 0 || bytesToServer != 0 {
			network["bytes"] = bytesToClient + bytesToServer
		}
		if pktsToClient != 0 || pktsToServer != 0 {
			network["packets"] = pktsToClient + pktsToServer
		}
	}

	j, err := json.Marshal(doc)
	if err != nil {
		return storage.Event{}, err
	}

	return storage.Event{
		EventID:      eventID,
		EventKind:    "event",
		EventDataset: "netflow.flow",
		Timestamp:    ts,
		DocJSON:      j,
	}, nil
}

func normalizeDNS(cfg config.Config, agentVersion string, ts time.Time, raw []byte, m map[string]any) (storage.Event, error) {
	now := time.Now().UTC()
	dns, _ := m["dns"].(map[string]any)

	qname := getString(dns, "rrname")
	qtype := getString(dns, "rrtype")
	if qname == "" {
		qname = getString(dns, "query")
	}
	if qtype == "" {
		qtype = "A"
	}

	srcIP := getString(m, "src_ip")
	dstIP := getString(m, "dest_ip")
	srcPort := getInt64(m, "src_port")
	dstPort := getInt64(m, "dest_port")
	transport := strings.ToLower(getString(m, "proto"))
	if transport == "" {
		transport = "udp"
	}

	eventID := "evt-" + normalize.SHA1Hex(fmt.Sprintf("suricata|dns|%s|%s|%s|%s|%d|%d",
		ts.Format(time.RFC3339Nano), qname, srcIP, dstIP, srcPort, dstPort,
	))

	eventObj := map[string]any{
		"id":       eventID,
		"kind":     "event",
		"created":  now.Format(time.RFC3339Nano),
		"ingested": now.Format(time.RFC3339Nano),
		"category": []string{"network"},
		"type":     []string{"info"},
		"action":   "dns_query",
		"dataset":  "netflow.dns",
		"original": string(raw),
	}

	doc := map[string]any{
		"ecs":         map[string]any{"version": normalize.ECSVersion},
		"@timestamp":  ts.Format(time.RFC3339Nano),
		"event":       eventObj,
		"host":        map[string]any{"id": cfg.HostID, "name": cfg.HostName},
		"agent":       map[string]any{"name": "suricata", "version": agentVersion},
		"source":      map[string]any{"ip": srcIP, "port": srcPort},
		"destination": map[string]any{"ip": dstIP, "port": dstPort},
		"network": map[string]any{
			"transport": transport,
			"protocol":  "dns",
		},
		"dns": map[string]any{
			"question": map[string]any{
				"name": qname,
				"type": qtype,
			},
		},
		"custom": map[string]any{
			"dns": map[string]any{
				"entropy":      normalize.ShannonEntropy(qname),
				"query_length": len(qname),
			},
		},
	}

	if rcode := getString(dns, "rcode"); rcode != "" {
		dnsObj := doc["dns"].(map[string]any)
		dnsObj["response_code"] = rcode
	}

	j, err := json.Marshal(doc)
	if err != nil {
		return storage.Event{}, err
	}

	return storage.Event{
		EventID:      eventID,
		EventKind:    "event",
		EventDataset: "netflow.dns",
		Timestamp:    ts,
		DocJSON:      j,
	}, nil
}

func normalizeHTTP(cfg config.Config, agentVersion string, ts time.Time, raw []byte, m map[string]any) (storage.Event, error) {
	now := time.Now().UTC()
	httpObj, _ := m["http"].(map[string]any)

	method := strings.ToUpper(getString(httpObj, "http_method"))
	if method == "" {
		method = "GET"
	}
	hostname := getString(httpObj, "hostname")
	path := getString(httpObj, "url")
	if path == "" {
		path = "/"
	}
	fullURL := path
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		fullURL = path
	} else if hostname != "" {
		fullURL = "http://" + hostname + path
	}

	srcIP := getString(m, "src_ip")
	dstIP := getString(m, "dest_ip")
	srcPort := getInt64(m, "src_port")
	dstPort := getInt64(m, "dest_port")

	eventID := "evt-" + normalize.SHA1Hex(fmt.Sprintf("suricata|http|%s|%s|%s|%s|%s|%d|%s|%d",
		ts.Format(time.RFC3339Nano), method, fullURL, hostname, srcIP, srcPort, dstIP, dstPort,
	))

	eventObj := map[string]any{
		"id":       eventID,
		"kind":     "event",
		"created":  now.Format(time.RFC3339Nano),
		"ingested": now.Format(time.RFC3339Nano),
		"category": []string{"network"},
		"type":     []string{"info"},
		"action":   "http_request",
		"dataset":  "netflow.http",
		"original": string(raw),
	}

	doc := map[string]any{
		"ecs":         map[string]any{"version": normalize.ECSVersion},
		"@timestamp":  ts.Format(time.RFC3339Nano),
		"event":       eventObj,
		"host":        map[string]any{"id": cfg.HostID, "name": cfg.HostName},
		"agent":       map[string]any{"name": "suricata", "version": agentVersion},
		"source":      map[string]any{"ip": srcIP, "port": srcPort},
		"destination": map[string]any{"ip": dstIP, "port": dstPort},
		"network": map[string]any{
			"protocol": "http",
		},
		"http": map[string]any{
			"request": map[string]any{"method": method},
		},
		"url": map[string]any{
			"full":   fullURL,
			"domain": hostname,
		},
	}

	if status := getInt64(httpObj, "status"); status != 0 {
		httpObjEcs := doc["http"].(map[string]any)
		httpObjEcs["response"] = map[string]any{"status_code": status}
	}
	if ua := getString(httpObj, "http_user_agent"); ua != "" {
		doc["user_agent"] = map[string]any{"original": ua}
	}

	j, err := json.Marshal(doc)
	if err != nil {
		return storage.Event{}, err
	}

	return storage.Event{
		EventID:      eventID,
		EventKind:    "event",
		EventDataset: "netflow.http",
		Timestamp:    ts,
		DocJSON:      j,
	}, nil
}

func normalizeICMP(cfg config.Config, agentVersion string, ts time.Time, raw []byte, m map[string]any) (storage.Event, error) {
	now := time.Now().UTC()
	icmpObj, _ := m["icmp"].(map[string]any)

	typ := getInt64(icmpObj, "type")
	code := getInt64(icmpObj, "code")

	srcIP := getString(m, "src_ip")
	dstIP := getString(m, "dest_ip")

	eventID := "evt-" + normalize.SHA1Hex(fmt.Sprintf("suricata|icmp|%s|%s|%s|%d|%d",
		ts.Format(time.RFC3339Nano), srcIP, dstIP, typ, code,
	))

	eventObj := map[string]any{
		"id":       eventID,
		"kind":     "event",
		"created":  now.Format(time.RFC3339Nano),
		"ingested": now.Format(time.RFC3339Nano),
		"category": []string{"network"},
		"type":     []string{"info"},
		"action":   "icmp_echo",
		"dataset":  "netflow.icmp",
		"original": string(raw),
	}

	doc := map[string]any{
		"ecs":         map[string]any{"version": normalize.ECSVersion},
		"@timestamp":  ts.Format(time.RFC3339Nano),
		"event":       eventObj,
		"host":        map[string]any{"id": cfg.HostID, "name": cfg.HostName},
		"agent":       map[string]any{"name": "suricata", "version": agentVersion},
		"source":      map[string]any{"ip": srcIP},
		"destination": map[string]any{"ip": dstIP},
		"network": map[string]any{
			"transport": "icmp",
		},
		"icmp": map[string]any{
			"type": typ,
			"code": code,
		},
	}

	j, err := json.Marshal(doc)
	if err != nil {
		return storage.Event{}, err
	}

	return storage.Event{
		EventID:      eventID,
		EventKind:    "event",
		EventDataset: "netflow.icmp",
		Timestamp:    ts,
		DocJSON:      j,
	}, nil
}

func normalizeAlert(cfg config.Config, agentVersion string, ts time.Time, raw []byte, m map[string]any) (storage.Event, error) {
	now := time.Now().UTC()
	alert, _ := m["alert"].(map[string]any)

	signature := getString(alert, "signature")
	sid := getInt64(alert, "signature_id")
	severity := getInt64(alert, "severity")

	severity100 := int64(30)
	switch severity {
	case 1:
		severity100 = 90
	case 2:
		severity100 = 60
	case 3:
		severity100 = 30
	}

	srcIP := getString(m, "src_ip")
	dstIP := getString(m, "dest_ip")
	srcPort := getInt64(m, "src_port")
	dstPort := getInt64(m, "dest_port")
	transport := strings.ToLower(getString(m, "proto"))

	flowID := getInt64(m, "flow_id")
	flowIDStr := ""
	if flowID != 0 {
		flowIDStr = fmt.Sprintf("flow-%d", flowID)
	}

	ruleID := fmt.Sprintf("suricata-%d", sid)
	if sid == 0 {
		ruleID = "suricata-unknown"
	}

	eventID := "alrt-" + normalize.SHA1Hex(fmt.Sprintf("suricata|alert|%s|%s|%s|%d|%s|%s|%d|%d",
		ts.Format(time.RFC3339Nano), ruleID, signature, flowID, srcIP, dstIP, srcPort, dstPort,
	))

	eventObj := map[string]any{
		"id":       eventID,
		"kind":     "alert",
		"created":  now.Format(time.RFC3339Nano),
		"ingested": now.Format(time.RFC3339Nano),
		"category": []string{"network"},
		"type":     []string{"info"},
		"action":   "suricata_alert",
		"dataset":  "finding.raw",
		"severity": severity100,
		"original": string(raw),
	}

	doc := map[string]any{
		"ecs":        map[string]any{"version": normalize.ECSVersion},
		"@timestamp": ts.Format(time.RFC3339Nano),
		"event":      eventObj,
		"host":       map[string]any{"id": cfg.HostID, "name": cfg.HostName},
		"agent":      map[string]any{"name": "suricata", "version": agentVersion},
		"rule": map[string]any{
			"id":      ruleID,
			"name":    signature,
			"ruleset": "suricata",
		},
		"threat": map[string]any{
			"framework": "MITRE ATT&CK",
			"tactic":    map[string]any{"id": "TA0000", "name": "Unknown"},
			"technique": map[string]any{"id": "T0000", "name": "Unknown"},
		},
		"custom": map[string]any{
			"finding": map[string]any{
				"stage":     "raw",
				"providers": []string{"suricata"},
				"fingerprint": "fp-" + normalize.SHA1Hex(fmt.Sprintf("%s|%s|%s|%d",
					ruleID, cfg.HostID, flowIDStr, ts.Unix()/300,
				)),
			},
		},
		"source":      map[string]any{"ip": srcIP, "port": srcPort},
		"destination": map[string]any{"ip": dstIP, "port": dstPort},
		"network": map[string]any{
			"transport": transport,
		},
	}

	if flowIDStr != "" {
		doc["flow"] = map[string]any{"id": flowIDStr}
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

func getString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		switch t := v.(type) {
		case string:
			return t
		case json.Number:
			return t.String()
		case float64:
			return strconv.FormatFloat(t, 'f', -1, 64)
		case int64:
			return strconv.FormatInt(t, 10)
		}
	}
	return ""
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
