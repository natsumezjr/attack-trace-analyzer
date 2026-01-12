package api

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/natsumezjr/attack-trace-analyzer/client/backend/internal/config"
	"github.com/natsumezjr/attack-trace-analyzer/client/backend/internal/state"
)

func NewRouter(cfg config.Config, st *state.Manager) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":    "ok",
			"client_id": cfg.ClientID,
			"time":      time.Now().UTC().Format(time.RFC3339Nano),
		})
	})

	mux.HandleFunc("POST /api/v1/pull", func(w http.ResponseWriter, r *http.Request) {
		if !cfg.AuthDisable {
			if !checkBearerToken(r, st.GetClientToken()) {
				writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing or invalid token")
				return
			}
		}

		var req map[string]any
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid json body")
			return
		}

		cursor, _ := req["cursor"].(string)

		writeJSON(w, http.StatusOK, map[string]any{
			"status":      "ok",
			"items":       []any{},
			"next_cursor": cursor,
			"has_more":    false,
			"server_time": time.Now().UTC().Format(time.RFC3339Nano),
		})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"status": "error",
			"error": map[string]any{
				"code":    "NOT_FOUND",
				"message": "not found",
			},
		})
	})

	return mux
}

func checkBearerToken(r *http.Request, expected string) bool {
	if expected == "" {
		return false
	}
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	got := strings.TrimSpace(strings.TrimPrefix(auth, prefix))
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}

func writeError(w http.ResponseWriter, status int, code string, message string) {
	writeJSON(w, status, map[string]any{
		"status": "error",
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
