package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/natsumezjr/attack-trace-analyzer/client/backend/internal/config"
)

func NewRouter(cfg config.Config) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":    "ok",
			"client_id": cfg.ClientID,
			"time":      time.Now().UTC().Format(time.RFC3339Nano),
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

