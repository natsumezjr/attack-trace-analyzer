package api

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/natsumezjr/attack-trace-analyzer/client/backend/internal/config"
	"github.com/natsumezjr/attack-trace-analyzer/client/backend/internal/state"
	"github.com/natsumezjr/attack-trace-analyzer/client/backend/internal/storage"
)

type pullRequest struct {
	Cursor string `json:"cursor"`
	Limit  int    `json:"limit"`
	Want   struct {
		EventKinds []string `json:"event_kinds,omitempty"`
		Datasets   []string `json:"datasets,omitempty"`
	} `json:"want,omitempty"`
}

func NewRouter(cfg config.Config, st *state.Manager, store *storage.Store) http.Handler {
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

		if store == nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "storage not initialized")
			return
		}

		var req pullRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid json body")
			return
		}

		if req.Cursor == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "cursor is required")
			return
		}
		if req.Limit <= 0 {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "limit must be > 0")
			return
		}
		if req.Limit > 2000 {
			req.Limit = 2000
		}
		if _, err := strconv.ParseInt(req.Cursor, 10, 64); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "cursor must be a decimal integer string")
			return
		}

		res, err := store.Pull(r.Context(), req.Cursor, req.Limit, storage.Want{
			EventKinds: req.Want.EventKinds,
			Datasets:   req.Want.Datasets,
		})
		if err != nil {
			status := http.StatusInternalServerError
			code := "INTERNAL_ERROR"
			if isClientPullError(err) {
				status = http.StatusBadRequest
				code = "BAD_REQUEST"
			}
			writeError(w, status, code, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"status":      "ok",
			"items":       res.Items,
			"next_cursor": res.NextCursor,
			"has_more":    res.HasMore,
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

func isClientPullError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "invalid cursor") ||
		strings.Contains(msg, "limit must") ||
		strings.Contains(msg, "cursor must")
}
