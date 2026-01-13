package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/natsumezjr/attack-trace-analyzer/client/backend/internal/config"
	"github.com/natsumezjr/attack-trace-analyzer/client/backend/internal/state"
)

type registerRequest struct {
	ClientID      string `json:"client_id"`
	ClientVersion string `json:"client_version"`
	ListenURL     string `json:"listen_url"`
	Host          struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"host"`
	Capabilities struct {
		Filebeat bool `json:"filebeat"`
		Falco    bool `json:"falco"`
		Suricata bool `json:"suricata"`
	} `json:"capabilities"`
}

type registerResponse struct {
	Status              string `json:"status"`
	ClientToken         string `json:"client_token"`
	PollIntervalSeconds int    `json:"poll_interval_seconds"`
	ServerTime          string `json:"server_time"`
	Error               *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func RunRegisterLoop(ctx context.Context, cfg config.Config, st *state.Manager) {
	backoff := 2 * time.Second
	const maxBackoff = 60 * time.Second

	for {
		if err := registerOnce(ctx, cfg, st); err != nil {
			slog.Warn("register failed (will retry)", "error", err, "backoff", backoff.String())
		} else {
			slog.Info("register ok")
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func registerOnce(ctx context.Context, cfg config.Config, st *state.Manager) error {
	if cfg.CenterBaseURL == "" {
		return errors.New("CENTER_BASE_URL is empty")
	}

	endpoint := strings.TrimRight(cfg.CenterBaseURL, "/") + "/api/v1/clients/register"

	var req registerRequest
	req.ClientID = cfg.ClientID
	req.ClientVersion = cfg.ClientVersion
	req.ListenURL = cfg.ListenURL
	req.Host.ID = cfg.HostID
	req.Host.Name = cfg.HostName
	req.Capabilities.Filebeat = cfg.CapFilebeat
	req.Capabilities.Falco = cfg.CapFalco
	req.Capabilities.Suricata = cfg.CapSuricata

	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var rr registerResponse
	if err := json.Unmarshal(respBody, &rr); err != nil {
		return fmt.Errorf("register parse error: %w", err)
	}

	if resp.StatusCode/100 != 2 || rr.Status != "ok" {
		if rr.Error != nil {
			return fmt.Errorf("register rejected: %s (%s)", rr.Error.Message, rr.Error.Code)
		}
		return fmt.Errorf("register rejected: http=%d", resp.StatusCode)
	}
	if rr.ClientToken == "" {
		return errors.New("register response missing client_token")
	}

	st.SetClientToken(rr.ClientToken)
	st.SetLastRegister(rr.PollIntervalSeconds, rr.ServerTime)
	if err := st.Save(); err != nil {
		return fmt.Errorf("state save failed: %w", err)
	}

	// Never log the token.
	slog.Info("registered", "client_id", cfg.ClientID, "poll_interval_seconds", rr.PollIntervalSeconds)
	return nil
}
