package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type State struct {
	ClientToken          string `json:"client_token"`
	PollIntervalSeconds  int    `json:"poll_interval_seconds,omitempty"`
	LastRegisterTimeRFC  string `json:"last_register_time,omitempty"`
	LastRegisterServerTS string `json:"last_register_server_time,omitempty"`
}

type Manager struct {
	path string

	mu    sync.RWMutex
	state State
}

func NewManager(path string) (*Manager, error) {
	if path == "" {
		return nil, errors.New("state path is empty")
	}
	return &Manager{path: path}, nil
}

func (m *Manager) Load() error {
	b, err := os.ReadFile(m.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	m.mu.Lock()
	m.state = s
	m.mu.Unlock()
	return nil
}

func (m *Manager) Save() error {
	m.mu.RLock()
	b, err := json.MarshalIndent(m.state, "", "  ")
	m.mu.RUnlock()
	if err != nil {
		return err
	}

	dir := filepath.Dir(m.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

func (m *Manager) GetClientToken() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.ClientToken
}

func (m *Manager) SetClientToken(token string) {
	m.mu.Lock()
	m.state.ClientToken = token
	m.mu.Unlock()
}

func (m *Manager) SetLastRegister(pollIntervalSeconds int, serverTime string) {
	m.mu.Lock()
	m.state.PollIntervalSeconds = pollIntervalSeconds
	m.state.LastRegisterServerTS = serverTime
	m.state.LastRegisterTimeRFC = time.Now().UTC().Format(time.RFC3339Nano)
	m.mu.Unlock()
}
