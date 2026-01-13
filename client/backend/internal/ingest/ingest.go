package ingest

import (
	"context"
	"log/slog"
	"time"

	"github.com/natsumezjr/attack-trace-analyzer/client/backend/internal/collectors"
	"github.com/natsumezjr/attack-trace-analyzer/client/backend/internal/collectors/falco"
	"github.com/natsumezjr/attack-trace-analyzer/client/backend/internal/collectors/filebeat"
	"github.com/natsumezjr/attack-trace-analyzer/client/backend/internal/collectors/suricata"
	"github.com/natsumezjr/attack-trace-analyzer/client/backend/internal/config"
	"github.com/natsumezjr/attack-trace-analyzer/client/backend/internal/storage"
)

type Ingestor struct {
	cfg   config.Config
	store *storage.Store
}

func New(cfg config.Config, store *storage.Store) *Ingestor {
	return &Ingestor{cfg: cfg, store: store}
}

func (i *Ingestor) Start(ctx context.Context) {
	if i.store == nil {
		slog.Warn("ingest disabled: storage is nil")
		return
	}

	opt := collectors.TailOptions{
		StartAtEnd:   true,
		PollInterval: 300 * time.Millisecond,
	}

	if i.cfg.SuricataEveJSON != "" {
		go func() {
			slog.Info("tail suricata eve", "path", i.cfg.SuricataEveJSON)
			_ = collectors.TailFile(ctx, i.cfg.SuricataEveJSON, opt, func(line []byte) error {
				ev, err := suricata.NormalizeEveLine(i.cfg, line)
				if err != nil {
					return err
				}
				return i.store.InsertEvent(ctx, ev)
			})
		}()
	}

	if i.cfg.FalcoEventsJSON != "" {
		go func() {
			slog.Info("tail falco events", "path", i.cfg.FalcoEventsJSON)
			_ = collectors.TailFile(ctx, i.cfg.FalcoEventsJSON, opt, func(line []byte) error {
				ev, err := falco.NormalizeLine(i.cfg, line)
				if err != nil {
					return err
				}
				return i.store.InsertEvent(ctx, ev)
			})
		}()
	}

	if i.cfg.FilebeatEventsJSON != "" {
		go func() {
			slog.Info("tail filebeat events", "path", i.cfg.FilebeatEventsJSON)
			_ = collectors.TailFile(ctx, i.cfg.FilebeatEventsJSON, opt, func(line []byte) error {
				ev, err := filebeat.NormalizeLine(i.cfg, line)
				if err != nil {
					return err
				}
				return i.store.InsertEvent(ctx, ev)
			})
		}()
	}
}
