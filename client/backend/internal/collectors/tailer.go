package collectors

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"time"
)

type TailOptions struct {
	// If true, start tailing from end-of-file (recommended for very large existing logs).
	StartAtEnd bool

	// How often to poll when reaching EOF.
	PollInterval time.Duration
}

func TailFile(ctx context.Context, path string, opt TailOptions, onLine func([]byte) error) error {
	if path == "" {
		return errors.New("path is empty")
	}
	if onLine == nil {
		return errors.New("onLine is nil")
	}
	if opt.PollInterval <= 0 {
		opt.PollInterval = 500 * time.Millisecond
	}

	for {
		if err := tailOnce(ctx, path, opt, onLine); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			slog.Warn("tailer error, will reopen", "path", path, "error", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1 * time.Second):
		}
	}
}

func tailOnce(ctx context.Context, path string, opt TailOptions, onLine func([]byte) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if opt.StartAtEnd {
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			return err
		}
	}

	reader := bufio.NewReaderSize(f, 256*1024)
	var offset int64
	if pos, err := f.Seek(0, io.SeekCurrent); err == nil {
		offset = pos
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line, err := reader.ReadBytes('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				// Detect truncation/rotation.
				if st, statErr := f.Stat(); statErr == nil {
					if st.Size() < offset {
						return errors.New("file truncated (rotation?)")
					}
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(opt.PollInterval):
				}
				continue
			}
			return err
		}

		offset += int64(len(line))
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		if err := onLine(line); err != nil {
			// Parsing errors should not kill the tailer.
			slog.Warn("line handler error", "path", path, "error", err)
		}
	}
}
