package queue

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"

	amqp "github.com/rabbitmq/amqp091-go"
)

type Client struct {
	url  string
	log  *log.Logger
	conn *amqp.Connection
	mu   sync.Mutex
}

func NewClient(url string, logger *log.Logger) (*Client, error) {
	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, fmt.Errorf("rabbitmq connect failed: %w", err)
	}
	return &Client{
		url:  url,
		log:  logger,
		conn: conn,
	}, nil
}

func (c *Client) Close() {
	if c.conn != nil && !c.conn.IsClosed() {
		_ = c.conn.Close()
	}
}

func ensureEventID(body []byte) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}

	if existing, ok := doc["event.id"].(string); ok && strings.TrimSpace(existing) != "" {
		return body, nil
	}
	if ev, ok := doc["event"].(map[string]any); ok {
		if existing, ok := ev["id"].(string); ok && strings.TrimSpace(existing) != "" {
			return body, nil
		}
	}

	sum := sha1.Sum(body)
	full := fmt.Sprintf("%x", sum[:])
	eventID := "evt-" + full[:16]

	ev, ok := doc["event"].(map[string]any)
	if !ok || ev == nil {
		ev = map[string]any{}
		doc["event"] = ev
	}
	ev["id"] = eventID

	out, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) FetchAll(queueName string) ([]json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil || c.conn.IsClosed() {
		conn, err := amqp.Dial(c.url)
		if err != nil {
			return nil, fmt.Errorf("rabbitmq reconnect failed: %w", err)
		}
		c.conn = conn
	}

	ch, err := c.conn.Channel()
	if err != nil {
		return nil, fmt.Errorf("rabbitmq channel error: %w", err)
	}
	defer ch.Close()

	_, err = ch.QueueDeclare(queueName, true, false, false, false, nil)
	if err != nil {
		return nil, fmt.Errorf("rabbitmq declare queue %s: %w", queueName, err)
	}

	out := make([]json.RawMessage, 0)
	for {
		msg, ok, err := ch.Get(queueName, false)
		if err != nil {
			return nil, fmt.Errorf("rabbitmq get from %s: %w", queueName, err)
		}
		if !ok {
			break
		}
		if !json.Valid(msg.Body) {
			c.log.Printf("rabbitmq message dropped: invalid json payload queue=%s bytes=%d", queueName, len(msg.Body))
		} else {
			withID, err := ensureEventID(msg.Body)
			if err != nil {
				// Ensure we only return valid JSON objects (dict) per docs/87; bad payloads are logged then dropped.
				c.log.Printf("rabbitmq message dropped: ensure event.id failed queue=%s err=%v", queueName, err)
			} else {
				out = append(out, withID)
			}
		}
		if err := msg.Ack(false); err != nil {
			c.log.Printf("rabbitmq ack failed for %s: %v", queueName, err)
		}
	}
	return out, nil
}
