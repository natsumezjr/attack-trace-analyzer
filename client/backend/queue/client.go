package queue

import (
	"encoding/json"
	"fmt"
	"log"
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

	var out []json.RawMessage
	for {
		msg, ok, err := ch.Get(queueName, false)
		if err != nil {
			return nil, fmt.Errorf("rabbitmq get from %s: %w", queueName, err)
		}
		if !ok {
			break
		}
		if json.Valid(msg.Body) {
			out = append(out, msg.Body)
		}
		if err := msg.Ack(false); err != nil {
			c.log.Printf("rabbitmq ack failed for %s: %v", queueName, err)
		}
	}
	return out, nil
}
