package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"go-client/queue"

	"github.com/gin-gonic/gin"
)

func main() {
	amqpURL := getEnv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq:5672/")
	falcoQueue := getEnv("FALCO_QUEUE", "data.falco")
	filebeatQueue := getEnv("FILEBEAT_QUEUE", "data.filebeat")
	suricataQueue := getEnv("SURICATA_QUEUE", "data.suricata")
	serverIP := strings.TrimSpace(getEnv("SERVER_IP", ""))
	selfIP := strings.TrimSpace(getEnv("SELF_IP", ""))

	// NOTE: Client self-registration is best-effort and optional.
	// The recommended deployment flow registers clients via the center backend
	// `/api/v1/clients/register` (see docs/90-运维与靶场/92-一键编排.md).
	//
	// Keeping this optional avoids hard failures when the center is not up yet,
	// or when SERVER_IP/SELF_IP are not configured in multi-instance setups.
	if serverIP != "" {
		if selfIP == "" {
			detected, err := getLocalIPv4()
			if err != nil {
				log.Printf("WARN: failed to detect local IP, skip registration (set SELF_IP): %v", err)
			} else {
				selfIP = detected
			}
		}
		if selfIP != "" {
			if err := registerTarget(serverIP, selfIP); err != nil {
				log.Printf("WARN: failed to register target (non-fatal): %v", err)
			}
		}
	}

	client, err := queue.NewClient(amqpURL, log.Default())
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// 2. 初始化 Gin 引擎
	r := gin.Default()

	// 3. 定义路由：分别读取不同表
	registerEventsRoute(r, "/falco", client, falcoQueue)
	registerEventsRoute(r, "/suricata", client, suricataQueue)
	registerEventsRoute(r, "/filebeat", client, filebeatQueue)

	// 4. 启动服务，运行在 0.0.0.0:8888
	r.Run("0.0.0.0:8888")
}

func registerEventsRoute(r *gin.Engine, path string, client *queue.Client, queueName string) {
	r.GET(path, func(c *gin.Context) {
		events, err := client.FetchAll(queueName)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"total": len(events),
			"data":  events,
		})
	})
}

func getEnv(key string, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	return val
}

func registerTarget(serverIP string, selfIP string) error {
	registerURL := buildServerURL(serverIP) + "/api/v1/targets/register"
	payload := map[string]string{"ip": selfIP}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal register payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, registerURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create register request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send register request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		msg := strings.TrimSpace(string(respBody))
		if msg == "" {
			msg = "empty response body"
		}
		return fmt.Errorf("register request failed with %s: %s", resp.Status, msg)
	}

	return nil
}

func buildServerURL(serverIP string) string {
	serverIP = strings.TrimRight(serverIP, "/")
	if strings.HasPrefix(serverIP, "http://") || strings.HasPrefix(serverIP, "https://") {
		return serverIP
	}
	return "http://" + serverIP
}

func getLocalIPv4() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("list interfaces: %w", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			ip = ip.To4()
			if ip == nil || ip.IsLoopback() {
				continue
			}
			return ip.String(), nil
		}
	}
	return "", errors.New("no non-loopback IPv4 address found")
}
