package main

import (
	"log"
	"net/http"
	"os"

	"go-client/queue"

	"github.com/gin-gonic/gin"
)

func main() {
	amqpURL := getEnv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq:5672/")
	falcoQueue := getEnv("FALCO_QUEUE", "data.falco")
	filebeatQueue := getEnv("FILEBEAT_QUEUE", "data.filebeat")
	suricataQueue := getEnv("SURICATA_QUEUE", "data.suricata")

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
