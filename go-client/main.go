package main

import (
	"flag"
	"go-client/database"
	"go-client/model"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	dbPath := flag.String("db", "data.db", "sqlite database file path")
	flag.Parse()

	// 1. 初始化数据库
	if err := database.InitDB(*dbPath); err != nil {
		log.Fatal(err)
	}

	// 2. 初始化 Gin 引擎
	r := gin.Default()

	// 3. 定义路由：分别读取不同表
	registerEventsRoute(r, "/falco", "falco")
	registerEventsRoute(r, "/suricata", "suricata")
	registerEventsRoute(r, "/wazuh", "wazuh")

	// 4. 启动服务，运行在 0.0.0.0:8888
	r.Run("0.0.0.0:8888")
}

func registerEventsRoute(r *gin.Engine, path string, table string) {
	r.GET(path, func(c *gin.Context) {
		var events []model.EventData

		// 查询逻辑：从指定表中查找所有记录
		result := database.DB.Table(table).Find(&events)

		if result.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": result.Error.Error(),
			})
			return
		}

		// 返回 JSON 数据
		c.JSON(http.StatusOK, gin.H{
			"total": result.RowsAffected, // 返回记录总数
			"data":  events,              // 返回具体数据
		})
	})
}
