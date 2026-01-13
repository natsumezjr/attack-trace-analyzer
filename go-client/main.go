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

	// 3. 定义路由 GET /falco_events
	r.GET("/falco_events", func(c *gin.Context) {
		var events []model.EventData

		// 查询逻辑：从数据库中查找所有记录
		// Result 包含了查询结果和错误信息
		result := database.DB.Find(&events)

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

	// 4. 启动服务，运行在 0.0.0.0:8888
	r.Run("0.0.0.0:8888")
}
