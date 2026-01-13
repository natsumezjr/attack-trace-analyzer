package main

import (
	"go-client/database"
	"go-client/model"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	// 1. 初始化数据库
	database.InitDB()

	// 2. 初始化 Gin 引擎
	r := gin.Default()

	// 3. 定义路由 GET /falco_events
	r.GET("/falco_events", func(c *gin.Context) {
		var events []model.FalcoEvent

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

	// 4. 启动服务，默认运行在 :8080
	// 如果想修改端口，可以使用 r.Run(":8888")
	r.Run() 
}