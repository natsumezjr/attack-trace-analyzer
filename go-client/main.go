package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	// 引入我们自己写的包
	"go-client/database" // 对应 database 文件夹
	"go-client/model"    // 对应 model 文件夹
)

func main() {
	// 1. 初始化数据库
	database.Init()
	
	// (可选) 这里可以调用 database.DB.Create(...) 插入测试数据

	// 2. 启动 Gin
	r := gin.Default()
	api := r.Group("/api")
	{
		// 接口 1: 日志
		api.GET("/logs", func(c *gin.Context) {
			var logs []model.HostLog
			// 使用 database.DB 进行查询
			database.DB.Order("timestamp desc").Limit(100).Find(&logs)
			c.JSON(http.StatusOK, gin.H{"code": 200, "data": logs})
		})

		// 接口 2: 行为
		api.GET("/behaviors", func(c *gin.Context) {
			var behaviors []model.HostBehavior
			database.DB.Order("timestamp desc").Limit(100).Find(&behaviors)
			c.JSON(http.StatusOK, gin.H{"code": 200, "data": behaviors})
		})

		// 接口 3: 流量
		api.GET("/traffic", func(c *gin.Context) {
			var traffic []model.NetworkTraffic
			database.DB.Order("timestamp desc").Limit(100).Find(&traffic)
			c.JSON(http.StatusOK, gin.H{"code": 200, "data": traffic})
		})
	}

	log.Println("边缘节点服务已启动...")
	r.Run(":8080")
}