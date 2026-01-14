package main

import (
	"flag"
	"go-client/database"
	"go-client/model"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func main() {
	falcoDBPath := flag.String("falco-db", "falco.db", "falco sqlite database file path")
	filebeatDBPath := flag.String("filebeat-db", "filebeat.db", "filebeat sqlite database file path")
	suricataDBPath := flag.String("suricata-db", "suricata.db", "suricata sqlite database file path")
	flag.Parse()

	// 1. 初始化数据库
	if err := database.InitDBs(*falcoDBPath, *filebeatDBPath, *suricataDBPath); err != nil {
		log.Fatal(err)
	}

	// 2. 初始化 Gin 引擎
	r := gin.Default()

	// 3. 定义路由：分别读取不同表
	registerEventsRoute(r, "/falco", "falco", database.FalcoDB)
	registerEventsRoute(r, "/suricata", "suricata", database.SuricataDB)
	registerEventsRoute(r, "/filebeat", "filebeat", database.FilebeatDB)

	// 4. 启动服务，运行在 0.0.0.0:8888
	r.Run("0.0.0.0:8888")
}

func registerEventsRoute(r *gin.Engine, path string, table string, db *gorm.DB) {
	r.GET(path, func(c *gin.Context) {
		var events []model.EventData

		// 查询逻辑：从指定表中查找所有记录
		result := db.Table(table).Find(&events)

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
