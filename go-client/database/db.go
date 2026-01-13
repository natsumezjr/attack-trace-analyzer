package database

import (
	"go-client/model"
	"log"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() {
	var err error
	// 连接到当前目录下的 falco.db 文件
	// 如果你的数据库文件在别处，请修改这里的路径
	DB, err = gorm.Open(sqlite.Open("falco_events.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("无法连接数据库: ", err)
	}

	// 自动迁移：如果表不存在，GORM 会自动帮你创建表
	// 生产环境通常手动管理 SQL，但在开发初期这个功能非常方便
	err = DB.AutoMigrate(&model.FalcoEvent{})
	if err != nil {
		log.Fatal("数据库迁移失败: ", err)
	}
}