package database

import (
	"log"
	"os"
	"path/filepath"

	// 引入上面的 model 包 (注意：这里的 edge-node 要换成你 go.mod 里的名字)
	"go-client/model"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// 定义全局 DB 变量，供其他包调用
var DB *gorm.DB

const DB_PATH = "data/edge_monitor.db"

func Init() {
	// 1. 创建目录
	dir := filepath.Dir(DB_PATH)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Fatal("无法创建数据库目录:", err)
	}

	// 2. 连接
	var err error
	DB, err = gorm.Open(sqlite.Open(DB_PATH), &gorm.Config{})
	if err != nil {
		log.Fatal("无法连接数据库:", err)
	}

	// 3. 自动迁移 (引用 model 包里的结构体)
	err = DB.AutoMigrate(&model.HostLog{}, &model.HostBehavior{}, &model.NetworkTraffic{})
	if err != nil {
		log.Fatal("表结构迁移失败:", err)
	}
}