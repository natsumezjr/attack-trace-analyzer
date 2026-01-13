package database

import (
	"fmt"
	"go-client/model"
	"os"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB(dbPath string) error {
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("找不到数据库文件: %s", dbPath)
		}
		return fmt.Errorf("无法访问数据库文件: %w", err)
	}

	var err error
	// 连接到指定路径的 sqlite 文件
	DB, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("无法连接数据库: %w", err)
	}

	// 自动迁移：如果表不存在，GORM 会自动帮你创建表
	// 生产环境通常手动管理 SQL，但在开发初期这个功能非常方便
	err = DB.AutoMigrate(&model.EventData{})
	if err != nil {
		return fmt.Errorf("数据库迁移失败: %w", err)
	}

	return nil
}
