package database

import (
	"fmt"
	"os"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var FalcoDB *gorm.DB
var FilebeatDB *gorm.DB
var SuricataDB *gorm.DB

func openDB(dbPath string) (*gorm.DB, error) {
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			file, createErr := os.Create(dbPath)
			if createErr != nil {
				return nil, fmt.Errorf("无法创建数据库文件: %w", createErr)
			}
			if closeErr := file.Close(); closeErr != nil {
				return nil, fmt.Errorf("无法关闭数据库文件: %w", closeErr)
			}
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("无法访问数据库文件: %w", err)
		}
	}

	// 连接到指定路径的 sqlite 文件
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("无法连接数据库: %w", err)
	}

	return db, nil
}

func InitDBs(falcoPath string, filebeatPath string, suricataPath string) error {
	var err error
	FalcoDB, err = openDB(falcoPath)
	if err != nil {
		return fmt.Errorf("falco 数据库初始化失败: %w", err)
	}

	FilebeatDB, err = openDB(filebeatPath)
	if err != nil {
		return fmt.Errorf("filebeat 数据库初始化失败: %w", err)
	}

	SuricataDB, err = openDB(suricataPath)
	if err != nil {
		return fmt.Errorf("suricata 数据库初始化失败: %w", err)
	}

	return nil
}
