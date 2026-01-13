package model

import (
	"time"
)

// FalcoEvent 对应数据库中的 falco_events 表
type FalcoEvent struct {
	// gorm:"primaryKey;autoIncrement" 表示这是主键且自增
	ID       uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	
	// ts 对应 ECS @timestamp，通常是时间类型
	Ts       time.Time `gorm:"column:ts" json:"ts"`
	
	Kind     string    `gorm:"column:kind" json:"kind"`
	Severity string    `gorm:"column:severity" json:"severity"`
	Rule     string    `gorm:"column:rule" json:"rule"`
	Message  string    `gorm:"column:message" json:"message"`
	
	// 对应完整 ECS JSON，通常比较长，可以使用 text 类型
	RawJSON  string    `gorm:"column:raw_json;type:text" json:"raw_json"`
}

// TableName 强制指定表名为 falco_events (否则 GORM 默认会找 falco_eventss)
func (FalcoEvent) TableName() string {
	return "falco_events"
}