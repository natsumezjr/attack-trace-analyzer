package model

// EventData 对应数据库中的 data 表
type EventData struct {
	// gorm:"primaryKey;autoIncrement" 表示这是主键且自增
	ID uint `gorm:"primaryKey;autoIncrement" json:"id"`

	// 对应完整 ECS JSON，通常比较长，可以使用 text 类型
	EventJSON string `gorm:"column:event_json;type:text" json:"event_json"`
}

// TableName 强制指定表名为 data
func (EventData) TableName() string {
	return "data"
}
