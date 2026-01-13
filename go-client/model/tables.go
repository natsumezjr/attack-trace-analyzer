package model

import "time"

// 1. 主机日志 (Host Logs)
type HostLog struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Timestamp time.Time `json:"@timestamp"`
	HostName  string    `json:"host.name"`
	LogLevel  string    `json:"log.level"`
	Message   string    `json:"message"`
	Service   string    `json:"service.name"`
}

// 2. 主机行为 (Host Behavior)
type HostBehavior struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Timestamp   time.Time `json:"@timestamp"`
	HostName    string    `json:"host.name"`
	ProcessName string    `json:"process.name"`
	PID         int       `json:"process.pid"`
	CommandLine string    `json:"process.command_line"`
	User        string    `json:"user.name"`
	Action      string    `json:"event.action"`
}

// 3. 网络流量 (Network Traffic)
type NetworkTraffic struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Timestamp time.Time `json:"@timestamp"`
	SrcIP     string    `json:"source.ip"`
	SrcPort   int       `json:"source.port"`
	DstIP     string    `json:"destination.ip"`
	DstPort   int       `json:"destination.port"`
	Bytes     int64     `json:"network.bytes"`
	Protocol  string    `json:"network.transport"`
	Direction string    `json:"network.direction"`
}