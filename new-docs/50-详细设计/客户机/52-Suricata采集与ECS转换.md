# Suricata采集与ECS转换

## 文档目的

本文件定义客户机侧 Suricata 的采集方式、EVE 日志处理、以及转换为 ECS 子集字段并投递到 RabbitMQ 队列的固定规则。

## 读者对象

- 负责客户机实现与部署的同学
- 负责网络证据与验证的同学

## 引用关系

- ECS 字段规范：`../../80-规范/81-ECS字段规范.md`
- 客户机总体：`50-总体.md`
 - 客户机与中心机接口（拉取结构）：`../../80-规范/87-客户机与中心机接口.md`

## 1. 采集输入

### 1.1 Suricata 引擎

Suricata 引擎由容器 `suricata` 运行，启动脚本为：

- `client/sensor/suricata/engine/run-suricata.sh`

Suricata 输出 EVE 日志文件，供导出器消费：

- 默认路径：`/data/eve.json`

### 1.2 关键运行参数

Suricata 运行参数由环境变量确定：

- `SURICATA_MODE`：运行模式（`live` 或 `pcap`）
- `SURICATA_INTERFACE`：抓包网卡名
- `SURICATA_HOME_NET`：HOME_NET 地址组

上述变量的取值与运行行为在 `client/sensor/suricata/engine/run-suricata.sh` 中实现。

## 2. 转换规则

### 2.1 导出器位置

Suricata EVE 导出器位于：

- `client/sensor/suricata/exporter/app.py`

导出器持续读取 EVE 文件新增内容，解析为 ECS 子集并发布到 RabbitMQ 队列。

### 2.2 输出字段形态

Suricata 导出器输出为**点号扁平键形态**（例如 `event.dataset`、`source.ip`），中心机会在入库前把点号键合并为嵌套对象形态。

### 2.3 dataset 取值范围

Suricata 导出器根据 `event_type` 映射 dataset，取值固定在以下集合中：

- `netflow.flow`
- `netflow.dns`
- `netflow.http`

## 3. 网络字段与证据引用

Suricata 导出器按以下规则写入网络相关字段：

- `source.ip`、`source.port`
- `destination.ip`、`destination.port`
- `network.transport`、`network.protocol`
- `flow.id`、`network.community_id`

字段口径见 `../../80-规范/81-ECS字段规范.md`。

## 4. 队列投递

Suricata 导出器投递到 RabbitMQ：

- 队列：`data.suricata`
- `RABBITMQ_URL`、`RABBITMQ_QUEUE` 由容器环境变量指定

拉取接口返回前会补齐稳定 `event.id`，规则见 `../../80-规范/87-客户机与中心机接口.md`。

## 5. 故障处理

1. EVE 文件不存在时，导出器会创建必要目录并持续等待。
2. RabbitMQ 发布失败时，导出器会重连后重试发布。
3. 任意单条 EVE 行解析失败时，导出器跳过该行并继续处理后续行。
