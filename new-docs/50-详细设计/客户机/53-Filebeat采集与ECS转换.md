# Filebeat采集与ECS转换

## 文档目的

本文件定义客户机侧 Filebeat 采集、日志输出、Sigma 规则检测与 ECS 字段补齐，并将结果投递到 RabbitMQ 队列的固定规则。

## 读者对象

- 负责客户机实现与部署的同学
- 负责日志证据与验收的同学

## 引用关系

- ECS 字段规范：`../../80-规范/81-ECS字段规范.md`
- 客户机总体：`50-总体.md`
 - 客户机与中心机接口（拉取结构）：`../../80-规范/87-客户机与中心机接口.md`

## 1. 采集输入

### 1.1 采集来源

Filebeat 从宿主机挂载日志目录采集日志：

- `/var/log/host/auth.log`
- `/var/log/host/syslog`
- `/var/log/host/kern.log`

### 1.2 Filebeat 配置文件

容器使用配置文件：

- `client/sensor/filebeat/filebeat-docker.yml`

该配置将 Filebeat 输出写入容器内文件：

- `/tmp/filebeat-output/ecs_logs.json`

## 2. 解析与转换规则

### 2.1 两段式处理

Filebeat 采集链路由两个进程组成：

1. Filebeat：采集日志并写入 `/tmp/filebeat-output/ecs_logs.json`
2. detector：读取新增日志行，应用 Sigma 规则进行异常检测，并将结果发布到 RabbitMQ

detector 入口为：`client/sensor/filebeat/detector.py`。

### 2.2 ECS 关键字段补齐

detector 会对每条日志执行以下固定补齐：

- `ecs.version` 固定写为 `9.2.0`
- `event.ingested` 缺失时写入当前时间

当命中 Sigma 规则时，detector 将该事件标记为告警并补齐：

- `event.kind="alert"`
- `event.category=["intrusion_detection"]`
- `event.type=["indicator"]`
- `event.dataset="finding.raw.filebeat_sigma"`
- `rule.*`、`threat.*`、`custom.*` 等结构化字段

## 3. 会话重建字段

会话与进程实体标识由中心机入库阶段补齐：

- `session.id`：在 `event.dataset="hostlog.auth"` 的 Telemetry 中生成
- `process.entity_id`：在 `event.dataset="hostlog.process"` 的 Telemetry 中生成

具体规则见 `../../80-规范/81-ECS字段规范.md`。

## 4. 队列投递

Filebeat detector 投递到 RabbitMQ：

- 队列：`data.filebeat`
- 连接：`RABBITMQ_URL`
- 队列名：`RABBITMQ_QUEUE`

拉取接口返回前会补齐稳定 `event.id`，规则见 `../../80-规范/87-客户机与中心机接口.md`。

## 5. 故障处理

1. detector 未加载到 Sigma 规则时直接退出，避免产生无规则意义的数据流。
2. RabbitMQ 发布失败时重连后重试发布。
3. 日志解析失败时跳过该行，继续处理后续行，保证持续运行。
