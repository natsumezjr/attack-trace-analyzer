# RabbitMQ缓冲与队列语义

## 文档目的

本文件定义客户机侧 RabbitMQ 作为本地缓冲区的队列命名、消费语义、断连恢复与容量边界。

## 读者对象

- 负责客户机实现与部署的同学
- 负责稳定性与排障的同学

## 引用关系

- 客户机总体：`50-总体.md`
- 客户机与中心机接口：`../../80-规范/87-客户机与中心机接口.md`

## 1. 队列命名

客户机侧固定使用 3 个队列承载三类数据源：

| 数据源 | 默认队列名 | 环境变量 |
|---|---|---|
| Falco | `data.falco` | `FALCO_QUEUE` 或 `RABBITMQ_QUEUE` |
| Filebeat | `data.filebeat` | `FILEBEAT_QUEUE` 或 `RABBITMQ_QUEUE` |
| Suricata | `data.suricata` | `SURICATA_QUEUE` 或 `RABBITMQ_QUEUE` |

实际取值以 `client/docker-compose.yml` 为准。

### 1.1 消息流转架构

```mermaid
flowchart TD
    subgraph Producers["数据生产者"]
        FalcoECS[falco-ecs<br/>发布到 data.falco]
        FilebeatDetector[filebeat detector<br/>发布到 data.filebeat]
        SuricataExporter[suricata exporter<br/>发布到 data.suricata]
    end

    subgraph RabbitMQ["RabbitMQ 服务器"]
        QFalco[队列: data.falco<br/>durable 为 true]
        QFilebeat[队列: data.filebeat<br/>durable 为 true]
        QSuricata[队列: data.suricata<br/>durable 为 true]
    end

    subgraph Consumer["数据消费者"]
        Backend[客户机 Backend<br/>Gin API]
        APIS["<br/>GET /falco<br/>GET /filebeat<br/>GET /suricata"]
    end

    FalcoECS -->|publish| QFalco
    FilebeatDetector -->|publish| QFilebeat
    SuricataExporter -->|publish| QSuricata

    Backend -->|basic.get + ack| QFalco
    Backend -->|basic.get + ack| QFilebeat
    Backend -->|basic.get + ack| QSuricata

    Backend --> APIS

    classDef producerStyle fill:#e1f5fe,stroke:#0277bd,stroke-width:2px
    classDef queueStyle fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef consumerStyle fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px

    class FalcoECS,FilebeatDetector,SuricataExporter producerStyle
    class QFalco,QFilebeat,QSuricata queueStyle
    class Backend,APIS consumerStyle
```

## 2. 消费语义与增量语义

中心机通过客户机拉取接口拉取数据时，客户机 Go 后端会从队列中逐条读取消息并确认：

- 使用 `basic.get` 从队列拉取
- 拉取到的消息在返回前执行 `ack`
- 当队列为空时，接口返回空数组

因此，增量语义由 RabbitMQ 队列保证，不使用游标机制。

### 2.1 队列消费时序

```mermaid
sequenceDiagram
    participant Center as 中心机<br/>轮询器
    participant Backend as 客户机<br/>Backend API
    participant Queue as RabbitMQ<br/>队列
    participant Producer as 数据生产者<br/>falco-ecs/filebeat/suricata

    Note over Producer,Queue: 生产阶段
    Producer->>Queue: basic_publish(msg1)
    Producer->>Queue: basic_publish(msg2)
    Producer->>Queue: basic_publish(msg3)

    Note over Center,Queue: 消费阶段
    Center->>Backend: GET /falco

    Backend->>Queue: basic_get(queue)
    Queue-->>Backend: msg1 (delivery_tag=1)

    Backend->>Queue: basic_ack(delivery_tag=1)

    Backend->>Queue: basic_get(queue)
    Queue-->>Backend: msg2 (delivery_tag=2)

    Backend->>Queue: basic_ack(delivery_tag=2)

    Backend->>Queue: basic_get(queue)
    Queue-->>Backend: msg3 (delivery_tag=3)

    Backend->>Queue: basic_ack(delivery_tag=3)

    Backend->>Queue: basic_get(queue)
    Queue-->>Backend: null (队列为空)

    Backend-->>Center: 200 OK<br/>返回 3 条消息

    Note over Queue: 消息已 ack，不再返回
```

## 3. 幂等与重复处理

### 3.1 拉取层幂等

同一条消息被 `ack` 后不再被后续拉取返回，避免重复。

### 3.2 入库层幂等

中心机入库以 `event.id` 去重，重复写入不产生重复文档，见 `../../80-规范/81-ECS字段规范.md`。

## 4. 断连与恢复

RabbitMQ 连接断开时：

1. 客户机 Go 后端在下一次拉取请求到来时重连；
2. 重连失败时接口返回 500 错误并携带 `error` 字段；
3. 中心机会在下一轮轮询继续重试，并更新注册表中的错误信息。

## 5. 容量边界

RabbitMQ 的容量边界由宿主机磁盘与 RabbitMQ 默认策略决定。

为了保证演示稳定性：

1. 靶场运行前必须清理历史队列数据；
2. 复现与演示过程中，若出现磁盘空间不足，按 `../../90-运维与靶场/95-重置复现与排障.md` 执行清理后重跑。
