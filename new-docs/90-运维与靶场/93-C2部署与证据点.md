# c2-01（DNS + HTTP）：macvlan 优先方案

你只有一台宿主机时，C2 的关键不是“多高级”，而是两点：

1) **DNS+HTTP 服务稳定可用**
2) **client 访问 C2 的流量能被 Suricata 在 `ens5f1` 上观测到**

为此推荐：给 c2-01 分配一个**独立内网 IP**（macvlan），例如 `10.92.35.50`，并把域名 `c2.lab.local` 解析到该 IP。

---

## 1. 为什么要 macvlan（必须理解）

如果 C2 直接用宿主机自己的 IP（`10.92.35.13`）：

- client 访问 C2 很可能走本机协议栈/loopback
- Suricata 抓 `ens5f1` 时不一定看得到（你会误以为“没流量/没证据”）

macvlan 让容器拥有一个“像真实另一台机器”的内网 IP，宿主访问该 IP 会真实走 `ens5f1`，更利于观测与演示。

---

## 2. 你要固定的“可观测行为”

建议固定以下约定，后续演示全部用它们：

- 域名：`c2.lab.local`
- DNS 解析：`c2.lab.local -> 10.92.35.50`
- HTTP 路径：
  - `http://c2.lab.local/health`
  - `http://c2.lab.local/payload`（内容为无害文本即可）

这样你能稳定产生：

- DNS 查询（Host/Process → Domain）
- 域名解析（Domain → IP）
- HTTP 连接（Host/Process → IP:80）

---

## 3. 方案 A（推荐）：CoreDNS + nginx

### 3.1 DNS：CoreDNS

CoreDNS 用最简单的 A 记录即可。

你需要两类配置概念：

- `Corefile`：监听 `:53`，加载 zone
- zone 文件：写 `c2.lab.local` 的 A 记录

### 3.2 HTTP：nginx

nginx 提供两个路径返回固定内容即可：

- `/health` → 200
- `/payload` → 200（文本）

---

## 4. macvlan 部署检查清单（你落地时按这个逐项验证）

在你真正写 compose 之前，先验证“环境是否支持 macvlan”：

- 你的内网网段是 `10.92.35.0/24`，网卡 `ens5f1`
- 你选择的 IP（例如 `10.92.35.50`）未被占用（ping 不通/ARP 无响应）

验证成功标准（非常具体）：

- 在宿主机执行 DNS 查询，`c2.lab.local` 返回 `10.92.35.50`
- 在宿主机访问 `http://10.92.35.50/health` 返回 200
- 用 tcpdump/Suricata 抓 `ens5f1` 能看到到 `10.92.35.50:53` 与 `:80` 的流量

---

## 5. 备选方案（macvlan 不可用时）

如果你内网环境不允许 macvlan（少数云环境会限制），你仍然可以：

- 把 DNS/HTTP 用 host network 跑起来（简单）
- 但为了让 Suricata 在 `ens5f1` 可观测，最好让“发起请求”的主体不是宿主机自己：
  - 用一台外部操作机（你的笔记本/另一台内网机器）去访问 C2（这样流量会进出 `ens5f1`）

---

下一步：把这套 C2 加入靶场整体验证流程，见：

- `04-验证清单（网络-采集-证据）.md`

