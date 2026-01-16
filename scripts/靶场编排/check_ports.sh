#!/bin/bash
# 检查远程主机端口是否开启的脚本

set -e

# 颜色输出
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 端口列表（与 start.sh 中的验证端口一致）
PORTS=(9200 9600 7474 7687 8001 3000 18881 18882 18883 18884)

# 端口对应的服务名称
declare -A PORT_SERVICES=(
    [9200]="OpenSearch"
    [9600]="OpenSearch (备用)"
    [7474]="Neo4j HTTP"
    [7687]="Neo4j Bolt"
    [8001]="后端 FastAPI"
    [3000]="前端 Next.js"
    [18881]="客户机-01"
    [18882]="客户机-02"
    [18883]="客户机-03"
    [18884]="客户机-04"
)

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

show_help() {
    cat <<EOF
用法: $0 [选项] [远程主机]

选项:
  -h, --help              显示此帮助信息
  -u, --user USER         SSH 用户名（默认: ubuntu）
  -p, --ports PORTS       指定要检查的端口（用逗号分隔，默认: 所有端口）

示例:
  $0                                    # 检查本地端口
  $0 10.92.35.13                       # 检查远程主机端口
  $0 -u ubuntu 10.92.35.13             # 指定 SSH 用户名
  $0 -p 9200,8001,3000                 # 只检查指定端口（本地）
  $0 -p 9200,8001,3000 10.92.35.13     # 只检查指定端口（远程）

默认检查的端口:
  9200  - OpenSearch
  9600  - OpenSearch (备用)
  7474  - Neo4j HTTP
  7687  - Neo4j Bolt
  8001  - 后端 FastAPI
  3000  - 前端 Next.js
  18881 - 客户机-01
  18882 - 客户机-02
  18883 - 客户机-03
  18884 - 客户机-04
EOF
}

# 解析参数
REMOTE_HOST=""
SSH_USER="ubuntu"
CUSTOM_PORTS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -u|--user)
            SSH_USER="$2"
            shift 2
            ;;
        -p|--ports)
            CUSTOM_PORTS="$2"
            shift 2
            ;;
        -*)
            log_error "未知选项: $1"
            show_help
            exit 1
            ;;
        *)
            if [ -z "$REMOTE_HOST" ]; then
                REMOTE_HOST="$1"
            else
                log_error "只能指定一个远程主机"
                show_help
                exit 1
            fi
            shift
            ;;
    esac
done

# 如果指定了自定义端口，使用自定义端口列表
if [ -n "$CUSTOM_PORTS" ]; then
    IFS=',' read -ra PORTS <<< "$CUSTOM_PORTS"
fi

# 检查端口是否开启
check_port() {
    local port=$1
    local remote_host=$2
    local ssh_user=$3
    
    if [ -n "$remote_host" ]; then
        # 远程检查：通过 SSH 执行 ss 命令
        ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
            "$ssh_user@$remote_host" \
            "ss -lntup 2>/dev/null | grep -q \":$port \" && echo 'open' || echo 'closed'" 2>/dev/null
    else
        # 本地检查：直接执行 ss 命令
        ss -lntup 2>/dev/null | grep -q ":$port " && echo "open" || echo "closed"
    fi
}

# 主函数
main() {
    if [ -n "$REMOTE_HOST" ]; then
        log_info "=========================================="
        log_info "检查远程主机端口状态"
        log_info "=========================================="
        log_info "远程主机: $REMOTE_HOST"
        log_info "SSH 用户: $SSH_USER"
        log_info "=========================================="
        
        # 测试 SSH 连接
        if ! ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
            "$SSH_USER@$REMOTE_HOST" "echo 'SSH连接成功'" >/dev/null 2>&1; then
            log_error "无法连接到远程主机 $REMOTE_HOST"
            log_error "请检查："
            log_error "  1. 主机地址是否正确"
            log_error "  2. SSH 服务是否运行"
            log_error "  3. 用户名是否正确"
            log_error "  4. 是否需要配置 SSH 密钥"
            exit 1
        fi
    else
        log_info "=========================================="
        log_info "检查本地端口状态"
        log_info "=========================================="
    fi
    
    log_info ""
    log_info "端口检查结果:"
    log_info "----------------------------------------"
    
    local open_count=0
    local closed_count=0
    local open_ports=()
    local closed_ports=()
    
    for port in "${PORTS[@]}"; do
        local status=$(check_port "$port" "$REMOTE_HOST" "$SSH_USER")
        local service="${PORT_SERVICES[$port]:-未知服务}"
        
        if [ "$status" = "open" ]; then
            echo -e "${GREEN}✓${NC} 端口 $port ($service) - ${GREEN}已开启${NC}"
            open_ports+=("$port")
            open_count=$((open_count + 1))
        else
            echo -e "${RED}✗${NC} 端口 $port ($service) - ${RED}未开启${NC}"
            closed_ports+=("$port")
            closed_count=$((closed_count + 1))
        fi
    done
    
    log_info "----------------------------------------"
    log_info "统计:"
    log_info "  已开启: ${GREEN}$open_count${NC} 个端口"
    log_info "  未开启: ${RED}$closed_count${NC} 个端口"
    
    if [ $closed_count -gt 0 ]; then
        log_info ""
        log_warn "未开启的端口: ${closed_ports[*]}"
    fi
    
    if [ $open_count -eq ${#PORTS[@]} ]; then
        log_info ""
        log_info "所有端口都已开启！"
    fi
    
    log_info "=========================================="
}

# 执行主函数
main
