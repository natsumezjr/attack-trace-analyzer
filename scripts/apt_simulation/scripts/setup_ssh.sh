#!/bin/bash
#
# SSH 免密登录配置脚本
#
# 作用：配置中心机到虚拟机的 SSH 免密登录
#

set -e

echo "=========================================="
echo "SSH 免密登录配置"
echo "=========================================="
echo ""

# 检查是否已存在密钥
if [ ! -f ~/.ssh/id_rsa ]; then
    echo "未找到 SSH 密钥，正在生成..."
    ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""
    echo "✓ 密钥生成完成"
else
    echo "✓ SSH 密钥已存在"
fi

echo ""
echo "请输入 4 个虚拟机的信息："
echo ""

# 虚拟机配置
read -p "victim-01 IP 地址 [默认: 192.168.1.11]: " VM1
VM1=${VM1:-192.168.1.11}

read -p "victim-02 IP 地址 [默认: 192.168.1.12]: " VM2
VM2=${VM2:-192.168.1.12}

read -p "victim-03 IP 地址 [默认: 192.168.1.13]: " VM3
VM3=${VM3:-192.168.1.13}

read -p "victim-04 IP 地址 [默认: 192.168.1.14]: " VM4
VM4=${VM4:-192.168.1.14}

read -p "用户名 [默认: ubuntu]: " USER
USER=${USER:-ubuntu}

echo ""
echo "配置信息："
echo "  victim-01: $USER@$VM1"
echo "  victim-02: $USER@$VM2"
echo "  victim-03: $USER@$VM3"
echo "  victim-04: $USER@$VM4"
echo ""

read -p "确认配置？(y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "已取消"
    exit 1
fi

# 复制公钥到各个虚拟机
echo ""
echo "正在复制公钥到虚拟机..."
echo ""

for HOST in $VM1 $VM2 $VM3 $VM4; do
    echo "→ $USER@$HOST"
    ssh-copy-id -o StrictHostKeyChecking=no "$USER@$HOST" || {
        echo "✗ 失败: $USER@$HOST"
        echo "  请检查："
        echo "  1. 虚拟机是否开机"
        echo "  2. IP 地址是否正确"
        echo "  3. SSH 服务是否运行"
        exit 1
    }
    echo "✓ 成功"
    echo ""
done

echo "=========================================="
echo "配置完成！"
echo "=========================================="
echo ""
echo "验证 SSH 连接..."
echo ""

for HOST in $VM1 $VM2 $VM3 $VM4; do
    if ssh -o ConnectTimeout=5 "$USER@$HOST" "echo '✓ $USER@$HOST 连接成功'"; then
        :
    else
        echo "✗ $USER@$HOST 连接失败"
        exit 1
    fi
done

echo ""
echo "=========================================="
echo "所有配置完成！"
echo "=========================================="
echo ""
echo "现在可以直接从中心机控制虚拟机了"
echo ""
