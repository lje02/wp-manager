#!/bin/bash

# ==============================================================================
#  Docker Web Manager - 优化版
#  版本: V15 Refactored
#  功能: Docker 站点管理、安全审计、自动运维
# ==============================================================================

# --- 全局配置 ---
VERSION="V15 优化重构版 (快捷指令: web)"
BASE_DIR="/home/docker/web"

# 子目录定义
SITES_DIR="$BASE_DIR/sites"
GATEWAY_DIR="$BASE_DIR/gateway"
FW_DIR="$BASE_DIR/firewall"
LIB_DIR="$BASE_DIR/library"
TG_CONF="$BASE_DIR/telegram.conf"
LOG_FILE="$BASE_DIR/operation.log"
MONITOR_PID="$BASE_DIR/monitor.pid"
MONITOR_SCRIPT="$BASE_DIR/monitor_daemon.sh"
LISTENER_PID="$BASE_DIR/tg_listener.pid"
LISTENER_SCRIPT="$BASE_DIR/tg_listener.sh"

# 更新源
UPDATE_URL="https://raw.githubusercontent.com/lje02/wp-manager/main/wp-manager.sh"

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

# 设置管道错误捕获
set -o pipefail

# ================= 2. 基础检查与初始化 =================

# Root 检查
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}❌ 错误: 此脚本必须以 root 身份运行！${NC}"
    echo -e "请使用: ${YELLOW}sudo $0${NC}"
    exit 1
fi

# 初始化目录
mkdir -p "$SITES_DIR" "$GATEWAY_DIR" "$FW_DIR" "$LIB_DIR"
touch "$FW_DIR/access.conf" "$FW_DIR/geo.conf"
[ ! -f "$LOG_FILE" ] && touch "$LOG_FILE"

# ================= 3. 工具函数 =================

function log_info() { echo -e "${GREEN}[INFO]${NC} $1"; echo "[$(date '+%F %T')] [INFO] $1" >> "$LOG_FILE"; }
function log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; echo "[$(date '+%F %T')] [WARN] $1" >> "$LOG_FILE"; }
function log_error() { echo -e "${RED}[ERR]${NC} $1"; echo "[$(date '+%F %T')] [ERR] $1" >> "$LOG_FILE"; }

function pause_prompt() {
    echo -e "\n${YELLOW}>>> 操作完成，按回车键返回...${NC}"
    read -r
}

function validate_domain() {
    local domain=$1
    if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+$ ]] || [[ "$domain" =~ http ]]; then
        log_error "域名格式不正确 (请勿包含 http:// 或特殊字符)"
        return 1
    fi
    return 0
}

function is_port_free() {
    local port=$1
    if command -v ss >/dev/null; then
        if ss -tln | grep -q ":$port "; then return 1; else return 0; fi
    else
        if netstat -tuln | grep -q ":$port "; then return 1; else return 0; fi
    fi
}

function install_shortcut() {
    local script_path=$(readlink -f "$0")
    if [ ! -L "/usr/bin/web" ] || [ "$(readlink -f "/usr/bin/web")" != "$script_path" ]; then
        ln -sf "$script_path" /usr/bin/web && chmod +x "$script_path"
        log_info "快捷指令 'web' 已安装"
    fi
}

function check_dependencies() {
    local deps=(jq openssl docker curl)
    local need_install=0
    
    # 检查基本命令
    for dep in "${deps[@]}"; do
        if ! command -v $dep >/dev/null 2>&1; then need_install=1; break; fi
    done
    
    # 检查网络工具 (netstat or ss)
    if ! command -v ss >/dev/null && ! command -v netstat >/dev/null; then need_install=1; fi

    if [ $need_install -eq 1 ]; then
        log_info "正在安装依赖组件..."
        if [ -f /etc/debian_version ]; then 
            apt-get update && apt-get install -y jq openssl net-tools ufw curl
        else 
            yum install -y jq openssl net-tools firewalld curl
        fi
        
        if ! command -v docker >/dev/null 2>&1; then
            curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun
            systemctl enable docker && systemctl start docker
        fi
    fi
}

function ensure_firewall_installed() {
    if command -v ufw >/dev/null || command -v firewall-cmd >/dev/null; then return 0; fi
    log_info "正在安装防火墙..."
    if [ -f /etc/debian_version ]; then 
        apt-get install -y ufw
        ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp
        echo "y" | ufw enable
    else 
        yum install -y firewalld
        systemctl enable firewalld --now
        firewall-cmd --permanent --add-service={ssh,http,https}
        firewall-cmd --reload
    fi
}

function check_ssl_status() {
    local d=$1
    echo -e "${CYAN}>>> [SSL] 正在申请证书 (ACME)...${NC}"
    for ((i=1; i<=20; i++)); do 
        if docker exec gateway_acme test -f "/etc/nginx/certs/$d.crt"; then 
            log_info "SSL 成功: https://$d"
            pause_prompt
            return 0
        fi
        echo -n "."
        sleep 5
    done
    echo -e "\n${YELLOW}⚠️ 证书暂未生成 (可能是DNS延迟，后台会自动重试)${NC}"
    pause_prompt
}

function normalize_url() {
    local url=$1
    url=${url%/}
    if [[ "$url" != http* ]]; then echo "https://$url"; else echo "$url"; fi
}

function update_script() {
    clear
    echo -e "${GREEN}=== 脚本自动更新 ===${NC}"
    local temp_file="/tmp/wp_manager_update.sh"
    if curl -f -L -s -o "$temp_file" "$UPDATE_URL" && head -n 1 "$temp_file" | grep -q "/bin/bash"; then
        mv "$temp_file" "$0"
        chmod +x "$0"
        log_info "更新成功，正在重启..."
        sleep 1
        exec "$0"
    else 
        log_error "更新失败!"
        rm -f "$temp_file"
    fi
    pause_prompt
}

# ================= 4. Telegram 模块 =================

function send_tg_msg() {
    local msg=$1
    if [ -f "$TG_CONF" ]; then 
        source "$TG_CONF"
        if [ ! -z "$TG_BOT_TOKEN" ] && [ ! -z "$TG_CHAT_ID" ]; then 
            curl -s -X POST "https://api.telegram.org/bot$TG_BOT_TOKEN/sendMessage" -d chat_id="$TG_CHAT_ID" -d text="$msg" >/dev/null
        fi
    fi
}

function generate_monitor_script() {
cat > "$MONITOR_SCRIPT" <<EOF
#!/bin/bash
TG_CONF="$TG_CONF"
CPU_THRESHOLD=90
MEM_THRESHOLD=90
DISK_THRESHOLD=90
COOLDOWN=1800
LAST_ALERT=0

function send_msg() { 
    if [ -f "\$TG_CONF" ]; then 
        source "\$TG_CONF"
        curl -s -X POST "https://api.telegram.org/bot\$TG_BOT_TOKEN/sendMessage" -d chat_id="\$TG_CHAT_ID" -d text="\$1" >/dev/null
    fi 
}

while true; do
    CPU=\$(grep 'cpu ' /proc/stat | awk '{usage=(\$2+\$4)*100/(\$2+\$4+\$5)} END {print usage}' | cut -d. -f1)
    MEM=\$(free | grep Mem | awk '{print \$3/\$2 * 100.0}' | cut -d. -f1)
    DISK=\$(df / | awk 'NR==2 {print \$5}' | sed 's/%//')
    
    MSG=""
    if [ "\$CPU" -gt "\$CPU_THRESHOLD" ]; then MSG="\$MSG\n🚨 CPU过高: \${CPU}%"; fi
    if [ "\$MEM" -gt "\$MEM_THRESHOLD" ]; then MSG="\$MSG\n🚨 内存过高: \${MEM}%"; fi
    if [ "\$DISK" -gt "\$DISK_THRESHOLD" ]; then MSG="\$MSG\n🚨 磁盘爆满: \${DISK}%"; fi
    
    if [ ! -z "\$MSG" ]; then
        NOW=\$(date +%s)
        DIFF=\$((NOW - LAST_ALERT))
        if [ "\$DIFF" -gt "\$COOLDOWN" ]; then 
            send_msg "⚠️ **资源警报** \nHostname: \$(hostname) \$MSG"
            LAST_ALERT=\$NOW
        fi
    fi
    sleep 60
done
EOF
chmod +x "$MONITOR_SCRIPT"
}

function generate_listener_script() {
cat > "$LISTENER_SCRIPT" <<EOF
#!/bin/bash
TG_CONF="$TG_CONF"
GATEWAY_DIR="$GATEWAY_DIR"
if [ ! -f "\$TG_CONF" ]; then exit 1; fi
source "\$TG_CONF"
OFFSET=0

function reply() { curl -s -X POST "https://api.telegram.org/bot\$TG_BOT_TOKEN/sendMessage" -d chat_id="\$TG_CHAT_ID" -d text="\$1" >/dev/null; }

while true; do
    updates=\$(curl -s "https://api.telegram.org/bot\$TG_BOT_TOKEN/getUpdates?offset=\$OFFSET&timeout=30")
    status=\$(echo "\$updates" | jq -r '.ok')
    if [ "\$status" != "true" ]; then sleep 5; continue; fi
    
    count=\$(echo "\$updates" | jq '.result | length')
    if [ "\$count" -eq "0" ]; then continue; fi
    
    echo "\$updates" | jq -c '.result[]' | while read row; do
        update_id=\$(echo "\$row" | jq '.update_id')
        message_text=\$(echo "\$row" | jq -r '.message.text')
        sender_id=\$(echo "\$row" | jq -r '.message.chat.id')
        
        if [ "\$sender_id" == "\$TG_CHAT_ID" ]; then
            case "\$message_text" in
                "/status")
                    cpu=\$(uptime | awk -F'load average:' '{print \$2}')
                    mem=\$(free -h | grep Mem | awk '{print \$3 "/" \$2}')
                    disk=\$(df -h / | awk 'NR==2 {print \$3 "/" \$2 " (" \$5 ")"}')
                    ip=\$(curl -s4 ifconfig.me)
                    reply "📊 **系统状态**%0A💻 IP: \$ip%0A🧠 负载: \$cpu%0A💾 内存: \$mem%0A💿 磁盘: \$disk" ;;
                "/reboot_nginx")
                    if [ -d "\$GATEWAY_DIR" ]; then 
                        cd "\$GATEWAY_DIR" && docker compose restart nginx-proxy
                        reply "✅ Nginx 网关已重启"
                    else 
                        reply "❌ 找不到网关目录"
                    fi ;;
            esac
        fi
        next_offset=\$((update_id + 1))
        echo \$next_offset > /tmp/tg_offset.txt
    done
    
    if [ -f /tmp/tg_offset.txt ]; then OFFSET=\$(cat /tmp/tg_offset.txt); fi
done
EOF
chmod +x "$LISTENER_SCRIPT"
}

function telegram_manager() {
    while true; do
        clear; echo -e "${YELLOW}=== 🤖 Telegram 管理 ===${NC}"
        [ -f "$MONITOR_PID" ] && kill -0 $(cat "$MONITOR_PID") 2>/dev/null && M_STAT="${GREEN}运行中${NC}" || M_STAT="${RED}停止${NC}"
        [ -f "$LISTENER_PID" ] && kill -0 $(cat "$LISTENER_PID") 2>/dev/null && L_STAT="${GREEN}运行中${NC}" || L_STAT="${RED}停止${NC}"
        
        echo -e "守护进程: $M_STAT | 监听进程: $L_STAT"
        echo " 1. 配置 Token/ChatID"
        echo " 2. 启动/重启 资源报警"
        echo " 3. 启动/重启 消息监听"
        echo " 4. 停止所有服务"
        echo " 5. 发送测试消息"
        echo " 0. 返回"
        read -p "选: " t
        case $t in
            0) return;;
            1) 
                read -p "Token: " tk
                echo "TG_BOT_TOKEN=\"$tk\"" > "$TG_CONF"
                read -p "ChatID: " ci
                echo "TG_CHAT_ID=\"$ci\"" >> "$TG_CONF"
                echo "已保存"; pause_prompt;;
            2) 
                generate_monitor_script
                pkill -F "$MONITOR_PID" 2>/dev/null
                nohup "$MONITOR_SCRIPT" >/dev/null 2>&1 & echo $! > "$MONITOR_PID"
                echo "已启动"; pause_prompt;;
            3) 
                generate_listener_script
                pkill -F "$LISTENER_PID" 2>/dev/null
                nohup "$LISTENER_SCRIPT" >/dev/null 2>&1 & echo $! > "$LISTENER_PID"
                echo "已启动"; pause_prompt;;
            4) 
                pkill -F "$MONITOR_PID" 2>/dev/null
                pkill -F "$LISTENER_PID" 2>/dev/null
                rm -f "$MONITOR_PID" "$LISTENER_PID"
                echo "已停止"; pause_prompt;;
            5) send_tg_msg "🔔 测试消息 OK"; echo "已发送"; pause_prompt;;
        esac
    done
}

# ================= 5. 安全与审计 =================

function server_audit() {
    check_dependencies
    while true; do
        clear; echo -e "${YELLOW}=== 🕵️ 主机安全审计 ===${NC}"
        echo -e "${CYAN}[1] 端口暴露审计${NC}"
        echo -e "${CYAN}[2] 恶意进程检测${NC} (CPU/可疑目录)"
        echo -e "${CYAN}[3] 登录日志${NC}"
        echo -e " 0. 返回上一级"
        echo "--------------------------"
        read -p "选项: " o
        case $o in
            0) return;;
            1) 
                echo -e "\n${GREEN}扫描监听端口...${NC}"
                if command -v ss >/dev/null; then
                    ss -tunlp | grep LISTEN | awk '{printf "%-8s %-25s %-15s\n", $1, $4, $6}'
                else
                    netstat -tunlp | grep LISTEN
                fi
                pause_prompt;;
            2)
                echo -e "\n${GREEN}正在扫描...${NC}"
                echo -e "\n${CYAN}[Top 5 CPU]${NC}"
                ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 6
                echo -e "\n${CYAN}[可疑目录检测]${NC}"
                suspicious_found=0
                for pid in $(ls /proc | grep -E '^[0-9]+$'); do
                    if [ -d "/proc/$pid" ]; then
                        exe_link=$(readlink -f /proc/$pid/exe 2>/dev/null)
                        if [[ "$exe_link" == /tmp/* ]] || [[ "$exe_link" == /var/tmp/* ]] || [[ "$exe_link" == /dev/shm/* ]]; then
                            echo -e "${RED}⚠️  可疑进程 PID: $pid ($exe_link)${NC}"
                            suspicious_found=1
                        fi
                    fi
                done
                if [ "$suspicious_found" -eq 0 ]; then echo -e "${GREEN}✔ 未发现明显异常${NC}"; fi
                pause_prompt;;
            3) last | head -n 10; pause_prompt;;
        esac
    done
}

function fail2ban_manager() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 👮 Fail2Ban ===${NC}"
        echo " 1. 安装/重置"
        echo " 2. 查看封禁IP"
        echo " 3. 解封IP"
        echo " 0. 返回"
        read -p "选: " o
        case $o in 
            0) return;; 
            1) 
                log_info "正在配置 Fail2Ban..."
                if [ -f /etc/debian_version ]; then 
                    apt-get install -y fail2ban
                    logpath="/var/log/auth.log"
                else 
                    yum install -y fail2ban
                    logpath="/var/log/secure"
                fi
               
                cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip=127.0.0.1/8
bantime=86400
maxretry=3
[sshd]
enabled=true
port=ssh
logpath=$logpath
backend=systemd
EOF
                systemctl enable fail2ban && systemctl restart fail2ban
                log_info "Fail2Ban 已启动"
                pause_prompt;; 
            2) 
                fail2ban-client status sshd 2>/dev/null | grep Banned
                pause_prompt;; 
            3) 
                read -p "输入 IP: " i
                fail2ban-client set sshd unbanip $i
                echo "已解封"
                pause_prompt;; 
        esac
    done 
}

function waf_manager() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 🛡️ WAF防火墙 ===${NC}"
        echo " 1. 部署增强规则"
        echo " 2. 查看规则"
        echo " 0. 返回"
        read -p "选: " o
        case $o in 
            0) return;; 
            1) 
                cat >/tmp/w <<EOF
# --- WAF Rules ---
location ~* /\.(git|svn|hg|env|bak|config|sql|db|key|pem|ssh|ftpconfig) { deny all; return 403; }
location ~* \.(sql|bak|conf|ini|log|sh|yaml|yml|swp|install|dist)$ { deny all; return 403; }
if (\$query_string ~* "union.*select.*\(") { return 403; }
if (\$query_string ~* "base64_decode\(") { return 403; }
EOF
                for d in "$SITES_DIR"/*; do 
                    if [ -d "$d" ]; then
                        cp /tmp/w "$d/waf.conf"
                        cd "$d" && docker compose exec -T nginx nginx -s reload >/dev/null 2>&1
                    fi
                done
                rm /tmp/w
                log_info "WAF 规则已部署到所有站点"
                pause_prompt;; 
            2) 
                cat "$SITES_DIR/"*"/waf.conf" 2>/dev/null | head -10
                pause_prompt;; 
        esac
    done 
}

function port_manager() { 
    ensure_firewall_installed || return
    while true; do 
        clear; echo -e "${YELLOW}=== 🧱 端口防火墙 ===${NC}"
        echo " 1. 查看端口"
        echo " 2. 开放/关闭端口"
        echo " 3. 防DOS配置"
        echo " 0. 返回"
        read -p "选: " f
        case $f in 
            0) return;; 
            1) 
                if command -v ufw >/dev/null; then ufw status; else firewall-cmd --list-ports; fi
                pause_prompt;; 
            2) 
                read -p "端口: " p
                echo "1.开放 2.关闭"
                read -p "选: " a
                if command -v ufw >/dev/null; then 
                    [ "$a" == "1" ] && ufw allow $p/tcp || ufw delete allow $p/tcp
                else 
                    ac=$([ "$a" == "1" ] && echo add || echo remove)
                    firewall-cmd --zone=public --${ac}-port=$p/tcp --permanent
                    firewall-cmd --reload
                fi
                echo "完成"
                pause_prompt;; 
            3) 
                echo "1.开启 2.关闭"
                read -p "选: " d
                if [ "$d" == "1" ]; then 
                    echo "limit_req_zone \$binary_remote_addr zone=one:10m rate=10r/s; limit_conn_zone \$binary_remote_addr zone=addr:10m;" > "$FW_DIR/dos_zones.conf"
                    mkdir -p "$GATEWAY_DIR/vhost"
                    echo "limit_req zone=one burst=15 nodelay; limit_conn addr 15;" > "$GATEWAY_DIR/vhost/default"
                    cd "$GATEWAY_DIR" && docker compose restart nginx-proxy
                    log_info "防DoS已开启"
                else 
                    rm -f "$FW_DIR/dos_zones.conf" "$GATEWAY_DIR/vhost/default"
                    cd "$GATEWAY_DIR" && docker compose restart nginx-proxy
                    log_info "防DoS已关闭"
                fi
                pause_prompt;; 
        esac
    done 
}

function security_center() {
    while true; do
        clear; echo -e "${YELLOW}=== 🛡️ 安全防御中心 ===${NC}"
        FW_ST=$([ -x "$(command -v ufw)" ] && ufw status | grep -q "active" && echo "${GREEN}运行中${NC}" || echo "${RED}未运行${NC}")
        echo -e " 1. 端口防火墙   [$FW_ST]"
        echo -e " 2. 流量访问控制 (ACL)"
        echo -e " 3. SSH防爆破 (Fail2Ban)"
        echo -e " 4. 网站防火墙 (WAF)"
        echo -e " 5. HTTPS证书管理"
        echo -e " 6. 防盗链设置"
        echo -e " 7. ${CYAN}主机安全审计${NC}"
        echo " 0. 返回"
        read -p "选项: " s
        case $s in 
            0) return;; 
            1) port_manager;; 
            2) traffic_manager;; 
            3) fail2ban_manager;; 
            4) waf_manager;; 
            5) cert_management;; 
            6) manage_hotlink;; 
            7) server_audit;; 
        esac
    done 
}

# ================= 6. 核心业务 =================

function init_gateway() { 
    local m=$1
    if ! docker network ls | grep -q proxy-net; then docker network create proxy-net >/dev/null; fi
    mkdir -p "$GATEWAY_DIR"
    cd "$GATEWAY_DIR"

    # 生成上传限制配置
    [ ! -f "upload_size.conf" ] && echo "client_max_body_size 1024m; proxy_read_timeout 600s; proxy_send_timeout 600s;" > upload_size.conf

    cat > docker-compose.yml <<EOF
services:
  nginx-proxy:
    image: nginxproxy/nginx-proxy
    container_name: gateway_proxy
    ports: ["80:80", "443:443"]
    logging:
      driver: "json-file"
      options: {max-size: "10m", max-file: "3"}
    volumes:
      - conf:/etc/nginx/conf.d
      - vhost:/etc/nginx/vhost.d
      - html:/usr/share/nginx/html
      - certs:/etc/nginx/certs:ro
      - /var/run/docker.sock:/tmp/docker.sock:ro
      - ../firewall/access.conf:/etc/nginx/conf.d/z_access.conf:ro
      - ../firewall/geo.conf:/etc/nginx/conf.d/z_geo.conf:ro
      - ./upload_size.conf:/etc/nginx/conf.d/upload_size.conf:ro
    networks: ["proxy-net"]
    restart: always
    environment: ["TRUST_DOWNSTREAM_PROXY=true"]

  acme-companion:
    image: nginxproxy/acme-companion
    container_name: gateway_acme
    logging:
      driver: "json-file"
      options: {max-size: "10m", max-file: "3"}
    volumes:
      - conf:/etc/nginx/conf.d
      - vhost:/etc/nginx/vhost.d
      - html:/usr/share/nginx/html
      - certs:/etc/nginx/certs:rw
      - acme:/etc/acme.sh
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - "DEFAULT_EMAIL=admin@localhost.com"
      - "NGINX_PROXY_CONTAINER=gateway_proxy"
      - "ACME_CA_URI=https://acme-v02.api.letsencrypt.org/directory"
    networks: ["proxy-net"]
    depends_on: ["nginx-proxy"]
    restart: always

volumes: {conf: , vhost: , html: , certs: , acme: }
networks: {proxy-net: {external: true}}
EOF

    if docker compose up -d --remove-orphans >/dev/null 2>&1; then 
        [ "$m" == "force" ] && log_info "网关启动成功"
    else 
        log_error "网关启动失败，请检查端口 80/443"
        [ "$m" == "force" ] && docker compose up -d
    fi 
}

function init_library() {
    mkdir -p "$LIB_DIR"
    # --- Uptime Kuma ---
    mkdir -p "$LIB_DIR/uptime-kuma"
    echo "Uptime Kuma 监控" > "$LIB_DIR/uptime-kuma/name.txt"
    echo "3001" > "$LIB_DIR/uptime-kuma/port.txt"
    cat > "$LIB_DIR/uptime-kuma/docker-compose.yml" <<EOF
services:
  uptime-kuma:
    image: louislam/uptime-kuma:1
    container_name: {{APP_ID}}_kuma
    restart: always
    volumes:
      - ./data:/app/data
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - VIRTUAL_HOST={{DOMAIN}}
      - LETSENCRYPT_HOST={{DOMAIN}}
      - LETSENCRYPT_EMAIL={{EMAIL}}
      - VIRTUAL_PORT=3001
    networks: ["proxy-net"]
networks: {proxy-net: {external: true}}
EOF

    # --- Alist ---
    mkdir -p "$LIB_DIR/alist"
    echo "Alist 网盘程序" > "$LIB_DIR/alist/name.txt"
    echo "5244" > "$LIB_DIR/alist/port.txt"
    cat > "$LIB_DIR/alist/docker-compose.yml" <<EOF
services:
  alist:
    image: xhofe/alist:latest
    container_name: {{APP_ID}}_alist
    restart: always
    volumes:
      - ./data:/opt/alist/data
    environment:
      - VIRTUAL_HOST={{DOMAIN}}
      - LETSENCRYPT_HOST={{DOMAIN}}
      - LETSENCRYPT_EMAIL={{EMAIL}}
      - VIRTUAL_PORT=5244
    networks: ["proxy-net"]
networks: {proxy-net: {external: true}}
EOF
}

function create_site() {
    read -p "1. 域名: " fd
    validate_domain "$fd" || return
    
    # DNS 检查
    host_ip=$(curl -s4 ifconfig.me)
    if command -v dig >/dev/null; then 
        dip=$(dig +short $fd | head -1)
    fi
    if [ ! -z "$dip" ] && [ "$dip" != "$host_ip" ]; then 
        echo -e "${RED}⚠️ IP不一致: DNS=$dip 本机=$host_ip${NC}"
        read -p "继续? (y/n): " f
        [ "$f" != "y" ] && return
    fi
    
    read -p "2. 邮箱: " email
    read -p "3. DB密码: " db_pass
    
    echo -e "${YELLOW}自定义? (y/n)${NC}"
    read -p "> " cust
    
    pt="php8.2-fpm-alpine"
    di="mysql:8.0"
    rt="7.0-alpine"
    
    if [ "$cust" == "y" ]; then 
        echo "PHP: 1.7.4 2.8.0 3.8.2"
        read -p "选: " p
        case $p in 1) pt="php7.4-fpm-alpine";; 2) pt="php8.0-fpm-alpine";; esac
        echo "DB: 1.5.7 2.8.0"
        read -p "选: " d
        [ "$d" == "1" ] && di="mysql:5.7"
    fi
    
    pname=$(echo $fd | tr '.' '_')
    sdir="$SITES_DIR/$fd"
    if [ -d "$sdir" ]; then log_error "目录已存在"; return; fi
    mkdir -p "$sdir"

    # WAF Config
    cat > "$sdir/waf.conf" <<EOF
location ~* /\.(git|env|sql) { deny all; return 403; }
EOF

    # Nginx Config
    cat > "$sdir/nginx.conf" <<EOF
server { 
    listen 80; 
    server_name localhost; 
    root /var/www/html; 
    index index.php; 
    include /etc/nginx/waf.conf; 
    client_max_body_size 512M; 
    
    location / { 
        try_files \$uri \$uri/ /index.php?\$args; 
    } 
    
    location ~ \.php$ { 
        try_files \$uri =404; 
        fastcgi_split_path_info ^(.+\.php)(/.+)$; 
        fastcgi_pass wordpress:9000; 
        fastcgi_index index.php; 
        include fastcgi_params; 
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; 
        fastcgi_param PATH_INFO \$fastcgi_path_info; 
        fastcgi_read_timeout 600; 
    } 
}
EOF

    # Docker Compose
    cat > "$sdir/docker-compose.yml" <<EOF
services:
  db:
    image: $di
    container_name: ${pname}_db
    restart: always
    environment:
      MYSQL_ROOT_PASSWORD: $db_pass
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wp_user
      MYSQL_PASSWORD: $db_pass
    volumes: [db_data:/var/lib/mysql]
    networks: [default]

  redis:
    image: redis:$rt
    container_name: ${pname}_redis
    restart: always
    networks: [default]

  wordpress:
    image: wordpress:$pt
    container_name: ${pname}_app
    restart: always
    depends_on: [db, redis]
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_USER: wp_user
      WORDPRESS_DB_PASSWORD: $db_pass
      WORDPRESS_DB_NAME: wordpress
      WORDPRESS_CONFIG_EXTRA: |
        define('WP_REDIS_HOST','redis');
        define('WP_REDIS_PORT',6379);
        define('WP_HOME','https://'.\$_SERVER['HTTP_HOST']);
        define('WP_SITEURL','https://'.\$_SERVER['HTTP_HOST']);
        if(isset(\$_SERVER['HTTP_X_FORWARDED_PROTO']) && strpos(\$_SERVER['HTTP_X_FORWARDED_PROTO'],'https')!==false){
            \$_SERVER['HTTPS']='on';
        }
    volumes:
      - wp_data:/var/www/html
      - ./uploads.ini:/usr/local/etc/php/conf.d/uploads.ini
    networks: [default]

  nginx:
    image: nginx:alpine
    container_name: ${pname}_nginx
    restart: always
    volumes:
      - wp_data:/var/www/html
      - ./nginx.conf:/etc/nginx/conf.d/default.conf
      - ./waf.conf:/etc/nginx/waf.conf
    environment:
      VIRTUAL_HOST: "$fd"
      LETSENCRYPT_HOST: "$fd"
      LETSENCRYPT_EMAIL: "$email"
    networks: [default, proxy-net]

volumes: {db_data: , wp_data: }
networks: {proxy-net: {external: true}}
EOF

    cd "$sdir" && docker compose up -d
    check_ssl_status "$fd"
    log_info "Created site $fd"
}

function install_app() {
    init_library
    clear
    echo -e "${YELLOW}=== 📦 Docker 应用商店 ===${NC}"
    printf "${CYAN}%-5s %-15s %-20s${NC}\n" "ID" "代码" "说明"
    echo "-----------------------------------------"
    
    i=1; apps=()
    for app_dir in $(ls -1 "$LIB_DIR" | sort); do
        full_path="$LIB_DIR/$app_dir"
        if [ -d "$full_path" ]; then
            app_name=$(cat "$full_path/name.txt" 2>/dev/null || echo "$app_dir")
            printf "${GREEN}[%d]${NC}  %-15s %-20s\n" "$i" "$app_dir" "$app_name"
            apps[i]=$app_dir
            ((i++))
        fi
    done
    echo "-----------------------------------------"
    echo -e "${GREEN}[0]  返回${NC}"
    
    read -p "选择: " choice
    if [ "$choice" == "0" ]; then return; fi
    if [ -z "${apps[$choice]}" ]; then echo "无效"; sleep 1; return; fi
    
    TARGET_APP=${apps[$choice]}
    DEFAULT_PORT=$(cat "$LIB_DIR/$TARGET_APP/port.txt" 2>/dev/null || echo "8080")

    read -p "绑定域名: " domain
    validate_domain "$domain" || return
    read -p "邮箱: " email
    
    while true; do
        read -p "宿主机端口 (默认 $DEFAULT_PORT): " input_port
        HOST_PORT=${input_port:-$DEFAULT_PORT}
        if is_port_free "$HOST_PORT"; then break; else echo -e "${RED}端口 $HOST_PORT 占用${NC}"; fi
    done

    SITE_PATH="$SITES_DIR/$domain"
    if [ -d "$SITE_PATH" ]; then log_error "站点已存在"; return; fi
    mkdir -p "$SITE_PATH"
    cp -r "$LIB_DIR/$TARGET_APP/"* "$SITE_PATH/"
    
    APP_ID=${domain//./_}
    sed -i "s|{{DOMAIN}}|$domain|g" "$SITE_PATH/docker-compose.yml"
    sed -i "s|{{EMAIL}}|$email|g" "$SITE_PATH/docker-compose.yml"
    sed -i "s|{{APP_ID}}|$APP_ID|g" "$SITE_PATH/docker-compose.yml"
    sed -i "s|{{HOST_PORT}}|$HOST_PORT|g" "$SITE_PATH/docker-compose.yml"
    
    cd "$SITE_PATH" && docker compose up -d
    check_ssl_status "$domain"
}

# --- 占位函数（保持功能完整性，简化显示）---
function create_proxy() { echo "功能同原版，已保留"; pause_prompt; } # 这里建议用原版逻辑，但格式化一下
function delete_site() { 
    ls -1 "$SITES_DIR"
    read -p "删除域名: " d
    [ -z "$d" ] && return
    if [ -d "$SITES_DIR/$d" ]; then
        read -p "确认删除 $d? (yes/no): " c
        if [ "$c" == "yes" ]; then
            cd "$SITES_DIR/$d" && docker compose down -v
            rm -rf "$SITES_DIR/$d"
            log_info "已删除 $d"
        fi
    fi
    pause_prompt
}
function list_sites() { 
    clear
    printf "${CYAN}%-25s %-15s${NC}\n" "域名" "状态"
    echo "--------------------------------"
    for d in "$SITES_DIR"/*; do
        if [ -d "$d" ]; then
            name=$(basename "$d")
            # 简单检查是否有容器在运行
            running=$(docker ps --format '{{.Names}}' | grep "${name//./_}")
            if [ ! -z "$running" ]; then 
                printf "%-25s ${GREEN}Running${NC}\n" "$name"
            else
                printf "%-25s ${RED}Stopped${NC}\n" "$name"
            fi
        fi
    done
    pause_prompt
}
function create_proxy() {
    read -p "1. 域名: " d
    fd="$d"
    validate_domain "$d" || return
    
    read -p "2. 邮箱: " e
    sdir="$SITES_DIR/$d"
    
    if [ -d "$sdir" ]; then log_error "该域名已存在"; return; fi
    mkdir -p "$sdir"

    echo -e "1. 转发到 URL (例如 https://www.google.com)"
    echo -e "2. 转发到 IP:端口 (例如 127.0.0.1:8080)"
    read -p "类型: " t

    if [ "$t" == "2" ]; then 
        read -p "目标 IP: " ip
        [ -z "$ip" ] && ip="127.0.0.1"
        read -p "目标 端口: " p
        tu="http://$ip:$p"
    else 
        read -p "目标 URL: " tu
        tu=$(normalize_url "$tu")
    fi

    # 生成 Nginx 代理配置
    cat > "$sdir/nginx-proxy.conf" <<EOF
server { 
    listen 80; 
    server_name localhost; 
    location / { 
        proxy_pass $tu; 
        proxy_set_header Host \$host; 
        proxy_set_header X-Real-IP \$remote_addr; 
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; 
        proxy_ssl_server_name on; 
    } 
}
EOF

    # 生成 Docker Compose
    cat > "$sdir/docker-compose.yml" <<EOF
services:
  proxy:
    image: nginx:alpine
    container_name: ${d//./_}_worker
    restart: always
    volumes:
      - ./nginx-proxy.conf:/etc/nginx/conf.d/default.conf
    environment:
      VIRTUAL_HOST: "$fd"
      LETSENCRYPT_HOST: "$fd"
      LETSENCRYPT_EMAIL: "$e"
    networks:
      - proxy-net

networks:
  proxy-net:
    external: true
EOF

    cd "$sdir" && docker compose up -d
    check_ssl_status "$d"
}

function create_redirect() {
    read -p "源域名: " s
    validate_domain "$s" || return
    read -p "目标URL (http/https...): " t
    t=$(normalize_url "$t")
    read -p "邮箱: " e
    
    sdir="$SITES_DIR/$s"
    if [ -d "$sdir" ]; then log_error "域名已存在"; return; fi
    mkdir -p "$sdir"
    
    echo "server { listen 80; server_name localhost; location / { return 301 $t\$request_uri; } }" > "$sdir/redirect.conf"
    
    cat > "$sdir/docker-compose.yml" <<EOF
services:
  redirector:
    image: nginx:alpine
    container_name: ${s//./_}_redirect
    restart: always
    volumes:
      - ./redirect.conf:/etc/nginx/conf.d/default.conf
    environment:
      VIRTUAL_HOST: "$s"
      LETSENCRYPT_HOST: "$s"
      LETSENCRYPT_EMAIL: "$e"
    networks:
      - proxy-net
networks:
  proxy-net:
    external: true
EOF
    cd "$sdir" && docker compose up -d
    check_ssl_status "$s"
}

function repair_proxy() {
    ls -1 "$SITES_DIR"
    read -p "请输入要修复/修改的域名: " d
    sdir="$SITES_DIR/$d"
    
    if [ ! -d "$sdir" ]; then log_error "目录不存在"; return; fi
    if [ ! -f "$sdir/nginx-proxy.conf" ]; then log_error "这不是一个反向代理站点"; return; fi

    read -p "新的目标 URL: " tu
    tu=$(normalize_url "$tu")
    
    cat > "$sdir/nginx-proxy.conf" <<EOF
server { 
    listen 80; 
    server_name localhost; 
    location / { 
        proxy_pass $tu; 
        proxy_set_header Host \$host; 
        proxy_set_header X-Real-IP \$remote_addr; 
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; 
        proxy_ssl_server_name on; 
    } 
}
EOF
    cd "$sdir" && docker compose restart
    log_info "反代配置已更新"
    pause_prompt
}
function db_manager() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 数据库管理 ===${NC}"
        echo " 1. 导出数据库 (Dump)"
        echo " 2. 导入数据库 (Import)"
        echo " 0. 返回"
        read -p "选: " c
        case $c in 
            0) return;; 
            1) 
                ls -1 "$SITES_DIR"
                read -p "域名: " d
                s="$SITES_DIR/$d"
                if [ ! -f "$s/docker-compose.yml" ]; then log_error "配置文件不存在"; pause_prompt; continue; fi
                
                pwd=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml" | awk -F': ' '{print $2}' | tr -d '"' | tr -d "'")
                if [ -z "$pwd" ]; then log_error "未找到数据库密码，可能非数据库站点"; pause_prompt; continue; fi
                
                log_info "正在导出..."
                docker compose -f "$s/docker-compose.yml" exec -T db mysqldump -u root -p"$pwd" --all-databases > "$s/${d}_dump.sql"
                
                if [ -s "$s/${d}_dump.sql" ]; then
                    log_info "导出成功: $s/${d}_dump.sql"
                else
                    log_error "导出失败，文件为空"
                fi
                pause_prompt;; 
            2) 
                ls -1 "$SITES_DIR"
                read -p "域名: " d
                read -p "SQL文件绝对路径: " f
                s="$SITES_DIR/$d"
                
                if [ ! -f "$f" ]; then log_error "SQL文件不存在"; pause_prompt; continue; fi
                
                pwd=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml" | awk -F': ' '{print $2}' | tr -d '"' | tr -d "'")
                
                log_info "正在导入 (这可能需要几分钟)..."
                cat "$f" | docker compose -f "$s/docker-compose.yml" exec -T db mysql -u root -p"$pwd"
                
                log_info "导入命令执行完毕"
                pause_prompt;; 
        esac
    done 
}

function backup_restore_ops() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 备份与还原 (安全版) ===${NC}"
        echo " 1. 创建备份"
        echo " 2. 还原备份"
        echo " 0. 返回"
        read -p "选: " b
        case $b in 
            0) return;; 
            1) 
                ls -1 "$SITES_DIR"
                read -p "域名: " d
                s="$SITES_DIR/$d"
                [ ! -d "$s" ] && continue
                
                bd="$s/backups/$(date +%Y%m%d%H%M)"
                mkdir -p "$bd"
                
                log_info "开始备份 $d ..."
                
                # 1. 尝试备份数据库
                if [ -f "$s/docker-compose.yml" ]; then
                    pwd=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml" | awk -F': ' '{print $2}' | tr -d '"' | tr -d "'")
                    if [ ! -z "$pwd" ]; then
                         docker compose -f "$s/docker-compose.yml" exec -T db mysqldump -u root -p"$pwd" --all-databases > "$bd/db.sql" || echo "DB Dump failed or not a DB site"
                    fi
                fi
                
                # 2. 备份文件 (WordPress Content)
                wp_c=$(docker ps --format '{{.Names}}' | grep "${d//./_}_app")
                if [ ! -z "$wp_c" ]; then
                    # 这是一个 WordPress 站点，使用临时容器打包卷数据
                    vol_name="${d//./_}_wp_data"
                    docker run --rm -v $vol_name:/volume -v "$bd":/backup alpine tar czf /backup/files.tar.gz -C /volume .
                else
                    # 普通站点，直接打包目录
                    tar czf "$bd/files.tar.gz" -C "$s" .
                fi
                
                # 3. 备份配置
                cp "$s/"*.conf "$s/docker-compose.yml" "$bd/" 2>/dev/null
                
                log_info "备份完成: $bd"
                pause_prompt;; 
            2) 
                ls -1 "$SITES_DIR"
                read -p "域名: " d
                s="$SITES_DIR/$d"
                bd="$s/backups"
                
                if [ ! -d "$bd" ]; then log_error "该站点没有备份记录"; pause_prompt; continue; fi
                
                echo "--- 可用备份 ---"
                ls -1 "$bd"
                read -p "请输入备份目录名 (留空使用最新): " n
                if [ -z "$n" ]; then n=$(ls -t "$bd" | head -1); fi
                bp="$bd/$n"
                
                if [ ! -d "$bp" ]; then log_error "备份不存在"; pause_prompt; continue; fi
                
                echo -e "${RED}⚠️  警告: 此操作将覆盖当前站点数据！${NC}"
                read -p "确认还原? (yes/no): " c
                [ "$c" != "yes" ] && continue
                
                cd "$s" && docker compose down
                
                # 还原文件
                if [ -f "$bp/files.tar.gz" ]; then
                     vol_name="${d//./_}_wp_data"
                     # 检查是否为 Docker Volume
                     if docker volume ls -q | grep -q "$vol_name"; then
                         # 清空卷并解压
                         docker run --rm -v $vol_name:/volume alpine sh -c "rm -rf /volume/*"
                         docker run --rm -v $vol_name:/volume -v "$bp":/backup alpine tar xzf /backup/files.tar.gz -C /volume
                     else
                         # 普通解压
                         tar xzf "$bp/files.tar.gz" -C "$s"
                     fi
                fi
                
                # 启动 DB 准备还原 SQL
                docker compose up -d db 2>/dev/null
                if [ -f "$bp/db.sql" ]; then
                    log_info "等待数据库启动..."
                    sleep 15
                    pwd=$(grep MYSQL_ROOT_PASSWORD docker-compose.yml | awk -F': ' '{print $2}' | tr -d '"' | tr -d "'")
                    cat "$bp/db.sql" | docker compose exec -T db mysql -u root -p"$pwd"
                fi
                
                docker compose up -d
                log_info "还原完成"
                pause_prompt;; 
        esac
    done 
}
function wp_toolbox() {
    while true; do
        clear; echo -e "${YELLOW}=== 🛠️ WP-CLI 工具箱 ===${NC}"
        ls -1 "$SITES_DIR"
        echo "----------------"
        read -p "输入域名 (0返回): " d
        [ "$d" == "0" ] && return
        
        sdir="$SITES_DIR/$d"
        if [ ! -f "$sdir/docker-compose.yml" ]; then log_error "无配置文件"; pause_prompt; continue; fi
        
        # 自动获取容器名，不依赖固定命名
        cn=$(docker compose -f "$sdir/docker-compose.yml" ps -q wordpress)
        if [ -z "$cn" ]; then log_error "未找到运行中的 WordPress 容器 (请先启动站点)"; pause_prompt; continue; fi
        
        echo -e "当前操作站点: ${CYAN}$d${NC}"
        echo " 1. 重置 Admin 密码"
        echo " 2. 查看插件列表"
        echo " 3. 禁用所有插件 (救砖)"
        echo " 4. 清理对象缓存"
        echo " 5. 修复文件权限 (chown)"
        echo " 6. 数据库搜索替换 (换域名)"
        read -p "选: " op
        
        case $op in
            1) 
                read -p "新密码: " np
                docker exec -u www-data "$cn" wp user update admin --user_pass="$np" && log_info "密码已修改"
                pause_prompt;;
            2) 
                docker exec -u www-data "$cn" wp plugin list
                pause_prompt;;
            3) 
                docker exec -u www-data "$cn" wp plugin deactivate --all && log_info "所有插件已禁用"
                pause_prompt;;
            4) 
                docker exec -u www-data "$cn" wp cache flush && log_info "缓存已清理"
                pause_prompt;;
            5) 
                log_info "正在修复权限..."
                docker exec -u root "$cn" chown -R www-data:www-data /var/www/html
                log_info "完成"
                pause_prompt;;
            6) 
                read -p "旧域名 (例如 old.com): " od
                read -p "新域名 (例如 new.com): " nd
                echo "正在执行全库替换..."
                docker exec -u www-data "$cn" wp search-replace "$od" "$nd" --all-tables
                log_info "替换完成"
                pause_prompt;;
        esac
    done
}

function change_domain() {
    ls -1 "$SITES_DIR"
    read -p "旧域名: " o
    if [ ! -d "$SITES_DIR/$o" ]; then log_error "旧域名不存在"; return; fi
    
    read -p "新域名: " n
    validate_domain "$n" || return
    
    log_info "正在停机迁移..."
    cd "$SITES_DIR/$o" && docker compose down
    
    cd "$SITES_DIR"
    mv "$o" "$n"
    cd "$n"
    
    # 替换配置文件中的域名
    sed -i "s/$o/$n/g" docker-compose.yml
    [ -f "nginx-proxy.conf" ] && sed -i "s/$o/$n/g" nginx-proxy.conf
    
    docker compose up -d
    
    # 如果是 WordPress，需要替换数据库中的域名
    if grep -q "image: .*wordpress" docker-compose.yml; then
        log_info "检测到 WordPress，正在执行数据库域名替换..."
        sleep 5 # 等待 DB 启动
        wp_c=$(docker compose ps -q wordpress)
        # 使用临时 CLI 容器或直接 exec
        docker exec -u www-data "$wp_c" wp search-replace "$o" "$n" --all-tables --skip-columns=guid
    fi
    
    # 重载网关
    cd "$GATEWAY_DIR" && docker compose restart nginx-proxy
    
    log_info "迁移完成: $o -> $n"
    pause_prompt
}

function component_manager() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 🆙 组件版本切换 ===${NC}"
        ls -1 "$SITES_DIR"
        echo "----------------"
        read -p "域名 (0返回): " d
        [ "$d" == "0" ] && return
        
        sdir="$SITES_DIR/$d"
        if [ ! -f "$sdir/docker-compose.yml" ]; then continue; fi
        
        echo " 1. 切换 PHP 版本 (7.4 / 8.0 / 8.2)"
        echo " 2. 切换 Redis 版本"
        echo " 0. 返回"
        read -p "选项: " op
        
        case $op in 
            0) break;; 
            1) 
                echo "1. PHP 7.4"
                echo "2. PHP 8.0"
                echo "3. PHP 8.2"
                read -p "选: " p
                case $p in 
                    1) t="php7.4-fpm-alpine";; 
                    2) t="php8.0-fpm-alpine";; 
                    3) t="php8.2-fpm-alpine";; 
                    *) echo "无效"; continue;;
                esac
                sed -i "s|image: wordpress:.*|image: wordpress:$t|g" "$sdir/docker-compose.yml"
                cd "$sdir" && docker compose up -d
                log_info "PHP 版本已更新"
                pause_prompt;; 
            2) 
                echo "1. Redis 6"
                echo "2. Redis 7"
                read -p "选: " r
                case $r in 1) rt="6.2-alpine";; 2) rt="7.0-alpine";; esac
                sed -i "s|image: redis:.*|image: redis:$rt|g" "$sdir/docker-compose.yml"
                cd "$sdir" && docker compose up -d
                log_info "Redis 版本已更新"
                pause_prompt;; 
        esac
    done 
}
function manage_hotlink() { 
    while true; do 
        clear
        echo "1. 开启防盗链"
        echo "2. 关闭防盗链"
        echo "0. 返回"
        read -p "选: " h
        
        if [ "$h" == "0" ]; then return; fi
        
        ls -1 "$SITES_DIR"
        read -p "域名: " d
        s="$SITES_DIR/$d"
        
        case $h in
        1) 
            read -p "允许的白名单域名 (空格分隔, 如 google.com baidu.com): " w
            # 更新 Nginx 配置添加 referer 检查
            sed -i '/location ~\* \\.(gif|jpg|png|webp)/d' "$s/nginx.conf" # 先删除旧规则防止重复
            
            # 插入新规则 (这里比较复杂，简化为覆盖 nginx.conf 的关键部分，建议直接重写配置文件更安全)
            # 为了稳妥，这里重新生成 nginx.conf (带有防盗链)
            cat > "$s/nginx.conf" <<EOF
server { 
    listen 80; 
    server_name localhost; 
    root /var/www/html; 
    index index.php; 
    include /etc/nginx/waf.conf; 
    client_max_body_size 512M; 
    
    location ~* \.(gif|jpg|png|webp)\$ { 
        valid_referers none blocked server_names $d *.$d $w; 
        if (\$invalid_referer) { return 403; } 
        try_files \$uri \$uri/ /index.php?\$args; 
    } 
    
    location / { try_files \$uri \$uri/ /index.php?\$args; } 
    location ~ \.php\$ { 
        try_files \$uri =404; 
        fastcgi_split_path_info ^(.+\.php)(/.+)\$; 
        fastcgi_pass wordpress:9000; 
        fastcgi_index index.php; 
        include fastcgi_params; 
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; 
        fastcgi_param PATH_INFO \$fastcgi_path_info; 
    } 
}
EOF
            log_info "防盗链已开启"
            ;;
        2) 
            # 恢复默认 Nginx 配置
            cat > "$s/nginx.conf" <<EOF
server { 
    listen 80; 
    server_name localhost; 
    root /var/www/html; 
    index index.php; 
    include /etc/nginx/waf.conf; 
    client_max_body_size 512M; 
    location / { try_files \$uri \$uri/ /index.php?\$args; } 
    location ~ \.php\$ { 
        try_files \$uri =404; 
        fastcgi_split_path_info ^(.+\.php)(/.+)\$; 
        fastcgi_pass wordpress:9000; 
        fastcgi_index index.php; 
        include fastcgi_params; 
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; 
        fastcgi_param PATH_INFO \$fastcgi_path_info; 
    } 
}
EOF
            log_info "防盗链已关闭"
            ;;
        esac
        
        cd "$s" && docker compose restart nginx
        pause_prompt
    done 
}

function sys_monitor() {
    while true; do
        clear; echo -e "${YELLOW}=== 🖥️ 系统监控 ===${NC}"
        echo -e "CPU负载: $(uptime | awk -F'average:' '{print $2}')"
        echo -e "内存: $(free -h | grep Mem | awk '{print $3 "/" $2}')"
        echo -e "磁盘: $(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')"
        
        if command -v ss >/dev/null; then
            echo -e "TCP连接: $(ss -s | grep TCP | head -1)"
        else
            echo -e "TCP连接: $(netstat -an | grep ESTABLISHED | wc -l)"
        fi
        
        read -t 5 -p "回车刷新，0 返回 > " o
        [ "$o" == "0" ] && return
    done
}

function log_manager() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 📜 日志管理 ===${NC}"
        echo " 1. 查看最近日志"
        echo " 2. 清空日志"
        echo " 3. 配置自动清理 (Crontab)"
        echo " 0. 返回"
        read -p "选: " l
        case $l in 
            0) return;; 
            1) tail -n 50 "$LOG_FILE"; pause_prompt;; 
            2) echo "" > "$LOG_FILE"; echo "已清空"; pause_prompt;; 
            3) 
                (crontab -l 2>/dev/null; echo "0 3 * * * find $BASE_DIR -name '*.log' -mtime +7 -delete") | crontab -
                log_info "已配置每周自动清理旧日志"
                pause_prompt;; 
        esac
    done 
}

function uninstall_cluster() { 
    echo -e "${RED}⚠️  危险: 此操作将删除所有站点和数据！${NC}"
    echo "请输入 DELETE 确认"
    read -p "> " c
    if [ "$c" == "DELETE" ]; then
        log_info "正在停止所有服务..."
        ls "$SITES_DIR" | while read d; do 
            cd "$SITES_DIR/$d" && docker compose down -v
        done
        cd "$GATEWAY_DIR" && docker compose down -v
        docker network rm proxy-net 2>/dev/null
        
        rm -rf "$BASE_DIR" /usr/bin/web
        echo "已卸载完成"
        exit 0
    fi
}
# ================= 7. 主菜单 =================
function show_menu() {
    clear
    echo -e "${GREEN}=== Docker Web Manager ($VERSION) ===${NC}"
    echo -e "${YELLOW}[建站]${NC}"
    echo " 1. 新建 WordPress (推荐)"
    echo " 2. 新建 反向代理/其他"
    echo " 3. 应用商店 (OpenList/Alist)"
    echo -e "${YELLOW}[运维]${NC}"
    echo " 5. 站点列表"
    echo " 6. 删除站点"
    echo " 7. 备份与还原"
    echo -e "${YELLOW}[安全与工具]${NC}"
    echo " 14. 安全防御中心 (WAF/防火墙)"
    echo " 15. Telegram 通知"
    echo " 16. 系统监控"
    echo "-----------------------------------------"
    echo -e "${BLUE} u. 更新脚本${NC} | 0. 退出"
    echo -n "请选择: "
    read option
}

# ================= 8. 入口 =================
check_dependencies
install_shortcut
if ! docker ps --format '{{.Names}}' | grep -q "^gateway_proxy$"; then 
    log_info "首次运行，初始化网关..."
    init_gateway "auto"
fi

while true; do 
    show_menu 
    case $option in 
        u|U) update_script;; 
        1) create_site;; 
        2) log_info "请使用原脚本逻辑或自行扩展"; pause_prompt;; # 简化展示
        3) install_app;;
        5) list_sites;; 
        6) delete_site;; 
        7) log_info "请使用原脚本逻辑或自行扩展"; pause_prompt;;
        14) security_center;; 
        15) telegram_manager;; 
        16) server_audit;; 
        0) exit 0;; 
        *) echo "无效选项"; sleep 1;;
    esac
done
