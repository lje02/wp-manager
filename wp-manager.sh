#!/bin/bash

# ================= 1. 配置区域 =================
# 脚本版本号
VERSION="V14 全功能整合版 (快捷指令: web)"

# 数据存储路径
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

# 自动更新源
UPDATE_URL="https://raw.githubusercontent.com/lje02/wp-manager/main/wp-manager.sh"

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

# ================= 2. 基础检查与初始化 =================

# 强制 Root 检查
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

function write_log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

function pause_prompt() {
    echo -e "\n${YELLOW}>>> 操作完成，按回车键返回...${NC}"
    read -r
}

function validate_domain() {
    local domain=$1
    if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        echo -e "${RED}❌ 错误: 域名格式不正确 (请勿包含 http:// 或特殊字符)${NC}"
        return 1
    fi
    return 0
}

function is_port_free() {
    local port=$1
    if netstat -tuln | grep -q ":$port "; then return 1; else return 0; fi
}

function install_shortcut() {
    local script_path=$(readlink -f "$0")
    if [ ! -L "/usr/bin/web" ] || [ "$(readlink -f "/usr/bin/web")" != "$script_path" ]; then
        ln -sf "$script_path" /usr/bin/web && chmod +x "$script_path"
        echo -e "${GREEN}>>> 快捷指令 'web' 已安装${NC}"
    fi
}

function check_dependencies() {
    local deps=(jq openssl netstat docker)
    local need_install=0
    for dep in "${deps[@]}"; do
        if ! command -v $dep >/dev/null 2>&1; then need_install=1; break; fi
    done
    if [ $need_install -eq 1 ]; then
        echo -e "${YELLOW}>>> 正在安装依赖组件...${NC}"
        if [ -f /etc/debian_version ]; then apt-get update && apt-get install -y jq openssl net-tools ufw; else yum install -y jq openssl net-tools firewalld; fi
        if ! command -v docker >/dev/null 2>&1; then
            curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun
            systemctl enable docker && systemctl start docker
        fi
    fi
}

function ensure_firewall_installed() {
    if command -v ufw >/dev/null || command -v firewall-cmd >/dev/null; then return 0; fi
    echo -e "${YELLOW}>>> 正在安装防火墙...${NC}"
    if [ -f /etc/debian_version ]; then apt-get install -y ufw; ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp; echo "y" | ufw enable
    else yum install -y firewalld; systemctl enable firewalld --now; firewall-cmd --permanent --add-service={ssh,http,https}; firewall-cmd --reload; fi
}

function check_ssl_status() {
    local d=$1; echo -e "${CYAN}>>> [SSL] 正在申请证书...${NC}"; for ((i=1; i<=20; i++)); do if docker exec gateway_acme test -f "/etc/nginx/certs/$d.crt"; then echo -e "${GREEN}✔ SSL 成功: https://$d${NC}"; pause_prompt; return 0; fi; echo -n "."; sleep 5; done; echo -e "\n${YELLOW}⚠️ 证书暂未生成 (可能是DNS延迟)${NC}"; pause_prompt;
}

function normalize_url() {
    local url=$1; url=${url%/}; if [[ "$url" != http* ]]; then echo "https://$url"; else echo "$url"; fi
}

function update_script() {
    clear; echo -e "${GREEN}=== 脚本自动更新 ===${NC}"; echo -e "版本: $VERSION"
    temp_file="/tmp/wp_manager_update.sh"
    if curl -f -L -s -o "$temp_file" "$UPDATE_URL" && head -n 1 "$temp_file" | grep -q "/bin/bash"; then
        mv "$temp_file" "$0"; chmod +x "$0"; echo -e "${GREEN}✔ 更新成功，正在重启...${NC}"; sleep 1; exec "$0"
    else echo -e "${RED}❌ 更新失败!${NC}"; rm -f "$temp_file"; fi; pause_prompt
}

function send_tg_msg() {
    local msg=$1; if [ -f "$TG_CONF" ]; then source "$TG_CONF"; if [ ! -z "$TG_BOT_TOKEN" ] && [ ! -z "$TG_CHAT_ID" ]; then curl -s -X POST "https://api.telegram.org/bot$TG_BOT_TOKEN/sendMessage" -d chat_id="$TG_CHAT_ID" -d text="$msg" >/dev/null; fi; fi
}

# --- Telegram 后台脚本生成器 ---
function generate_monitor_script() {
cat > "$MONITOR_SCRIPT" <<EOF
#!/bin/bash
TG_CONF="$TG_CONF"; CPU_THRESHOLD=90; MEM_THRESHOLD=90; DISK_THRESHOLD=90; COOLDOWN=1800; LAST_ALERT=0
function send_msg() { if [ -f "\$TG_CONF" ]; then source "\$TG_CONF"; curl -s -X POST "https://api.telegram.org/bot\$TG_BOT_TOKEN/sendMessage" -d chat_id="\$TG_CHAT_ID" -d text="\$1" >/dev/null; fi }
while true; do
    CPU=\$(grep 'cpu ' /proc/stat | awk '{usage=(\$2+\$4)*100/(\$2+\$4+\$5)} END {print usage}' | cut -d. -f1)
    MEM=\$(free | grep Mem | awk '{print \$3/\$2 * 100.0}' | cut -d. -f1)
    DISK=\$(df / | awk 'NR==2 {print \$5}' | sed 's/%//')
    MSG=""
    if [ "\$CPU" -gt "\$CPU_THRESHOLD" ]; then MSG="\$MSG\n🚨 CPU过高: \${CPU}%"; fi
    if [ "\$MEM" -gt "\$MEM_THRESHOLD" ]; then MSG="\$MSG\n🚨 内存过高: \${MEM}%"; fi
    if [ "\$DISK" -gt "\$DISK_THRESHOLD" ]; then MSG="\$MSG\n🚨 磁盘爆满: \${DISK}%"; fi
    if [ ! -z "\$MSG" ]; then
        NOW=\$(date +%s); DIFF=\$((NOW - LAST_ALERT))
        if [ "\$DIFF" -gt "\$COOLDOWN" ]; then send_msg "⚠️ **资源警报** \nHostname: \$(hostname) \$MSG"; LAST_ALERT=\$NOW; fi
    fi
    sleep 60
done
EOF
chmod +x "$MONITOR_SCRIPT"
}

function generate_listener_script() {
cat > "$LISTENER_SCRIPT" <<EOF
#!/bin/bash
TG_CONF="$TG_CONF"; GATEWAY_DIR="$GATEWAY_DIR"
if [ ! -f "\$TG_CONF" ]; then exit 1; fi; source "\$TG_CONF"; OFFSET=0
function reply() { curl -s -X POST "https://api.telegram.org/bot\$TG_BOT_TOKEN/sendMessage" -d chat_id="\$TG_CHAT_ID" -d text="\$1" >/dev/null; }
while true; do
    updates=\$(curl -s "https://api.telegram.org/bot\$TG_BOT_TOKEN/getUpdates?offset=\$OFFSET&timeout=30")
    status=\$(echo "\$updates" | jq -r '.ok'); if [ "\$status" != "true" ]; then sleep 5; continue; fi
    count=\$(echo "\$updates" | jq '.result | length'); if [ "\$count" -eq "0" ]; then continue; fi
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
                    if [ -d "\$GATEWAY_DIR" ]; then cd "\$GATEWAY_DIR" && docker compose restart nginx-proxy; reply "✅ Nginx 网关已重启"; else reply "❌ 找不到网关目录"; fi ;;
            esac
        fi
        next_offset=\$((update_id + 1)); echo \$next_offset > /tmp/tg_offset.txt
    done
    if [ -f /tmp/tg_offset.txt ]; then OFFSET=\$(cat /tmp/tg_offset.txt); fi
done
EOF
chmod +x "$LISTENER_SCRIPT"
}

# ================= 4. 高级业务功能 =================

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
            1) echo -e "\n${GREEN}扫描监听端口...${NC}"; netstat -tunlp | grep LISTEN | awk '{printf "%-8s %-25s %-15s %-20s\n", $1, $4, $6, $7}'; pause_prompt;;
            2)
                echo -e "\n${GREEN}正在扫描...${NC}"
                echo -e "\n${CYAN}[Top 5 CPU]${NC}"; ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 6
                echo -e "\n${CYAN}[可疑目录检测]${NC}"
                suspicious_found=0
                for pid in $(ls /proc | grep -E '^[0-9]+$'); do
                    if [ -d "/proc/$pid" ]; then
                        exe_link=$(readlink -f /proc/$pid/exe 2>/dev/null)
                        if [[ "$exe_link" == /tmp/* ]] || [[ "$exe_link" == /var/tmp/* ]] || [[ "$exe_link" == /dev/shm/* ]]; then
                            echo -e "${RED}⚠️  可疑进程 PID: $pid ($exe_link)${NC}"; suspicious_found=1
                        fi
                    fi
                done
                if [ "$suspicious_found" -eq 0 ]; then echo -e "${GREEN}✔ 未发现明显异常${NC}"; fi
                pause_prompt;;
            3) last | head -n 10; pause_prompt;;
        esac
    done
}

function security_center() {
    while true; do
        clear; echo -e "${YELLOW}=== 🛡️ 安全防御中心 ===${NC}"
        FW_ST=$([ -x "$(command -v ufw)" ] && ufw status | grep -q "active" && echo "${GREEN}运行中${NC}" || echo "${RED}未运行${NC}")
        WAF_ST=$(grep -r "V69" "$SITES_DIR" >/dev/null 2>&1 && echo "${GREEN}增强版${NC}" || echo "${YELLOW}基础/未部署${NC}")
        echo -e " 1. 端口防火墙   [$FW_ST]"
        echo -e " 2. 流量访问控制 (ACL)"
        echo -e " 3. SSH防爆破 (Fail2Ban)"
        echo -e " 4. 网站防火墙    [$WAF_ST]"
        echo -e " 5. HTTPS证书管理"
        echo -e " 6. 防盗链设置"
        echo -e " 7. ${CYAN}主机安全审计${NC}"
        echo " 0. 返回"
        read -p "选项: " s
        case $s in 0) return;; 1) port_manager;; 2) traffic_manager;; 3) fail2ban_manager;; 4) waf_manager;; 5) cert_management;; 6) manage_hotlink;; 7) server_audit;; esac
    done 
}

function wp_toolbox() {
    while true; do
        clear; echo -e "${YELLOW}=== 🛠️ WP-CLI 工具箱 ===${NC}"; ls -1 "$SITES_DIR"; echo "----------------"
        read -p "输入域名 (0返回): " d; [ "$d" == "0" ] && return
        sdir="$SITES_DIR/$d"
        if [ ! -f "$sdir/docker-compose.yml" ]; then echo -e "${RED}无配置${NC}"; pause_prompt; continue; fi
        cn=$(grep "container_name: .*_app" "$sdir/docker-compose.yml" | awk '{print $2}')
        if [ -z "$cn" ]; then echo -e "${RED}非标准WP站点${NC}"; pause_prompt; continue; fi
        echo -e "操作站点: ${CYAN}$d${NC}"; echo " 1. 重置密码  2. 插件列表  3. 禁用所有插件  4. 清理缓存  5. 修复权限  6. 数据库换域名"; read -p "选: " op
        case $op in
            1) read -p "新密码: " np; docker exec -u www-data "$cn" wp user update admin --user_pass="$np" && echo "✔ 完成"; pause_prompt;;
            2) docker exec -u www-data "$cn" wp plugin list; pause_prompt;;
            3) docker exec -u www-data "$cn" wp plugin deactivate --all && echo "✔ 完成"; pause_prompt;;
            4) docker exec -u www-data "$cn" wp cache flush && echo "✔ 完成"; pause_prompt;;
            5) docker compose -f "$sdir/docker-compose.yml" exec -T -u root wordpress chown -R www-data:www-data /var/www/html && echo "✔ 完成"; pause_prompt;;
            6) read -p "旧域名: " od; read -p "新域名: " nd; docker exec -u www-data "$cn" wp search-replace "$od" "$nd" --all-tables && echo "✔ 完成"; pause_prompt;;
        esac
    done
}

function telegram_manager() {
    while true; do
        clear; echo -e "${YELLOW}=== 🤖 Telegram 管理 ===${NC}"
        [ -f "$MONITOR_PID" ] && kill -0 $(cat "$MONITOR_PID") 2>/dev/null && M_STAT="${GREEN}运行中${NC}" || M_STAT="${RED}停止${NC}"
        [ -f "$LISTENER_PID" ] && kill -0 $(cat "$LISTENER_PID") 2>/dev/null && L_STAT="${GREEN}运行中${NC}" || L_STAT="${RED}停止${NC}"
        echo -e "守护进程: $M_STAT | 监听进程: $L_STAT"
        echo " 1. 配置Token/ChatID  2. 启动报警  3. 启动监听  4. 停止所有  5. 测试消息  0. 返回"
        read -p "选: " t
        case $t in
            0) return;;
            1) read -p "Token: " tk; echo "TG_BOT_TOKEN=\"$tk\"" > "$TG_CONF"; read -p "ChatID: " ci; echo "TG_CHAT_ID=\"$ci\"" >> "$TG_CONF"; echo "已保存"; pause_prompt;;
            2) generate_monitor_script; nohup "$MONITOR_SCRIPT" >/dev/null 2>&1 & echo $! > "$MONITOR_PID"; echo "已启动"; pause_prompt;;
            3) generate_listener_script; nohup "$LISTENER_SCRIPT" >/dev/null 2>&1 & echo $! > "$LISTENER_PID"; echo "已启动"; pause_prompt;;
            4) pkill -F "$MONITOR_PID" 2>/dev/null; pkill -F "$LISTENER_PID" 2>/dev/null; rm -f "$MONITOR_PID" "$LISTENER_PID"; echo "已停止"; pause_prompt;;
            5) send_tg_msg "🔔 测试消息 OK"; echo "已发送"; pause_prompt;;
        esac
    done
}

function sys_monitor() {
    while true; do
        clear; echo -e "${YELLOW}=== 🖥️ 系统监控 ===${NC}"
        echo -e "CPU负载: $(uptime|awk -F'average:' '{print $2}')"
        echo -e "内存: $(free -h|grep Mem|awk '{print $3 "/" $2}')"
        echo -e "磁盘: $(df -h /|awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')"
        echo -e "连接数: $(netstat -an|grep ESTABLISHED|wc -l 2>/dev/null || ss -s|grep est|awk '{print $2}')"
        read -t 5 -p "回车刷新，0 返回 > " o; [ "$o" == "0" ] && return
    done
}

function log_manager() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 📜 日志管理 ===${NC}"
        echo " 1. 查看日志  2. 清空日志  3. 自动清理(7天)  0. 返回"
        read -p "选: " l
        case $l in 
            0) return;; 1) tail -n 50 "$LOG_FILE"; pause_prompt;; 2) echo "">"$LOG_FILE"; echo "已清空"; pause_prompt;; 
            3) (crontab -l 2>/dev/null; echo "0 3 * * * find $BASE_DIR -name '*.log' -mtime +7 -delete") | crontab -; echo "已配置"; pause_prompt;; 
        esac
    done 
}

function component_manager() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 🆙 组件升级 ===${NC}"
        ls -1 "$SITES_DIR"; echo "----------------"; read -p "域名 (0返回): " d; [ "$d" == "0" ] && return
        sdir="$SITES_DIR/$d"; [ ! -f "$sdir/docker-compose.yml" ] && continue
        echo " 1. 切换 PHP 版本"
        echo " 2. 切换 数据库 版本 (⚠️ 高危)"
        echo " 3. 切换 Redis 版本"
        echo " 0. 返回"
        read -p "选项: " op
        case $op in 
            0) break;; 
            1) echo "1.PHP7.4 2.PHP8.0 3.PHP8.2"; read -p "选: " p; case $p in 1) t="php7.4-fpm-alpine";; 2) t="php8.0-fpm-alpine";; 3) t="php8.2-fpm-alpine";; esac; 
               sed -i "s|image: wordpress:.*|image: wordpress:$t|g" "$sdir/docker-compose.yml"; cd "$sdir" && docker compose up -d; echo "完成"; pause_prompt;; 
            2) echo -e "${RED}警告: 跨版本升级可能导致DB崩溃，请先备份！${NC}"; echo "1.MySQL5.7 2.MySQL8.0"; read -p "选: " v; case $v in 1) i="mysql:5.7";; 2) i="mysql:8.0";; esac; 
               sed -i "s|image: .*sql:.*|image: $i|g" "$sdir/docker-compose.yml"; cd "$sdir" && docker compose up -d; echo "完成"; pause_prompt;; 
            3) echo "1.Redis6 2.Redis7"; read -p "选: " r; case $r in 1) rt="6.2-alpine";; 2) rt="7.0-alpine";; esac; 
               sed -i "s|image: redis:.*|image: redis:$rt|g" "$sdir/docker-compose.yml"; cd "$sdir" && docker compose up -d; echo "完成"; pause_prompt;; 
        esac
    done 
}

function fail2ban_manager() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 👮 Fail2Ban ===${NC}"
        echo " 1. 安装/重置  2. 查看封禁IP  3. 解封IP  0. 返回"
        read -p "选: " o
        case $o in 
            0) return;; 
            1) if [ -f /etc/debian_version ]; then apt-get install -y fail2ban; lp="/var/log/auth.log"; else yum install -y fail2ban; lp="/var/log/secure"; fi; 
               cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip=127.0.0.1/8
bantime=86400
maxretry=3
[sshd]
enabled=true
port=ssh
logpath=$lp
backend=systemd
EOF
               systemctl enable fail2ban; systemctl restart fail2ban; echo "完成"; pause_prompt;; 
            2) fail2ban-client status sshd 2>/dev/null|grep Banned; pause_prompt;; 
            3) read -p "输入 IP: " i; fail2ban-client set sshd unbanip $i; echo "已解封"; pause_prompt;; 
        esac
    done 
}

function waf_manager() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 🛡️ WAF防火墙 ===${NC}"
        echo " 1. 部署增强规则  2. 查看规则  0. 返回"
        read -p "选: " o
        case $o in 
            0) return;; 
            1) cat >/tmp/w <<EOF
location ~* /\.(git|svn|hg|env|bak|config|sql|db|key|pem|ssh|ftpconfig) { deny all; return 403; }
location ~* \.(sql|bak|conf|ini|log|sh|yaml|yml|swp|install|dist)$ { deny all; return 403; }
if (\$query_string ~* "union.*select.*\(") { return 403; }
if (\$query_string ~* "base64_decode\(") { return 403; }
EOF
                for d in "$SITES_DIR"/*; do [ -d "$d" ] && cp /tmp/w "$d/waf.conf" && cd "$d" && docker compose exec -T nginx nginx -s reload >/dev/null 2>&1; done; rm /tmp/w; echo -e "${GREEN}✔ 已部署${NC}"; pause_prompt;; 
            2) cat "$SITES_DIR/"*"/waf.conf" 2>/dev/null|head -10; pause_prompt;; 
        esac
    done 
}

function port_manager() { 
    ensure_firewall_installed || return
    while true; do 
        clear; echo -e "${YELLOW}=== 🧱 端口防火墙 ===${NC}"
        echo " 1. 查看端口  2. 开放/关闭端口  3. 防DOS  0. 返回"
        read -p "选: " f
        case $f in 
            0) return;; 
            1) if command -v ufw >/dev/null; then ufw status; else firewall-cmd --list-ports; fi; pause_prompt;; 
            2) read -p "端口: " p; echo "1.开放 2.关闭"; read -p "选: " a; 
               if command -v ufw >/dev/null; then [ "$a" == "1" ] && ufw allow $p/tcp || ufw delete allow $p/tcp; else ac=$([ "$a" == "1" ] && echo add || echo remove); firewall-cmd --zone=public --${ac}-port=$p/tcp --permanent; firewall-cmd --reload; fi; echo "完成"; pause_prompt;; 
            3) echo "1.开启 2.关闭"; read -p "选: " d; if [ "$d" == "1" ]; then echo "limit_req_zone \$binary_remote_addr zone=one:10m rate=10r/s; limit_conn_zone \$binary_remote_addr zone=addr:10m;" > "$FW_DIR/dos_zones.conf"; mkdir -p "$GATEWAY_DIR/vhost"; echo "limit_req zone=one burst=15 nodelay; limit_conn addr 15;" > "$GATEWAY_DIR/vhost/default"; cd "$GATEWAY_DIR" && docker compose restart nginx-proxy; echo "已开启"; else rm -f "$FW_DIR/dos_zones.conf" "$GATEWAY_DIR/vhost/default"; cd "$GATEWAY_DIR" && docker compose restart nginx-proxy; echo "已关闭"; fi; pause_prompt;; 
        esac
    done 
}

function traffic_manager() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 🌐 流量控制 ===${NC}"
        echo " 1. 黑名单IP  2. 白名单IP  3. 封禁国家  4. 清空  0. 返回"
        read -p "选: " t
        case $t in 
            0) return;; 
            1|2) tp="deny"; [ "$t" == "2" ] && tp="allow"; read -p "IP: " i; echo "$tp $i;" >> "$FW_DIR/access.conf"; cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload; echo "OK"; pause_prompt;; 
            3) read -p "国家代码(cn): " c; wget -qO- "http://www.ipdeny.com/ipblocks/data/countries/$c.zone" | while read l; do echo "deny $l;" >> "$FW_DIR/geo.conf"; done; cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload; echo "OK"; pause_prompt;; 
            4) echo "">"$FW_DIR/access.conf"; echo "">"$FW_DIR/geo.conf"; cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload; echo "OK"; pause_prompt;; 
        esac
    done 
}

# ================= 5. 核心操作函数 =================

function init_gateway() { 
    local m=$1
    if ! docker network ls|grep -q proxy-net; then docker network create proxy-net >/dev/null; fi
    mkdir -p "$GATEWAY_DIR"; cd "$GATEWAY_DIR"
    [ ! -f "upload_size.conf" ] && echo "client_max_body_size 1024m; proxy_read_timeout 600s; proxy_send_timeout 600s;" > upload_size.conf
    cat > docker-compose.yml <<EOF
services:
  nginx-proxy: {image: nginxproxy/nginx-proxy, container_name: gateway_proxy, ports: ["80:80", "443:443"], logging: {driver: "json-file", options: {max-size: "10m", max-file: "3"}}, volumes: [conf:/etc/nginx/conf.d, vhost:/etc/nginx/vhost.d, html:/usr/share/nginx/html, certs:/etc/nginx/certs:ro, /var/run/docker.sock:/tmp/docker.sock:ro, ../firewall/access.conf:/etc/nginx/conf.d/z_access.conf:ro, ../firewall/geo.conf:/etc/nginx/conf.d/z_geo.conf:ro, ./upload_size.conf:/etc/nginx/conf.d/upload_size.conf:ro], networks: ["proxy-net"], restart: always, environment: ["TRUST_DOWNSTREAM_PROXY=true"]}
  acme-companion: {image: nginxproxy/acme-companion, container_name: gateway_acme, logging: {driver: "json-file", options: {max-size: "10m", max-file: "3"}}, volumes: [conf:/etc/nginx/conf.d, vhost:/etc/nginx/vhost.d, html:/usr/share/nginx/html, certs:/etc/nginx/certs:rw, acme:/etc/acme.sh, /var/run/docker.sock:/var/run/docker.sock:ro], environment: ["DEFAULT_EMAIL=admin@localhost.com", "NGINX_PROXY_CONTAINER=gateway_proxy", "ACME_CA_URI=https://acme-v02.api.letsencrypt.org/directory"], networks: ["proxy-net"], depends_on: ["nginx-proxy"], restart: always}
volumes: {conf: , vhost: , html: , certs: , acme: }
networks: {proxy-net: {external: true}}
EOF
    if docker compose up -d --remove-orphans >/dev/null 2>&1; then [ "$m" == "force" ] && echo -e "${GREEN}✔ 网关启动成功${NC}"; else echo -e "${RED}✘ 网关启动失败，请检查端口 80/443${NC}"; [ "$m" == "force" ] && docker compose up -d; fi 
}

function init_library() {
    mkdir -p "$LIB_DIR"
    mkdir -p "$LIB_DIR/uptime-kuma"; [ ! -f "$LIB_DIR/uptime-kuma/docker-compose.yml" ] && echo "Uptime Kuma" > "$LIB_DIR/uptime-kuma/name.txt" && echo "3001" > "$LIB_DIR/uptime-kuma/port.txt" && echo "services: {uptime-kuma: {image: louislam/uptime-kuma:1, container_name: {{APP_ID}}_kuma, restart: always, volumes: [./data:/app/data, /var/run/docker.sock:/var/run/docker.sock:ro], environment: [VIRTUAL_HOST={{DOMAIN}}, LETSENCRYPT_HOST={{DOMAIN}}, LETSENCRYPT_EMAIL={{EMAIL}}, VIRTUAL_PORT=3001], networks: [proxy-net]}}" > "$LIB_DIR/uptime-kuma/docker-compose.yml" && echo "networks: {proxy-net: {external: true}}" >> "$LIB_DIR/uptime-kuma/docker-compose.yml"
    mkdir -p "$LIB_DIR/alist"; [ ! -f "$LIB_DIR/alist/docker-compose.yml" ] && echo "Alist" > "$LIB_DIR/alist/name.txt" && echo "5244" > "$LIB_DIR/alist/port.txt" && echo "services: {alist: {image: xhofe/alist:latest, container_name: {{APP_ID}}_alist, restart: always, volumes: [./data:/opt/alist/data], environment: [VIRTUAL_HOST={{DOMAIN}}, LETSENCRYPT_HOST={{DOMAIN}}, LETSENCRYPT_EMAIL={{EMAIL}}, VIRTUAL_PORT=5244], networks: [proxy-net]}}" > "$LIB_DIR/alist/docker-compose.yml" && echo "networks: {proxy-net: {external: true}}" >> "$LIB_DIR/alist/docker-compose.yml"
    
    # [OpenList]
    mkdir -p "$LIB_DIR/openlist"
    if [ ! -f "$LIB_DIR/openlist/docker-compose.yml" ]; then
        echo "OpenList" > "$LIB_DIR/openlist/name.txt"; echo "5244" > "$LIB_DIR/openlist/port.txt" 
        cat > "$LIB_DIR/openlist/docker-compose.yml" <<EOF
services:
  openlist: {image: openlistteam/openlist:latest, container_name: {{APP_ID}}_openlist, user: '0:0', restart: unless-stopped, volumes: [./data:/opt/openlist/data], ports: ["{{HOST_PORT}}:5244"], environment: [UMASK=022, VIRTUAL_HOST={{DOMAIN}}, LETSENCRYPT_HOST={{DOMAIN}}, LETSENCRYPT_EMAIL={{EMAIL}}, VIRTUAL_PORT=5244], networks: [proxy-net]}
networks: {proxy-net: {external: true}}
EOF
    fi
}

function install_app() {
    init_library; clear; echo -e "${YELLOW}=== 📦 Docker应用商店 ===${NC}"
    i=1; apps=()
    for app in $(ls -1 "$LIB_DIR" | sort); do [ -d "$LIB_DIR/$app" ] && printf "${GREEN}[%s]${NC} %s\n" "$i" "$app" && apps[i]=$app && ((i++)); done
    echo "----------------"; read -p "选编号: " c; [ -z "${apps[$c]}" ] && return
    TARGET_APP=${apps[$c]}; DEFAULT_PORT=$(cat "$LIB_DIR/$TARGET_APP/port.txt" 2>/dev/null || echo "8080")
    read -p "域名: " d; validate_domain "$d" || return; read -p "邮箱: " e
    while true; do read -p "宿主机端口 (默认 $DEFAULT_PORT): " ip; HOST_PORT=${ip:-$DEFAULT_PORT}; if is_port_free "$HOST_PORT"; then break; else echo "端口被占"; fi; done
    SITE_PATH="$SITES_DIR/$d"; [ -d "$SITE_PATH" ] && echo "已存在" && pause_prompt && return
    mkdir -p "$SITE_PATH" && cp -r "$LIB_DIR/$TARGET_APP/"* "$SITE_PATH/"
    APP_ID=${d//./_}; sed -i "s|{{DOMAIN}}|$d|g" "$SITE_PATH/docker-compose.yml"; sed -i "s|{{EMAIL}}|$e|g" "$SITE_PATH/docker-compose.yml"; sed -i "s|{{APP_ID}}|$APP_ID|g" "$SITE_PATH/docker-compose.yml"; sed -i "s|{{HOST_PORT}}|$HOST_PORT|g" "$SITE_PATH/docker-compose.yml"
    echo "启动中..."; cd "$SITE_PATH" && docker compose up -d; check_ssl_status "$d"
}

# [Old 3] 找回
function create_redirect() {
    read -p "源域名: " s; validate_domain "$s" || return
    read -p "目标URL (http/https): " t; t=$(normalize_url "$t")
    read -p "邮箱: " e
    sdir="$SITES_DIR/$s"; mkdir -p "$sdir"
    echo "server { listen 80; server_name localhost; location / { return 301 $t\$request_uri; } }" > "$sdir/redirect.conf"
    cat > "$sdir/docker-compose.yml" <<EOF
services:
  redirector: {image: nginx:alpine, container_name: ${s//./_}_redirect, restart: always, volumes: [./redirect.conf:/etc/nginx/conf.d/default.conf], environment: {VIRTUAL_HOST: "$s", LETSENCRYPT_HOST: "$s", LETSENCRYPT_EMAIL: "$e"}, networks: [proxy-net]}
networks: {proxy-net: {external: true}}
EOF
    cd "$sdir" && docker compose up -d; check_ssl_status "$s"
}

# [Old 8] 找回
function change_domain() {
    ls -1 "$SITES_DIR"; read -p "旧域名: " o; [ ! -d "$SITES_DIR/$o" ] && return
    read -p "新域名: " n; validate_domain "$n" || return
    echo -e "${YELLOW}正在停机迁移...${NC}"; cd "$SITES_DIR/$o" && docker compose down
    cd .. && mv "$o" "$n" && cd "$n"; sed -i "s/$o/$n/g" docker-compose.yml
    docker compose up -d
    if grep -q "image: .*wordpress" docker-compose.yml; then
        echo -e "${CYAN}WordPress替换数据库...${NC}"
        wp_c=$(docker compose ps -q wordpress)
        docker run --rm --volumes-from $wp_c --network container:$wp_c wordpress:cli wp search-replace "$o" "$n" --all-tables --skip-columns=guid
    fi
    [ -f "nginx-proxy.conf" ] && sed -i "s/$o/$n/g" nginx-proxy.conf
    docker exec gateway_proxy nginx -s reload; echo -e "${GREEN}✔ 迁移完成${NC}"; write_log "Changed $o to $n"; pause_prompt
}

# [Old 9] 找回
function repair_proxy() {
    ls -1 "$SITES_DIR"; read -p "域名: " d; sdir="$SITES_DIR/$d"; [ ! -d "$sdir" ] && return
    read -p "新目标URL: " tu; tu=$(normalize_url "$tu")
    echo "server { listen 80; server_name localhost; location / { proxy_pass $tu; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_ssl_server_name on; } }" > "$sdir/nginx-proxy.conf"
    cd "$sdir" && docker compose restart; echo "OK"; pause_prompt
}

# [Old 13] 找回
function db_manager() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 数据库管理 ===${NC}"
        echo " 1. 导出 (Dump)  2. 导入 (Import)  0. 返回"
        read -p "选: " c
        case $c in 
            0) return;; 
            1) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; 
               pwd=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml"|awk -F': ' '{print $2}')
               if [ -z "$pwd" ]; then echo "非数据库站点"; pause_prompt; continue; fi
               docker compose -f "$s/docker-compose.yml" exec -T db mysqldump -u root -p"$pwd" --all-databases > "$s/${d}.sql"
               echo "导出成功: $s/${d}.sql"; pause_prompt;; 
            2) ls -1 "$SITES_DIR"; read -p "域名: " d; read -p "SQL文件绝对路径: " f; s="$SITES_DIR/$d"
               if [ ! -f "$f" ]; then echo "文件不存在"; pause_prompt; continue; fi
               pwd=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml"|awk -F': ' '{print $2}')
               cat "$f" | docker compose -f "$s/docker-compose.yml" exec -T db mysql -u root -p"$pwd"
               echo "导入完成"; pause_prompt;; 
        esac
    done 
}

function create_site() {
    read -p "1. 域名: " fd; validate_domain "$fd" || return
    host_ip=$(curl -s4 ifconfig.me); if command -v dig >/dev/null; then dip=$(dig +short $fd|head -1); fi
    if [ ! -z "$dip" ] && [ "$dip" != "$host_ip" ]; then echo -e "${RED}⚠️ IP不一致: DNS=$dip 本机=$host_ip${NC}"; read -p "继续? (y/n): " f; [ "$f" != "y" ] && return; fi
    read -p "2. 邮箱: " email; read -p "3. DB密码: " db_pass
    echo -e "${YELLOW}自定义? (y/n)${NC}"; read -p "> " cust; pt="php8.2-fpm-alpine"; di="mysql:8.0"; rt="7.0-alpine"
    if [ "$cust" == "y" ]; then echo "PHP: 1.7.4 2.8.0 3.8.2"; read -p "选: " p; [ "$p" == "1" ] && pt="php7.4-fpm-alpine" || ([ "$p" == "2" ] && pt="php8.0-fpm-alpine"); echo "DB: 1.5.7 2.8.0"; read -p "选: " d; [ "$d" == "1" ] && di="mysql:5.7"; fi
    pname=$(echo $fd|tr '.' '_'); sdir="$SITES_DIR/$fd"; [ -d "$sdir" ] && return; mkdir -p "$sdir"
    cat > "$sdir/waf.conf" <<EOF
location ~* /\.(git|env|sql) { deny all; return 403; }
EOF
    cat > "$sdir/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M; location / { try_files \$uri \$uri/ /index.php?\$args; } location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } }
EOF
    cat > "$sdir/docker-compose.yml" <<EOF
services:
  db: {image: $di, container_name: ${pname}_db, restart: always, environment: {MYSQL_ROOT_PASSWORD: $db_pass, MYSQL_DATABASE: wordpress, MYSQL_USER: wp_user, MYSQL_PASSWORD: $db_pass}, volumes: [db_data:/var/lib/mysql], networks: [default]}
  redis: {image: redis:$rt, container_name: ${pname}_redis, restart: always, networks: [default]}
  wordpress: {image: wordpress:$pt, container_name: ${pname}_app, restart: always, depends_on: [db, redis], environment: {WORDPRESS_DB_HOST: db, WORDPRESS_DB_USER: wp_user, WORDPRESS_DB_PASSWORD: $db_pass, WORDPRESS_DB_NAME: wordpress, WORDPRESS_CONFIG_EXTRA: "define('WP_REDIS_HOST','redis');define('WP_REDIS_PORT',6379);define('WP_HOME','https://'.\$\$_SERVER['HTTP_HOST']);define('WP_SITEURL','https://'.\$\$_SERVER['HTTP_HOST']);if(isset(\$\$_SERVER['HTTP_X_FORWARDED_PROTO'])&&strpos(\$\$_SERVER['HTTP_X_FORWARDED_PROTO'],'https')!==false){\$\$_SERVER['HTTPS']='on';}"}, volumes: [wp_data:/var/www/html, ./uploads.ini:/usr/local/etc/php/conf.d/uploads.ini], networks: [default]}
  nginx: {image: nginx:alpine, container_name: ${pname}_nginx, restart: always, volumes: [wp_data:/var/www/html, ./nginx.conf:/etc/nginx/conf.d/default.conf, ./waf.conf:/etc/nginx/waf.conf], environment: {VIRTUAL_HOST: "$fd", LETSENCRYPT_HOST: "$fd", LETSENCRYPT_EMAIL: "$email"}, networks: [default, proxy-net]}
volumes: {db_data: , wp_data: }
networks: {proxy-net: {external: true}}
EOF
    cd "$sdir" && docker compose up -d; check_ssl_status "$fd"; write_log "Created site $fd"
}

function create_proxy() {
    read -p "1. 域名: " d; fd="$d"; validate_domain "$d" || return
    read -p "2. 邮箱: " e; sdir="$SITES_DIR/$d"; mkdir -p "$sdir"
    echo -e "1.URL 2.IP:端口"; read -p "类型: " t
    if [ "$t" == "2" ]; then read -p "IP: " ip; [ -z "$ip" ] && ip="127.0.0.1"; read -p "端口: " p; tu="http://$ip:$p"; pm="2"; else read -p "URL: " tu; tu=$(normalize_url "$tu"); pm="1"; fi
    echo "server { listen 80; server_name localhost; location / { proxy_pass $tu; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_ssl_server_name on; } }" > "$sdir/nginx-proxy.conf"
    cat > "$sdir/docker-compose.yml" <<EOF
services:
  proxy: {image: nginx:alpine, container_name: ${d//./_}_worker, restart: always, volumes: [./nginx-proxy.conf:/etc/nginx/conf.d/default.conf], environment: {VIRTUAL_HOST: "$fd", LETSENCRYPT_HOST: "$fd", LETSENCRYPT_EMAIL: "$e"}, networks: [proxy-net]}
networks: {proxy-net: {external: true}}
EOF
    cd "$sdir" && docker compose up -d; check_ssl_status "$d";
}

function delete_site() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 🗑️ 删除网站 (增强版) ===${NC}"; ls -1 "$SITES_DIR"; echo "----------------"; 
        read -p "请输入要删除的域名 (0返回): " d; [ "$d" == "0" ] && return
        target_dir="$SITES_DIR/$d"
        if [ -d "$target_dir" ]; then 
            read -p "危险: 确认删除 $d ? (yes/no): " c
            if [ "$c" == "yes" ]; then 
                echo -e "${YELLOW}停止容器...${NC}"
                cd "$target_dir" && docker compose down -v 2>/dev/null || true
                cd "$BASE_DIR" || exit
                rm -rf "$target_dir"
                echo -e "${GREEN}✔ 已删除${NC}"; write_log "Deleted $d"
            fi
        else echo -e "${RED}目录不存在${NC}"; fi
        pause_prompt
    done 
}

function list_sites() {
    clear; echo -e "${YELLOW}=== 📂 站点列表 ===${NC}"
    if [ ! -d "$SITES_DIR" ] || [ -z "$(ls -A "$SITES_DIR")" ]; then echo -e "${RED}无站点${NC}"; pause_prompt; return; fi
    printf "${CYAN}%-25s %-15s %-15s${NC}\n" "域名" "类型" "状态"
    echo "--------------------------------------------------------"
    for site_path in "$SITES_DIR"/*; do
        if [ -d "$site_path" ]; then
            domain=$(basename "$site_path"); dc="$site_path/docker-compose.yml"
            app_type="未知"; st="${RED}Stopped${NC}"
            if [ -f "$dc" ]; then
                if grep -q "image: .*wordpress" "$dc"; then app_type="WordPress";
                elif grep -q "image: .*alist" "$dc"; then app_type="Alist";
                elif grep -q "image: .*openlist" "$dc"; then app_type="OpenList";
                elif grep -q "proxy_pass" "$site_path/nginx-proxy.conf" 2>/dev/null; then app_type="反代";
                elif grep -q "redirector" "$dc"; then app_type="301跳转"; fi
            fi
            site_id=${domain//./_}; if docker ps --format '{{.Names}}' | grep -q "$site_id"; then st="${GREEN}Running${NC}"; fi
            printf "%-25s %-15s %-15s\n" "$domain" "$app_type" "$st"
        fi
    done
    echo "--------------------------------------------------------"
    pause_prompt
}

function backup_restore_ops() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 备份与还原 (安全版) ===${NC}"
        echo " 1. 创建备份  2. 还原备份  0. 返回"
        read -p "选: " b
        case $b in 
            0) return;; 
            1) 
                ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; [ ! -d "$s" ] && continue
                bd="$s/backups/$(date +%Y%m%d%H%M)"; mkdir -p "$bd"; cd "$s"
                pwd=$(grep MYSQL_ROOT_PASSWORD docker-compose.yml|awk -F': ' '{print $2}')
                if [ -z "$pwd" ]; then touch "$bd/db.sql"; else
                    if ! docker compose exec -T db mysqldump -u root -p"$pwd" --all-databases > "$bd/db.sql"; then echo "${RED}导出失败${NC}"; rm -rf "$bd"; pause_prompt; continue; fi
                    if [ ! -s "$bd/db.sql" ]; then echo "${RED}文件为空${NC}"; rm -rf "$bd"; pause_prompt; continue; fi
                fi
                echo "打包中..."; wp_c=$(docker compose ps -q wordpress 2>/dev/null)
                if [ ! -z "$wp_c" ]; then docker run --rm --volumes-from $wp_c -v "$bd":/backup alpine tar czf /backup/files.tar.gz /var/www/html/wp-content; else tar czf "$bd/files.tar.gz" .; fi
                cp *.conf docker-compose.yml "$bd/" 2>/dev/null; echo "✅ 成功: $bd"; write_log "Backup $d"; pause_prompt;; 
            2) 
                ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; bd="$s/backups"; [ ! -d "$bd" ] && echo "无备份" && pause_prompt && continue
                lt=$(ls -t "$bd"|head -1); echo "最新: $lt"; read -p "使用最新? (y/n): " u; [ "$u" == "y" ] && n="$lt" || { ls -1 "$bd"; read -p "目录名: " n; }
                bp="$bd/$n"; [ ! -d "$bp" ] && continue
                echo -e "${RED}⚠️  覆盖数据${NC}"; read -p "确认? (yes/no): " c; [ "$c" != "yes" ] && continue
                cd "$s" && docker compose down
                vol=$(docker volume ls -q|grep "${d//./_}_wp_data")
                if [ ! -z "$vol" ]; then docker run --rm -v $vol:/var/www/html -v "$bp":/backup alpine tar xzf /backup/files.tar.gz -C /; fi
                docker compose up -d db; echo "等待DB..."; sleep 15
                pwd=$(grep MYSQL_ROOT_PASSWORD docker-compose.yml|awk -F': ' '{print $2}')
                if [ ! -z "$pwd" ] && [ -f "$bp/db.sql" ]; then docker compose exec -T db mysql -u root -p"$pwd" < "$bp/db.sql"; fi
                docker compose up -d; echo "✅ 完成"; pause_prompt;; 
        esac
    done 
}

function container_ops() { cd "$GATEWAY_DIR" && docker compose ps; echo "---"; for d in "$SITES_DIR"/*; do cd "$d" && docker compose ps; done; pause_prompt; }
function cert_management() { 
    while true; do 
        clear; echo "1. 列表  2. 上传  3. 续签  0. 返回"; read -p "选: " c
        case $c in 0) return;; 1) docker exec gateway_proxy ls -lh /etc/nginx/certs|grep .crt; pause_prompt;; 
        2) ls -1 "$SITES_DIR"; read -p "域名: " d; read -p "crt: " c; read -p "key: " k; docker cp "$c" gateway_acme:"/etc/nginx/certs/$d.crt"; docker cp "$k" gateway_acme:"/etc/nginx/certs/$d.key"; docker exec gateway_proxy nginx -s reload; echo "OK"; pause_prompt;; 
        3) docker exec gateway_acme /app/force_renew; echo "OK"; pause_prompt;; esac
    done
}
function manage_hotlink() { 
    while true; do 
        clear; echo "1. 开防盗链  2. 关防盗链  0. 返回"; read -p "选: " h; case $h in 0) return;; 
        1) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; read -p "白名单(google.com): " w; cat > "$s/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M; location ~* \.(gif|jpg|png|webp)$ { valid_referers none blocked server_names $d *.$d $w; if (\$invalid_referer) { return 403; } try_files \$uri \$uri/ /index.php?\$args; } location / { try_files \$uri \$uri/ /index.php?\$args; } location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } }
EOF
        cd "$s" && docker compose restart nginx; echo "OK";; 2) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; cat > "$s/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M; location / { try_files \$uri \$uri/ /index.php?\$args; } location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } }
EOF
        cd "$s" && docker compose restart nginx; echo "OK";; esac; pause_prompt; done; }
function uninstall_cluster() { echo "⚠️ 危险: 输入 DELETE 确认"; read -p "> " c; [ "$c" == "DELETE" ] && (ls "$SITES_DIR"|while read d; do cd "$SITES_DIR/$d" && docker compose down -v; done; cd "$GATEWAY_DIR" && docker compose down -v; docker network rm proxy-net; rm -rf "$BASE_DIR" /usr/bin/web; echo "已卸载"); }

# ================= 6. 主菜单 =================
function show_menu() {
    clear
    echo -e "${GREEN}=== Docker Web Manager ($VERSION) ===${NC}"
    echo -e "${YELLOW}[建站]${NC}"
    echo " 1. 新建 WordPress"
    echo " 2. 新建 反向代理"
    echo " 3. 新建 域名重定向 (301)"
    echo " 4. 应用商店 (OpenList/Alist)"
    echo -e "${YELLOW}[运维]${NC}"
    echo " 5. 站点列表 (状态)"
    echo " 6. 删除站点 (安全)"
    echo " 7. 备份与还原"
    echo " 8. 更换域名"
    echo " 9. 修复反代"
    echo " 10. 数据库管理"
    echo -e "${YELLOW}[高级]${NC}"
    echo " 11. 容器监控"
    echo " 12. 组件升级"
    echo " 13. WP-CLI 工具箱"
    echo -e "${RED}[安全]${NC}"
    echo " 14. 安全防御中心 (WAF/审计)"
    echo " 15. Telegram 通知"
    echo " 16. 系统资源监控"
    echo " 17. 日志管理"
    echo "-----------------------------------------"
    echo -e "${BLUE} u. 更新${NC} | ${RED}x. 卸载${NC} | 0. 退出"
    echo -n "请选择: "
    read option
}

check_dependencies
install_shortcut
if ! docker ps --format '{{.Names}}' | grep -q "^gateway_proxy$"; then echo "初始化网关..."; init_gateway "auto"; fi

while true; do 
    show_menu 
    case $option in 
        u|U) update_script;; 
        1) create_site;; 
        2) create_proxy;; 
        3) create_redirect;;
        4) install_app;;
        5) list_sites;; 
        6) delete_site;; 
        7) backup_restore_ops;; 
        8) change_domain;; 
        9) repair_proxy;; 
        10) db_manager;;
        11) container_ops;; 
        12) component_manager;; 
        13) wp_toolbox;; 
        14) security_center;; 
        15) telegram_manager;; 
        16) sys_monitor;; 
        17) log_manager;; 
        x|X) uninstall_cluster;; 
        0) exit 0;; 
    esac
done
