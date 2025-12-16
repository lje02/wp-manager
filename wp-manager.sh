#!/bin/bash

# ================= 1. 配置区域 =================
# 脚本版本号
VERSION="V64 (TG-Monitor-Daemon)"

# 数据存储路径
BASE_DIR="/root/wp-cluster"
SITES_DIR="$BASE_DIR/sites"
GATEWAY_DIR="$BASE_DIR/gateway"
FW_DIR="$BASE_DIR/firewall"
TG_CONF="$BASE_DIR/telegram.conf"
LOG_FILE="$BASE_DIR/operation.log"
MONITOR_PID="$BASE_DIR/monitor.pid"
MONITOR_SCRIPT="$BASE_DIR/monitor_daemon.sh"

# 自动更新源
UPDATE_URL="https://raw.githubusercontent.com/lje02/wp-manager/main/wp-manager.sh"

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

# 初始化目录
mkdir -p "$SITES_DIR" "$GATEWAY_DIR" "$FW_DIR"
touch "$FW_DIR/access.conf" "$FW_DIR/geo.conf"
[ ! -f "$LOG_FILE" ] && touch "$LOG_FILE"

# ================= 2. 基础工具函数 =================

function write_log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

function pause_prompt() {
    echo -e "\n${YELLOW}>>> 操作完成，按回车键返回...${NC}"
    read -r
}

function install_shortcut() {
    local script_path=$(readlink -f "$0")
    if [ ! -L "/usr/bin/wp" ] || [ "$(readlink -f "/usr/bin/wp")" != "$script_path" ]; then
        ln -sf "$script_path" /usr/bin/wp && chmod +x "$script_path"
    fi
}

function check_and_install_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${YELLOW}未检测到 Docker，准备自动安装...${NC}"
        curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun
        systemctl enable docker && systemctl start docker
        write_log "Installed Docker"
    fi
}

function ensure_firewall_installed() {
    if command -v ufw >/dev/null || command -v firewall-cmd >/dev/null; then return 0; fi
    echo -e "${YELLOW}>>> 正在安装防火墙...${NC}"
    if [ -f /etc/debian_version ]; then
        apt-get update -y && apt-get install -y ufw
        ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp
        echo "y" | ufw enable
    elif [ -f /etc/redhat-release ]; then
        yum install -y firewalld; systemctl enable firewalld --now
        firewall-cmd --permanent --add-service={ssh,http,https}; firewall-cmd --reload
    else
        echo -e "${RED}❌ 系统不支持自动安装防火墙${NC}"; pause_prompt; return 1
    fi
    write_log "Installed Firewall"
    echo -e "${GREEN}✔ 防火墙就绪${NC}"; sleep 1
}

function check_ssl_status() {
    local d=$1; echo -e "${CYAN}>>> [SSL] 正在向 Let's Encrypt 申请证书...${NC}"; for ((i=1; i<=20; i++)); do if docker exec gateway_acme test -f "/etc/nginx/certs/$d.crt"; then echo -e "${GREEN}✔ SSL 证书获取成功: https://$d${NC}"; pause_prompt; return 0; fi; echo -n "."; sleep 5; done; echo -e "\n${YELLOW}⚠️ 证书暂未生成 (可能是DNS延迟)${NC}"; pause_prompt;
}

function normalize_url() {
    local url=$1; url=${url%/}; if [[ "$url" != http* ]]; then echo "https://$url"; else echo "$url"; fi
}

function update_script() {
    clear; echo -e "${GREEN}=== 脚本自动更新 ===${NC}"; echo -e "版本: $VERSION"; echo -e "源: github.com/lje02/wp-manager"
    temp_file="/tmp/wp_manager_new.sh"
    if curl -f -L -s -o "$temp_file" "$UPDATE_URL" && head -n 1 "$temp_file" | grep -q "/bin/bash"; then
        mv "$temp_file" "$0"; chmod +x "$0"; echo -e "${GREEN}✔ 更新成功，重启中...${NC}"; write_log "Updated script"; sleep 1; exec "$0"
    else 
        echo -e "${RED}❌ 更新失败!${NC}"; rm -f "$temp_file"
    fi
    pause_prompt
}

# --- Telegram 核心发送函数 ---
function send_tg_msg() {
    local msg=$1
    if [ -f "$TG_CONF" ]; then
        source "$TG_CONF"
        if [ ! -z "$TG_BOT_TOKEN" ] && [ ! -z "$TG_CHAT_ID" ]; then
            curl -s -X POST "https://api.telegram.org/bot$TG_BOT_TOKEN/sendMessage" -d chat_id="$TG_CHAT_ID" -d text="$msg" >/dev/null
        fi
    fi
}

# --- 生成后台监控脚本 (核心逻辑) ---
function generate_monitor_script() {
cat > "$MONITOR_SCRIPT" <<EOF
#!/bin/bash
TG_CONF="$TG_CONF"
# 阈值设置 (百分比)
CPU_THRESHOLD=90
MEM_THRESHOLD=90
DISK_THRESHOLD=90
# 冷却时间 (秒) - 30分钟
COOLDOWN=1800
LAST_ALERT=0

function send_msg() {
    if [ -f "\$TG_CONF" ]; then source "\$TG_CONF"; curl -s -X POST "https://api.telegram.org/bot\$TG_BOT_TOKEN/sendMessage" -d chat_id="\$TG_CHAT_ID" -d text="\$1" >/dev/null; fi
}

while true; do
    # 获取指标
    CPU_USAGE=\$(grep 'cpu ' /proc/stat | awk '{usage=(\$2+\$4)*100/(\$2+\$4+\$5)} END {print usage}' | cut -d. -f1)
    MEM_USAGE=\$(free | grep Mem | awk '{print \$3/\$2 * 100.0}' | cut -d. -f1)
    DISK_USAGE=\$(df / | awk 'NR==2 {print \$5}' | sed 's/%//')
    
    ALERT_MSG=""
    
    if [ "\$CPU_USAGE" -gt "\$CPU_THRESHOLD" ]; then ALERT_MSG="\$ALERT_MSG\n🚨 CPU 过高: \${CPU_USAGE}%"; fi
    if [ "\$MEM_USAGE" -gt "\$MEM_THRESHOLD" ]; then ALERT_MSG="\$ALERT_MSG\n🚨 内存过高: \${MEM_USAGE}%"; fi
    if [ "\$DISK_USAGE" -gt "\$DISK_THRESHOLD" ]; then ALERT_MSG="\$ALERT_MSG\n🚨 磁盘爆满: \${DISK_USAGE}%"; fi
    
    if [ ! -z "\$ALERT_MSG" ]; then
        NOW=\$(date +%s)
        DIFF=\$((NOW - LAST_ALERT))
        if [ "\$DIFF" -gt "\$COOLDOWN" ]; then
            send_msg "⚠️ **服务器资源警报** \nHostname: \$(hostname) \$ALERT_MSG"
            LAST_ALERT=\$NOW
        fi
    fi
    
    sleep 60
done
EOF
chmod +x "$MONITOR_SCRIPT"
}

# ================= 3. 业务功能函数 =================

# --- Telegram 管理与监控 ---
function telegram_manager() {
    while true; do
        clear; echo -e "${YELLOW}=== 🤖 Telegram 监控机器人 ===${NC}"
        if [ -f "$TG_CONF" ]; then source "$TG_CONF"; fi
        
        # 检查后台进程状态
        if [ -f "$MONITOR_PID" ] && kill -0 $(cat "$MONITOR_PID") 2>/dev/null; then
            DAEMON_STATUS="${GREEN}运行中 (PID: $(cat $MONITOR_PID))${NC}"
        else
            DAEMON_STATUS="${RED}未启动${NC}"
        fi

        echo -e "机器人状态: ${CYAN}${TG_BOT_TOKEN:0:10}******${NC}"
        echo -e "守护进程: $DAEMON_STATUS"
        echo "--------------------------"
        echo " 1. 配置 Token 和 ChatID"
        echo " 2. 发送一次系统状态 (立即)"
        echo " 3. 启动/重启 自动报警守护进程 (CPU/内存>90%)"
        echo " 4. 停止 自动报警"
        echo " 5. 发送测试消息"
        echo " 0. 返回"
        read -p "选择: " t
        case $t in
            0) return;;
            1) 
                read -p "Bot Token: " tk; echo "TG_BOT_TOKEN=\"$tk\"" > "$TG_CONF"
                read -p "Chat ID: " ci; echo "TG_CHAT_ID=\"$ci\"" >> "$TG_CONF"
                echo -e "${GREEN}✔ 配置已保存${NC}"; pause_prompt;;
            2)
                echo "正在收集系统信息..."
                cpu=$(uptime | awk -F'load average:' '{print $2}')
                mem=$(free -h | grep Mem | awk '{print $3 "/" $2}')
                disk=$(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')
                ip=$(curl -s4 ifconfig.me)
                msg="📊 **系统状态报告**%0A💻 主机: $(hostname)%0A🌐 IP: $ip%0A🧠 负载: $cpu%0A💾 内存: $mem%0A💿 磁盘: $disk"
                send_tg_msg "$msg"
                echo -e "${GREEN}✔ 报告已发送${NC}"; pause_prompt;;
            3)
                generate_monitor_script
                # 杀死旧进程
                if [ -f "$MONITOR_PID" ]; then kill $(cat "$MONITOR_PID") 2>/dev/null; fi
                # 后台启动
                nohup "$MONITOR_SCRIPT" >/dev/null 2>&1 &
                echo $! > "$MONITOR_PID"
                send_tg_msg "✅ 自动监控守护进程已启动"
                echo -e "${GREEN}✔ 守护进程已启动，报警功能生效${NC}"; pause_prompt;;
            4)
                if [ -f "$MONITOR_PID" ]; then kill $(cat "$MONITOR_PID") 2>/dev/null; rm "$MONITOR_PID"; fi
                echo -e "${RED}✔ 守护进程已停止${NC}"; pause_prompt;;
            5) send_tg_msg "🔔 这是一条测试消息"; echo "已发送"; pause_prompt;;
        esac
    done
}

# --- 系统监控 (本地) ---
function sys_monitor() {
    while true; do
        clear; echo -e "${YELLOW}=== 🖥️ 系统资源监控 ===${NC}"
        load=$(uptime | awk -F'load average:' '{print $2}')
        echo -e "CPU 负载 : ${GREEN}$load${NC}"
        if command -v free >/dev/null; then mem=$(free -h | grep Mem | awk '{print $3 "/" $2}'); echo -e "内存使用 : ${CYAN}$mem${NC}"; fi
        disk=$(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')
        echo -e "磁盘占用 : ${BLUE}$disk${NC}"
        up=$(uptime -p); echo -e "运行时间 : ${YELLOW}$up${NC}"
        conn=$(netstat -an | grep ESTABLISHED | wc -l 2>/dev/null || ss -s | grep est | awk '{print $2}')
        echo -e "TCP连接数: ${RED}$conn${NC}"
        echo "--------------------------"; echo "按回车刷新，输入 0 返回"; read -t 5 -p "> " op; [ "$op" == "0" ] && return
    done
}

# --- 日志管理 ---
function log_manager() {
    while true; do
        clear; echo -e "${YELLOW}=== 📜 日志管理系统 ===${NC}"
        echo -e "日志文件: $LOG_FILE"; echo -e "文件大小: $(du -h $LOG_FILE 2>/dev/null | awk '{print $1}')"
        echo "--------------------------"
        echo " 1. 查看日志 (最新50条)"; echo " 2. 清空日志"; echo " 3. 配置自动清理 (7天)"; echo " 0. 返回"; read -p "选择: " l
        case $l in
            0) return;;
            1) echo -e "${CYAN}--- Start ---${NC}"; tail -n 50 "$LOG_FILE"; echo -e "${CYAN}--- End ---${NC}"; pause_prompt;;
            2) echo "" > "$LOG_FILE"; echo "已清空"; write_log "Cleared logs"; pause_prompt;;
            3) crontab -l 2>/dev/null | grep -v "wp-cluster" | crontab -; (crontab -l 2>/dev/null; echo "0 3 * * * find $BASE_DIR -name '*.log' -mtime +7 -delete #wp-cluster-log-clean") | crontab -; echo "定时任务已添加"; pause_prompt;;
        esac
    done
}

# --- 容器监控 ---
function container_ops() {
    while true; do
        clear; echo -e "${YELLOW}=== 📊 容器状态监控 ===${NC}"
        echo "---------------------------------------------------"
        echo -e "核心网关:"; cd "$GATEWAY_DIR" && docker compose ps --format "table {{.Service}}\t{{.State}}\t{{.Status}}" | tail -n +2 | while read l; do if echo "$l"|grep -q "running"; then echo -e "${GREEN}  $l (运行中)${NC}"; else echo -e "${RED}  $l (异常)${NC}"; fi; done
        for d in "$SITES_DIR"/*; do
            if [ -d "$d" ]; then
                echo "---------------------------------------------------"
                echo -e "站点: ${CYAN}$(basename "$d")${NC}"
                cd "$d" && docker compose ps --all --format "table {{.Service}}\t{{.State}}\t{{.Status}}" | tail -n +2 | while read l; do
                    if echo "$l" | grep -q "running"; then echo -e "${GREEN}  $l${NC}"; elif echo "$l" | grep -q "exited"; then echo -e "${RED}  $l (停止)${NC}"; else echo -e "${YELLOW}  $l${NC}"; fi
                done
            fi
        done
        echo "---------------------------------------------------"
        echo " 1. 一键全启  2. 一键全停  3. 一键重启  4. 指定操作  0. 返回"; read -p "选择: " c
        case $c in
            0) return;;
            1) cd "$GATEWAY_DIR" && docker compose up -d; for d in "$SITES_DIR"/*; do cd "$d" && docker compose up -d; done; echo "完成"; write_log "Start All"; pause_prompt;;
            2) for d in "$SITES_DIR"/*; do cd "$d" && docker compose stop; done; cd "$GATEWAY_DIR" && docker compose stop; echo "完成"; write_log "Stop All"; pause_prompt;;
            3) cd "$GATEWAY_DIR" && docker compose restart; for d in "$SITES_DIR"/*; do cd "$d" && docker compose restart; done; echo "完成"; write_log "Restart All"; pause_prompt;;
            4) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; [ -d "$s" ] && cd "$s" && read -p "1.启 2.停 3.重启: " a && ([ "$a" == "1" ] && docker compose up -d || ([ "$a" == "2" ] && docker compose stop || docker compose restart)); echo "完成"; write_log "Op site $d"; pause_prompt;;
        esac
    done
}

# --- 组件管理 ---
function component_manager() {
    while true; do
        clear; echo -e "${YELLOW}=== 🆙 组件版本升降级 ===${NC}"
        ls -1 "$SITES_DIR"; echo "--------------------------"; read -p "域名(0返回): " d; [ "$d" == "0" ] && return
        sdir="$SITES_DIR/$d"; [ ! -d "$sdir" ] && continue
        cur_wp=$(grep "image: wordpress" "$sdir/docker-compose.yml"|awk '{print $2}'); cur_db=$(grep "image: .*sql" "$sdir/docker-compose.yml"|awk '{print $2}')
        echo -e "当前: PHP=[$cur_wp] DB=[$cur_db]"
        echo " 1. PHP  2. DB(高危)  3. Redis  4. Nginx  0. 返回"; read -p "选择: " op
        case $op in
            0) break;;
            1) echo "1.7.4 2.8.0 3.8.1 4.8.2 5.Latest"; read -p "选: " p; case $p in 1) t="php7.4-fpm-alpine";; 2) t="php8.0-fpm-alpine";; 3) t="php8.1-fpm-alpine";; 4) t="php8.2-fpm-alpine";; 5) t="fpm-alpine";; *) continue;; esac; sed -i "s|image: wordpress:.*|image: wordpress:$t|g" "$sdir/docker-compose.yml"; cd "$sdir" && docker compose up -d; echo "OK"; write_log "PHP update $d $t"; pause_prompt;;
            2) echo "1.MySQL5.7 2.MySQL8.0 3.MySQL最新 4.MariaDB10.6 5.MariaDB最新"; read -p "选: " v; case $v in 1) i="mysql:5.7";; 2) i="mysql:8.0";; 3) i="mysql:latest";; 4) i="mariadb:10.6";; 5) i="mariadb:latest";; *) continue;; esac; sed -i "s|image: .*sql:.*|image: $i|g" "$sdir/docker-compose.yml"; sed -i "s|image: mariadb:.*|image: $i|g" "$sdir/docker-compose.yml"; cd "$sdir" && docker compose up -d; echo "OK"; write_log "DB update $d $i"; pause_prompt;;
            3) echo "1.Redis6.2 2.Redis7.0 3.Latest"; read -p "选: " r; case $r in 1) rt="6.2-alpine";; 2) rt="7.0-alpine";; 3) rt="alpine";; esac; sed -i "s|image: redis:.*|image: redis:$rt|g" "$sdir/docker-compose.yml"; cd "$sdir" && docker compose up -d; echo "OK"; write_log "Redis update $d $rt"; pause_prompt;;
            4) echo "1.Alpine 2.Latest"; read -p "选: " n; [ "$n" == "2" ] && nt="latest" || nt="alpine"; sed -i "s|image: nginx:.*|image: nginx:$nt|g" "$sdir/docker-compose.yml"; cd "$sdir" && docker compose up -d; echo "OK"; write_log "Nginx update $d $nt"; pause_prompt;;
        esac
    done
}

# --- 防御中心 ---
function fail2ban_manager() {
    while true; do clear; echo -e "${YELLOW}=== Fail2Ban ===${NC}"; echo "1.安装(5次封24h) 2.列表 3.解封 0.返回"; read -p "选: " o; case $o in 0) return;; 1) echo "安装..."; if [ -f /etc/debian_version ]; then apt-get install -y fail2ban; lp="/var/log/auth.log"; else yum install -y fail2ban; lp="/var/log/secure"; fi; cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip=127.0.0.1/8
bantime=86400
findtime=3600
maxretry=5
[sshd]
enabled=true
port=ssh
logpath=$lp
backend=systemd
EOF
    systemctl enable fail2ban; systemctl restart fail2ban; echo "OK"; pause_prompt;; 2) fail2ban-client status sshd 2>/dev/null|grep Banned; pause_prompt;; 3) read -p "IP: " i; fail2ban-client set sshd unbanip $i; echo "OK"; pause_prompt;; esac; done
}

function waf_manager() {
    while true; do clear; echo -e "${YELLOW}=== WAF ===${NC}"; echo "1.部署 2.查看 0.返回"; read -p "选: " o; case $o in 0) return;; 1) cat >/tmp/w <<EOF
location ~* /\.(git|svn|env|sql|db) { deny all; return 403; }
if (\$query_string ~* "(union.*select|eval\(|base64_)") { return 403; }
if (\$http_user_agent ~* (scan|sqlmap|nikto)) { return 403; }
EOF
    for d in "$SITES_DIR"/*; do [ -d "$d" ] && cp /tmp/w "$d/waf.conf" && cd "$d" && docker compose exec -T nginx nginx -s reload; done; rm /tmp/w; echo "OK"; pause_prompt;; 2) cat "$SITES_DIR/"*"/waf.conf" 2>/dev/null|head -5; pause_prompt;; esac; done
}

function port_manager() {
    ensure_firewall_installed || return
    if command -v ufw >/dev/null && ! ufw status | grep -q "active"; then ufw allow 22/tcp >/dev/null; ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null; echo "y" | ufw enable >/dev/null; fi
    while true; do 
        clear; echo -e "${YELLOW}=== 端口防火墙 ===${NC}"; if command -v ufw >/dev/null; then FW="UFW"; else FW="Firewalld"; fi; echo "防火墙: $FW"
        echo "1.列表 2.开关端口(多端口) 3.防DOS 4.全开/全锁 0.返回"; read -p "选: " f
        case $f in
            0) return;;
            1) if [ "$FW" == "UFW" ]; then ufw status; else firewall-cmd --list-ports; fi; pause_prompt;;
            2) read -p "端口(如 80 443): " ports; echo "1.开 2.关"; read -p "选: " a
               for p in $ports; do
                   if [ "$FW" == "UFW" ]; then [ "$a" == "1" ] && ufw allow $p/tcp || ufw delete allow $p/tcp
                   else ac=$([ "$a" == "1" ] && echo add || echo remove); firewall-cmd --zone=public --${ac}-port=$p/tcp --permanent; fi
               done
               [ "$FW" != "UFW" ] && firewall-cmd --reload
               echo "完成"; pause_prompt;;
            3) echo "1.开启防DOS 2.关闭"; read -p "选: " d; if [ "$d" == "1" ]; then echo "limit_req_zone \$binary_remote_addr zone=one:10m rate=10r/s; limit_conn_zone \$binary_remote_addr zone=addr:10m;" > "$FW_DIR/dos_zones.conf"; mkdir -p "$GATEWAY_DIR/vhost"; echo "limit_req zone=one burst=15 nodelay; limit_conn addr 15;" > "$GATEWAY_DIR/vhost/default"; cd "$GATEWAY_DIR" && docker compose up -d >/dev/null 2>&1 && docker exec gateway_proxy nginx -s reload; echo "已开启"; else rm -f "$FW_DIR/dos_zones.conf" "$GATEWAY_DIR/vhost/default"; cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload; echo "已关闭"; fi; pause_prompt;;
            4) echo "1.全开 2.全锁"; read -p "选: " m; if [ "$m" == "1" ]; then [ "$FW" == "UFW" ] && ufw default allow incoming || firewall-cmd --set-default-zone=trusted; else if [ "$FW" == "UFW" ]; then ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp; ufw default deny incoming; else firewall-cmd --permanent --add-service={ssh,http,https}; firewall-cmd --set-default-zone=drop; firewall-cmd --reload; fi; fi; echo "完成"; pause_prompt;;
        esac
    done
}

function traffic_manager() {
    while true; do clear; echo -e "${YELLOW}=== 流量控制 ===${NC}"; echo "1.加黑 2.加白 3.国家 4.清空 0.返回"; read -p "选: " t; case $t in 0) return;; 1|2) tp="deny"; [ "$t" == "2" ] && tp="allow"; read -p "IP: " i; echo "$tp $i;" >> "$FW_DIR/access.conf"; cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload; echo "OK"; pause_prompt;; 3) read -p "代码(cn): " c; wget -qO- "http://www.ipdeny.com/ipblocks/data/countries/$c.zone" | while read l; do echo "deny $l;" >> "$FW_DIR/geo.conf"; done; cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload; echo "OK"; pause_prompt;; 4) echo "" > "$FW_DIR/access.conf"; echo "" > "$FW_DIR/geo.conf"; cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload; echo "OK"; pause_prompt;; esac; done
}

function security_center() {
    while true; do clear; echo -e "${YELLOW}=== 安全中心 ===${NC}"; echo "1.端口 2.流量ACL 3.Fail2Ban 4.WAF 5.证书 6.防盗链 0.返回"; read -p "选: " s; case $s in 0) return;; 1) port_manager;; 2) traffic_manager;; 3) fail2ban_manager;; 4) waf_manager;; 5) cert_management;; 6) manage_hotlink;; esac; done
}

# --- 基础操作函数 ---
function init_gateway() { local m=$1; if ! docker network ls|grep -q proxy-net; then docker network create proxy-net >/dev/null; fi; mkdir -p "$GATEWAY_DIR"; cd "$GATEWAY_DIR"; echo "client_max_body_size 1024m;" > upload_size.conf; echo "proxy_read_timeout 600s;" >> upload_size.conf; echo "proxy_send_timeout 600s;" >> upload_size.conf; cat > docker-compose.yml <<EOF
services:
  nginx-proxy: {image: nginxproxy/nginx-proxy, container_name: gateway_proxy, ports: ["80:80", "443:443"], volumes: [conf:/etc/nginx/conf.d, vhost:/etc/nginx/vhost.d, html:/usr/share/nginx/html, certs:/etc/nginx/certs:ro, /var/run/docker.sock:/tmp/docker.sock:ro, ../firewall/access.conf:/etc/nginx/conf.d/z_access.conf:ro, ../firewall/geo.conf:/etc/nginx/conf.d/z_geo.conf:ro, ./upload_size.conf:/etc/nginx/conf.d/upload_size.conf:ro], networks: ["proxy-net"], restart: always, environment: ["TRUST_DOWNSTREAM_PROXY=true"]}
  acme-companion: {image: nginxproxy/acme-companion, container_name: gateway_acme, volumes: [conf:/etc/nginx/conf.d, vhost:/etc/nginx/vhost.d, html:/usr/share/nginx/html, certs:/etc/nginx/certs:rw, acme:/etc/acme.sh, /var/run/docker.sock:/var/run/docker.sock:ro], environment: ["DEFAULT_EMAIL=admin@localhost.com", "NGINX_PROXY_CONTAINER=gateway_proxy", "ACME_CA_URI=https://acme-v02.api.letsencrypt.org/directory"], networks: ["proxy-net"], depends_on: ["nginx-proxy"], restart: always}
volumes: {conf: , vhost: , html: , certs: , acme: }
networks: {proxy-net: {external: true}}
EOF
if docker compose up -d --remove-orphans >/dev/null 2>&1; then [ "$m" == "force" ] && echo -e "${GREEN}✔ 网关启动成功${NC}"; else echo -e "${RED}✘ 网关启动失败${NC}"; [ "$m" == "force" ] && docker compose up -d; fi; }

function create_site() {
    read -p "1. 域名: " fd; host_ip=$(curl -s4 ifconfig.me); if command -v dig >/dev/null; then dip=$(dig +short $fd|head -1); else dip=$(getent hosts $fd|awk '{print $1}'); fi; if [ ! -z "$dip" ] && [ "$dip" != "$host_ip" ]; then echo -e "${RED}IP不符${NC}"; read -p "继续? (y/n): " f; [ "$f" != "y" ] && return; fi
    read -p "2. 邮箱: " email; read -p "3. DB密码: " db_pass
    echo -e "${YELLOW}自定义版本? (默:PHP8.2/MySQL8.0/Redis7)${NC}"; read -p "y/n: " cust
    pt="php8.2-fpm-alpine"; di="mysql:8.0"; rt="7.0-alpine"
    if [ "$cust" == "y" ]; then
        echo "PHP: 1.7.4 2.8.0 3.8.1 4.8.2 5.8.3 6.最新"; read -p "选: " p; case $p in 1) pt="php7.4-fpm-alpine";; 2) pt="php8.0-fpm-alpine";; 3) pt="php8.1-fpm-alpine";; 4) pt="php8.2-fpm-alpine";; 5) pt="php8.3-fpm-alpine";; 6) pt="fpm-alpine";; esac
        echo "DB: 1.MySQL5.7 2.MySQL8.0 3.最新 4.MariaDB10.6 5.最新"; read -p "选: " d; case $d in 1) di="mysql:5.7";; 2) di="mysql:8.0";; 3) di="mysql:latest";; 4) di="mariadb:10.6";; 5) di="mariadb:latest";; esac
        echo "Redis: 1.6.2 2.7.0 3.最新"; read -p "选: " r; case $r in 1) rt="6.2-alpine";; 2) rt="7.0-alpine";; 3) rt="alpine";; esac
    fi
    pname=$(echo $fd|tr '.' '_'); sdir="$SITES_DIR/$fd"; [ -d "$sdir" ] && echo -e "已存在" && pause_prompt && return; mkdir -p "$sdir"
    cat > "$sdir/waf.conf" <<EOF
location ~* /\.(git|env|sql) { deny all; return 403; }
EOF
    cat > "$sdir/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M; location / { try_files \$uri \$uri/ /index.php?\$args; } location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } }
EOF
    cat > "$sdir/uploads.ini" <<EOF
file_uploads=On; memory_limit=512M; upload_max_filesize=512M; post_max_size=512M; max_execution_time=600;
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
    read -p "1. 域名: " d; fd="$d"; read -p "2. 邮箱: " e; sdir="$SITES_DIR/$d"; mkdir -p "$sdir"
    echo -e "1.URL 2.IP:端口"; read -p "类型: " t; if [ "$t" == "2" ]; then read -p "IP: " ip; [ -z "$ip" ] && ip="127.0.0.1"; read -p "端口: " p; tu="http://$ip:$p"; pm="2"; else read -p "URL: " tu; tu=$(normalize_url "$tu"); echo "1.镜像 2.代理"; read -p "模式: " pm; [ -z "$pm" ] && pm="1"; fi
    generate_nginx_conf "$tu" "$d" "$pm"
    cat > "$sdir/docker-compose.yml" <<EOF
services:
  proxy: {image: nginx:alpine, container_name: ${d//./_}_worker, restart: always, volumes: [./nginx-proxy.conf:/etc/nginx/conf.d/default.conf], extra_hosts: ["host.docker.internal:host-gateway"], environment: {VIRTUAL_HOST: "$fd", LETSENCRYPT_HOST: "$fd", LETSENCRYPT_EMAIL: "$e"}, networks: [proxy-net]}
networks: {proxy-net: {external: true}}
EOF
    cd "$sdir" && docker compose up -d; check_ssl_status "$d"; write_log "Created proxy $d"
}

function generate_nginx_conf() {
    local u=$1; local d=$2; local m=$3; local h=$(echo $u|awk -F/ '{print $3}'); local f="$SITES_DIR/$d/nginx-proxy.conf"
    echo "server { listen 80; server_name localhost; resolver 8.8.8.8; location / {" > "$f"
    if [ "$m" == "2" ]; then
        echo "proxy_pass $u; proxy_set_header Host $h; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_ssl_server_name on;" >> "$f"
    else
        echo "proxy_pass $u; proxy_set_header Host $h; proxy_set_header Referer $u; proxy_ssl_server_name on; proxy_set_header Accept-Encoding \"\"; sub_filter \"</head>\" \"<meta name='referrer' content='no-referrer'></head>\"; sub_filter \"$h\" \"$d\"; sub_filter \"https://$h\" \"https://$d\"; sub_filter \"http://$h\" \"https://$d\";" >> "$f"
        echo -e "${YELLOW}资源聚合 (回车结束)${NC}"; c=1
        while true; do read -p "URL: " re; [ -z "$re" ] && break; re=$(normalize_url "$re"); rh=$(echo $re|awk -F/ '{print $3}'); k="_res_$c"; cat >> "$f" <<EOF
sub_filter "$rh" "$d/$k"; sub_filter "https://$rh" "https://$d/$k"; sub_filter "http://$rh" "https://$d/$k";
EOF
        cat >> "$f.loc" <<EOF
location /$k/ { rewrite ^/$k/(.*) /\$1 break; proxy_pass $re; proxy_set_header Host $rh; proxy_set_header Referer $re; proxy_ssl_server_name on; proxy_set_header Accept-Encoding ""; }
EOF
        ((c++)); done
        echo "sub_filter_once off; sub_filter_types *;" >> "$f"
    fi
    echo "}" >> "$f"; [ -f "$f.loc" ] && cat "$f.loc" >> "$f" && rm "$f.loc"; echo "}" >> "$f"
}

function repair_proxy() { ls -1 "$SITES_DIR"; read -p "域名: " d; sdir="$SITES_DIR/$d"; [ ! -d "$sdir" ] && return; read -p "新URL: " tu; tu=$(normalize_url "$tu"); generate_nginx_conf "$tu" "$d" "1"; cd "$sdir" && docker compose restart; echo "OK"; pause_prompt; }
function fix_upload_limit() { ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; cat > "$s/uploads.ini" <<EOF
file_uploads=On; memory_limit=512M; upload_max_filesize=512M; post_max_size=512M; max_execution_time=600;
EOF
if [ -f "$s/nginx.conf" ]; then sed -i 's/client_max_body_size .*/client_max_body_size 512M;/g' "$s/nginx.conf"; fi; cd "$s" && docker compose restart; echo "OK"; pause_prompt; }
function create_redirect() { read -p "源域名: " s; read -p "跳转: " t; t=$(normalize_url "$t"); read -p "邮箱: " e; sdir="$SITES_DIR/$s"; mkdir -p "$sdir"; echo "server { listen 80; server_name localhost; location / { return 301 $t\$request_uri; } }" > "$sdir/redirect.conf"; echo "services: {redirector: {image: nginx:alpine, container_name: ${s//./_}_redirect, restart: always, volumes: [./redirect.conf:/etc/nginx/conf.d/default.conf], environment: {VIRTUAL_HOST: \"$s\", LETSENCRYPT_HOST: \"$s\", LETSENCRYPT_EMAIL: \"$e\"}, networks: [proxy-net]}}" > "$sdir/docker-compose.yml"; echo "networks: {proxy-net: {external: true}}" >> "$sdir/docker-compose.yml"; cd "$sdir" && docker compose up -d; check_ssl_status "$s"; }
function delete_site() { while true; do clear; echo "=== 🗑️ 删除网站 ==="; ls -1 "$SITES_DIR"; echo "----------------"; read -p "域名(0返回): " d; [ "$d" == "0" ] && return; if [ -d "$SITES_DIR/$d" ]; then read -p "删除? (y/n): " c; [ "$c" == "y" ] && cd "$SITES_DIR/$d" && docker compose down -v >/dev/null 2>&1 && cd .. && rm -rf "$SITES_DIR/$d" && echo "Deleted"; write_log "Deleted site $d"; fi; pause_prompt; done; }
function list_sites() { clear; echo "=== 📂 站点列表 ==="; ls -1 "$SITES_DIR"; echo "----------------"; pause_prompt; }
function cert_management() { while true; do clear; echo "1.列表 2.上传 3.重置 4.续签 0.返回"; read -p "选: " c; case $c in 0) return;; 1) docker exec gateway_proxy ls -lh /etc/nginx/certs|grep .crt; pause_prompt;; 2) ls -1 "$SITES_DIR"; read -p "域名: " d; read -p "crt: " c; read -p "key: " k; docker cp "$c" gateway_acme:"/etc/nginx/certs/$d.crt"; docker cp "$k" gateway_acme:"/etc/nginx/certs/$d.key"; docker exec gateway_proxy nginx -s reload; echo "OK"; pause_prompt;; 3) read -p "域名: " d; docker exec gateway_acme rm -f "/etc/nginx/certs/$d.crt" "/etc/nginx/certs/$d.key"; docker restart gateway_acme; echo "OK"; pause_prompt;; 4) docker exec gateway_acme /app/force_renew; echo "OK"; pause_prompt;; esac; done; }
function db_manager() { while true; do clear; echo "1.导出 2.导入 0.返回"; read -p "选: " c; case $c in 0) return;; 1) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; pwd=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml"|awk -F': ' '{print $2}'); docker compose -f "$s/docker-compose.yml" exec -T db mysqldump -u root -p"$pwd" --all-databases > "$s/${d}.sql"; echo "OK: $s/${d}.sql";; 2) ls -1 "$SITES_DIR"; read -p "域名: " d; read -p "SQL: " f; s="$SITES_DIR/$d"; pwd=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml"|awk -F': ' '{print $2}'); cat "$f" | docker compose -f "$s/docker-compose.yml" exec -T db mysql -u root -p"$pwd"; echo "OK";; esac; pause_prompt; done; }
function change_domain() { ls -1 "$SITES_DIR"; read -p "旧域名: " o; [ ! -d "$SITES_DIR/$o" ] && return; read -p "新域名: " n; cd "$SITES_DIR/$o" && docker compose down; cd .. && mv "$o" "$n" && cd "$n"; sed -i "s/$o/$n/g" docker-compose.yml; docker compose up -d; wp_c=$(docker compose ps -q wordpress); docker run --rm --volumes-from $wp_c --network container:$wp_c wordpress:cli wp search-replace "$o" "$n" --all-tables --skip-columns=guid; docker exec gateway_proxy nginx -s reload; echo "OK"; write_log "Changed $o to $n"; pause_prompt; }
function manage_hotlink() { while true; do clear; echo "1.开 2.关 0.返"; read -p "选: " h; case $h in 0) return;; 1) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; read -p "白名单: " w; cat > "$s/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M; location ~* \.(gif|jpg|png|webp)$ { valid_referers none blocked server_names $d *.$d $w; if (\$invalid_referer) { return 403; } try_files \$uri \$uri/ /index.php?\$args; } location / { try_files \$uri \$uri/ /index.php?\$args; } location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } }
EOF
cd "$s" && docker compose restart nginx; echo "OK";; 2) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; cat > "$s/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M; location / { try_files \$uri \$uri/ /index.php?\$args; } location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } }
EOF
cd "$s" && docker compose restart nginx; echo "OK";; esac; pause_prompt; done; }
function uninstall_cluster() { echo "⚠️ 危险: 输入 DELETE 确认卸载"; read -p "> " c; [ "$c" == "DELETE" ] && (ls "$SITES_DIR"|while read d; do cd "$SITES_DIR/$d" && docker compose down -v; done; cd "$GATEWAY_DIR" && docker compose down -v; docker network rm proxy-net; rm -rf "$BASE_DIR" /usr/bin/wp; echo "已卸载"); }

# ================= 4. 菜单显示函数 =================
function show_menu() {
    clear
    echo -e "${GREEN}=== WordPress Docker 集群管理 ($VERSION) ===${NC}"
    echo -e "${CYAN}GitHub: lje02/wp-manager${NC}"
    echo "-----------------------------------------"
    echo -e "${YELLOW}[新建站点]${NC}"
    echo " 1. 部署 WordPress 新站"
    echo " 2. 新建 反向代理 (IP:端口 / 域名)"
    echo " 3. 新建 域名重定向 (301)"
    echo ""
    echo -e "${YELLOW}[站点运维]${NC}"
    echo " 4. 查看站点列表"
    echo " 5. 容器状态监控"
    echo " 6. 销毁指定站点"
    echo " 7. 更换网站域名"
    echo " 8. 修复反代配置"
    echo -e " 9. ${CYAN}组件版本升降级 (含 Redis)${NC}"
    echo " 10. 解除上传限制"
    echo ""
    echo -e "${YELLOW}[数据管理]${NC}"
    echo " 11. 数据库 导出/导入"
    echo " 12. 整站 备份与还原 (智能扫描)"
    echo ""
    echo -e "${RED}[安全与监控]${NC}"
    echo " 13. 安全防御中心 (Firewall/WAF/证书)"
    echo " 14. Telegram 通知设置 (含监控)"
    echo " 15. 系统资源监控"
    echo " 16. 日志管理系统"
    echo "-----------------------------------------"
    echo -e "${BLUE} u. 检查更新${NC} | ${RED}x. 卸载${NC} | 0. 退出"
    echo -n "请选择: "
    read option
}

# ================= 5. 主程序循环 =================
check_and_install_docker
install_shortcut
if ! docker ps --format '{{.Names}}' | grep -q "^gateway_proxy$"; then echo -e "${YELLOW}后台初始化...${NC}"; init_gateway "auto"; fi

while true; do 
    show_menu 
    case $option in 
        u|U) update_script;; 
        1) create_site;; 
        2) create_proxy;; 
        3) create_redirect;; 
        4) list_sites;; 
        5) container_ops;; 
        6) delete_site;; 
        7) change_domain;; 
        8) repair_proxy;; 
        9) component_manager;; 
        10) fix_upload_limit;; 
        11) db_manager;; 
        12) backup_restore_ops;; 
        13) security_center;; 
        14) telegram_manager;; 
        15) sys_monitor;; 
        16) log_manager;; 
        x|X) uninstall_cluster;; 
        0) exit 0;; 
    esac
done
