#!/bin/bash

# ================= 1. 配置区域 =================
# 脚本版本号
VERSION="V63 (CN-Localized+SmartBackup)"

# 数据存储路径
BASE_DIR="/root/wp-cluster"
SITES_DIR="$BASE_DIR/sites"
GATEWAY_DIR="$BASE_DIR/gateway"
FW_DIR="$BASE_DIR/firewall"
TG_CONF="$BASE_DIR/telegram.conf"
LOG_FILE="$BASE_DIR/operation.log"

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

# --- 日志记录 ---
function write_log() {
    local action=$1
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $action" >> "$LOG_FILE"
}

# --- 交互暂停 ---
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
        write_log "已安装 Docker"
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
        echo -e "${RED}❌ 系统不支持自动安装防火墙，请手动安装${NC}"; pause_prompt; return 1
    fi
    write_log "已安装防火墙组件"
    echo -e "${GREEN}✔ 防火墙就绪${NC}"; sleep 1
}

function check_ssl_status() {
    local d=$1; echo -e "${CYAN}>>> [SSL] 正在向 Let's Encrypt 申请证书...${NC}"; for ((i=1; i<=20; i++)); do if docker exec gateway_acme test -f "/etc/nginx/certs/$d.crt"; then echo -e "${GREEN}✔ SSL 证书获取成功: https://$d${NC}"; pause_prompt; return 0; fi; echo -n "."; sleep 5; done; echo -e "\n${YELLOW}⚠️ 证书暂未生成 (可能是DNS延迟，请稍后在菜单13检查)${NC}"; pause_prompt;
}

function normalize_url() {
    local url=$1; url=${url%/}; if [[ "$url" != http* ]]; then echo "https://$url"; else echo "$url"; fi
}

function update_script() {
    clear; echo -e "${GREEN}=== 脚本自动更新 ===${NC}"; echo -e "当前版本: $VERSION"; echo -e "更新源: github.com/lje02/wp-manager"
    temp_file="/tmp/wp_manager_new.sh"
    if curl -f -L -s -o "$temp_file" "$UPDATE_URL" && head -n 1 "$temp_file" | grep -q "/bin/bash"; then
        mv "$temp_file" "$0"; chmod +x "$0"; echo -e "${GREEN}✔ 更新成功，正在重启脚本...${NC}"; write_log "Script updated to latest"; sleep 1; exec "$0"
    else 
        echo -e "${RED}❌ 更新失败! 请检查网络或仓库地址。${NC}"; rm -f "$temp_file"
    fi
    pause_prompt
}

function send_tg_msg() {
    local msg=$1; if [ -f "$TG_CONF" ]; then source "$TG_CONF"; if [ ! -z "$TG_BOT_TOKEN" ] && [ ! -z "$TG_CHAT_ID" ]; then curl -s -X POST "https://api.telegram.org/bot$TG_BOT_TOKEN/sendMessage" -d chat_id="$TG_CHAT_ID" -d text="$msg" >/dev/null; fi; fi
}

# ================= 3. 业务功能函数 =================

# --- 系统监控 ---
function sys_monitor() {
    while true; do
        clear; echo -e "${YELLOW}=== 🖥️ 系统资源监控 ===${NC}"
        
        load=$(uptime | awk -F'load average:' '{print $2}')
        echo -e "CPU 负载 : ${GREEN}$load${NC}"
        
        if command -v free >/dev/null; then
            mem=$(free -h | grep Mem | awk '{print $3 "/" $2}')
            echo -e "内存使用 : ${CYAN}$mem${NC}"
        fi
        
        disk=$(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')
        echo -e "磁盘占用 : ${BLUE}$disk${NC}"
        
        up=$(uptime -p)
        echo -e "运行时间 : ${YELLOW}$up${NC}"
        
        conn=$(netstat -an | grep ESTABLISHED | wc -l 2>/dev/null || ss -s | grep est | awk '{print $2}')
        echo -e "TCP连接数: ${RED}$conn${NC}"
        
        echo "--------------------------"
        echo "按回车刷新，输入 0 返回主菜单"
        read -t 5 -p "> " op
        [ "$op" == "0" ] && return
    done
}

# --- 日志管理 ---
function log_manager() {
    while true; do
        clear; echo -e "${YELLOW}=== 📜 日志管理系统 ===${NC}"
        echo -e "日志文件: $LOG_FILE"
        echo -e "文件大小: $(du -h $LOG_FILE 2>/dev/null | awk '{print $1}')"
        echo "--------------------------"
        echo " 1. 查看最新 50 条日志"
        echo " 2. 一键清空日志"
        echo " 3. 配置自动清理 (保留7天)"
        echo " 0. 返回"
        read -p "选择: " l
        case $l in
            0) return;;
            1) echo -e "${CYAN}--- 日志开始 ---${NC}"; tail -n 50 "$LOG_FILE"; echo -e "${CYAN}--- 日志结束 ---${NC}"; pause_prompt;;
            2) echo "" > "$LOG_FILE"; echo -e "${GREEN}✔ 日志已清空${NC}"; write_log "Cleared logs manually"; pause_prompt;;
            3) 
                echo -e "${BLUE}>>> 正在添加 Crontab 任务 (每天凌晨3点清理)...${NC}"
                crontab -l 2>/dev/null | grep -v "wp-cluster" | crontab -
                (crontab -l 2>/dev/null; echo "0 3 * * * find $BASE_DIR -name '*.log' -mtime +7 -delete #wp-cluster-log-clean") | crontab -
                echo -e "${GREEN}✔ 定时任务已配置${NC}"; write_log "Enabled auto log cleanup"; pause_prompt;;
        esac
    done
}

# --- 容器监控 (汉化) ---
function container_ops() {
    while true; do
        clear; echo -e "${YELLOW}=== 📊 容器状态监控 ===${NC}"
        echo "---------------------------------------------------"
        echo -e "核心网关 (Gateway):"
        cd "$GATEWAY_DIR" && docker compose ps --format "table {{.Service}}\t{{.State}}\t{{.Status}}" | tail -n +2 | while read l; do if echo "$l"|grep -q "running"; then echo -e "${GREEN}  $l (运行中)${NC}"; else echo -e "${RED}  $l (异常)${NC}"; fi; done
        for d in "$SITES_DIR"/*; do
            if [ -d "$d" ]; then
                echo "---------------------------------------------------"
                echo -e "站点: ${CYAN}$(basename "$d")${NC}"
                cd "$d" && docker compose ps --all --format "table {{.Service}}\t{{.State}}\t{{.Status}}" | tail -n +2 | while read l; do
                    if echo "$l" | grep -q "running"; then echo -e "${GREEN}  $l (正常)${NC}"; elif echo "$l" | grep -q "exited"; then echo -e "${RED}  $l (已停止)${NC}"; else echo -e "${YELLOW}  $l (状态未知)${NC}"; fi
                done
            fi
        done
        echo "---------------------------------------------------"
        echo " 1. 一键全启 (Start All)"
        echo " 2. 一键全停 (Stop All)"
        echo " 3. 一键重启 (Restart All)"
        echo " 4. 指定站点操作"
        echo " 0. 返回"
        read -p "选择: " c
        case $c in
            0) return;;
            1) cd "$GATEWAY_DIR" && docker compose up -d; for d in "$SITES_DIR"/*; do cd "$d" && docker compose up -d; done; echo -e "${GREEN}✔ 所有容器已发送启动指令${NC}"; write_log "Started all containers"; pause_prompt;;
            2) for d in "$SITES_DIR"/*; do cd "$d" && docker compose stop; done; cd "$GATEWAY_DIR" && docker compose stop; echo -e "${RED}✔ 所有容器已停止${NC}"; write_log "Stopped all containers"; pause_prompt;;
            3) cd "$GATEWAY_DIR" && docker compose restart; for d in "$SITES_DIR"/*; do cd "$d" && docker compose restart; done; echo -e "${YELLOW}✔ 所有容器已重启${NC}"; write_log "Restarted all containers"; pause_prompt;;
            4) ls -1 "$SITES_DIR"; read -p "请输入域名: " d; s="$SITES_DIR/$d"; [ -d "$s" ] && cd "$s" && read -p "1.启动 2.停止 3.重启: " a && ([ "$a" == "1" ] && docker compose up -d || ([ "$a" == "2" ] && docker compose stop || docker compose restart)); echo -e "${GREEN}✔ 操作完成${NC}"; write_log "Operated on site $d"; pause_prompt;;
        esac
    done
}

# --- 组件管理 (汉化) ---
function component_manager() {
    while true; do
        clear; echo -e "${YELLOW}=== 🆙 组件版本升降级 ===${NC}"
        ls -1 "$SITES_DIR"; echo "--------------------------"; read -p "输入域名(0返回): " d; [ "$d" == "0" ] && return
        sdir="$SITES_DIR/$d"; [ ! -d "$sdir" ] && continue
        cur_wp=$(grep "image: wordpress" "$sdir/docker-compose.yml"|awk '{print $2}'); cur_db=$(grep "image: .*sql" "$sdir/docker-compose.yml"|awk '{print $2}')
        echo -e "当前版本: PHP=[$cur_wp] DB=[$cur_db]"
        echo " 1. 切换 PHP 版本"
        echo " 2. 切换 数据库 版本 (高危)"
        echo " 3. 切换 Redis 版本"
        echo " 4. 切换 Nginx 版本"
        echo " 0. 返回"
        read -p "选择: " op
        case $op in
            0) break;;
            1) echo "1.PHP 7.4  2.PHP 8.0  3.PHP 8.1  4.PHP 8.2  5.Latest(最新)"; read -p "选择: " p; case $p in 1) t="php7.4-fpm-alpine";; 2) t="php8.0-fpm-alpine";; 3) t="php8.1-fpm-alpine";; 4) t="php8.2-fpm-alpine";; 5) t="fpm-alpine";; *) continue;; esac; sed -i "s|image: wordpress:.*|image: wordpress:$t|g" "$sdir/docker-compose.yml"; cd "$sdir" && docker compose up -d; echo -e "${GREEN}✔ PHP 已切换至 $t${NC}"; write_log "Changed PHP ver for $d to $t"; pause_prompt;;
            2) echo -e "${RED}⚠️ 警告：数据库降级可能导致数据损坏，请先备份！${NC}"; echo "1.MySQL5.7 2.MySQL8.0 3.MySQL最新 4.MariaDB10.6 5.MariaDB最新"; read -p "选择: " v; case $v in 1) i="mysql:5.7";; 2) i="mysql:8.0";; 3) i="mysql:latest";; 4) i="mariadb:10.6";; 5) i="mariadb:latest";; *) continue;; esac; sed -i "s|image: .*sql:.*|image: $i|g" "$sdir/docker-compose.yml"; sed -i "s|image: mariadb:.*|image: $i|g" "$sdir/docker-compose.yml"; cd "$sdir" && docker compose up -d; echo -e "${GREEN}✔ 数据库已重建为 $i${NC}"; write_log "Changed DB ver for $d to $i"; pause_prompt;;
            3) echo "1.Redis6.2 2.Redis7.0 3.Latest(最新)"; read -p "选择: " r; case $r in 1) rt="6.2-alpine";; 2) rt="7.0-alpine";; 3) rt="alpine";; *) continue;; esac; sed -i "s|image: redis:.*|image: redis:$rt|g" "$sdir/docker-compose.yml"; cd "$sdir" && docker compose up -d; echo -e "${GREEN}✔ Redis 已切换${NC}"; write_log "Changed Redis ver for $d to $rt"; pause_prompt;;
            4) echo "1.Alpine(稳定) 2.Latest(最新)"; read -p "选择: " n; [ "$n" == "2" ] && nt="latest" || nt="alpine"; sed -i "s|image: nginx:.*|image: nginx:$nt|g" "$sdir/docker-compose.yml"; cd "$sdir" && docker compose up -d; echo -e "${GREEN}✔ Nginx 已切换${NC}"; write_log "Changed Nginx ver for $d to $nt"; pause_prompt;;
        esac
    done
}

# --- 备份还原 (V63: 智能扫描) ---
function backup_restore_ops() {
    while true; do 
        clear; echo -e "${YELLOW}=== 备份与还原系统 ===${NC}"
        echo " 1. 备份网站 (整站+数据库)"
        echo " 2. 还原网站 (自动扫描最新)"
        echo " 0. 返回"
        read -p "选择: " br 
        case $br in
            0) return;;
            1) 
                ls -1 "$SITES_DIR"; echo "----------------"; read -p "输入要备份的域名: " d; s="$SITES_DIR/$d"
                [ ! -d "$s" ] && echo -e "${RED}❌ 站点不存在${NC}" && pause_prompt && continue
                bd="$s/backups/$(date +%Y%m%d_%H%M%S)"; mkdir -p "$bd"
                echo -e "${BLUE}>>> 正在导出数据库...${NC}"
                cd "$s"; pwd=$(grep MYSQL_ROOT_PASSWORD docker-compose.yml|awk -F': ' '{print $2}')
                docker compose exec -T db mysqldump -u root -p"$pwd" --all-databases > "$bd/db.sql"
                echo -e "${BLUE}>>> 正在打包网站文件...${NC}"
                wp_c=$(docker compose ps -q wordpress); docker run --rm --volumes-from $wp_c -v "$bd":/backup alpine tar czf /backup/files.tar.gz /var/www/html/wp-content
                cp *.conf docker-compose.yml "$bd/"
                echo -e "${GREEN}✔ 备份成功! 路径: $bd${NC}"; write_log "Backup site $d"; pause_prompt;;
            
            2) 
                ls -1 "$SITES_DIR"; echo "----------------"; read -p "输入要还原的域名: " d; s="$SITES_DIR/$d"; bd="$s/backups"
                if [ ! -d "$bd" ]; then echo -e "${RED}❌ 没有找到备份记录${NC}"; pause_prompt; continue; fi
                
                # --- V63 智能逻辑 ---
                latest=$(ls -t "$bd" | head -n 1)
                target_backup=""
                
                if [ -n "$latest" ]; then
                    echo -e "🔎 发现最新备份: ${CYAN}$latest${NC}"
                    read -p "是否直接还原此备份? (y/n): " confirm
                    if [ "$confirm" == "y" ]; then
                        target_backup="$latest"
                    fi
                fi
                
                if [ -z "$target_backup" ]; then
                    echo -e "${YELLOW}--- 所有可用备份 ---${NC}"
                    ls -1 "$bd"
                    echo "--------------------"
                    read -p "请输入备份文件夹名称: " target_backup
                fi
                
                bp="$bd/$target_backup"
                if [ ! -d "$bp" ]; then echo -e "${RED}❌ 备份目录不存在${NC}"; pause_prompt; continue; fi
                
                echo -e "${YELLOW}>>> 正在还原 [$target_backup]...${NC}"
                cd "$s" && docker compose down
                echo -e "${BLUE}>>> 恢复文件...${NC}"
                vol=$(docker volume ls -q|grep "${d//./_}_wp_data")
                docker run --rm -v $vol:/var/www/html -v "$bp":/backup alpine tar xzf /backup/files.tar.gz -C /
                echo -e "${BLUE}>>> 恢复数据库...${NC}"
                docker compose up -d db; echo "等待数据库启动..."; sleep 15
                pwd=$(grep MYSQL_ROOT_PASSWORD docker-compose.yml|awk -F': ' '{print $2}')
                docker compose exec -T db mysql -u root -p"$pwd" < "$bp/db.sql"
                docker compose up -d
                echo -e "${GREEN}✔ 还原完成!${NC}"; write_log "Restored site $d from $target_backup"; pause_prompt;;
        esac
    done
}

# --- 其他模块 ---
function notify_manager() {
    while true; do
        clear; echo -e "${YELLOW}=== 📢 Telegram 通知设置 ===${NC}"
        if [ -f "$TG_CONF" ]; then source "$TG_CONF"; fi
        echo "Token: ${TG_BOT_TOKEN:0:10}******"
        echo "ChatID: $TG_CHAT_ID"
        echo " 1. 设置 Bot Token"
        echo " 2. 设置 Chat ID"
        echo " 3. 发送测试消息"
        echo " 0. 返回"
        read -p "选择: " n
        case $n in
            0) return;; 
            1) read -p "输入 Token: " t; echo "TG_BOT_TOKEN=\"$t\"" > "$TG_CONF"; [ ! -z "$TG_CHAT_ID" ] && echo "TG_CHAT_ID=\"$TG_CHAT_ID\"" >> "$TG_CONF";;
            2) read -p "输入 ID: " c; [ ! -z "$TG_BOT_TOKEN" ] && echo "TG_BOT_TOKEN=\"$TG_BOT_TOKEN\"" > "$TG_CONF"; echo "TG_CHAT_ID=\"$c\"" >> "$TG_CONF";;
            3) send_tg_msg "🔔 [WP-Cluster] 测试消息发送成功！"; echo -e "${GREEN}✔ 已发送${NC}"; pause_prompt;;
        esac
    done
}

function fail2ban_manager() {
    while true; do clear; echo -e "${YELLOW}=== 👮 Fail2Ban 防暴力破解 ===${NC}"; echo "1. 安装/重置 (5次封24h)"; echo "2. 查看被封禁 IP"; echo "3. 解封指定 IP"; echo "0. 返回"; read -p "选择: " o; case $o in 0) return;; 1) echo "安装配置中..."; if [ -f /etc/debian_version ]; then apt-get install -y fail2ban; lp="/var/log/auth.log"; else yum install -y fail2ban; lp="/var/log/secure"; fi; cat >/etc/fail2ban/jail.local <<EOF
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
    systemctl enable fail2ban; systemctl restart fail2ban; echo -e "${GREEN}✔ 配置成功${NC}"; write_log "Installed Fail2Ban"; pause_prompt;; 2) fail2ban-client status sshd 2>/dev/null|grep Banned; pause_prompt;; 3) read -p "输入 IP: " i; fail2ban-client set sshd unbanip $i; echo -e "${GREEN}✔ 已解封${NC}"; write_log "Fail2Ban unbanned $i"; pause_prompt;; esac; done
}

function waf_manager() {
    while true; do clear; echo -e "${YELLOW}=== 🛡️ WAF 网站防火墙 ===${NC}"; echo "1. 一键部署增强规则"; echo "2. 查看规则内容"; echo "0. 返回"; read -p "选择: " o; case $o in 0) return;; 1) cat >/tmp/w <<EOF
location ~* /\.(git|svn|env|sql|db) { deny all; return 403; }
if (\$query_string ~* "(union.*select|eval\(|base64_)") { return 403; }
if (\$http_user_agent ~* (scan|sqlmap|nikto)) { return 403; }
EOF
    for d in "$SITES_DIR"/*; do [ -d "$d" ] && cp /tmp/w "$d/waf.conf" && cd "$d" && docker compose exec -T nginx nginx -s reload; done; rm /tmp/w; echo -e "${GREEN}✔ 规则已分发${NC}"; write_log "Updated WAF rules"; pause_prompt;; 2) cat "$SITES_DIR/"*"/waf.conf" 2>/dev/null|head -5; pause_prompt;; esac; done
}

function port_manager() {
    ensure_firewall_installed || return
    if command -v ufw >/dev/null; then
        if ! ufw status | grep -q "Status: active"; then
            echo -e "${YELLOW}正在激活 UFW 防火墙...${NC}"; ufw allow 22/tcp >/dev/null; ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null; echo "y" | ufw enable >/dev/null
        fi
    fi
    while true; do 
        clear; echo -e "${YELLOW}=== 🧱 端口防火墙管理 ===${NC}"
        if command -v ufw >/dev/null; then FW="UFW"; if ufw status | grep -q "active"; then STAT="${GREEN}运行中${NC}"; else STAT="${RED}未运行${NC}"; fi; else FW="Firewalld"; STAT="${GREEN}运行中${NC}"; fi
        echo -e "系统: $FW | 状态: $STAT"
        echo "--------------------------"
        echo " 1. 查看开放端口"; echo " 2. 开放/关闭 端口 (支持批量)"; echo " 3. 防 DOS 攻击 (开启/关闭)"; echo " 4. 一键全开 / 一键全锁"; echo " 0. 返回"; read -p "选择: " f
        case $f in
            0) return;;
            1) if [ "$FW" == "UFW" ]; then ufw status; else firewall-cmd --list-ports; fi; pause_prompt;;
            2) 
                read -p "输入端口 (空格分隔, 如 80 443): " ports
                echo "1. 开放端口"; echo "2. 关闭端口"; read -p "选择: " a
                for p in $ports; do
                    echo -e "${BLUE}正在处理端口: $p ...${NC}"
                    if [ "$FW" == "UFW" ]; then 
                        [ "$a" == "1" ] && ufw allow $p/tcp || ufw delete allow $p/tcp
                    else 
                        ac=$([ "$a" == "1" ] && echo add || echo remove)
                        firewall-cmd --zone=public --${ac}-port=$p/tcp --permanent
                    fi
                done
                [ "$FW" != "UFW" ] && firewall-cmd --reload
                echo -e "${GREEN}✔ 批量配置完成${NC}"; write_log "Firewall ports modified: $ports"; pause_prompt;;
            3) echo "1.开启防DOS 2.关闭"; read -p "选择: " d; if [ "$d" == "1" ]; then echo "limit_req_zone \$binary_remote_addr zone=one:10m rate=10r/s; limit_conn_zone \$binary_remote_addr zone=addr:10m;" > "$FW_DIR/dos_zones.conf"; mkdir -p "$GATEWAY_DIR/vhost"; echo "limit_req zone=one burst=15 nodelay; limit_conn addr 15;" > "$GATEWAY_DIR/vhost/default"; cd "$GATEWAY_DIR" && docker compose up -d >/dev/null 2>&1 && docker exec gateway_proxy nginx -s reload; echo -e "${GREEN}✔ 已开启${NC}"; write_log "Enabled Anti-DOS"; else rm -f "$FW_DIR/dos_zones.conf" "$GATEWAY_DIR/vhost/default"; cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload; echo -e "${GREEN}✔ 已关闭${NC}"; write_log "Disabled Anti-DOS"; fi; pause_prompt;;
            4) echo "1.允许所有 2.封锁所有(保留SSH)"; read -p "选择: " m; if [ "$m" == "1" ]; then [ "$FW" == "UFW" ] && ufw default allow incoming || firewall-cmd --set-default-zone=trusted; else if [ "$FW" == "UFW" ]; then ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp; ufw default deny incoming; else firewall-cmd --permanent --add-service={ssh,http,https}; firewall-cmd --set-default-zone=drop; firewall-cmd --reload; fi; fi; echo -e "${GREEN}✔ 策略已应用${NC}"; write_log "Applied Global Firewall Policy"; pause_prompt;;
        esac
    done
}

function traffic_manager() {
    while true; do clear; echo -e "${YELLOW}=== 🌐 流量访问控制 (ACL) ===${NC}"; echo "1. 添加黑名单 IP"; echo "2. 添加白名单 IP"; echo "3. 封禁指定国家"; echo "4. 清空所有规则"; echo "0. 返回"; read -p "选择: " t; case $t in 0) return;; 1|2) tp="deny"; [ "$t" == "2" ] && tp="allow"; read -p "输入IP: " i; echo "$tp $i;" >> "$FW_DIR/access.conf"; cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload; echo -e "${GREEN}✔ 已添加 $tp $i${NC}"; write_log "ACL $tp $i"; pause_prompt;; 3) read -p "国家代码(cn/us): " c; wget -qO- "http://www.ipdeny.com/ipblocks/data/countries/$c.zone" | while read l; do echo "deny $l;" >> "$FW_DIR/geo.conf"; done; cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload; echo -e "${GREEN}✔ 已封禁 $c${NC}"; write_log "Blocked country $c"; pause_prompt;; 4) echo "" > "$FW_DIR/access.conf"; echo "" > "$FW_DIR/geo.conf"; cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload; echo -e "${GREEN}✔ 规则已清空${NC}"; write_log "Cleared ACL"; pause_prompt;; esac; done
}

function security_center() {
    while true; do clear; echo -e "${YELLOW}=== 🛡️ 安全防御中心 ===${NC}"; echo " 1. 端口防火墙 (系统层)"; echo " 2. 流量访问控制 (Nginx层)"; echo " 3. SSH 防暴破 (Fail2Ban)"; echo " 4. 网站防火墙 (WAF)"; echo " 5. HTTPS 证书管理"; echo " 6. 防盗链设置"; echo " 0. 返回"; read -p "选择: " s; case $s in 0) return;; 1) port_manager;; 2) traffic_manager;; 3) fail2ban_manager;; 4) waf_manager;; 5) cert_management;; 6) manage_hotlink;; esac; done
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
    read -p "1. 输入主域名: " fd; host_ip=$(curl -s4 ifconfig.me); if command -v dig >/dev/null; then dip=$(dig +short $fd|head -1); else dip=$(getent hosts $fd|awk '{print $1}'); fi; if [ ! -z "$dip" ] && [ "$dip" != "$host_ip" ]; then echo -e "${RED}IP 不匹配 (域名未解析到本机)${NC}"; read -p "是否强制继续? (y/n): " f; [ "$f" != "y" ] && return; fi
    read -p "2. 管理员邮箱: " email; read -p "3. 数据库密码: " db_pass
    echo -e "${YELLOW}是否使用自定义版本? (默认: PHP8.2 / MySQL8.0 / Redis7)${NC}"; read -p "输入 y 自定义, 回车默认: " cust
    pt="php8.2-fpm-alpine"; di="mysql:8.0"; rt="7.0-alpine"
    if [ "$cust" == "y" ]; then
        echo "PHP版本: 1.7.4 2.8.0 3.8.1 4.8.2 5.8.3 6.最新版"; read -p "选择: " p; case $p in 1) pt="php7.4-fpm-alpine";; 2) pt="php8.0-fpm-alpine";; 3) pt="php8.1-fpm-alpine";; 4) pt="php8.2-fpm-alpine";; 5) pt="php8.3-fpm-alpine";; 6) pt="fpm-alpine";; esac
        echo "DB版本: 1.MySQL5.7 2.MySQL8.0 3.MySQL最新 4.MariaDB10.6 5.MariaDB最新"; read -p "选择: " d; case $d in 1) di="mysql:5.7";; 2) di="mysql:8.0";; 3) di="mysql:latest";; 4) di="mariadb:10.6";; 5) di="mariadb:latest";; esac
        echo "Redis版本: 1.6.2 2.7.0 3.最新版"; read -p "选择: " r; case $r in 1) rt="6.2-alpine";; 2) rt="7.0-alpine";; 3) rt="alpine";; esac
    fi
    pname=$(echo $fd|tr '.' '_'); sdir="$SITES_DIR/$fd"; [ -d "$sdir" ] && echo -e "${RED}❌ 站点已存在${NC}" && pause_prompt && return; mkdir -p "$sdir"
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
    read -p "1. 主域名: " d; fd="$d"; read -p "2. 邮箱: " e; sdir="$SITES_DIR/$d"; mkdir -p "$sdir"
    echo -e "1. 域名/URL\n2. IP:端口"; read -p "选择类型: " t; if [ "$t" == "2" ]; then read -p "IP: " ip; [ -z "$ip" ] && ip="127.0.0.1"; read -p "端口: " p; tu="http://$ip:$p"; pm="2"; else read -p "目标URL: " tu; tu=$(normalize_url "$tu"); echo "1. 镜像(高级替换)\n2. 代理(透传)"; read -p "选择模式: " pm; [ -z "$pm" ] && pm="1"; fi
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
        echo -e "${YELLOW}外部资源聚合 (回车结束)${NC}"; c=1
        while true; do read -p "资源URL: " re; [ -z "$re" ] && break; re=$(normalize_url "$re"); rh=$(echo $re|awk -F/ '{print $3}'); k="_res_$c"; cat >> "$f" <<EOF
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

function repair_proxy() { ls -1 "$SITES_DIR"; read -p "输入域名: " d; sdir="$SITES_DIR/$d"; [ ! -d "$sdir" ] && return; read -p "新目标URL: " tu; tu=$(normalize_url "$tu"); generate_nginx_conf "$tu" "$d" "1"; cd "$sdir" && docker compose restart; echo -e "${GREEN}✔ 修复完成${NC}"; pause_prompt; }
function fix_upload_limit() { ls -1 "$SITES_DIR"; read -p "输入域名: " d; s="$SITES_DIR/$d"; cat > "$s/uploads.ini" <<EOF
file_uploads=On; memory_limit=512M; upload_max_filesize=512M; post_max_size=512M; max_execution_time=600;
EOF
if [ -f "$s/nginx.conf" ]; then sed -i 's/client_max_body_size .*/client_max_body_size 512M;/g' "$s/nginx.conf"; fi; cd "$s" && docker compose restart; echo -e "${GREEN}✔ 优化完成${NC}"; pause_prompt; }
function create_redirect() { read -p "源域名: " s; read -p "跳转目标: " t; t=$(normalize_url "$t"); read -p "邮箱: " e; sdir="$SITES_DIR/$s"; mkdir -p "$sdir"; echo "server { listen 80; server_name localhost; location / { return 301 $t\$request_uri; } }" > "$sdir/redirect.conf"; echo "services: {redirector: {image: nginx:alpine, container_name: ${s//./_}_redirect, restart: always, volumes: [./redirect.conf:/etc/nginx/conf.d/default.conf], environment: {VIRTUAL_HOST: \"$s\", LETSENCRYPT_HOST: \"$s\", LETSENCRYPT_EMAIL: \"$e\"}, networks: [proxy-net]}}" > "$sdir/docker-compose.yml"; echo "networks: {proxy-net: {external: true}}" >> "$sdir/docker-compose.yml"; cd "$sdir" && docker compose up -d; check_ssl_status "$s"; }
function delete_site() { while true; do clear; echo "=== 🗑️ 删除网站 ==="; ls -1 "$SITES_DIR"; echo "----------------"; read -p "输入域名(0返回): " d; [ "$d" == "0" ] && return; if [ -d "$SITES_DIR/$d" ]; then read -p "确认删除? (y/n): " c; [ "$c" == "y" ] && cd "$SITES_DIR/$d" && docker compose down -v >/dev/null 2>&1 && cd .. && rm -rf "$SITES_DIR/$d" && echo -e "${GREEN}✔ 已删除${NC}"; write_log "Deleted site $d"; fi; pause_prompt; done; }
function list_sites() { clear; echo "=== 📂 站点列表 ==="; ls -1 "$SITES_DIR"; echo "----------------"; pause_prompt; }
function cert_management() { while true; do clear; echo "1.证书列表 2.手动上传 3.重置证书 4.强制续签 0.返回"; read -p "选择: " c; case $c in 0) return;; 1) docker exec gateway_proxy ls -lh /etc/nginx/certs|grep .crt; pause_prompt;; 2) ls -1 "$SITES_DIR"; read -p "域名: " d; read -p "crt路径: " c; read -p "key路径: " k; docker cp "$c" gateway_acme:"/etc/nginx/certs/$d.crt"; docker cp "$k" gateway_acme:"/etc/nginx/certs/$d.key"; docker exec gateway_proxy nginx -s reload; echo -e "${GREEN}✔ 上传成功${NC}"; pause_prompt;; 3) read -p "域名: " d; docker exec gateway_acme rm -f "/etc/nginx/certs/$d.crt" "/etc/nginx/certs/$d.key"; docker restart gateway_acme; echo -e "${GREEN}✔ 重置完成${NC}"; pause_prompt;; 4) docker exec gateway_acme /app/force_renew; echo -e "${GREEN}✔ 续签指令已发送${NC}"; pause_prompt;; esac; done; }
function db_manager() { while true; do clear; echo "1.导出数据库 2.导入数据库 0.返回"; read -p "选择: " c; case $c in 0) return;; 1) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; pwd=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml"|awk -F': ' '{print $2}'); docker compose -f "$s/docker-compose.yml" exec -T db mysqldump -u root -p"$pwd" --all-databases > "$s/${d}.sql"; echo -e "${GREEN}✔ 导出成功: $s/${d}.sql${NC}";; 2) ls -1 "$SITES_DIR"; read -p "域名: " d; read -p "SQL文件路径: " f; s="$SITES_DIR/$d"; pwd=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml"|awk -F': ' '{print $2}'); cat "$f" | docker compose -f "$s/docker-compose.yml" exec -T db mysql -u root -p"$pwd"; echo -e "${GREEN}✔ 导入成功${NC}";; esac; pause_prompt; done; }
function change_domain() { ls -1 "$SITES_DIR"; read -p "旧域名: " o; [ ! -d "$SITES_DIR/$o" ] && return; read -p "新域名: " n; cd "$SITES_DIR/$o" && docker compose down; cd .. && mv "$o" "$n" && cd "$n"; sed -i "s/$o/$n/g" docker-compose.yml; docker compose up -d; wp_c=$(docker compose ps -q wordpress); docker run --rm --volumes-from $wp_c --network container:$wp_c wordpress:cli wp search-replace "$o" "$n" --all-tables --skip-columns=guid; docker exec gateway_proxy nginx -s reload; echo -e "${GREEN}✔ 更换完成${NC}"; write_log "Changed domain $o to $n"; pause_prompt; }
function manage_hotlink() { while true; do clear; echo "1.开启防盗链 2.关闭防盗链 0.返回"; read -p "选择: " h; case $h in 0) return;; 1) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; read -p "允许的白名单(空格隔开): " w; cat > "$s/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M; location ~* \.(gif|jpg|png|webp)$ { valid_referers none blocked server_names $d *.$d $w; if (\$invalid_referer) { return 403; } try_files \$uri \$uri/ /index.php?\$args; } location / { try_files \$uri \$uri/ /index.php?\$args; } location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } }
EOF
cd "$s" && docker compose restart nginx; echo -e "${GREEN}✔ 已配置${NC}";; 2) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; cat > "$s/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M; location / { try_files \$uri \$uri/ /index.php?\$args; } location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } }
EOF
cd "$s" && docker compose restart nginx; echo -e "${GREEN}✔ 已关闭${NC}";; esac; pause_prompt; done; }
function uninstall_cluster() { echo -e "${RED}⚠️ 危险操作: 输入 DELETE 确认卸载所有数据${NC}"; read -p "> " c; [ "$c" == "DELETE" ] && (ls "$SITES_DIR"|while read d; do cd "$SITES_DIR/$d" && docker compose down -v; done; cd "$GATEWAY_DIR" && docker compose down -v; docker network rm proxy-net; rm -rf "$BASE_DIR" /usr/bin/wp; echo "已卸载"); }

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
    echo " 5. 容器状态监控 (启停/重启)"
    echo " 6. 销毁指定站点"
    echo " 7. 更换网站域名"
    echo " 8. 修复反代配置"
    echo -e " 9. ${CYAN}组件版本升降级 (PHP/DB/Redis)${NC}"
    echo " 10. 解除上传限制"
    echo ""
    echo -e "${YELLOW}[数据管理]${NC}"
    echo " 11. 数据库 导出/导入"
    echo " 12. 整站 备份与还原 (智能扫描)"
    echo ""
    echo -e "${RED}[安全与监控]${NC}"
    echo " 13. 安全防御中心 (防火墙/WAF/证书)"
    echo " 14. Telegram 通知设置"
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
        14) notify_manager;; 
        15) sys_monitor;; 
        16) log_manager;; 
        x|X) uninstall_cluster;; 
        0) exit 0;; 
    esac
done
