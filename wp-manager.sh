#!/bin/bash

# ================= 1. 配置区域 =================
# 脚本版本号
VERSION="V11 增强优化版 (快捷指令: web)"

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

# 初始化目录
mkdir -p "$SITES_DIR" "$GATEWAY_DIR" "$FW_DIR" "$LIB_DIR"
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

# 校验域名格式
function validate_domain() {
    local domain=$1
    # 简单的正则：不包含协议头，只包含字母数字点和横线
    if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        echo -e "${RED}❌ 错误: 域名格式不正确 (请勿包含 http:// 或特殊字符)${NC}"
        return 1
    fi
    return 0
}

# 检查端口占用
function is_port_free() {
    local port=$1
    if netstat -tuln | grep -q ":$port "; then
        return 1 # 被占用
    else
        return 0 # 空闲
    fi
}

function install_shortcut() {
    local script_path=$(readlink -f "$0")
    if [ ! -L "/usr/bin/web" ] || [ "$(readlink -f "/usr/bin/web")" != "$script_path" ]; then
        ln -sf "$script_path" /usr/bin/web && chmod +x "$script_path"
        echo -e "${GREEN}>>> 快捷指令 'web' 已安装 (输入 web 即可启动)${NC}"
    fi
}

function check_dependencies() {
    local deps=(jq openssl netstat docker)
    local need_install=0
    
    for dep in "${deps[@]}"; do
        if ! command -v $dep >/dev/null 2>&1; then
            need_install=1
            break
        fi
    done

    if [ $need_install -eq 1 ]; then
        echo -e "${YELLOW}>>> 检测到缺失依赖，正在自动安装...${NC}"
        if [ -f /etc/debian_version ]; then 
            apt-get update && apt-get install -y jq openssl net-tools ufw
        else 
            yum install -y jq openssl net-tools firewalld
        fi
        
        if ! command -v docker >/dev/null 2>&1; then
            echo -e "${YELLOW}>>> 正在安装 Docker...${NC}"
            curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun
            systemctl enable docker && systemctl start docker
            write_log "Installed Docker"
        fi
    fi
}

function ensure_firewall_installed() {
    if command -v ufw >/dev/null || command -v firewall-cmd >/dev/null; then return 0; fi
    echo -e "${YELLOW}>>> 正在安装防火墙...${NC}"
    if [ -f /etc/debian_version ]; then apt-get update && apt-get install -y ufw; ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp; echo "y" | ufw enable
    elif [ -f /etc/redhat-release ]; then yum install -y firewalld; systemctl enable firewalld --now; firewall-cmd --permanent --add-service={ssh,http,https}; firewall-cmd --reload
    else echo -e "${RED}❌ 系统不支持自动安装防火墙${NC}"; pause_prompt; return 1; fi
    echo -e "${GREEN}✔ 防火墙就绪${NC}"; sleep 1
}

function check_ssl_status() {
    local d=$1; echo -e "${CYAN}>>> [SSL] 正在申请证书...${NC}"; for ((i=1; i<=20; i++)); do if docker exec gateway_acme test -f "/etc/nginx/certs/$d.crt"; then echo -e "${GREEN}✔ SSL 成功: https://$d${NC}"; pause_prompt; return 0; fi; echo -n "."; sleep 5; done; echo -e "\n${YELLOW}⚠️ 证书暂未生成 (可能是DNS延迟)${NC}"; pause_prompt;
}

function normalize_url() {
    local url=$1; url=${url%/}; if [[ "$url" != http* ]]; then echo "https://$url"; else echo "$url"; fi
}

function update_script() {
    clear; echo -e "${GREEN}=== 脚本自动更新 ===${NC}"; echo -e "版本: $VERSION"; echo -e "源: GitHub (lje02/wp-manager)"
    temp_file="/tmp/wp_manager_update.sh"
    if curl -f -L -s -o "$temp_file" "$UPDATE_URL" && head -n 1 "$temp_file" | grep -q "/bin/bash"; then
        mv "$temp_file" "$0"; chmod +x "$0"; echo -e "${GREEN}✔ 更新成功，正在重启...${NC}"; write_log "Updated script"; sleep 1; exec "$0"
    else echo -e "${RED}❌ 更新失败! 请检查网络或源地址。${NC}"; rm -f "$temp_file"; fi; pause_prompt
}

function send_tg_msg() {
    local msg=$1; if [ -f "$TG_CONF" ]; then source "$TG_CONF"; if [ ! -z "$TG_BOT_TOKEN" ] && [ ! -z "$TG_CHAT_ID" ]; then curl -s -X POST "https://api.telegram.org/bot$TG_BOT_TOKEN/sendMessage" -d chat_id="$TG_CHAT_ID" -d text="$msg" >/dev/null; fi; fi
}

# --- 后台脚本生成器 ---
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

# ================= 3. 业务功能函数 =================

# [V9] 主机安全审计
function server_audit() {
    check_dependencies
    while true; do
        clear; echo -e "${YELLOW}=== 🕵️ 主机安全审计 (V9) ===${NC}"
        
        echo -e "${CYAN}[1] 端口暴露审计${NC} - 检查开放端口"
        echo -e "${CYAN}[2] 恶意进程检测${NC} - 检查CPU占用与可疑目录"
        echo -e "${CYAN}[3] 登录日志${NC}     - 查看最近登录记录"
        echo -e " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-3]: " o
        case $o in
            0) return;;
            1) 
                echo -e "\n${GREEN}>>> 正在扫描监听端口...${NC}"
                echo -e "${YELLOW}注意: 0.0.0.0 或 ::: 表示对全网开放${NC}"
                printf "%-8s %-25s %-15s %-20s\n" "协议" "本地地址:端口" "状态" "进程PID/名称"
                netstat -tunlp | grep LISTEN | awk '{printf "%-8s %-25s %-15s %-20s\n", $1, $4, $6, $7}'
                pause_prompt;;
            2)
                echo -e "\n${GREEN}>>> 正在执行安全扫描...${NC}"
                echo -e "\n${CYAN}[Check 1] CPU 占用最高的 5 个进程:${NC}"
                ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 6
                echo -e "\n${CYAN}[Check 2] 检查可疑目录运行的进程 (/tmp, /dev/shm):${NC}"
                suspicious_found=0
                for pid in $(ls /proc | grep -E '^[0-9]+$'); do
                    if [ -d "/proc/$pid" ]; then
                        exe_link=$(readlink -f /proc/$pid/exe 2>/dev/null)
                        if [[ "$exe_link" == /tmp/* ]] || [[ "$exe_link" == /var/tmp/* ]] || [[ "$exe_link" == /dev/shm/* ]]; then
                            echo -e "${RED}⚠️  发现可疑进程 PID: $pid${NC} -> $exe_link"
                            suspicious_found=1
                        fi
                    fi
                done
                if [ "$suspicious_found" -eq 0 ]; then echo -e "${GREEN}✔ 未发现明显的可疑目录进程${NC}"; fi
                pause_prompt;;
            3) last | head -n 10; pause_prompt;;
        esac
    done
}

function security_center() {
    while true; do
        clear; echo -e "${YELLOW}=== 🛡️ 安全防御中心 (V9) ===${NC}"
        
        # 状态检测逻辑 (简化显示)
        FW_ST=$([ -x "$(command -v ufw)" ] && ufw status | grep -q "active" && echo "${GREEN}运行中${NC}" || echo "${RED}未运行${NC}")
        WAF_ST=$(grep -r "V69" "$SITES_DIR" >/dev/null 2>&1 && echo "${GREEN}增强版${NC}" || echo "${YELLOW}基础/未部署${NC}")

        echo -e " 1. 端口防火墙   [$FW_ST]"
        echo -e " 2. 流量访问控制 (Nginx Layer7)"
        echo -e " 3. SSH防暴力破解 (Fail2Ban)"
        echo -e " 4. 网站防火墙    [$WAF_ST]"
        echo -e " 5. HTTPS证书管理"
        echo -e " 6. 防盗链设置"
        echo -e " 7. ${CYAN}主机安全审计${NC}"
        echo " 0. 返回主菜单"
        echo "--------------------------"
        read -p "请输入选项 [0-7]: " s
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

function wp_toolbox() {
    # WP-CLI 工具箱
    while true; do
        clear; echo -e "${YELLOW}=== 🛠️ WP-CLI 瑞士军刀 ===${NC}"
        ls -1 "$SITES_DIR"; echo "--------------------------"
        read -p "请输入要操作的域名 (0返回): " d; [ "$d" == "0" ] && return
        sdir="$SITES_DIR/$d"
        if [ ! -d "$sdir" ]; then echo -e "${RED}目录不存在${NC}"; sleep 1; continue; fi
        
        if [ -f "$sdir/docker-compose.yml" ]; then
            container_name=$(grep "container_name: .*_app" "$sdir/docker-compose.yml" | awk '{print $2}')
        fi
        
        if [ -z "$container_name" ]; then echo -e "${RED}无法识别WP容器${NC}"; sleep 2; continue; fi

        echo -e "操作站点: ${CYAN}$d${NC}"
        echo " 1. 重置密码 (user=admin)"
        echo " 2. 列出插件"
        echo " 3. 禁用所有插件"
        echo " 4. 清理缓存"
        echo " 5. 修复权限"
        echo " 6. 数据库域名替换"
        echo " 0. 返回"
        read -p "选项: " op
        
        case $op in
            0) break;;
            1) read -p "新密码: " newpass; docker exec -u www-data "$container_name" wp user update admin --user_pass="$newpass" && echo "✔ 完成"; pause_prompt;;
            2) docker exec -u www-data "$container_name" wp plugin list; pause_prompt;;
            3) docker exec -u www-data "$container_name" wp plugin deactivate --all && echo "✔ 完成"; pause_prompt;;
            4) docker exec -u www-data "$container_name" wp cache flush && echo "✔ 完成"; pause_prompt;;
            5) docker compose -f "$sdir/docker-compose.yml" exec -T -u root wordpress chown -R www-data:www-data /var/www/html && echo "✔ 完成"; pause_prompt;;
            6) read -p "旧域名: " old_d; read -p "新域名: " new_d; docker exec -u www-data "$container_name" wp search-replace "$old_d" "$new_d" --all-tables && echo "✔ 完成"; pause_prompt;;
        esac
    done
}

function telegram_manager() {
    while true; do
        clear; echo -e "${YELLOW}=== 🤖 Telegram 机器人管理 ===${NC}"
        if [ -f "$TG_CONF" ]; then source "$TG_CONF"; fi
        [ -f "$MONITOR_PID" ] && kill -0 $(cat "$MONITOR_PID") 2>/dev/null && M_STAT="${GREEN}运行中${NC}" || M_STAT="${RED}停止${NC}"
        [ -f "$LISTENER_PID" ] && kill -0 $(cat "$LISTENER_PID") 2>/dev/null && L_STAT="${GREEN}运行中${NC}" || L_STAT="${RED}停止${NC}"
        
        echo -e "守护进程: $M_STAT | 监听进程: $L_STAT"
        echo "--------------------------"
        echo " 1. 配置 Token 和 ChatID"
        echo " 2. 启动/重启 资源报警"
        echo " 3. 启动/重启 指令监听"
        echo " 4. 停止所有"
        echo " 5. 测试消息"
        echo " 0. 返回"
        read -p "选项: " t
        case $t in
            0) return;;
            1) read -p "Token: " tk; echo "TG_BOT_TOKEN=\"$tk\"" > "$TG_CONF"; read -p "ChatID: " ci; echo "TG_CHAT_ID=\"$ci\"" >> "$TG_CONF"; echo "已保存"; pause_prompt;;
            2) generate_monitor_script; nohup "$MONITOR_SCRIPT" >/dev/null 2>&1 & echo $! > "$MONITOR_PID"; send_tg_msg "✅ 资源报警已启动"; echo "已启动"; pause_prompt;;
            3) generate_listener_script; nohup "$LISTENER_SCRIPT" >/dev/null 2>&1 & echo $! > "$LISTENER_PID"; send_tg_msg "✅ 指令监听已启动"; echo "已启动"; pause_prompt;;
            4) pkill -F "$MONITOR_PID" 2>/dev/null; pkill -F "$LISTENER_PID" 2>/dev/null; rm -f "$MONITOR_PID" "$LISTENER_PID"; echo "已停止"; pause_prompt;;
            5) send_tg_msg "🔔 测试消息 OK"; echo "已发送"; pause_prompt;;
        esac
    done
}

function sys_monitor() {
    while true; do
        clear; echo -e "${YELLOW}=== 🖥️ 系统资源监控 ===${NC}"
        echo -e "CPU 负载 : $(uptime|awk -F'average:' '{print $2}')"
        echo -e "内存使用 : $(free -h|grep Mem|awk '{print $3 "/" $2}')"
        echo -e "磁盘占用 : $(df -h /|awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')"
        echo -e "TCP连接数: $(netstat -an|grep ESTABLISHED|wc -l 2>/dev/null || ss -s|grep est|awk '{print $2}')"
        echo "--------------------------"
        read -t 5 -p "按回车刷新，0 返回 > " o; [ "$o" == "0" ] && return
    done
}

function log_manager() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 📜 日志管理系统 ===${NC}"
        echo " 1. 查看最新日志"
        echo " 2. 清空日志"
        echo " 3. 配置自动清理 (7天)"
        echo " 0. 返回"
        read -p "选项: " l
        case $l in 
            0) return;; 
            1) tail -n 50 "$LOG_FILE"; pause_prompt;; 
            2) echo "">"$LOG_FILE"; echo "已清空"; pause_prompt;; 
            3) (crontab -l 2>/dev/null; echo "0 3 * * * find $BASE_DIR -name '*.log' -mtime +7 -delete") | crontab -; echo "定时任务已配置"; pause_prompt;; 
        esac
    done 
}

function container_ops() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 📊 容器状态监控 ===${NC}"
        echo -e "【核心网关】"; cd "$GATEWAY_DIR" && docker compose ps --format "table {{.Service}}\t{{.State}}\t{{.Status}}"|tail -n +2
        echo -e "\n【站点列表】"
        for d in "$SITES_DIR"/*; do [ -d "$d" ] && echo -e "> $(basename "$d")" && cd "$d" && docker compose ps --format "table {{.Service}}\t{{.State}}"|tail -n +2 | awk '{printf "  %-15s %s\n", $1, $2}'; done
        echo "--------------------------"
        echo " 1. 全部启动  2. 全部停止  3. 全部重启"
        echo " 4. 指定站点操作"
        echo " 0. 返回"
        read -p "选项: " c
        case $c in 
            0) return;; 
            1) cd "$GATEWAY_DIR" && docker compose up -d; for d in "$SITES_DIR"/*; do cd "$d" && docker compose up -d; done; echo "完成"; pause_prompt;; 
            2) for d in "$SITES_DIR"/*; do cd "$d" && docker compose stop; done; cd "$GATEWAY_DIR" && docker compose stop; echo "完成"; pause_prompt;; 
            3) cd "$GATEWAY_DIR" && docker compose restart; for d in "$SITES_DIR"/*; do cd "$d" && docker compose restart; done; echo "完成"; pause_prompt;; 
            4) ls -1 "$SITES_DIR"; read -p "输入域名: " d; cd "$SITES_DIR/$d" && read -p "1.启动 2.停止 3.重启: " a && ([ "$a" == "1" ] && docker compose up -d || ([ "$a" == "2" ] && docker compose stop || docker compose restart)); echo "完成"; pause_prompt;; 
        esac
    done 
}

function component_manager() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 🆙 组件版本升降级 ===${NC}"
        ls -1 "$SITES_DIR"; echo "--------------------------"; read -p "输入域名 (0返回): " d; [ "$d" == "0" ] && return
        sdir="$SITES_DIR/$d"; 
        [ ! -f "$sdir/docker-compose.yml" ] && echo "配置文件不存在" && pause_prompt && continue
        
        cur_wp=$(grep "image: wordpress" "$sdir/docker-compose.yml"|awk '{print $2}'); 
        echo -e "当前: PHP=[$cur_wp]"
        echo " 1. 切换 PHP 版本"
        echo " 2. 切换 数据库 版本 (高危)"
        echo " 3. 切换 Redis 版本"
        echo " 0. 返回"
        read -p "选项: " op
        case $op in 
            0) break;; 
            1) echo "1.PHP 7.4  2.PHP 8.0  3.PHP 8.1  4.PHP 8.2"; read -p "选择: " p; 
               case $p in 1) t="php7.4-fpm-alpine";; 2) t="php8.0-fpm-alpine";; 3) t="php8.1-fpm-alpine";; 4) t="php8.2-fpm-alpine";; *) continue;; esac; 
               sed -i "s|image: wordpress:.*|image: wordpress:$t|g" "$sdir/docker-compose.yml"; cd "$sdir" && docker compose up -d; echo "完成"; pause_prompt;; 
            2) echo "1.MySQL5.7 2.MySQL8.0 3.MariaDB10.6"; read -p "选择: " v; 
               case $v in 1) i="mysql:5.7";; 2) i="mysql:8.0";; 3) i="mariadb:10.6";; *) continue;; esac; 
               sed -i "s|image: .*sql:.*|image: $i|g" "$sdir/docker-compose.yml"; cd "$sdir" && docker compose up -d; echo "完成"; pause_prompt;; 
            3) echo "1.Redis6.2 2.Redis7.0"; read -p "选择: " r; 
               case $r in 1) rt="6.2-alpine";; 2) rt="7.0-alpine";; *) continue;; esac; 
               sed -i "s|image: redis:.*|image: redis:$rt|g" "$sdir/docker-compose.yml"; cd "$sdir" && docker compose up -d; echo "完成"; pause_prompt;; 
        esac
    done 
}

function fail2ban_manager() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 👮 Fail2Ban 防护专家 ===${NC}"
        echo " 1. 安装/重置"
        echo " 2. 查看被封禁 IP"
        echo " 3. 解封指定 IP"
        echo " 0. 返回"
        read -p "选项: " o
        case $o in 
            0) return;; 
            1) echo "安装配置中..."; 
               if [ -f /etc/debian_version ]; then apt-get install -y fail2ban; lp="/var/log/auth.log"; else yum install -y fail2ban; lp="/var/log/secure"; fi; 
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
               systemctl enable fail2ban; systemctl restart fail2ban; echo "配置完成"; pause_prompt;; 
            2) fail2ban-client status sshd 2>/dev/null|grep Banned; pause_prompt;; 
            3) read -p "输入 IP: " i; fail2ban-client set sshd unbanip $i; echo "已解封"; pause_prompt;; 
        esac
    done 
}

function waf_manager() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 🛡️ WAF 网站防火墙 (V70) ===${NC}"
        echo " 1. 部署增强规则"
        echo " 2. 查看当前规则"
        echo " 0. 返回"
        read -p "选项: " o
        case $o in 
            0) return;; 
            1) 
                echo -e "${BLUE}>>> 正在部署规则...${NC}"
                cat >/tmp/w <<EOF
# --- V69 Ultra WAF Rules ---
location ~* /\.(git|svn|hg|env|bak|config|sql|db|key|pem|ssh|ftpconfig) { deny all; return 403; }
location ~* \.(sql|bak|conf|ini|log|sh|yaml|yml|swp|install|dist)$ { deny all; return 403; }
if (\$query_string ~* "union.*select.*\(") { return 403; }
if (\$query_string ~* "base64_decode\(") { return 403; }
if (\$http_user_agent ~* (netcrawler|nikto|wikto|sf|sqlmap|bsqlbf|w3af|acunetix|havij|appscan)) { return 403; }
EOF
                count=0
                for d in "$SITES_DIR"/*; do 
                    if [ -d "$d" ]; then 
                        cp /tmp/w "$d/waf.conf" 
                        cd "$d" && docker compose exec -T nginx nginx -s reload >/dev/null 2>&1
                        ((count++))
                    fi 
                done
                rm /tmp/w; echo -e "${GREEN}✔ 成功部署 $count 个站点${NC}"; pause_prompt;; 
            2) cat "$SITES_DIR/"*"/waf.conf" 2>/dev/null|head -10; pause_prompt;; 
        esac
    done 
}

function port_manager() { 
    ensure_firewall_installed || return
    while true; do 
        clear; echo -e "${YELLOW}=== 🧱 端口防火墙 ===${NC}"
        echo " 1. 查看开放端口"
        echo " 2. 开放/关闭 端口"
        echo " 3. 防 DOS 攻击 (开启/关闭)"
        echo " 0. 返回"
        read -p "选项: " f
        case $f in 
            0) return;; 
            1) if command -v ufw >/dev/null; then ufw status; else firewall-cmd --list-ports; fi; pause_prompt;; 
            2) read -p "输入端口 (如 8080): " p; echo "1.开放 2.关闭"; read -p "选: " a; 
               if command -v ufw >/dev/null; then 
                   [ "$a" == "1" ] && ufw allow $p/tcp || ufw delete allow $p/tcp; 
               else 
                   ac=$([ "$a" == "1" ] && echo add || echo remove); firewall-cmd --zone=public --${ac}-port=$p/tcp --permanent; firewall-cmd --reload;
               fi; echo "完成"; pause_prompt;; 
            3) echo "1.开启防DOS 2.关闭"; read -p "选: " d; 
               if [ "$d" == "1" ]; then 
                   echo "limit_req_zone \$binary_remote_addr zone=one:10m rate=10r/s; limit_conn_zone \$binary_remote_addr zone=addr:10m;" > "$FW_DIR/dos_zones.conf"
                   mkdir -p "$GATEWAY_DIR/vhost"; echo "limit_req zone=one burst=15 nodelay; limit_conn addr 15;" > "$GATEWAY_DIR/vhost/default"
                   cd "$GATEWAY_DIR" && docker compose restart nginx-proxy; echo "已开启"
               else 
                   rm -f "$FW_DIR/dos_zones.conf" "$GATEWAY_DIR/vhost/default"; cd "$GATEWAY_DIR" && docker compose restart nginx-proxy; echo "已关闭"
               fi; pause_prompt;; 
        esac
    done 
}

function traffic_manager() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 🌐 流量控制 (ACL) ===${NC}"
        echo " 1. 添加 黑名单 IP"
        echo " 2. 添加 白名单 IP"
        echo " 3. 封禁 指定国家"
        echo " 4. 清空 所有规则"
        echo " 0. 返回"
        read -p "选项: " t
        case $t in 
            0) return;; 
            1|2) tp="deny"; [ "$t" == "2" ] && tp="allow"; read -p "IP: " i; echo "$tp $i;" >> "$FW_DIR/access.conf"; cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload; echo "OK"; pause_prompt;; 
            3) read -p "国家代码(cn): " c; wget -qO- "http://www.ipdeny.com/ipblocks/data/countries/$c.zone" | while read l; do echo "deny $l;" >> "$FW_DIR/geo.conf"; done; cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload; echo "OK"; pause_prompt;; 
            4) echo "">"$FW_DIR/access.conf"; echo "">"$FW_DIR/geo.conf"; cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload; echo "OK"; pause_prompt;; 
        esac
    done 
}

# --- 基础操作函数 ---
function init_gateway() { 
    local m=$1
    if ! docker network ls|grep -q proxy-net; then docker network create proxy-net >/dev/null; fi
    mkdir -p "$GATEWAY_DIR"; cd "$GATEWAY_DIR"
    
    # 上传限制配置
    if [ ! -f "upload_size.conf" ]; then
        echo "client_max_body_size 1024m;" > upload_size.conf
        echo "proxy_read_timeout 600s;" >> upload_size.conf
        echo "proxy_send_timeout 600s;" >> upload_size.conf
    fi

    cat > docker-compose.yml <<EOF
services:
  nginx-proxy: {image: nginxproxy/nginx-proxy, container_name: gateway_proxy, ports: ["80:80", "443:443"], logging: {driver: "json-file", options: {max-size: "10m", max-file: "3"}}, volumes: [conf:/etc/nginx/conf.d, vhost:/etc/nginx/vhost.d, html:/usr/share/nginx/html, certs:/etc/nginx/certs:ro, /var/run/docker.sock:/tmp/docker.sock:ro, ../firewall/access.conf:/etc/nginx/conf.d/z_access.conf:ro, ../firewall/geo.conf:/etc/nginx/conf.d/z_geo.conf:ro, ./upload_size.conf:/etc/nginx/conf.d/upload_size.conf:ro], networks: ["proxy-net"], restart: always, environment: ["TRUST_DOWNSTREAM_PROXY=true"]}
  acme-companion: {image: nginxproxy/acme-companion, container_name: gateway_acme, logging: {driver: "json-file", options: {max-size: "10m", max-file: "3"}}, volumes: [conf:/etc/nginx/conf.d, vhost:/etc/nginx/vhost.d, html:/usr/share/nginx/html, certs:/etc/nginx/certs:rw, acme:/etc/acme.sh, /var/run/docker.sock:/var/run/docker.sock:ro], environment: ["DEFAULT_EMAIL=admin@localhost.com", "NGINX_PROXY_CONTAINER=gateway_proxy", "ACME_CA_URI=https://acme-v02.api.letsencrypt.org/directory"], networks: ["proxy-net"], depends_on: ["nginx-proxy"], restart: always}
volumes: {conf: , vhost: , html: , certs: , acme: }
networks: {proxy-net: {external: true}}
EOF
    
    if docker compose up -d --remove-orphans >/dev/null 2>&1; then 
        [ "$m" == "force" ] && echo -e "${GREEN}✔ 网关启动成功${NC}"
    else 
        echo -e "${RED}✘ 网关启动失败${NC}"; [ "$m" == "force" ] && docker compose up -d
    fi 
}

function create_site() {
    read -p "1. 域名: " fd
    validate_domain "$fd" || { pause_prompt; return; }
    
    # IP 检查
    host_ip=$(curl -s4 ifconfig.me)
    if command -v dig >/dev/null; then dip=$(dig +short $fd|head -1); else dip=$(getent hosts $fd|awk '{print $1}'); fi
    if [ ! -z "$dip" ] && [ "$dip" != "$host_ip" ]; then echo -e "${RED}⚠️ 警告: 域名解析IP ($dip) 与本机 ($host_ip) 不一致${NC}"; read -p "继续? (y/n): " f; [ "$f" != "y" ] && return; fi
    
    read -p "2. 邮箱: " email; read -p "3. DB密码: " db_pass
    echo -e "${YELLOW}自定义版本? (默:PHP8.2/MySQL8.0/Redis7)${NC}"; read -p "y/n: " cust
    pt="php8.2-fpm-alpine"; di="mysql:8.0"; rt="7.0-alpine"
    if [ "$cust" == "y" ]; then 
        echo "PHP: 1.7.4 2.8.0 3.8.1 4.8.2 5.8.3 6.Latest"; read -p "选: " p; case $p in 1) pt="php7.4-fpm-alpine";; 2) pt="php8.0-fpm-alpine";; 3) pt="php8.1-fpm-alpine";; 4) pt="php8.2-fpm-alpine";; 5) pt="php8.3-fpm-alpine";; 6) pt="fpm-alpine";; esac
        echo "DB: 1.M5.7 2.M8.0 3.Latest 4.Ma10.6"; read -p "选: " d; case $d in 1) di="mysql:5.7";; 2) di="mysql:8.0";; 3) di="mysql:latest";; 4) di="mariadb:10.6";; esac
    fi
    
    pname=$(echo $fd|tr '.' '_'); sdir="$SITES_DIR/$fd"
    [ -d "$sdir" ] && echo -e "已存在" && pause_prompt && return; mkdir -p "$sdir"
    
    cat > "$sdir/waf.conf" <<EOF
location ~* /\.(git|env|sql) { deny all; return 403; }
EOF
    cat > "$sdir/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M; location / { try_files \$uri \$uri/ /index.php?\$args; } location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } }
EOF
    cat > "$sdir/uploads.ini" <<EOF
file_uploads = On
memory_limit = 512M
upload_max_filesize = 512M
post_max_size = 512M
max_execution_time = 600
EOF
    cat > "$sdir/docker-compose.yml" <<EOF
services:
  db: {image: $di, container_name: ${pname}_db, restart: always, logging: {driver: "json-file", options: {max-size: "10m", max-file: "3"}}, environment: {MYSQL_ROOT_PASSWORD: $db_pass, MYSQL_DATABASE: wordpress, MYSQL_USER: wp_user, MYSQL_PASSWORD: $db_pass}, volumes: [db_data:/var/lib/mysql], networks: [default]}
  redis: {image: redis:$rt, container_name: ${pname}_redis, restart: always, logging: {driver: "json-file", options: {max-size: "10m", max-file: "3"}}, networks: [default]}
  wordpress: {image: wordpress:$pt, container_name: ${pname}_app, restart: always, logging: {driver: "json-file", options: {max-size: "10m", max-file: "3"}}, depends_on: [db, redis], environment: {WORDPRESS_DB_HOST: db, WORDPRESS_DB_USER: wp_user, WORDPRESS_DB_PASSWORD: $db_pass, WORDPRESS_DB_NAME: wordpress, WORDPRESS_CONFIG_EXTRA: "define('WP_REDIS_HOST','redis');define('WP_REDIS_PORT',6379);define('WP_HOME','https://'.\$\$_SERVER['HTTP_HOST']);define('WP_SITEURL','https://'.\$\$_SERVER['HTTP_HOST']);if(isset(\$\$_SERVER['HTTP_X_FORWARDED_PROTO'])&&strpos(\$\$_SERVER['HTTP_X_FORWARDED_PROTO'],'https')!==false){\$\$_SERVER['HTTPS']='on';}"}, volumes: [wp_data:/var/www/html, ./uploads.ini:/usr/local/etc/php/conf.d/uploads.ini], networks: [default]}
  nginx: {image: nginx:alpine, container_name: ${pname}_nginx, restart: always, logging: {driver: "json-file", options: {max-size: "10m", max-file: "3"}}, volumes: [wp_data:/var/www/html, ./nginx.conf:/etc/nginx/conf.d/default.conf, ./waf.conf:/etc/nginx/waf.conf], environment: {VIRTUAL_HOST: "$fd", LETSENCRYPT_HOST: "$fd", LETSENCRYPT_EMAIL: "$email"}, networks: [default, proxy-net]}
volumes: {db_data: , wp_data: }
networks: {proxy-net: {external: true}}
EOF
    cd "$sdir" && docker compose up -d; check_ssl_status "$fd"; write_log "Created site $fd"
}

# ================= 通用应用商店逻辑 =================
# ================= 1. 初始化应用库 (内嵌模板) =================
function init_library() {
    mkdir -p "$LIB_DIR"
    # --- App 1: Uptime Kuma ---
    mkdir -p "$LIB_DIR/uptime-kuma"
    if [ ! -f "$LIB_DIR/uptime-kuma/docker-compose.yml" ]; then
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
    networks:
      - proxy-net
networks: {proxy-net: {external: true}}
EOF
    fi

    # --- App 2: Alist ---
    mkdir -p "$LIB_DIR/alist"
    if [ ! -f "$LIB_DIR/alist/docker-compose.yml" ]; then
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
    networks:
      - proxy-net
networks: {proxy-net: {external: true}}
EOF
    fi

# --- App 3: openlist ---
    mkdir -p "$LIB_DIR/openlist"
    echo "Openlist 网盘挂载程序" > "$LIB_DIR/openlist/name.txt"
    echo "5244" > "$LIB_DIR/openlist/port.txt" 

    if [ ! -f "$LIB_DIR/openlist/docker-compose.yml" ]; then
        cat > "$LIB_DIR/openlist/docker-compose.yml" <<EOF
services:
  openlist:
    image: openlistteam/openlist:latest
    container_name: {{APP_ID}}_openlist
  user: '0:0'
    volumes:
      - ./data:/opt/openlist/data
    environment:
      - UMASK=022
    restart: unless-stopped
      - VIRTUAL_HOST={{DOMAIN}}
      - LETSENCRYPT_HOST={{DOMAIN}}
      - LETSENCRYPT_EMAIL={{EMAIL}}
      - VIRTUAL_PORT=5244
    networks:
      - proxy-net
networks:
  proxy-net:
    external: true
EOF
    fi
}

function install_app() {
    init_library
    clear; echo -e "${YELLOW}=== 📦 Docker 其它应用 ===${NC}"
    printf "%-5s %-20s %-30s\n" "ID" "应用代号" "说明"
    echo "--------------------------------------------------------"
    
    i=1; apps=()
    for app in $(ls -1 "$LIB_DIR" | sort); do
        if [ -d "$LIB_DIR/$app" ]; then
            display_name=$(cat "$LIB_DIR/$app/name.txt" 2>/dev/null || echo $app)
            printf "${GREEN}%-5s${NC} %-20s %-30s\n" "[$i]" "$app" "$display_name"
            apps[i]=$app; ((i++))
        fi
    done
    echo "--------------------------------------------------------"
    
    read -p "选择应用编号 (0返回): " choice
    if [ "$choice" == "0" ] || [ -z "${apps[$choice]}" ]; then return; fi
    
    TARGET_APP=${apps[$choice]}
    DEFAULT_PORT=$(cat "$LIB_DIR/$TARGET_APP/port.txt" 2>/dev/null || echo "8080")

    read -p "绑定域名: " domain
    validate_domain "$domain" || { pause_prompt; return; }
    read -p "邮箱: " email
    
    # 端口检测与重写
    while true; do
        read -p "宿主机端口 (默认 $DEFAULT_PORT): " input_port
        HOST_PORT=${input_port:-$DEFAULT_PORT}
        if is_port_free "$HOST_PORT"; then
            break
        else
            echo -e "${RED}端口 $HOST_PORT 已被占用，请更换！${NC}"
        fi
    done

    SITE_PATH="$SITES_DIR/$domain"
    if [ -d "$SITE_PATH" ]; then echo -e "${RED}站点已存在${NC}"; pause_prompt; return; fi
    
    mkdir -p "$SITE_PATH"
    cp -r "$LIB_DIR/$TARGET_APP/"* "$SITE_PATH/"
    
    APP_ID=${domain//./_}
    sed -i "s|{{DOMAIN}}|$domain|g" "$SITE_PATH/docker-compose.yml"
    sed -i "s|{{EMAIL}}|$email|g" "$SITE_PATH/docker-compose.yml"
    sed -i "s|{{APP_ID}}|$APP_ID|g" "$SITE_PATH/docker-compose.yml"
    sed -i "s|{{HOST_PORT}}|$HOST_PORT|g" "$SITE_PATH/docker-compose.yml"
    
    echo -e "${YELLOW}正在启动...${NC}"
    cd "$SITE_PATH" && docker compose up -d
    check_ssl_status "$domain"
}

function create_proxy() {
    read -p "1. 域名: " d; fd="$d"; validate_domain "$d" || return
    read -p "2. 邮箱: " e; sdir="$SITES_DIR/$d"; mkdir -p "$sdir"
    echo -e "1.URL 2.IP:端口"; read -p "类型: " t
    if [ "$t" == "2" ]; then 
        read -p "IP: " ip; [ -z "$ip" ] && ip="127.0.0.1"; read -p "端口: " p; tu="http://$ip:$p"; pm="2"
    else 
        read -p "URL: " tu; tu=$(normalize_url "$tu"); echo "1.镜像 2.代理"; read -p "模式: " pm; [ -z "$pm" ] && pm="1"
    fi
    generate_nginx_conf "$tu" "$d" "$pm"
    cat > "$sdir/docker-compose.yml" <<EOF
services:
  proxy: {image: nginx:alpine, container_name: ${d//./_}_worker, restart: always, logging: {driver: "json-file", options: {max-size: "10m", max-file: "3"}}, volumes: [./nginx-proxy.conf:/etc/nginx/conf.d/default.conf], extra_hosts: ["host.docker.internal:host-gateway"], environment: {VIRTUAL_HOST: "$fd", LETSENCRYPT_HOST: "$fd", LETSENCRYPT_EMAIL: "$e"}, networks: [proxy-net]}
networks: {proxy-net: {external: true}}
EOF
    cd "$sdir" && docker compose up -d; check_ssl_status "$d"; write_log "Created proxy $d"
}

function generate_nginx_conf() {
    local u=$1; local d=$2; local m=$3; local h=$(echo $u|awk -F/ '{print $3}'); local f="$SITES_DIR/$d/nginx-proxy.conf"
    echo "server { listen 80; server_name localhost; resolver 1.1.1.1; location / {" > "$f"
    if [ "$m" == "2" ]; then echo "proxy_pass $u; proxy_set_header Host $h; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_ssl_server_name on;" >> "$f"
    else echo "proxy_pass $u; proxy_set_header Host $h; proxy_set_header Referer $u; proxy_ssl_server_name on; proxy_set_header Accept-Encoding \"\"; sub_filter \"</head>\" \"<meta name='referrer' content='no-referrer'></head>\"; sub_filter \"$h\" \"$d\"; sub_filter \"https://$h\" \"https://$d\"; sub_filter \"http://$h\" \"https://$d\";" >> "$f"; echo -e "${YELLOW}资源聚合(回车结束)${NC}"; c=1; while true; do read -p "URL: " re; [ -z "$re" ] && break; re=$(normalize_url "$re"); rh=$(echo $re|awk -F/ '{print $3}'); k="_res_$c"; cat >> "$f" <<EOF
sub_filter "$rh" "$d/$k"; sub_filter "https://$rh" "https://$d/$k"; sub_filter "http://$rh" "https://$d/$k";
EOF
cat >> "$f.loc" <<EOF
location /$k/ { rewrite ^/$k/(.*) /\$1 break; proxy_pass $re; proxy_set_header Host $rh; proxy_set_header Referer $re; proxy_ssl_server_name on; proxy_set_header Accept-Encoding ""; }
EOF
((c++)); done; echo "sub_filter_once off; sub_filter_types *;" >> "$f"; fi; echo "}" >> "$f"; [ -f "$f.loc" ] && cat "$f.loc" >> "$f" && rm "$f.loc"; echo "}" >> "$f"
}

function repair_proxy() { ls -1 "$SITES_DIR"; read -p "域名: " d; sdir="$SITES_DIR/$d"; [ ! -d "$sdir" ] && return; read -p "新URL: " tu; tu=$(normalize_url "$tu"); generate_nginx_conf "$tu" "$d" "1"; cd "$sdir" && docker compose restart; echo "OK"; pause_prompt; }

function fix_upload_limit() { ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; cat > "$s/uploads.ini" <<EOF
file_uploads = On
memory_limit = 512M
upload_max_filesize = 512M
post_max_size = 512M
max_execution_time = 600
EOF
if [ -f "$s/nginx.conf" ]; then sed -i 's/client_max_body_size .*/client_max_body_size 512M;/g' "$s/nginx.conf"; fi; cd "$s" && docker compose restart; echo "OK"; pause_prompt; }

function create_redirect() { read -p "Src Domain: " s; validate_domain "$s" || return; read -p "Target URL: " t; t=$(normalize_url "$t"); read -p "Email: " e; sdir="$SITES_DIR/$s"; mkdir -p "$sdir"; echo "server { listen 80; server_name localhost; location / { return 301 $t\$request_uri; } }" > "$sdir/redirect.conf"; echo "services: {redirector: {image: nginx:alpine, container_name: ${s//./_}_redirect, restart: always, logging: {driver: "json-file", options: {max-size: "10m", max-file: "3"}}, volumes: [./redirect.conf:/etc/nginx/conf.d/default.conf], environment: {VIRTUAL_HOST: \"$s\", LETSENCRYPT_HOST: \"$s\", LETSENCRYPT_EMAIL: \"$e\"}, networks: [proxy-net]}}" > "$sdir/docker-compose.yml"; echo "networks: {proxy-net: {external: true}}" >> "$sdir/docker-compose.yml"; cd "$sdir" && docker compose up -d; check_ssl_status "$s"; }

function delete_site() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 🗑️ 删除网站 (增强版) ===${NC}"; 
        ls -1 "$SITES_DIR"; 
        echo "----------------"; 
        read -p "请输入要删除的域名 (0返回): " d; 
        [ "$d" == "0" ] && return; 
        
        target_dir="$SITES_DIR/$d"
        
        if [ -d "$target_dir" ]; then 
            echo -e "${RED}⚠️  警告: 此操作将永久删除网站数据和数据库！${NC}"
            read -p "确认删除 $d ? (输入 yes 确认): " c; 
            
            if [ "$c" == "yes" ]; then 
                echo -e "${YELLOW}1. 正在尝试停止容器...${NC}"
                # 尝试停止容器，容忍失败 (|| true 表示即使失败也不报错退出)
                if [ -f "$target_dir/docker-compose.yml" ]; then
                    cd "$target_dir" && docker compose down -v 2>/dev/null || true
                else
                    echo "   配置文件缺失，跳过停止步骤..."
                fi
                
                echo -e "${YELLOW}2. 正在清理文件...${NC}"
                # 确保切回主目录，防止在删除目录内执行删除
                cd "$BASE_DIR" || exit
                rm -rf "$target_dir"
                
                if [ ! -d "$target_dir" ]; then
                    echo -e "${GREEN}✔ 网站 $d 已彻底删除${NC}"
                    write_log "Deleted site $d"
                else
                    echo -e "${RED}❌ 删除失败，可能是权限问题或文件被占用${NC}"
                fi
            else
                echo "操作已取消"
            fi
        else
            echo -e "${RED}❌ 目录不存在${NC}"
        fi
        pause_prompt; 
    done; 
}

function cert_management() { 
    while true; do 
        clear; echo -e "${YELLOW}=== HTTPS 证书管理 ===${NC}"
        echo " 1. 列表"
        echo " 2. 上传已有证书"
        echo " 3. 重置证书缓存"
        echo " 4. 强制续签"
        echo " 0. 返回"
        read -p "选: " c
        case $c in 
            0) return;; 
            1) docker exec gateway_proxy ls -lh /etc/nginx/certs|grep .crt; pause_prompt;; 
            2) ls -1 "$SITES_DIR"; read -p "域名: " d; read -p "crt路径: " c; read -p "key路径: " k; docker cp "$c" gateway_acme:"/etc/nginx/certs/$d.crt"; docker cp "$k" gateway_acme:"/etc/nginx/certs/$d.key"; docker exec gateway_proxy nginx -s reload; echo "OK"; pause_prompt;; 
            3) read -p "域名: " d; docker exec gateway_acme rm -f "/etc/nginx/certs/$d.crt" "/etc/nginx/certs/$d.key"; docker restart gateway_acme; echo "OK"; pause_prompt;; 
            4) docker exec gateway_acme /app/force_renew; echo "OK"; pause_prompt;; 
        esac
    done
}

function db_manager() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 数据库管理 ===${NC}"
        echo " 1. 导出 (Dump)"
        echo " 2. 导入 (Import)"
        echo " 0. 返回"
        read -p "选: " c
        case $c in 
            0) return;; 
            1) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; 
               pwd=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml"|awk -F': ' '{print $2}')
               docker compose -f "$s/docker-compose.yml" exec -T db mysqldump -u root -p"$pwd" --all-databases > "$s/${d}.sql"
               echo "导出成功: $s/${d}.sql"; pause_prompt;; 
            2) ls -1 "$SITES_DIR"; read -p "域名: " d; read -p "SQL文件: " f; s="$SITES_DIR/$d"
               pwd=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml"|awk -F': ' '{print $2}')
               cat "$f" | docker compose -f "$s/docker-compose.yml" exec -T db mysql -u root -p"$pwd"
               echo "导入完成"; pause_prompt;; 
        esac
    done 
}

function change_domain() { ls -1 "$SITES_DIR"; read -p "旧域名: " o; [ ! -d "$SITES_DIR/$o" ] && return; read -p "新域名: " n; validate_domain "$n" || return; cd "$SITES_DIR/$o" && docker compose down; cd .. && mv "$o" "$n" && cd "$n"; sed -i "s/$o/$n/g" docker-compose.yml; docker compose up -d; wp_c=$(docker compose ps -q wordpress); docker run --rm --volumes-from $wp_c --network container:$wp_c wordpress:cli wp search-replace "$o" "$n" --all-tables --skip-columns=guid; docker exec gateway_proxy nginx -s reload; echo "OK"; write_log "Changed $o to $n"; pause_prompt; }

function manage_hotlink() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 防盗链设置 ===${NC}"
        echo " 1. 开启防盗链"
        echo " 2. 关闭防盗链"
        echo " 0. 返回"
        read -p "选: " h
        case $h in 
            0) return;; 
            1) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; read -p "允许的白名单(如 google.com): " w
               cat > "$s/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M; location ~* \.(gif|jpg|png|webp)$ { valid_referers none blocked server_names $d *.$d $w; if (\$invalid_referer) { return 403; } try_files \$uri \$uri/ /index.php?\$args; } location / { try_files \$uri \$uri/ /index.php?\$args; } location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } }
EOF
               cd "$s" && docker compose restart nginx; echo "OK"; pause_prompt;; 
            2) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"
               # 恢复默认 Nginx 配置
               cat > "$s/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M; location / { try_files \$uri \$uri/ /index.php?\$args; } location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } }
EOF
               cd "$s" && docker compose restart nginx; echo "OK"; pause_prompt;; 
        esac
    done 
}

function backup_restore_ops() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 备份与还原 ===${NC}"
        echo " 1. 创建备份 (Backup)"
        echo " 2. 还原备份 (Restore)"
        echo " 0. 返回"
        read -p "选: " b
        case $b in 
            0) return;; 
            1) 
                ls -1 "$SITES_DIR"; read -p "选择域名: " d; s="$SITES_DIR/$d"; [ ! -d "$s" ] && continue
                bd="$s/backups/$(date +%Y%m%d%H%M)"; mkdir -p "$bd"; cd "$s"
                pwd=$(grep MYSQL_ROOT_PASSWORD docker-compose.yml|awk -F': ' '{print $2}')
                
                echo -e "${CYAN}正在导出数据库...${NC}"
                docker compose exec -T db mysqldump -u root -p"$pwd" --all-databases > "$bd/db.sql"
                
                echo -e "${CYAN}正在打包文件...${NC}"
                wp_c=$(docker compose ps -q wordpress)
                docker run --rm --volumes-from $wp_c -v "$bd":/backup alpine tar czf /backup/files.tar.gz /var/www/html/wp-content
                cp *.conf docker-compose.yml "$bd/"
                
                echo "✅ 备份完成: $bd"; write_log "Backup $d"; pause_prompt;; 
            2) 
                ls -1 "$SITES_DIR"; read -p "选择域名: " d; s="$SITES_DIR/$d"; bd="$s/backups"; [ ! -d "$bd" ] && echo "无备份记录" && pause_prompt && continue
                
                # 自动找最新备份
                lt=$(ls -t "$bd"|head -1)
                if [ ! -z "$lt" ]; then echo "发现最新备份: $lt"; read -p "使用此备份? (y/n): " u; [ "$u" == "y" ] && n="$lt"; fi
                if [ -z "$n" ]; then ls -1 "$bd"; read -p "输入备份文件夹名: " n; fi
                
                bp="$bd/$n"; [ ! -d "$bp" ] && echo "备份不存在" && pause_prompt && continue
                
                echo -e "${RED}⚠️  警告: 将覆盖当前站点数据${NC}"; read -p "确认还原? (y/n): " confirm; [ "$confirm" != "y" ] && continue
                
                cd "$s" && docker compose down
                vol=$(docker volume ls -q|grep "${d//./_}_wp_data")
                
                echo -e "${CYAN}还原文件...${NC}"
                docker run --rm -v $vol:/var/www/html -v "$bp":/backup alpine tar xzf /backup/files.tar.gz -C /
                
                docker compose up -d db; echo "等待数据库启动..."; sleep 15
                
                echo -e "${CYAN}还原数据库...${NC}"
                pwd=$(grep MYSQL_ROOT_PASSWORD docker-compose.yml|awk -F': ' '{print $2}')
                docker compose exec -T db mysql -u root -p"$pwd" < "$bp/db.sql"
                
                docker compose up -d; echo "✅ 还原完成"; write_log "Restored $d"; pause_prompt;; 
        esac
    done 
}

function uninstall_cluster() { echo "⚠️ 危险: 输入 DELETE 确认"; read -p "> " c; [ "$c" == "DELETE" ] && (ls "$SITES_DIR"|while read d; do cd "$SITES_DIR/$d" && docker compose down -v; done; cd "$GATEWAY_DIR" && docker compose down -v; docker network rm proxy-net; rm -rf "$BASE_DIR" /usr/bin/web; echo "已卸载"); }

# ================= 4. 菜单显示函数 =================
function show_menu() {
    clear
    echo -e "${GREEN}=== Docker web 集群管理 ($VERSION) ===${NC}"
    echo -e "${CYAN}===请勿在生产环境中使用===${NC}"
    echo "-----------------------------------------"
    echo -e "${YELLOW}[新建站点]${NC}"
    echo " 1. 部署 WordPress 新站"
    echo " 2. 新建 反向代理 (IP:端口 / 域名)"
    echo " 3. 新建 域名重定向 (301)"
    echo -e " 4. ${CYAN}其它应用 (一键部署)${NC}"
    echo ""
    echo -e "${YELLOW}[站点运维]${NC}"
    echo " 5. 查看站点列表"
    echo " 6. 容器状态监控"
    echo " 7. 删除指定站点"
    echo " 8. 更换网站域名"
    echo " 9. 修复反代配置"
    echo -e " 10. ${CYAN}组件版本升降级 (PHP/DB/Redis)${NC}"
    echo " 11. 解除上传限制 (一键扩容)"
    echo -e " 12. ${GREEN}WP-CLI 瑞士军刀 (重置密码/插件)${NC}"
    echo ""
    echo -e "${YELLOW}[数据管理]${NC}"
    echo " 13. 数据库 导出/导入"
    echo " 14. 整站 备份与还原 (智能扫描)"
    echo ""
    echo -e "${RED}[安全与监控]${NC}"
    echo -e " 15. 安全防御中心 ${GREEN}(含主机审计/挖矿检测)${NC}"
    echo " 16. Telegram 通知 (报警/查看)"
    echo " 17. 系统资源监控"
    echo " 18. 日志管理系统"
    echo "-----------------------------------------"
    echo -e "${BLUE} u. 检查更新${NC} | ${RED}x. 卸载${NC} | 0. 退出"
    echo -n "请选择: "
    read option
}

# ================= 5. 主程序循环 =================
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
        6) container_ops;; 
        7) delete_site;; 
        8) change_domain;; 
        9) repair_proxy;; 
        10) component_manager;; 
        11) fix_upload_limit;; 
        12) wp_toolbox;; 
        13) db_manager;; 
        14) backup_restore_ops;; 
        15) security_center;; 
        16) telegram_manager;; 
        17) sys_monitor;; 
        18) log_manager;; 
        x|X) uninstall_cluster;; 
        0) exit 0;; 
    esac
done
