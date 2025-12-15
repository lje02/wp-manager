#!/bin/bash

# ================= 配置区域 =================
BASE_DIR="/root/wp-cluster"
SITES_DIR="$BASE_DIR/sites"
GATEWAY_DIR="$BASE_DIR/gateway"
FW_DIR="$BASE_DIR/firewall"
TG_CONF="$BASE_DIR/telegram.conf"
LOG_FILE="$BASE_DIR/logs/cluster.log"
ERROR_LOG="$BASE_DIR/logs/error.log"

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

# 初始化目录
mkdir -p "$SITES_DIR" "$GATEWAY_DIR" "$FW_DIR" "$BASE_DIR/logs"

# ================= 核心工具函数 =================

# --- 日志函数 ---
function log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1" >> "$LOG_FILE"
}

function log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$ERROR_LOG"
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

# --- 自动注册快捷指令 wp ---
function install_shortcut() {
    local script_path=$(readlink -f "$0")
    if [ ! -L "/usr/bin/wp" ] || [ "$(readlink -f "/usr/bin/wp")" != "$script_path" ]; then
        ln -sf "$script_path" /usr/bin/wp && chmod +x "$script_path"
        log_info "快捷指令注册成功"
    fi
}

function check_and_install_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${YELLOW}未检测到 Docker，准备自动安装...${NC}"
        log_info "开始安装 Docker"
        curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun
        systemctl enable docker && systemctl start docker
        log_info "Docker 安装完成"
    fi
}

function check_ssl_status() {
    local d=$1
    echo -e "${CYAN}>>> 正在申请 SSL...${NC}"
    for ((i=1; i<=20; i++)); do
        if docker exec gateway_acme test -f "/etc/nginx/certs/$d.crt" 2>/dev/null; then
            echo -e "${GREEN}✔ 成功: https://$d${NC}"
            log_info "SSL 证书申请成功: $d"
            read -p "按回车返回..."
            return 0
        fi
        echo -n "."
        sleep 5
    done
    echo -e "\n${YELLOW}⚠️ 证书暂未生成 (请检查DNS)${NC}"
    log_error "SSL 证书申请超时: $d"
    read -p "按回车返回..."
}

function normalize_url() {
    local url=$1
    url=${url%/}
    if [[ "$url" != http* ]]; then echo "https://$url"; else echo "$url"; fi
}

# --- 域名验证和消毒 ---
function validate_and_sanitize_domain() {
    local domain=$1
    domain=${domain#http://}
    domain=${domain#https://}
    domain=${domain#*://}
    domain=${domain%%/*}
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]; then
        echo -e "${RED}错误: 无效的域名格式${NC}"
        log_error "无效的域名格式: $1"
        return 1
    fi
    echo "$domain"
    return 0
}

# --- 检查容器是否运行 ---
function check_container_running() {
    local container_name=$1
    if docker ps --format '{{.Names}}' | grep -q "^$container_name$"; then return 0; else return 1; fi
}

# --- 证书监控状态检查 ---
function check_monitoring_status() {
    if [ -f /etc/cron.daily/wp-cluster-cert-check ]; then
        echo -e "${GREEN}[系统] 证书监控服务运行中${NC}"
    fi
}

# --- 创建 Telegram 配置文件模板 ---
function create_telegram_config() {
    if [ ! -f "$TG_CONF" ]; then
        cat > "$TG_CONF" << 'EOF'
# Telegram Bot 配置
# export TELEGRAM_BOT_TOKEN="YOUR_TOKEN"
# export TELEGRAM_CHAT_ID="YOUR_ID"
EOF
        log_info "创建 Telegram 配置文件"
    fi
}

# ================= 证书增强管理函数 =================

# --- 证书状态监控面板 ---
function cert_status_dashboard() {
    clear
    echo -e "${CYAN}=== SSL 证书状态监控面板 ===${NC}"
    echo ""
    echo -e "${YELLOW}[容器状态检查]${NC}"
    if check_container_running "gateway_acme"; then echo -e "${GREEN}✓ acme-companion 运行正常${NC}"; else echo -e "${RED}✗ acme-companion 未运行${NC}"; fi
    if check_container_running "gateway_proxy"; then echo -e "${GREEN}✓ nginx-proxy 运行正常${NC}"; else echo -e "${RED}✗ nginx-proxy 未运行${NC}"; fi
    echo ""
    echo -e "${YELLOW}[证书状态详情]${NC}"
    printf "%-25s | %-20s | %-10s | %s\n" "域名" "过期时间" "剩余天数" "状态"
    echo "------------------------------------------------------------------------"
    for site_dir in "$SITES_DIR"/*; do
        if [ -d "$site_dir" ]; then
            domain=$(basename "$site_dir")
            cert_file="/etc/nginx/certs/$domain.crt"
            if docker exec gateway_acme test -f "$cert_file" 2>/dev/null; then
                expiry_info=$(docker exec gateway_acme openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null)
                if [ $? -eq 0 ]; then
                    expiry_date=$(echo "$expiry_info" | cut -d= -f2)
                    expiry_ts=$(date -d "$expiry_date" +%s 2>/dev/null)
                    if [ ! -z "$expiry_ts" ]; then
                        current_ts=$(date +%s)
                        days_left=$(( (expiry_ts - current_ts) / 86400 ))
                        printf "%-25s | %-20s | " "$domain" "$expiry_date"
                        if [ $days_left -lt 0 ]; then printf "%-10s | ${RED}已过期${NC}\n" "0"
                        elif [ $days_left -lt 7 ]; then printf "%-10d | ${RED}急需续签${NC}\n" "$days_left"
                        elif [ $days_left -lt 30 ]; then printf "%-10d | ${YELLOW}即将过期${NC}\n" "$days_left"
                        else printf "%-10d | ${GREEN}正常${NC}\n" "$days_left"; fi
                    else printf "%-25s | %-20s | %-10s | ${YELLOW}解析失败${NC}\n" "$domain" "未知" "-"
                    fi
                fi
            else printf "%-25s | %-20s | %-10s | ${RED}无证书${NC}\n" "$domain" "-" "-"
            fi
        fi
    done
    echo ""
    read -p "按回车返回主菜单..."
}

# --- 证书到期监控和通知 (修复版) ---
function setup_cert_monitoring() {
    clear
    echo -e "${CYAN}=== 证书到期监控设置 ===${NC}"
    echo "1. 仅记录日志"
    echo "2. Telegram 通知 (推荐)"
    echo "3. 取消监控"
    read -p "选择通知方式 [1-3]: " notify_type
    
    CRON_FILE="/etc/cron.daily/wp-cluster-cert-check"
    
    case $notify_type in
        1)
            cat > "$CRON_FILE" << 'EOF'
#!/bin/bash
BASE_DIR="/root/wp-cluster"
LOG_FILE="$BASE_DIR/logs/cert-monitor.log"
echo "[$(date)] 检查证书..." >> "$LOG_FILE"
# 简化的检查逻辑
docker exec gateway_acme acme.sh --list >> "$LOG_FILE" 2>&1
EOF
            chmod +x "$CRON_FILE"
            echo -e "${GREEN}✓ 已设置日志监控${NC}"
            ;;
        2)
            if [ ! -f "$TG_CONF" ]; then echo -e "${RED}请先配置 Telegram Bot${NC}"; return; fi
            source "$TG_CONF"
            if [ -z "$TELEGRAM_BOT_TOKEN" ]; then echo -e "${RED}Token为空${NC}"; return; fi
            
            # 写入真正的 TG 监控脚本
            cat > "$CRON_FILE" << EOF
#!/bin/bash
BASE_DIR="/root/wp-cluster"
source "\$BASE_DIR/telegram.conf"
LOG_FILE="\$BASE_DIR/logs/cert-monitor.log"

function send_msg() {
    curl -s -X POST "https://api.telegram.org/bot\$TELEGRAM_BOT_TOKEN/sendMessage" -d chat_id="\$TELEGRAM_CHAT_ID" -d text="\$1" >/dev/null
}

for site_dir in "\$BASE_DIR/sites"/*; do
    if [ -d "\$site_dir" ]; then
        domain=\$(basename "\$site_dir")
        cert_file="/etc/nginx/certs/\$domain.crt"
        if docker exec gateway_acme test -f "\$cert_file" 2>/dev/null; then
            expiry_info=\$(docker exec gateway_acme openssl x509 -in "\$cert_file" -noout -enddate 2>/dev/null)
            expiry_date=\$(echo "\$expiry_info" | cut -d= -f2)
            expiry_ts=\$(date -d "\$expiry_date" +%s 2>/dev/null)
            current_ts=\$(date +%s)
            days_left=\$(( (expiry_ts - current_ts) / 86400 ))
            
            if [ \$days_left -lt 7 ] && [ \$days_left -ge 0 ]; then
                send_msg "⚠️ 证书警告: \$domain 还有 \$days_left 天过期！"
            fi
        fi
    fi
done
EOF
            chmod +x "$CRON_FILE"
            echo -e "${GREEN}✓ Telegram 监控已设置${NC}"
            ;;
        3)
            rm -f "$CRON_FILE"
            echo -e "${GREEN}✓ 监控已取消${NC}"
            ;;
    esac
    read -p "按回车返回..."
}

# --- 增强版证书管理菜单 ---
function enhanced_cert_management() {
    while true; do
        clear
        echo -e "${CYAN}=== 增强版 HTTPS 证书管理 ===${NC}"
        echo "1. 查看证书状态面板"
        echo "2. 手动续签指定证书"
        echo "3. 手动续签所有证书"
        echo "4. 上传自定义证书"
        echo "5. 删除并重置证书"
        echo "6. 切换证书颁发机构 (CA)"
        echo "7. 设置证书到期监控"
        echo "0. 返回主菜单"
        echo -n "请选择操作 [1-7]: "
        read cert_choice
        case $cert_choice in
            1) cert_status_dashboard ;;
            2) 
                ls -1 "$SITES_DIR"; read -p "输入域名: " d; 
                [ -d "$SITES_DIR/$d" ] && docker exec gateway_acme /app/force_renew 2>&1 | grep -i "$d" || echo "不存在"
                read -p "..." ;;
            3) 
                docker exec gateway_acme /app/force_renew; read -p "..." ;;
            4)
                ls -1 "$SITES_DIR"; read -p "域名: " d
                read -p "crt路径: " c; read -p "key路径: " k
                docker cp "$c" gateway_acme:"/etc/nginx/certs/$d.crt"
                docker cp "$k" gateway_acme:"/etc/nginx/certs/$d.key"
                docker exec gateway_proxy nginx -s reload
                read -p "完成..." ;;
            5)
                ls -1 "$SITES_DIR"; read -p "域名: " d
                docker exec gateway_acme rm -f "/etc/nginx/certs/$d.crt" "/etc/nginx/certs/$d.key"
                docker restart gateway_acme; read -p "已重置..." ;;
            6)
                echo "1. Let's Encrypt  2. ZeroSSL"; read -p "选: " ca
                [ "$ca" == "1" ] && s="letsencrypt" || s="zerossl"
                docker exec gateway_acme acme.sh --set-default-ca --server $s; read -p "OK..." ;;
            7) setup_cert_monitoring ;;
            0) return ;;
        esac
    done
}

# ================= 菜单系统 (V48 增强版) =================
function show_menu() {
    clear
    echo -e "${GREEN}=== WordPress Docker 集群管理 (V48 增强版) ===${NC}"
    check_monitoring_status
    echo "-----------------------------------------"
    echo -e "${YELLOW}[系统基石]${NC}"
    echo " 1. 初始化/重置网关"
    echo " 2. 容器状态监控与控制"
    echo " 3. SSH 密钥安全管理"
    echo ""
    echo -e "${YELLOW}[新建站点]${NC}"
    echo " 4. 部署 WordPress 新站"
    echo " 5. 新建 反向代理 (含资源聚合)"
    echo " 6. 新建 域名重定向 (301)"
    echo ""
    echo -e "${YELLOW}[站点运维]${NC}"
    echo " 7. 查看站点列表"
    echo " 8. 销毁指定站点"
    echo " 9. 更换网站域名"
    echo " 10. 修复反代配置 (纠错/改网址)"
    echo " 11. 修复上传限制 (一键扩容)"
    echo ""
    echo -e "${YELLOW}[安全防御]${NC}"
    echo " 12. 防火墙配置 (端口/黑白名单)"
    echo " 13. HTTPS 证书管理 (增强版)"
    echo " 14. 防盗链设置"
    echo ""
    echo -e "${YELLOW}[数据管理]${NC}"
    echo " 15. 数据库 导出/导入"
    echo " 16. 整站 备份与还原"
    echo "-----------------------------------------"
    echo -e "${RED} 17. [危险] 彻底卸载脚本与数据${NC}"
    echo " 0. 退出"
    echo "-----------------------------------------"
    echo -n "请选择操作 [0-17]: "
    read option
}

# --- 17. 卸载功能 ---
function uninstall_cluster() {
    clear
    echo -e "${RED}⚠️  危险警告：彻底卸载  ⚠️${NC}"
    echo "此操作将删除所有网站、数据库和数据！"
    read -p "请输入 'DELETE' 以确认: " confirm
    if [ "$confirm" != "DELETE" ]; then return; fi
    
    echo -e "${YELLOW}正在停止服务...${NC}"
    if [ -d "$SITES_DIR" ]; then
        for d in "$SITES_DIR"/*; do [ -d "$d" ] && cd "$d" && docker compose down -v 2>/dev/null; done
    fi
    [ -d "$GATEWAY_DIR" ] && cd "$GATEWAY_DIR" && docker compose down -v 2>/dev/null
    docker network rm proxy-net 2>/dev/null
    
    echo -e "${YELLOW}删除数据...${NC}"
    cd /root && rm -rf "$BASE_DIR"
    rm -f "/usr/bin/wp" /etc/cron.daily/wp-cluster-cert-check
    echo -e "${GREEN}卸载完成。${NC}"
    exit 0
}

# --- 1. 网关初始化 ---
function init_gateway() {
    local m=$1
    if ! docker network ls | grep -q "proxy-net"; then docker network create proxy-net >/dev/null; fi
    mkdir -p "$GATEWAY_DIR" && cd "$GATEWAY_DIR"
    echo "client_max_body_size 1024m;" > "upload_size.conf"
    echo "proxy_read_timeout 600s;" >> "upload_size.conf"
    echo "proxy_send_timeout 600s;" >> "upload_size.conf"
    
    read -p "输入SSL通知邮箱 [默认:admin@localhost]: " admin_email
    admin_email=${admin_email:-admin@localhost.com}
    
    cat > docker-compose.yml <<EOF
services:
  nginx-proxy:
    image: nginxproxy/nginx-proxy
    container_name: gateway_proxy
    ports: ["80:80", "443:443"]
    volumes: [conf:/etc/nginx/conf.d, vhost:/etc/nginx/vhost.d, html:/usr/share/nginx/html, certs:/etc/nginx/certs:ro, /var/run/docker.sock:/tmp/docker.sock:ro, ../firewall:/etc/nginx/conf.d/custom_firewall:ro, ./upload_size.conf:/etc/nginx/conf.d/upload_size.conf:ro]
    networks: ["proxy-net"]
    restart: always
    environment: ["TRUST_DOWNSTREAM_PROXY=true"]
  acme-companion:
    image: nginxproxy/acme-companion
    container_name: gateway_acme
    volumes: [conf:/etc/nginx/conf.d, vhost:/etc/nginx/vhost.d, html:/usr/share/nginx/html, certs:/etc/nginx/certs:rw, acme:/etc/acme.sh, /var/run/docker.sock:/var/run/docker.sock:ro]
    environment: ["DEFAULT_EMAIL=$admin_email", "NGINX_PROXY_CONTAINER=gateway_proxy", "ACME_CA_URI=https://acme-v02.api.letsencrypt.org/directory"]
    networks: ["proxy-net"]
    depends_on: ["nginx-proxy"]
    restart: always
volumes: {conf: , vhost: , html: , certs: , acme: }
networks: {proxy-net: {external: true}}
EOF
    if docker compose up -d --remove-orphans >/dev/null 2>&1; then 
        [ "$m" == "force" ] && echo -e "${GREEN}✔ 网关启动成功${NC}"
        log_info "网关启动成功"
    else
        echo -e "${RED}✘ 网关启动失败${NC}"; log_error "网关启动失败"
    fi
}

# --- 4. 创建WP站点 ---
function create_site() {
    read -p "1. 主域名: " raw_domain
    fd=$(validate_and_sanitize_domain "$raw_domain") || return 1
    
    host_ip=$(curl -s4 ifconfig.me 2>/dev/null); dip=$(dig +short "$fd" 2>/dev/null | head -1)
    if [ ! -z "$dip" ] && [ "$dip" != "$host_ip" ]; then
        echo -e "${RED}⚠️ IP不符: $dip vs $host_ip${NC}"; read -p "继续? (y/n): " f; [ "$f" != "y" ] && return
    fi
    
    read -p "2. 邮箱: " email; email=${email:-admin@$fd}
    read -p "3. DB密码: " db_pass; [ -z "$db_pass" ] && return
    
    pname=$(echo "$fd" | tr '.' '_'); sdir="$SITES_DIR/$fd"
    [ -d "$sdir" ] && { echo "已存在"; return; }
    mkdir -p "$sdir"
    
    cat > "$sdir/waf.conf" <<EOF
location ~* /\.(git|svn|hg|env|bak|config|sql) { deny all; return 403; }
location ~* \.(sql|bak|conf|ini|log|sh|yaml|yml)$ { deny all; return 403; }
EOF
    cat > "$sdir/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M;
location / { try_files \$uri \$uri/ /index.php?\$args; }
location ~ \.php\$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)\$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } }
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
  db: {image: mysql:8.0, container_name: ${pname}_db, restart: always, command: --default-authentication-plugin=mysql_native_password, environment: {MYSQL_ROOT_PASSWORD: $db_pass, MYSQL_DATABASE: wordpress, MYSQL_USER: wp_user, MYSQL_PASSWORD: $db_pass}, volumes: [db_data:/var/lib/mysql], networks: [default]}
  redis: {image: redis:alpine, container_name: ${pname}_redis, restart: always, networks: [default]}
  wordpress: {image: wordpress:php8.2-fpm-alpine, container_name: ${pname}_app, restart: always, depends_on: [db, redis], environment: {WORDPRESS_DB_HOST: db, WORDPRESS_DB_USER: wp_user, WORDPRESS_DB_PASSWORD: $db_pass, WORDPRESS_DB_NAME: wordpress, WORDPRESS_CONFIG_EXTRA: "define('WP_REDIS_HOST','redis');define('WP_REDIS_PORT',6379);define('WP_HOME','https://'.\$\$_SERVER['HTTP_HOST']);define('WP_SITEURL','https://'.\$\$_SERVER['HTTP_HOST']);if(isset(\$\$_SERVER['HTTP_X_FORWARDED_PROTO'])&&strpos(\$\$_SERVER['HTTP_X_FORWARDED_PROTO'],'https')!==false){\$\$_SERVER['HTTPS']='on';}"}, volumes: [wp_data:/var/www/html, ./uploads.ini:/usr/local/etc/php/conf.d/uploads.ini], networks: [default]}
  nginx: {image: nginx:alpine, container_name: ${pname}_nginx, restart: always, volumes: [wp_data:/var/www/html, ./nginx.conf:/etc/nginx/conf.d/default.conf, ./waf.conf:/etc/nginx/waf.conf], environment: {VIRTUAL_HOST: "$fd", LETSENCRYPT_HOST: "$fd", LETSENCRYPT_EMAIL: "$email"}, networks: [default, proxy-net]}
volumes: {db_data: , wp_data: }
networks: {proxy-net: {external: true}}
EOF
    cd "$sdir" && docker compose up -d >/dev/null 2>&1
    check_ssl_status "$fd"
}

# --- 其他辅助函数 ---
function fix_upload_limit() {
    ls -1 "$SITES_DIR"; read -p "输入域名: " d; sdir="$SITES_DIR/$d"
    [ ! -d "$sdir" ] && return
    cat > "$sdir/uploads.ini" <<EOF
file_uploads = On
memory_limit = 512M
upload_max_filesize = 512M
post_max_size = 512M
max_execution_time = 600
EOF
    [ -f "$sdir/nginx.conf" ] && sed -i 's/client_max_body_size [0-9]\+[mM]/client_max_body_size 512M/' "$sdir/nginx.conf"
    cd "$sdir" && docker compose restart >/dev/null 2>&1
    echo -e "${GREEN}完成${NC}"; read -p "..."
}

function generate_nginx_conf() {
    local u=$1; local d=$2; local h=$(echo "$u" | awk -F/ '{print $3}'); local f="$SITES_DIR/$d/nginx-proxy.conf"
    cat > "$f" <<EOF
server { listen 80; server_name localhost; resolver 8.8.8.8;
    location / { proxy_pass $u; proxy_set_header Host $h; proxy_set_header Referer $u; proxy_ssl_server_name on; proxy_set_header Accept-Encoding "";
        sub_filter "</head>" "<meta name='referrer' content='no-referrer'></head>";
        sub_filter "$h" "$d"; sub_filter "https://$h" "https://$d"; sub_filter "http://$h" "https://$d";
EOF
    while true; do
        read -p "外部资源URL(回车跳过): " ext; [ -z "$ext" ] && break
        ext=$(normalize_url "$ext"); eh=$(echo "$ext" | awk -F/ '{print $3}'); k="_res_$(date +%s%N)"
        echo ">>> $eh -> $d/$k/"
        cat >> "$f" <<EOF
        sub_filter "$eh" "$d/$k"; sub_filter "https://$eh" "https://$d/$k";
EOF
        cat >> "$f.loc" <<EOF
    location /$k/ { rewrite ^/$k/(.*) /\$1 break; proxy_pass $ext; proxy_set_header Host $eh; proxy_set_header Referer $ext; proxy_ssl_server_name on; proxy_set_header Accept-Encoding ""; }
EOF
    done
    cat >> "$f" <<EOF
        sub_filter_once off; sub_filter_types *; }
EOF
    [ -f "$f.loc" ] && cat "$f.loc" >> "$f" && rm "$f.loc"
    echo "}" >> "$f"
}

function create_proxy() {
    read -p "1. 主域名: " d; d=$(validate_and_sanitize_domain "$d") || return
    read -p "2. 邮箱: " e; e=${e:-admin@$d}
    sdir="$SITES_DIR/$d"; mkdir -p "$sdir"
    read -p "目标URL: " tu; tu=$(normalize_url "$tu")
    generate_nginx_conf "$tu" "$d"
    cat > "$sdir/docker-compose.yml" <<EOF
services:
  proxy: {image: nginx:alpine, container_name: ${d//./_}_worker, restart: always, volumes: [./nginx-proxy.conf:/etc/nginx/conf.d/default.conf], extra_hosts: ["host.docker.internal:host-gateway"], environment: {VIRTUAL_HOST: "$d", LETSENCRYPT_HOST: "$d", LETSENCRYPT_EMAIL: "$e"}, networks: [proxy-net]}
networks: {proxy-net: {external: true}}
EOF
    cd "$sdir" && docker compose up -d >/dev/null 2>&1; check_ssl_status "$d"
}

function repair_proxy() {
    ls -1 "$SITES_DIR"; read -p "修复域名: " d; sdir="$SITES_DIR/$d"; [ ! -d "$sdir" ] && return
    read -p "目标URL: " tu; tu=$(normalize_url "$tu")
    generate_nginx_conf "$tu" "$d"
    cd "$sdir" && docker compose restart >/dev/null 2>&1; echo "完成"; read -p "..."
}

function create_redirect() {
    read -p "源域名: " s; s=$(validate_and_sanitize_domain "$s") || return
    read -p "目标: " t; t=$(normalize_url "$t"); e="admin@$s"
    sdir="$SITES_DIR/$s"; mkdir -p "$sdir"
    echo "server { listen 80; server_name localhost; location / { return 301 $t\$request_uri; } }" > "$sdir/redirect.conf"
    cat > "$sdir/docker-compose.yml" <<EOF
services: {redirector: {image: nginx:alpine, container_name: ${s//./_}_redirect, restart: always, volumes: [./redirect.conf:/etc/nginx/conf.d/default.conf], environment: {VIRTUAL_HOST: "$s", LETSENCRYPT_HOST: "$s", LETSENCRYPT_EMAIL: "$e"}, networks: [proxy-net]}}
networks: {proxy-net: {external: true}}
EOF
    cd "$sdir" && docker compose up -d >/dev/null 2>&1; check_ssl_status "$s"
}

function container_ops() {
    clear; echo "=== 容器管理 ==="
    echo "1. 全部重启  2. 指定重启  0. 返回"
    read -p "选: " c
    case $c in
        1) cd "$GATEWAY_DIR" && docker compose restart >/dev/null 2>&1; for d in "$SITES_DIR"/*; do [ -d "$d" ] && cd "$d" && docker compose restart >/dev/null 2>&1; done; echo "完成";;
        2) ls "$SITES_DIR"; read -p "域名: " d; [ -d "$SITES_DIR/$d" ] && cd "$SITES_DIR/$d" && docker compose restart >/dev/null 2>&1; echo "完成";;
    esac; read -p "..."
}

function ssh_key_manager() {
    clear; echo "1. 导入公钥 0. 返回"; read -p "选: " s; [ "$s" == "1" ] && { mkdir -p /root/.ssh; read -p "Key: " k; echo "$k" >> /root/.ssh/authorized_keys; echo "OK"; }; read -p "..."
}

function manage_firewall() {
    clear; echo "1. 封IP 2. 解封 4. 重载Nginx 0. 返回"; read -p "选: " f; case $f in
        1) read -p "IP: " i; echo "deny $i;" >> "$FW_DIR/blacklist.conf";;
        2) read -p "IP: " i; echo "allow $i;" >> "$FW_DIR/whitelist.conf";;
        4) docker exec gateway_proxy nginx -s reload;;
    esac; read -p "..."
}

function db_manager() {
    clear; echo "1. 导出 2. 导入 0. 返回"; read -p "选: " c; case $c in
        1) ls "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; p=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml"|awk -F': ' '{print $2}'); docker compose -f "$s/docker-compose.yml" exec -T db mysqldump -u root -p"$p" --all-databases > "$s/$d.sql"; echo "OK";;
        2) ls "$SITES_DIR"; read -p "域名: " d; read -p "SQL: " f; s="$SITES_DIR/$d"; p=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml"|awk -F': ' '{print $2}'); cat "$f" | docker compose -f "$s/docker-compose.yml" exec -T db mysql -u root -p"$p"; echo "OK";;
    esac; read -p "..."
}

function backup_restore_ops() {
    clear; echo "1. 备份 2. 还原 0. 返回"; read -p "选: " b; case $b in
        1) ls "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; bk="$s/backups/$(date +%Y%m%d)"; mkdir -p "$bk"; cp "$s/docker-compose.yml" "$bk/"; echo "备份至 $bk";;
        2) ls "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; ls "$s/backups"; read -p "备份名: " n; cp "$s/backups/$n/docker-compose.yml" "$s/"; echo "还原完成";;
    esac; read -p "..."
}

function manage_hotlink() {
    ls "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; [ -f "$s/nginx.conf" ] && {
        read -p "白名单: " w; cat > "$s/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M;
location ~* \.(gif|jpg|png)\$ { valid_referers none blocked server_names $d $w; if (\$invalid_referer) { return 403; } try_files \$uri \$uri/ /index.php?\$args; }
location / { try_files \$uri \$uri/ /index.php?\$args; }
location ~ \.php\$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)\$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; } }
EOF
        cd "$s" && docker compose restart nginx; echo "防盗链已设置";
    }; read -p "..."
}

function list_sites() { ls -1 "$SITES_DIR"; read -p "..."; }
function delete_site() { ls -1 "$SITES_DIR"; read -p "删除域名: " d; cd "$SITES_DIR/$d" && docker compose down -v; rm -rf "$SITES_DIR/$d"; echo "已删除"; read -p "..."; }
function change_domain() { read -p "旧域名: " o; read -p "新域名: " n; mv "$SITES_DIR/$o" "$SITES_DIR/$n"; cd "$SITES_DIR/$n"; sed -i "s/$o/$n/g" docker-compose.yml; docker compose up -d; echo "更换完成"; read -p "..."; }

# --- 主程序 ---
log_info "Start"
check_and_install_docker
install_shortcut
create_telegram_config
if ! docker ps --format '{{.Names}}' | grep -q "^gateway_proxy$"; then init_gateway "auto"; fi
while true; do show_menu; case $option in 1) init_gateway "force";; 2) container_ops;; 3) ssh_key_manager;; 4) create_site;; 5) create_proxy;; 6) create_redirect;; 7) list_sites;; 8) delete_site;; 9) change_domain;; 10) repair_proxy;; 11) fix_upload_limit;; 12) manage_firewall;; 13) enhanced_cert_management;; 14) manage_hotlink;; 15) db_manager;; 16) backup_restore_ops;; 17) uninstall_cluster;; 18) cert_status_dashboard;; 19) setup_cert_monitoring;; 0) exit 0;; esac; done
