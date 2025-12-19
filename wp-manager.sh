#!/bin/bash

# ================= 1. 配置区域 =================
# 脚本版本号
VERSION="V12 稳定终极版 (快捷指令: web)"

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

# [新增] 强制 Root 检查
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

# 校验域名格式
function validate_domain() {
    local domain=$1
    if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        echo -e "${RED}❌ 错误: 域名格式不正确 (请勿包含 http:// 或特殊字符)${NC}"
        return 1
    fi
    return 0
}

# 检查端口占用
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
        if [ -f /etc/debian_version ]; then 
            apt-get update && apt-get install -y jq openssl net-tools ufw
        else 
            yum install -y jq openssl net-tools firewalld
        fi
        if ! command -v docker >/dev/null 2>&1; then
            curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun
            systemctl enable docker && systemctl start docker
        fi
    fi
}

function check_ssl_status() {
    local d=$1; echo -e "${CYAN}>>> [SSL] 正在申请证书...${NC}"; for ((i=1; i<=20; i++)); do if docker exec gateway_acme test -f "/etc/nginx/certs/$d.crt"; then echo -e "${GREEN}✔ SSL 成功: https://$d${NC}"; pause_prompt; return 0; fi; echo -n "."; sleep 5; done; echo -e "\n${YELLOW}⚠️ 证书暂未生成 (可能是DNS延迟，请稍后刷新)${NC}"; pause_prompt;
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

# ================= 4. 业务逻辑函数 =================

# [V11增强] 初始化/修复网关
function init_gateway() { 
    local m=$1
    if ! docker network ls|grep -q proxy-net; then docker network create proxy-net >/dev/null; fi
    mkdir -p "$GATEWAY_DIR"; cd "$GATEWAY_DIR"
    if [ ! -f "upload_size.conf" ]; then
        echo "client_max_body_size 1024m; proxy_read_timeout 600s; proxy_send_timeout 600s;" > upload_size.conf
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
        echo -e "${RED}✘ 网关启动失败，请检查端口 80/443 是否被占用${NC}"; [ "$m" == "force" ] && docker compose up -d
    fi 
}

# [V11增强] 初始化应用商店
function init_library() {
    mkdir -p "$LIB_DIR"
    
    # --- Uptime Kuma ---
    mkdir -p "$LIB_DIR/uptime-kuma"
    if [ ! -f "$LIB_DIR/uptime-kuma/docker-compose.yml" ]; then
        echo "Uptime Kuma 监控" > "$LIB_DIR/uptime-kuma/name.txt"; echo "3001" > "$LIB_DIR/uptime-kuma/port.txt" 
        cat > "$LIB_DIR/uptime-kuma/docker-compose.yml" <<EOF
services:
  uptime-kuma: {image: louislam/uptime-kuma:1, container_name: {{APP_ID}}_kuma, restart: always, volumes: [./data:/app/data, /var/run/docker.sock:/var/run/docker.sock:ro], environment: [VIRTUAL_HOST={{DOMAIN}}, LETSENCRYPT_HOST={{DOMAIN}}, LETSENCRYPT_EMAIL={{EMAIL}}, VIRTUAL_PORT=3001], networks: [proxy-net]}
networks: {proxy-net: {external: true}}
EOF
    fi

    # --- Alist ---
    mkdir -p "$LIB_DIR/alist"
    if [ ! -f "$LIB_DIR/alist/docker-compose.yml" ]; then
        echo "Alist 网盘程序" > "$LIB_DIR/alist/name.txt"; echo "5244" > "$LIB_DIR/alist/port.txt"
        cat > "$LIB_DIR/alist/docker-compose.yml" <<EOF
services:
  alist: {image: xhofe/alist:latest, container_name: {{APP_ID}}_alist, restart: always, volumes: [./data:/opt/alist/data], environment: [VIRTUAL_HOST={{DOMAIN}}, LETSENCRYPT_HOST={{DOMAIN}}, LETSENCRYPT_EMAIL={{EMAIL}}, VIRTUAL_PORT=5244], networks: [proxy-net]}
networks: {proxy-net: {external: true}}
EOF
    fi

    # --- OpenList (你新加的) ---
    mkdir -p "$LIB_DIR/openlist"
    if [ ! -f "$LIB_DIR/openlist/docker-compose.yml" ]; then
        echo "OpenList 目录列表" > "$LIB_DIR/openlist/name.txt"; echo "5244" > "$LIB_DIR/openlist/port.txt" 
        cat > "$LIB_DIR/openlist/docker-compose.yml" <<EOF
services:
  openlist:
    image: openlistteam/openlist:latest
    container_name: {{APP_ID}}_openlist
    user: '0:0'
    restart: unless-stopped
    volumes: [./data:/opt/openlist/data]
    ports: ["{{HOST_PORT}}:5244"]
    environment: [UMASK=022, VIRTUAL_HOST={{DOMAIN}}, LETSENCRYPT_HOST={{DOMAIN}}, LETSENCRYPT_EMAIL={{EMAIL}}, VIRTUAL_PORT=5244]
    networks: [proxy-net]
networks: {proxy-net: {external: true}}
EOF
    fi
}

function install_app() {
    init_library
    clear; echo -e "${YELLOW}=== 📦 Docker 应用商店 ===${NC}"
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
    
    while true; do
        read -p "宿主机端口 (默认 $DEFAULT_PORT): " input_port
        HOST_PORT=${input_port:-$DEFAULT_PORT}
        if is_port_free "$HOST_PORT"; then break; else echo -e "${RED}端口 $HOST_PORT 已被占用！${NC}"; fi
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

# [V12修复] 安全删除
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

# [V12修复] 列表增强
function list_sites() {
    clear; echo -e "${YELLOW}=== 📂 站点列表 ===${NC}"
    if [ ! -d "$SITES_DIR" ] || [ -z "$(ls -A "$SITES_DIR")" ]; then echo -e "${RED}无站点${NC}"; pause_prompt; return; fi
    printf "${CYAN}%-25s %-15s %-15s${NC}\n" "域名" "类型" "状态"
    echo "--------------------------------------------------------"
    for site_path in "$SITES_DIR"/*; do
        if [ -d "$site_path" ]; then
            domain=$(basename "$site_path"); dc="$site_path/docker-compose.yml"
            app_type="未知"
            if [ -f "$dc" ]; then
                if grep -q "image: .*wordpress" "$dc"; then app_type="WordPress";
                elif grep -q "image: .*alist" "$dc"; then app_type="Alist";
                elif grep -q "image: .*openlist" "$dc"; then app_type="OpenList";
                elif grep -q "proxy_pass" "$site_path/nginx-proxy.conf" 2>/dev/null; then app_type="反代"; fi
            fi
            site_id=${domain//./_}
            if docker ps --format '{{.Names}}' | grep -q "$site_id"; then st="${GREEN}Running${NC}"; else st="${RED}Stopped${NC}"; fi
            printf "%-25s %-15s %-15s\n" "$domain" "$app_type" "$st"
        fi
    done
    echo "--------------------------------------------------------"
    pause_prompt
}

# [V12修复] 备份安全检查 (防止空备份)
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
                if [ -z "$pwd" ]; then echo "非数据库站点，仅备份文件..."; touch "$bd/db.sql"; else
                    echo -e "${CYAN}正在导出数据库...${NC}"
                    # 关键修复: 检查导出是否成功
                    if ! docker compose exec -T db mysqldump -u root -p"$pwd" --all-databases > "$bd/db.sql"; then
                        echo -e "${RED}❌ 数据库导出失败！容器可能未运行或密码错误。备份已终止。${NC}"
                        rm -rf "$bd"; pause_prompt; continue
                    fi
                    # 检查文件大小
                    if [ ! -s "$bd/db.sql" ]; then
                         echo -e "${RED}❌ 导出的数据库文件为空！备份已终止。${NC}"
                         rm -rf "$bd"; pause_prompt; continue
                    fi
                fi
                echo -e "${CYAN}正在打包文件...${NC}"
                wp_c=$(docker compose ps -q wordpress 2>/dev/null)
                if [ ! -z "$wp_c" ]; then
                    docker run --rm --volumes-from $wp_c -v "$bd":/backup alpine tar czf /backup/files.tar.gz /var/www/html/wp-content
                else
                    tar czf "$bd/files.tar.gz" .
                fi
                cp *.conf docker-compose.yml "$bd/" 2>/dev/null
                echo "✅ 备份成功: $bd"; write_log "Backup $d"; pause_prompt;; 
            2) 
                ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; bd="$s/backups"; [ ! -d "$bd" ] && echo "无备份" && pause_prompt && continue
                lt=$(ls -t "$bd"|head -1); echo "最新: $lt"; read -p "使用最新? (y/n): " u; [ "$u" == "y" ] && n="$lt" || { ls -1 "$bd"; read -p "输入目录名: " n; }
                bp="$bd/$n"; [ ! -d "$bp" ] && continue
                echo -e "${RED}⚠️  警告: 将覆盖数据${NC}"; read -p "确认? (yes/no): " c; [ "$c" != "yes" ] && continue
                cd "$s" && docker compose down
                vol=$(docker volume ls -q|grep "${d//./_}_wp_data")
                if [ ! -z "$vol" ]; then docker run --rm -v $vol:/var/www/html -v "$bp":/backup alpine tar xzf /backup/files.tar.gz -C /; fi
                docker compose up -d db; echo "等待DB启动..."; sleep 15
                pwd=$(grep MYSQL_ROOT_PASSWORD docker-compose.yml|awk -F': ' '{print $2}')
                if [ ! -z "$pwd" ] && [ -f "$bp/db.sql" ]; then docker compose exec -T db mysql -u root -p"$pwd" < "$bp/db.sql"; fi
                docker compose up -d; echo "✅ 还原完成"; pause_prompt;; 
        esac
    done 
}

# 其他保持不变但解压的函数
function create_site() {
    read -p "1. 域名: " fd; validate_domain "$fd" || return
    host_ip=$(curl -s4 ifconfig.me)
    if command -v dig >/dev/null; then dip=$(dig +short $fd|head -1); fi
    if [ ! -z "$dip" ] && [ "$dip" != "$host_ip" ]; then echo -e "${RED}⚠️ IP不一致: DNS=$dip 本机=$host_ip${NC}"; read -p "继续? (y/n): " f; [ "$f" != "y" ] && return; fi
    read -p "2. 邮箱: " email; read -p "3. DB密码: " db_pass
    echo -e "${YELLOW}自定义版本? (y/n)${NC}"; read -p "> " cust
    pt="php8.2-fpm-alpine"; di="mysql:8.0"; rt="7.0-alpine"
    if [ "$cust" == "y" ]; then 
        echo "PHP: 1.7.4 2.8.0 3.8.1 4.8.2"; read -p "选: " p; case $p in 1) pt="php7.4-fpm-alpine";; 2) pt="php8.0-fpm-alpine";; 3) pt="php8.1-fpm-alpine";; 4) pt="php8.2-fpm-alpine";; esac
        echo "DB: 1.M5.7 2.M8.0"; read -p "选: " d; case $d in 1) di="mysql:5.7";; 2) di="mysql:8.0";; esac
    fi
    pname=$(echo $fd|tr '.' '_'); sdir="$SITES_DIR/$fd"; [ -d "$sdir" ] && return; mkdir -p "$sdir"
    cat > "$sdir/waf.conf" <<EOF
location ~* /\.(git|env|sql) { deny all; return 403; }
EOF
    cat > "$sdir/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M; location / { try_files \$uri \$uri/ /index.php?\$args; } location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } }
EOF
    cat > "$sdir/uploads.ini" <<EOF
file_uploads = On; memory_limit = 512M; upload_max_filesize = 512M; post_max_size = 512M; max_execution_time = 600;
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
    if [ "$t" == "2" ]; then read -p "IP: " ip; [ -z "$ip" ] && ip="127.0.0.1"; read -p "端口: " p; tu="http://$ip:$p"; pm="2"
    else read -p "URL: " tu; tu=$(normalize_url "$tu"); echo "1.镜像 2.代理"; read -p "模式: " pm; [ -z "$pm" ] && pm="1"; fi
    
    # 简化版生成配置，避免复杂字符错误
    f="$sdir/nginx-proxy.conf"; echo "server { listen 80; server_name localhost; location / { proxy_pass $tu; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_ssl_server_name on; } }" > "$f"
    
    cat > "$sdir/docker-compose.yml" <<EOF
services:
  proxy: {image: nginx:alpine, container_name: ${d//./_}_worker, restart: always, volumes: [./nginx-proxy.conf:/etc/nginx/conf.d/default.conf], environment: {VIRTUAL_HOST: "$fd", LETSENCRYPT_HOST: "$fd", LETSENCRYPT_EMAIL: "$e"}, networks: [proxy-net]}
networks: {proxy-net: {external: true}}
EOF
    cd "$sdir" && docker compose up -d; check_ssl_status "$d";
}

function component_manager() { 
    clear; echo -e "${YELLOW}=== 组件升级 (慎用) ===${NC}"
    echo -e "${RED}警告: 数据库跨版本升级(如5.7->8.0)可能导致数据损坏，请先备份！${NC}"
    ls -1 "$SITES_DIR"; read -p "域名 (0返回): " d; [ "$d" == "0" ] && return
    sdir="$SITES_DIR/$d"; [ ! -f "$sdir/docker-compose.yml" ] && return
    echo "1. PHP版本  2. Redis版本"; read -p "选: " op
    case $op in
        1) echo "1.PHP7.4 2.PHP8.0 3.PHP8.2"; read -p "选: " p; case $p in 1) t="php7.4-fpm-alpine";; 2) t="php8.0-fpm-alpine";; 3) t="php8.2-fpm-alpine";; esac; 
           sed -i "s|image: wordpress:.*|image: wordpress:$t|g" "$sdir/docker-compose.yml"; cd "$sdir" && docker compose up -d; echo "已更新PHP";;
        2) echo "1.Redis6 2.Redis7"; read -p "选: " r; case $r in 1) rt="6.2-alpine";; 2) rt="7.0-alpine";; esac;
           sed -i "s|image: redis:.*|image: redis:$rt|g" "$sdir/docker-compose.yml"; cd "$sdir" && docker compose up -d; echo "已更新Redis";;
    esac; pause_prompt
}

# 简化的辅助菜单
function container_ops() { cd "$GATEWAY_DIR" && docker compose ps; echo "---"; for d in "$SITES_DIR"/*; do cd "$d" && docker compose ps; done; pause_prompt; }
function wp_toolbox() { echo "请使用 docker exec -it 容器名 /bin/bash 进入容器操作"; pause_prompt; }
function security_center() { echo "请确保 ufw/firewalld 已开启，并放行 80/443/22"; pause_prompt; }
function uninstall_cluster() { echo "⚠️ 危险: 输入 DELETE 确认"; read -p "> " c; [ "$c" == "DELETE" ] && (ls "$SITES_DIR"|while read d; do cd "$SITES_DIR/$d" && docker compose down -v; done; cd "$GATEWAY_DIR" && docker compose down -v; docker network rm proxy-net; rm -rf "$BASE_DIR" /usr/bin/web; echo "已卸载"); }

# ================= 5. 主菜单 =================
function show_menu() {
    clear; echo -e "${GREEN}=== Docker Web Manager ($VERSION) ===${NC}"
    echo " 1. [建站] WordPress"
    echo " 2. [建站] 反向代理"
    echo " 3. [建站] 应用商店 (Alist/OpenList/Kuma)"
    echo " 4. [运维] 站点列表 (状态监控)"
    echo " 5. [运维] 删除站点 (安全模式)"
    echo " 6. [运维] 备份与还原 (防空包)"
    echo " 7. [运维] 组件升级 (PHP/Redis)"
    echo " 8. [系统] 修复网关"
    echo " 9. [系统] 卸载脚本"
    echo " 0. 退出"
    read -p "请选择: " option
}

check_dependencies
install_shortcut
if ! docker ps --format '{{.Names}}' | grep -q "^gateway_proxy$"; then echo "初始化网关..."; init_gateway "auto"; fi

while true; do 
    show_menu 
    case $option in 
        1) create_site;; 
        2) create_proxy;; 
        3) install_app;;
        4) list_sites;; 
        5) delete_site;; 
        6) backup_restore_ops;; 
        7) component_manager;; 
        8) init_gateway "force"; pause_prompt;;
        9) uninstall_cluster;; 
        0) exit 0;; 
    esac
done
