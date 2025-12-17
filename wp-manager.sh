#!/bin/bash

# ================= 1. 全局配置区域 =================
# 脚本版本
VERSION="V11"

# 核心数据存储路径
BASE_DIR="/home/docker/web"

# 子目录定义
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

# ================= 2. 基础工具与依赖 =================

# 确保目录存在并赋予正确权限
function ensure_dir() {
    local dir=$1
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        chmod 755 "$dir"
    fi
}

# 写入日志
function write_log() {
    ensure_dir "$BASE_DIR"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# 暂停提示
function pause_prompt() {
    echo -e "\n${YELLOW}>>> 操作完成，按回车键返回...${NC}"
    read -r
}

# 安装快捷指令 'web'
function install_shortcut() {
    local script_path=$(readlink -f "$0")
    if [ ! -L "/usr/bin/web" ] || [ "$(readlink -f "/usr/bin/web")" != "$script_path" ]; then
        ln -sf "$script_path" /usr/bin/web && chmod +x "$script_path"
        echo -e "${GREEN}>>> 快捷指令 'web' 已安装 (输入 web 即可启动)${NC}"
    fi
}

# 检查系统依赖
function check_dependencies() {
    # 检查 jq
    if ! command -v jq >/dev/null 2>&1; then
        echo "正在安装 jq..."
        if [ -f /etc/debian_version ]; then apt-get update && apt-get install -y jq; else yum install -y jq; fi
    fi
    # 检查 openssl
    if ! command -v openssl >/dev/null 2>&1; then
        echo "正在安装 openssl..."
        if [ -f /etc/debian_version ]; then apt-get install -y openssl; else yum install -y openssl; fi
    fi
    # 检查 netstat
    if ! command -v netstat >/dev/null 2>&1; then
        echo "正在安装 net-tools..."
        if [ -f /etc/debian_version ]; then apt-get install -y net-tools; else yum install -y net-tools; fi
    fi
    # 检查 Docker
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${YELLOW}>>> 正在安装 Docker...${NC}"
        curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun
        systemctl enable docker && systemctl start docker
    fi
}

# ================= 3. 核心自愈机制 (关键) =================

# 强制生成 PHP 上传配置 (解决 2M 限制)
function generate_uploads_ini() {
    local target_dir=$1
    ensure_dir "$target_dir"
    cat > "$target_dir/uploads.ini" <<EOF
file_uploads=On
memory_limit=512M
upload_max_filesize=512M
post_max_size=512M
max_execution_time=600
EOF
    chmod 644 "$target_dir/uploads.ini"
}

# 强制生成网关配置 (解决网关启动失败)
function generate_gateway_config() {
    ensure_dir "$GATEWAY_DIR"
    
    # Nginx 核心配置
    cat > "$GATEWAY_DIR/upload_size.conf" <<EOF
client_max_body_size 1024m;
proxy_read_timeout 600s;
proxy_send_timeout 600s;
EOF
    chmod 644 "$GATEWAY_DIR/upload_size.conf"
    
    # 确保防火墙配置文件存在（防止挂载失败）
    ensure_dir "$FW_DIR"
    touch "$FW_DIR/access.conf" "$FW_DIR/geo.conf"
}

# 初始化/自愈网关
function init_gateway() { 
    local mode=$1
    
    # 1. 强制刷新配置
    generate_gateway_config 
    
    # 2. 确保网络存在
    if ! docker network ls | grep -q proxy-net; then 
        docker network create proxy-net >/dev/null
    fi

    # 3. 生成 docker-compose.yml
    if [ ! -f "$GATEWAY_DIR/docker-compose.yml" ]; then
        cat > "$GATEWAY_DIR/docker-compose.yml" <<EOF
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
    fi

    # 4. 状态检查与启动
    cd "$GATEWAY_DIR"
    if ! docker compose ps --services --filter "status=running" | grep -q nginx-proxy; then
        if [ "$mode" == "auto" ]; then
             docker compose up -d >/dev/null 2>&1
        else
             echo -e "${YELLOW}>>> 检测到网关未运行，正在自愈启动...${NC}"
             docker compose up -d
        fi
    fi
}
# ================= 4. 业务功能模块 =================

# SSL 证书状态检查
function check_ssl_status() {
    local d=$1
    echo -e "${CYAN}>>> [SSL] 正在请求证书，请稍候...${NC}"
    for ((i=1; i<=20; i++)); do 
        if docker exec gateway_acme test -f "/etc/nginx/certs/$d.crt"; then 
            echo -e "${GREEN}✔ SSL 证书获取成功: https://$d${NC}"
            pause_prompt
            return 0
        fi
        echo -n "."
        sleep 5
    done
    echo -e "\n${YELLOW}⚠️ 证书尚未生成，请稍后刷新浏览器检查。${NC}"
    pause_prompt
}

# 创建 WordPress 站点
function create_site() {
    echo -e "${YELLOW}=== 创建 WordPress 站点 ===${NC}"
    read -p "1. 输入域名 (例如 blog.com): " fd
    
    # 简单的 IP 检查
    host_ip=$(curl -s4 ifconfig.me)
    if command -v dig >/dev/null; then 
        dip=$(dig +short $fd | head -1)
    else 
        dip=$(getent hosts $fd | awk '{print $1}')
    fi
    
    if [ ! -z "$dip" ] && [ "$dip" != "$host_ip" ]; then 
        echo -e "${RED}警告: 域名解析IP ($dip) 与本机IP ($host_ip) 不一致！${NC}"
        read -p "是否继续? (y/n): " f
        [ "$f" != "y" ] && return
    fi

    read -p "2. 管理员邮箱 (用于SSL): " email
    read -p "3. 数据库密码: " db_pass
    
    # 版本选择
    echo -e "${YELLOW}是否自定义版本? (默认: PHP8.2 / MySQL8.0 / Redis7)${NC}"
    read -p "输入 y 自定义，直接回车默认: " cust
    pt="php8.2-fpm-alpine"; di="mysql:8.0"; rt="7.0-alpine"
    
    if [ "$cust" == "y" ]; then 
        echo "PHP版本: 1.7.4  2.8.0  3.8.1  4.8.2  5.最新"
        read -p "选择: " p
        case $p in 1) pt="php7.4-fpm-alpine";; 2) pt="php8.0-fpm-alpine";; 3) pt="php8.1-fpm-alpine";; 4) pt="php8.2-fpm-alpine";; 5) pt="fpm-alpine";; esac
        
        echo "数据库: 1.MySQL5.7  2.MySQL8.0  3.MariaDB10.6"
        read -p "选择: " d
        case $d in 1) di="mysql:5.7";; 2) di="mysql:8.0";; 3) di="mariadb:10.6";; esac
    fi
    
    # 准备目录
    pname=$(echo $fd | tr '.' '_')
    sdir="$SITES_DIR/$fd"
    ensure_dir "$sdir"
    
    # 生成核心配置 (利用自愈函数)
    generate_uploads_ini "$sdir"

    # 生成 WAF 配置
    cat > "$sdir/waf.conf" <<EOF
location ~* /\.(git|env|sql) { deny all; return 403; }
EOF

    # 生成 Nginx 配置
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
    
    # 生成 Docker Compose
    cat > "$sdir/docker-compose.yml" <<EOF
services:
  db:
    image: $di
    container_name: ${pname}_db
    restart: always
    logging: {driver: "json-file", options: {max-size: "10m", max-file: "3"}}
    environment:
      MYSQL_ROOT_PASSWORD: $db_pass
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wp_user
      MYSQL_PASSWORD: $db_pass
    volumes:
      - db_data:/var/lib/mysql
    networks: [default]

  redis:
    image: redis:$rt
    container_name: ${pname}_redis
    restart: always
    logging: {driver: "json-file", options: {max-size: "10m", max-file: "3"}}
    networks: [default]

  wordpress:
    image: wordpress:$pt
    container_name: ${pname}_app
    restart: always
    logging: {driver: "json-file", options: {max-size: "10m", max-file: "3"}}
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
    logging: {driver: "json-file", options: {max-size: "10m", max-file: "3"}}
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

    # 启动
    cd "$sdir" && docker compose up -d
    check_ssl_status "$fd"
    write_log "Created site $fd"
}

# 创建反向代理
function create_proxy() {
    echo -e "${YELLOW}=== 创建反向代理 ===${NC}"
    read -p "1. 绑定域名: " d
    read -p "2. 邮箱: " e
    
    sdir="$SITES_DIR/$d"
    ensure_dir "$sdir"
    
    echo -e "1. 反代 URL (例如 https://google.com)"
    echo -e "2. 反代 IP:端口 (例如 127.0.0.1:8080)"
    read -p "选择类型: " t
    
    if [ "$t" == "2" ]; then 
        read -p "输入目标 IP: " ip
        [ -z "$ip" ] && ip="127.0.0.1"
        read -p "输入目标端口: " p
        tu="http://$ip:$p"
        # IP模式通常是反代本地服务，不需要修改 Host 头
        proxy_mode="simple" 
    else 
        read -p "输入目标 URL: " tu
        # URL模式可能需要镜像
        echo "1. 镜像模式 (修改内容/Host，用于反代 Google 等)"
        echo "2. 普通代理 (透传 Host)"
        read -p "选择模式: " pm
        [ -z "$pm" ] && pm="1"
        proxy_mode="$pm"
    fi
    
    # 生成 Nginx 配置 (此处保留精简逻辑，核心在于配置文件生成)
    f="$sdir/nginx-proxy.conf"
    echo "server { listen 80; server_name localhost; resolver 1.1.1.1; location / {" > "$f"
    
    if [ "$proxy_mode" == "2" ] || [ "$t" == "2" ]; then
        # 普通代理
        echo "proxy_pass $tu; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_ssl_server_name on;" >> "$f"
    else
        # 镜像模式
        target_host=$(echo $tu | awk -F/ '{print $3}')
        echo "proxy_pass $tu; proxy_set_header Host $target_host; proxy_set_header Referer $tu; proxy_ssl_server_name on; proxy_set_header Accept-Encoding \"\";" >> "$f"
        echo "sub_filter \"$target_host\" \"$d\"; sub_filter_once off; sub_filter_types *;" >> "$f"
    fi
    echo "}}" >> "$f"

    # 生成 Docker Compose
    cat > "$sdir/docker-compose.yml" <<EOF
services:
  proxy:
    image: nginx:alpine
    container_name: ${d//./_}_worker
    restart: always
    logging: {driver: "json-file", options: {max-size: "10m", max-file: "3"}}
    volumes:
      - ./nginx-proxy.conf:/etc/nginx/conf.d/default.conf
    extra_hosts:
      - "host.docker.internal:host-gateway"
    environment:
      VIRTUAL_HOST: "$d"
      LETSENCRYPT_HOST: "$d"
      LETSENCRYPT_EMAIL: "$e"
    networks: [proxy-net]
networks: {proxy-net: {external: true}}
EOF
    cd "$sdir" && docker compose up -d
    check_ssl_status "$d"
    write_log "Created proxy $d"
}

# 容器运维中心
function container_ops() { 
    while true; do 
        clear
        echo -e "${YELLOW}=== 📊 容器状态监控 ===${NC}"
        
        echo -e "【核心网关】"
        cd "$GATEWAY_DIR" && docker compose ps --format "table {{.Service}}\t{{.State}}\t{{.Status}}" | tail -n +2
        
        echo "----------------------------------------"
        for d in "$SITES_DIR"/*; do 
            if [ -d "$d" ]; then
                echo -e "【站点: $(basename "$d")】"
                cd "$d" && docker compose ps --all --format "table {{.Service}}\t{{.State}}\t{{.Status}}" | tail -n +2
            fi
        done
        
        echo "----------------------------------------"
        echo " 1. 全部启动 (Start All)"
        echo " 2. 全部停止 (Stop All)"
        echo " 3. 全部重启 (Restart All)"
        echo " 4. 操作指定站点"
        echo " 0. 返回上一级"
        read -p "请选择: " c
        
        case $c in 
            0) return;; 
            1) cd "$GATEWAY_DIR" && docker compose up -d; for d in "$SITES_DIR"/*; do cd "$d" && docker compose up -d; done;; 
            2) for d in "$SITES_DIR"/*; do cd "$d" && docker compose stop; done; cd "$GATEWAY_DIR" && docker compose stop;; 
            3) cd "$GATEWAY_DIR" && docker compose restart; for d in "$SITES_DIR"/*; do cd "$d" && docker compose restart; done;; 
            4) ls -1 "$SITES_DIR"; read -p "输入域名: " d; cd "$SITES_DIR/$d" && docker compose restart; pause_prompt;; 
        esac
    done 
}

# WP-CLI 瑞士军刀
function wp_toolbox() {
    while true; do
        clear
        echo -e "${YELLOW}=== 🛠️ WP-CLI 瑞士军刀 ===${NC}"
        ls -1 "$SITES_DIR"
        echo "--------------------------"
        read -p "请输入要操作的域名 (0返回): " d; [ "$d" == "0" ] && return
        
        sdir="$SITES_DIR/$d"
        if [ ! -d "$sdir" ]; then echo "目录不存在"; sleep 1; continue; fi
        
        # 获取容器名
        container_name=$(grep "container_name: .*_app" "$sdir/docker-compose.yml" | awk '{print $2}')
        echo -e "当前站点: $d | 容器名: $container_name"
        
        echo " 1. 重置管理员密码"
        echo " 2. 列出所有插件"
        echo " 3. 禁用所有插件 (救砖)"
        echo " 4. 清理对象缓存"
        echo " 5. 修复文件权限 (chown)"
        echo " 6. 搜索并替换域名"
        read -p "选择操作: " op
        
        case $op in
            1) read -p "输入新密码: " newpass; docker exec -u www-data "$container_name" wp user update admin --user_pass="$newpass";;
            2) docker exec -u www-data "$container_name" wp plugin list;;
            3) docker exec -u www-data "$container_name" wp plugin deactivate --all;;
            4) docker exec -u www-data "$container_name" wp cache flush;;
            5) echo "正在修复权限..."; docker compose -f "$sdir/docker-compose.yml" exec -T -u root wordpress chown -R www-data:www-data /var/www/html;;
            6) read -p "旧域名: " old_d; read -p "新域名: " new_d; docker exec -u www-data "$container_name" wp search-replace "$old_d" "$new_d" --all-tables;;
        esac
        pause_prompt
    done
}
# ================= 补充：工具与运维函数 =================

# 生成 Nginx 反代配置的辅助函数
function generate_nginx_conf() {
    local u=$1
    local d=$2
    local m=$3
    local f="$SITES_DIR/$d/nginx-proxy.conf"
    
    echo "server { listen 80; server_name localhost; resolver 1.1.1.1; location / {" > "$f"
    
    if [ "$m" == "2" ]; then
        # 普通代理模式
        echo "proxy_pass $u; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_ssl_server_name on;" >> "$f"
    else
        # 镜像模式
        target_host=$(echo $u | awk -F/ '{print $3}')
        echo "proxy_pass $u; proxy_set_header Host $target_host; proxy_set_header Referer $u; proxy_ssl_server_name on; proxy_set_header Accept-Encoding \"\";" >> "$f"
        echo "sub_filter \"$target_host\" \"$d\"; sub_filter_once off; sub_filter_types *;" >> "$f"
    fi
    echo "}}" >> "$f"
}

# 修复反向代理配置
function repair_proxy() {
    ls -1 "$SITES_DIR"
    read -p "输入要修复的域名: " d
    sdir="$SITES_DIR/$d"
    if [ ! -d "$sdir" ]; then echo "目录不存在"; return; fi
    
    read -p "输入新的目标 URL: " tu
    tu=$(normalize_url "$tu")
    
    generate_nginx_conf "$tu" "$d" "1"
    cd "$sdir" && docker compose restart
    echo "修复完成"
    pause_prompt
}

# 一键修复上传限制 (512M)
function fix_upload_limit() { 
    ls -1 "$SITES_DIR"
    read -p "输入要修复的域名: " d
    s="$SITES_DIR/$d"
    
    # 调用核心自愈函数强制生成配置
    generate_uploads_ini "$s" 
    
    # 修正 Nginx 配置
    if [ -f "$s/nginx.conf" ]; then 
        if ! grep -q "client_max_body_size" "$s/nginx.conf"; then
            sed -i '/server_name/a \    client_max_body_size 512M;' "$s/nginx.conf"
        fi
    fi
    
    cd "$s" && docker compose restart
    echo "修复完成，请刷新 WordPress 后台查看。"
    pause_prompt
}

# 创建域名重定向
function create_redirect() { 
    read -p "源域名 (Source): " s
    read -p "目标 URL (Target): " t
    t=$(normalize_url "$t")
    read -p "邮箱: " e
    
    sdir="$SITES_DIR/$s"
    ensure_dir "$sdir"
    
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
    networks: [proxy-net]
networks: {proxy-net: {external: true}}
EOF
    cd "$sdir" && docker compose up -d
    check_ssl_status "$s"
}

# 列出所有站点
function list_sites() { 
    clear
    echo "=== 📂 站点列表 ==="
    ls -1 "$SITES_DIR"
    echo "----------------"
    pause_prompt
}

# 证书管理
function cert_management() { 
    while true; do 
        clear
        echo "=== HTTPS 证书管理 ==="
        echo " 1. 查看已生成证书"
        echo " 2. 强制重置/删除证书"
        echo " 3. 强制续签所有证书"
        echo " 0. 返回"
        read -p "选择: " c
        case $c in 
            0) return;; 
            1) docker exec gateway_proxy ls -lh /etc/nginx/certs | grep .crt; pause_prompt;; 
            2) 
                read -p "输入域名: " d
                docker exec gateway_acme rm -f "/etc/nginx/certs/$d.crt" "/etc/nginx/certs/$d.key"
                docker restart gateway_acme
                echo "已删除，容器重启后将尝试重新申请"; pause_prompt;; 
            3) docker exec gateway_acme /app/force_renew; echo "请求已发送"; pause_prompt;; 
        esac
    done 
}

# 数据库管理 (导入/导出)
function db_manager() { 
    while true; do 
        clear
        echo "=== 数据库管理 ==="
        echo " 1. 导出 SQL (备份)"
        echo " 2. 导入 SQL (恢复)"
        echo " 0. 返回"
        read -p "选择: " c
        case $c in 
            0) return;; 
            1) 
                ls -1 "$SITES_DIR"
                read -p "输入域名: " d
                s="$SITES_DIR/$d"
                # 获取数据库密码
                if [ -f "$s/docker-compose.yml" ]; then
                    pwd=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml" | awk -F': ' '{print $2}')
                    echo "正在导出..."
                    docker compose -f "$s/docker-compose.yml" exec -T db mysqldump -u root -p"$pwd" --all-databases > "$s/${d}_backup.sql"
                    echo "导出成功: $s/${d}_backup.sql"
                else
                    echo "未找到配置文件"
                fi
                pause_prompt;; 
            2) 
                ls -1 "$SITES_DIR"
                read -p "输入域名: " d
                read -p "SQL 文件全路径: " f
                s="$SITES_DIR/$d"
                if [ -f "$f" ] && [ -f "$s/docker-compose.yml" ]; then
                    pwd=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml" | awk -F': ' '{print $2}')
                    echo "正在导入..."
                    cat "$f" | docker compose -f "$s/docker-compose.yml" exec -T db mysql -u root -p"$pwd"
                    echo "导入完成"
                else
                    echo "文件不存在"
                fi
                pause_prompt;; 
        esac
    done 
}

# 更换域名
function change_domain() { 
    ls -1 "$SITES_DIR"
    read -p "旧域名: " o
    if [ ! -d "$SITES_DIR/$o" ]; then echo "站点不存在"; return; fi
    read -p "新域名: " n
    
    echo "正在停止服务..."
    cd "$SITES_DIR/$o" && docker compose down
    
    echo "重命名目录..."
    cd .. && mv "$o" "$n" && cd "$n"
    
    echo "修改配置..."
    sed -i "s/$o/$n/g" docker-compose.yml
    if [ -f "nginx.conf" ]; then sed -i "s/$o/$n/g" nginx.conf; fi
    
    echo "启动新服务..."
    docker compose up -d
    
    echo "执行数据库替换 (Search-Replace)..."
    wp_c=$(docker compose ps -q wordpress)
    # 等待数据库启动
    sleep 5
    docker run --rm --volumes-from $wp_c --network container:$wp_c wordpress:cli wp search-replace "$o" "$n" --all-tables --skip-columns=guid
    
    echo "完成，请记得检查 DNS 解析。"
    write_log "Changed domain $o to $n"
    pause_prompt 
}

# 防盗链设置
function manage_hotlink() { 
    while true; do 
        clear
        echo "=== 防盗链管理 ==="
        echo " 1. 开启防盗链"
        echo " 2. 关闭防盗链"
        echo " 0. 返回"
        read -p "选择: " h
        case $h in 
            0) return;; 
            1) 
                ls -1 "$SITES_DIR"
                read -p "输入域名: " d
                s="$SITES_DIR/$d"
                read -p "允许的白名单域名 (空格分隔，例如 google.com baidu.com): " w
                
                # 写入带防盗链的配置
                cat > "$s/nginx.conf" <<EOF
server { 
    listen 80; server_name localhost; root /var/www/html; index index.php; 
    include /etc/nginx/waf.conf; client_max_body_size 512M; 
    location ~* \.(gif|jpg|png|webp|jpeg)$ { 
        valid_referers none blocked server_names $d *.$d $w; 
        if (\$invalid_referer) { return 403; } 
        try_files \$uri \$uri/ /index.php?\$args; 
    } 
    location / { try_files \$uri \$uri/ /index.php?\$args; } 
    location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } 
}
EOF
                cd "$s" && docker compose restart nginx
                echo "已开启"; pause_prompt;; 
            2) 
                ls -1 "$SITES_DIR"
                read -p "输入域名: " d
                s="$SITES_DIR/$d"
                # 恢复默认配置
                cat > "$s/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M; location / { try_files \$uri \$uri/ /index.php?\$args; } location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } }
EOF
                cd "$s" && docker compose restart nginx
                echo "已关闭"; pause_prompt;; 
        esac
    done 
}

# 备份与恢复
function backup_restore_ops() { 
    while true; do 
        clear
        echo "=== 备份与恢复 ==="
        echo " 1. 整站备份 (代码+数据库)"
        echo " 2. 整站恢复"
        echo " 0. 返回"
        read -p "选择: " b
        case $b in 
            0) return;; 
            1) 
                ls -1 "$SITES_DIR"
                read -p "输入域名: " d
                s="$SITES_DIR/$d"
                [ ! -d "$s" ] && continue
                
                bd="$s/backups/$(date +%Y%m%d_%H%M)"
                mkdir -p "$bd"
                cd "$s"
                
                echo "备份数据库..."
                pwd=$(grep MYSQL_ROOT_PASSWORD docker-compose.yml | awk -F': ' '{print $2}')
                docker compose exec -T db mysqldump -u root -p"$pwd" --all-databases > "$bd/db.sql"
                
                echo "备份文件..."
                wp_c=$(docker compose ps -q wordpress)
                docker run --rm --volumes-from $wp_c -v "$bd":/backup alpine tar czf /backup/files.tar.gz /var/www/html/wp-content
                
                cp *.conf docker-compose.yml "$bd/"
                echo "✅ 备份完成: $bd"
                write_log "Backup $d"
                pause_prompt;; 
            2) 
                ls -1 "$SITES_DIR"
                read -p "输入域名: " d
                s="$SITES_DIR/$d"
                bd="$s/backups"
                
                if [ ! -d "$bd" ]; then echo "无备份记录"; pause_prompt; continue; fi
                
                echo "可用备份:"
                ls -1 "$bd"
                read -p "输入备份文件夹名称: " n
                bp="$bd/$n"
                [ ! -d "$bp" ] && continue
                
                echo "正在恢复..."
                cd "$s" && docker compose down
                
                # 恢复文件
                vol=$(docker volume ls -q | grep "${d//./_}_wp_data")
                docker run --rm -v $vol:/var/www/html -v "$bp":/backup alpine tar xzf /backup/files.tar.gz -C /
                
                # 恢复数据库
                docker compose up -d db
                echo "等待数据库启动..."
                sleep 15
                pwd=$(grep MYSQL_ROOT_PASSWORD docker-compose.yml | awk -F': ' '{print $2}')
                docker compose exec -T db mysql -u root -p"$pwd" < "$bp/db.sql"
                
                docker compose up -d
                echo "✅ 恢复完成"
                write_log "Restored $d"
                pause_prompt;; 
        esac
    done 
}

# 组件版本管理 (升降级)
function component_manager() { 
    while true; do 
        clear
        echo "=== 组件版本管理 ==="
        ls -1 "$SITES_DIR"
        echo "----------------"
        read -p "输入域名 (0返回): " d
        [ "$d" == "0" ] && return
        sdir="$SITES_DIR/$d"
        
        echo " 1. 切换 PHP 版本 (7.4 / 8.0 / 8.2)"
        echo " 2. 切换 数据库 版本"
        echo " 3. 切换 Nginx 版本"
        read -p "选择: " o
        
        case $o in 
            1) 
                echo "输入版本号 (如 7.4, 8.0, 8.2): " v
                read v
                # 简单的字符串替换
                sed -i "s|image: wordpress:.*|image: wordpress:php$v-fpm-alpine|g" "$sdir/docker-compose.yml"
                ;;
            2)
                echo "输入数据库镜像 (如 mysql:5.7, mariadb:latest): " v
                read v
                sed -i "s|image: .*sql:.*|image: $v|g" "$sdir/docker-compose.yml"
                sed -i "s|image: mariadb:.*|image: $v|g" "$sdir/docker-compose.yml"
                ;;
            3)
                sed -i "s|image: nginx:.*|image: nginx:latest|g" "$sdir/docker-compose.yml"
                ;;
        esac
        
        cd "$sdir" && docker compose up -d
        echo "更新完成"
        pause_prompt
    done 
}

# 简单的日志管理
function log_manager() { 
    while true; do 
        clear
        echo "=== 日志管理 ==="
        echo " 1. 查看操作日志"
        echo " 2. 清空操作日志"
        echo " 0. 返回"
        read -p "选择: " l
        case $l in 
            0) return;; 
            1) tail -n 50 "$LOG_FILE"; pause_prompt;; 
            2) echo "" > "$LOG_FILE"; echo "已清空"; pause_prompt;; 
        esac
    done 
}

# 简单的资源监控
function sys_monitor() { 
    while true; do 
        clear
        echo "=== 系统监控 ==="
        echo "CPU 负载: $(uptime | awk -F'load average:' '{print $2}')"
        echo "内存使用:"
        free -h | grep Mem
        echo "磁盘使用:"
        df -h / | awk 'NR==2'
        echo "----------------"
        echo "按 0 返回，任意键刷新"
        read -t 5 -p "> " o
        [ "$o" == "0" ] && return
    done 
}

# Fail2Ban 管理
function fail2ban_manager() { 
    while true; do 
        clear
        echo "=== Fail2Ban 管理 ==="
        echo " 1. 安装/启动"
        echo " 2. 查看状态 (SSH)"
        echo " 3. 解封 IP"
        echo " 0. 返回"
        read -p "选择: " o
        case $o in 
            0) return;; 
            1) 
                echo "正在安装..."
                if [ -f /etc/debian_version ]; then apt-get install -y fail2ban; else yum install -y fail2ban; fi
                systemctl enable fail2ban && systemctl start fail2ban
                echo "完成"; pause_prompt;; 
            2) fail2ban-client status sshd 2>/dev/null; pause_prompt;; 
            3) read -p "输入要解封的 IP: " i; fail2ban-client set sshd unbanip $i; echo "已执行"; pause_prompt;; 
        esac
    done 
}

# WAF 规则管理
function waf_manager() { 
    while true; do 
        clear
        echo "=== WAF 防火墙 ==="
        echo " 1. 部署/更新 增强规则 (所有站点)"
        echo " 2. 查看当前规则"
        echo " 0. 返回"
        read -p "选择: " o
        case $o in 
            0) return;; 
            1) 
                echo "正在部署..."
                cat >/tmp/w <<EOF
location ~* /\.(git|svn|hg|env|bak|config|sql|db|key|pem|ssh|ftpconfig) { deny all; return 403; }
location ~* \.(sql|bak|conf|ini|log|sh|yaml|yml|swp|install|dist)$ { deny all; return 403; }
if (\$query_string ~* "union.*select.*\(") { return 403; }
if (\$query_string ~* "concat.*\(") { return 403; }
EOF
                for d in "$SITES_DIR"/*; do 
                    if [ -d "$d" ]; then 
                        cp /tmp/w "$d/waf.conf" 
                        cd "$d" && docker compose exec -T nginx nginx -s reload
                        echo "已更新: $(basename "$d")"
                    fi
                done
                pause_prompt;; 
            2) cat "$SITES_DIR/"*"/waf.conf" 2>/dev/null | head -n 10; pause_prompt;; 
        esac
    done 
}

# 流量控制 (ACL)
function traffic_manager() { 
    while true; do 
        clear
        echo "=== 流量控制 (ACL) ==="
        echo " 1. 封禁 IP (黑名单)"
        echo " 2. 放行 IP (白名单)"
        echo " 3. 清空规则"
        echo " 0. 返回"
        read -p "选择: " t
        case $t in 
            0) return;; 
            1|2) 
                tp="deny"; [ "$t" == "2" ] && tp="allow"
                read -p "输入 IP: " i
                echo "$tp $i;" >> "$FW_DIR/access.conf"
                cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload
                echo "已生效"; pause_prompt;; 
            3) echo "" > "$FW_DIR/access.conf"; echo "已清空"; pause_prompt;; 
        esac
    done 
}

# Telegram 管理 (仅配置)
function telegram_manager() { 
    while true; do 
        clear
        echo "=== Telegram 设置 ==="
        echo " 1. 配置 Token 和 ChatID"
        echo " 0. 返回"
        read -p "选择: " t
        case $t in 
            0) return;; 
            1) 
                read -p "Bot Token: " tk
                echo "TG_BOT_TOKEN=\"$tk\"" > "$TG_CONF"
                read -p "Chat ID: " ci
                echo "TG_CHAT_ID=\"$ci\"" >> "$TG_CONF"
                echo "已保存"; pause_prompt;; 
        esac
    done 
}
# ================= 5. 安全与辅助功能 =================

# 主机安全审计
function server_audit() {
    check_dependencies
    while true; do
        clear
        echo -e "${YELLOW}=== 🕵️ 主机安全审计 (V11) ===${NC}"
        echo -e "${CYAN}[1] 端口暴露审计${NC}: 检查对外开放的端口"
        echo -e "${CYAN}[2] 恶意进程扫描${NC}: 检查高CPU及可疑路径进程"
        echo "--------------------------"
        echo " 1. 扫描开放端口 (netstat)"
        echo " 2. 执行恶意进程扫描"
        echo " 3. 查看最近登录记录"
        echo " 0. 返回"
        read -p "选择: " o
        
        case $o in
            0) return;;
            1) 
                echo -e "\n${GREEN}>>> 端口扫描结果:${NC}"
                netstat -tunlp | grep LISTEN
                pause_prompt;;
            2) 
                echo -e "\n${GREEN}>>> CPU 占用前 5 的进程:${NC}"
                ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 6
                
                echo -e "\n${GREEN}>>> 检查 /tmp 和 /dev/shm 下的可疑执行文件:${NC}"
                suspicious=$(ls -l /proc/*/exe 2>/dev/null | grep -E '/tmp|/dev/shm')
                if [ -z "$suspicious" ]; then echo "✔ 未发现明显异常"; else echo "$suspicious"; fi
                
                echo -e "\n${GREEN}>>> 检查已删除但仍在运行的文件 (Deleted Binaries):${NC}"
                ls -l /proc/*/exe 2>/dev/null | grep '(deleted)' | grep -v "docker" | grep -v "containerd"
                pause_prompt;;
            3) last | head -n 10; pause_prompt;;
        esac
    done
}

# 端口防火墙管理
function port_manager() {
    # 确保防火墙已安装
    if command -v ufw >/dev/null; then FW="ufw"; elif command -v firewall-cmd >/dev/null; then FW="firewalld"; else echo "未检测到防火墙"; return; fi
    
    while true; do
        clear
        echo -e "${YELLOW}=== 端口防火墙 ($FW) ===${NC}"
        echo " 1. 查看状态"
        echo " 2. 开放/关闭 端口"
        echo " 0. 返回"
        read -p "选择: " f
        
        case $f in
            0) return;;
            1) 
                if [ "$FW" == "ufw" ]; then ufw status; else firewall-cmd --list-ports; fi
                pause_prompt;;
            2) 
                read -p "输入端口 (如 8080): " p
                echo "1. 开放  2. 关闭"
                read -p "操作: " a
                if [ "$FW" == "ufw" ]; then
                    [ "$a" == "1" ] && ufw allow $p/tcp || ufw delete allow $p/tcp
                else
                    act=$([ "$a" == "1" ] && echo add || echo remove)
                    firewall-cmd --zone=public --${act}-port=$p/tcp --permanent
                    firewall-cmd --reload
                fi
                echo "完成"
                pause_prompt;;
        esac
    done
}

# 删除站点
function delete_site() {
    while true; do
        clear
        echo "=== 删除站点 ==="
        ls -1 "$SITES_DIR"
        echo "----------------"
        read -p "输入要删除的域名 (0返回): " d
        [ "$d" == "0" ] && return
        
        if [ -d "$SITES_DIR/$d" ]; then
            echo -e "${RED}警告: 此操作不可逆！${NC}"
            read -p "输入 DELETE 确认删除: " confirm
            if [ "$confirm" == "DELETE" ]; then
                cd "$SITES_DIR/$d" && docker compose down -v
                cd .. && rm -rf "$SITES_DIR/$d"
                echo "已删除"
                write_log "Deleted site $d"
            fi
        else
            echo "目录不存在"
        fi
        pause_prompt
    done
}

# 卸载脚本
function uninstall_cluster() {
    echo -e "${RED}⚠️  危险操作：这将删除所有容器和数据！${NC}"
    read -p "输入 DELETE 确认卸载: " c
    if [ "$c" == "DELETE" ]; then
        # 停止所有站点
        for d in "$SITES_DIR"/*; do
            [ -d "$d" ] && cd "$d" && docker compose down -v
        done
        # 停止网关
        cd "$GATEWAY_DIR" && docker compose down -v
        
        # 清理网络和文件
        docker network rm proxy-net 2>/dev/null
        rm -rf "$BASE_DIR"
        rm -f "/usr/bin/web"
        echo "卸载完成。"
        exit 0
    fi
}

# 安全中心菜单
function security_center() {
    while true; do
        clear
        echo -e "${YELLOW}=== 🛡️ 安全防御中心 ===${NC}"
        echo " 1. 端口防火墙管理"
        echo " 2. 主机安全审计 (扫描)"
        echo " 0. 返回上一级"
        read -p "选择: " s
        case $s in 
            0) return;; 
            1) port_manager;; 
            2) server_audit;; 
        esac
    done 
}

# ================= 6. 主程序循环 =================

# 启动前检查
check_dependencies
install_shortcut
init_gateway "auto" # 每次启动自动检查网关配置 (自愈)

while true; do 
    clear
    echo -e "${GREEN}=== Docker Web Manager ($VERSION) ===${NC}"
    echo -e "${CYAN}路径: $BASE_DIR${NC}"
    echo "-----------------------------------------"
    echo -e "${YELLOW}[新建]${NC}  1. WordPress建站   2. 反向代理"
    echo -e "${YELLOW}[运维]${NC}  3. 容器状态监控    4. 删除站点"
    echo -e "${YELLOW}[工具]${NC}  5. WP-CLI工具箱    6. 修复上传限制"
    echo -e "${RED}[安全]${NC}  7. 安全防御中心    8. 查看日志"
    echo "-----------------------------------------"
    echo -e "${BLUE}u. 更新脚本${NC} | ${RED}x. 卸载${NC} | 0. 退出"
    
    echo -n "请选择: "
    read option
    
    case $option in 
        1) create_site;; 
        2) create_proxy;; 
        3) container_ops;; 
        4) delete_site;; 
        5) wp_toolbox;; 
        6) fix_upload_limit;;  # 位于第二部分，如果这里报错找不到，确保复制了第二部分
        7) security_center;; 
        8) tail -n 50 "$LOG_FILE"; pause_prompt;;
        u|U) 
            echo "正在更新..."
            curl -f -L -s -o /tmp/web.sh "$UPDATE_URL" && mv /tmp/web.sh "$0" && chmod +x "$0" && exec "$0"
            ;;
        x|X) uninstall_cluster;; 
        0) exit 0;; 
        *) echo "无效选项"; sleep 1;;
    esac
done
