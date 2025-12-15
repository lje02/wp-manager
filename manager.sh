#!/bin/bash

# ================= 配置区域 =================
BASE_DIR="/root/wp-cluster"
SITES_DIR="$BASE_DIR/sites"
GATEWAY_DIR="$BASE_DIR/gateway"
FW_DIR="$BASE_DIR/firewall"
TG_CONF="$BASE_DIR/telegram.conf"

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

# 初始化目录
mkdir -p "$SITES_DIR" "$GATEWAY_DIR" "$FW_DIR"

# ================= 核心工具函数 =================

# --- 自动注册快捷指令 wp ---
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
    fi
}

function check_ssl_status() {
    local d=$1; echo -e "${CYAN}>>> 正在申请 SSL...${NC}"; for ((i=1; i<=20; i++)); do if docker exec gateway_acme test -f "/etc/nginx/certs/$d.crt"; then echo -e "${GREEN}✔ 成功: https://$d${NC}"; read -p "按回车返回..."; return 0; fi; echo -n "."; sleep 5; done; echo -e "\n${YELLOW}⚠️ 证书暂未生成 (请检查DNS)${NC}"; read -p "按回车返回...";
}

function normalize_url() {
    local url=$1; url=${url%/}; if [[ "$url" != http* ]]; then echo "https://$url"; else echo "$url"; fi
}

function validate_and_sanitize_domain() {
    local domain=$1
    domain=${domain#http://}
    domain=${domain#https://}
    domain=${domain#*://}
    domain=${domain%%/*}
    echo "$domain"
}

# ================= 菜单系统 (V49) =================
function show_menu() {
    clear
    echo -e "${GREEN}=== WordPress Docker 集群管理 (V49 进阶优化版) ===${NC}"
    echo -e "${CYAN}数据根目录: $BASE_DIR${NC}"
    echo "-----------------------------------------"
    echo -e "${YELLOW}[系统基石]${NC}"
    echo " 1. 初始化/重置网关"
    echo " 2. 容器状态监控与控制"
    echo " 3. SSH 密钥安全管理"
    echo ""
    echo -e "${YELLOW}[新建站点]${NC}"
    echo " 4. 部署 WordPress 新站"
    echo " 5. 新建 反向代理 (普通/高级)"
    echo " 6. 新建 域名重定向 (301)"
    echo ""
    echo -e "${YELLOW}[站点运维]${NC}"
    echo " 7. 查看站点列表"
    echo " 8. 销毁指定站点"
    echo " 9. 更换网站域名"
    echo " 10. 修复反代配置"
    echo " 11. 解除上传限制 (一键扩容)"
    echo ""
    echo -e "${YELLOW}[安全防御]${NC}"
    echo " 12. 防火墙配置 (端口/黑白名单)"
    echo " 13. HTTPS 证书管理"
    echo " 14. 防盗链设置"
    echo ""
    echo -e "${YELLOW}[数据管理]${NC}"
    echo " 15. 数据库 导出/导入"
    echo " 16. 整站 备份与还原 (智能扫描)"
    echo "-----------------------------------------"
    echo -e "${RED} 17. [危险] 彻底卸载脚本与数据${NC}"
    echo " 0. 退出"
    echo "-----------------------------------------"
    echo -n "请选择操作 [1-17]: "
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
    rm -f "/usr/bin/wp"
    echo -e "${GREEN}卸载完成。${NC}"
    exit 0
}

# --- 1. 网关初始化 ---
function init_gateway() {
    local m=$1; if ! docker network ls | grep -q "proxy-net"; then docker network create proxy-net >/dev/null; fi
    mkdir -p "$GATEWAY_DIR"; cd "$GATEWAY_DIR"
    echo "client_max_body_size 1024m;" > "upload_size.conf"
    echo "proxy_read_timeout 600s;" >> "upload_size.conf"
    echo "proxy_send_timeout 600s;" >> "upload_size.conf"
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
    environment: ["DEFAULT_EMAIL=admin@localhost.com", "NGINX_PROXY_CONTAINER=gateway_proxy", "ACME_CA_URI=https://acme-v02.api.letsencrypt.org/directory"]
    networks: ["proxy-net"]
    depends_on: ["nginx-proxy"]
    restart: always
volumes: {conf: , vhost: , html: , certs: , acme: }
networks: {proxy-net: {external: true}}
EOF
    if docker compose up -d --remove-orphans >/dev/null 2>&1; then [ "$m" == "force" ] && echo -e "${GREEN}✔ 网关启动成功${NC}"; else echo -e "${RED}✘ 网关启动失败${NC}"; [ "$m" == "force" ] && docker compose up -d; fi
}

# --- 4. 创建WP (新增提示) ---
function create_site() {
    read -p "1. 主域名: " raw_domain
    fd=$(validate_and_sanitize_domain "$raw_domain") || return
    
    host_ip=$(curl -s4 ifconfig.me 2>/dev/null); dip=$(dig +short "$fd" 2>/dev/null | head -1)
    if [ ! -z "$dip" ] && [ "$dip" != "$host_ip" ]; then echo -e "${RED}⚠️ IP不符: $dip vs $host_ip${NC}"; read -p "继续? (y/n): " f; [ "$f" != "y" ] && return; fi
    read -p "2. 邮箱: " email; email=${email:-admin@$fd}
    read -p "3. DB密码: " db_pass; [ -z "$db_pass" ] && return
    
    pname=$(echo $fd | tr '.' '_'); sdir="$SITES_DIR/$fd"
    [ -d "$sdir" ] && { echo "已存在"; return; }
    mkdir -p "$sdir"
    
    # 配置文件生成 (保持不变)...
    cat > "$sdir/waf.conf" <<EOF
location ~* /\.(git|svn|hg|env|bak|config|sql) { deny all; return 403; }
location ~* \.(sql|bak|conf|ini|log|sh|yaml|yml)$ { deny all; return 403; }
EOF
    cat > "$sdir/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M;
location / { try_files \$uri \$uri/ /index.php?\$args; }
location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } }
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
    
    # 增加创建提示
    echo -e "${YELLOW}>>> 正在初始化容器环境...${NC}"
    echo -e "${BLUE}  - 数据库 (MySQL 8.0)${NC}"
    echo -e "${BLUE}  - 缓存服务 (Redis)${NC}"
    echo -e "${BLUE}  - WordPress 核心程序${NC}"
    echo -e "${BLUE}  - Nginx Web服务器${NC}"
    cd "$sdir" && docker compose up -d >/dev/null 2>&1
    
    check_ssl_status "$fd"
}

# --- 11. 修复上传限制 ---
function fix_upload_limit() {
    ls -1 "$SITES_DIR"; read -p "输入域名: " d; sdir="$SITES_DIR/$d"
    if [ ! -d "$sdir" ]; then echo -e "${RED}❌ 找不到${NC}"; read -p "..."; return; fi
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

# --- Nginx 生成器 (V49: 增加简单/高级逻辑) ---
function generate_nginx_conf() {
    local target_url=$1; local my_domain=$2; local mode=$3
    local target_host=$(echo $target_url | awk -F/ '{print $3}')
    local conf_file="$SITES_DIR/$my_domain/nginx-proxy.conf"
    
    if [ "$mode" == "simple" ]; then
        # 普通反代模式
        cat > "$conf_file" <<EOF
server {
    listen 80; server_name localhost; resolver 8.8.8.8;
    location / {
        proxy_pass $target_url;
        proxy_set_header Host $target_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_ssl_server_name on;
    }
}
EOF
    else
        # 高级反代模式 (资源聚合)
        cat > "$conf_file" <<EOF
server {
    listen 80; server_name localhost; resolver 8.8.8.8;
    location / {
        proxy_pass $target_url; proxy_set_header Host $target_host; proxy_set_header Referer $target_url; proxy_ssl_server_name on; proxy_set_header Accept-Encoding "";
        sub_filter "</head>" "<meta name='referrer' content='no-referrer'></head>";
        sub_filter "$target_host" "$my_domain";
        sub_filter "https://$target_host" "https://$my_domain";
        sub_filter "http://$target_host" "https://$my_domain";
EOF
        echo -e "${YELLOW}--- 配置外部资源聚合 ---${NC}"; local count=1
        while true; do
            read -p "外部资源 URL (回车跳过): " raw_ext; [ -z "$raw_ext" ] && break
            local ext_url=$(normalize_url "$raw_ext"); local ext_host=$(echo $ext_url | awk -F/ '{print $3}'); local path_key="_res_${count}"
            echo -e "${GREEN}>>> 映射: $ext_host -> $my_domain/$path_key/${NC}"
            cat >> "$conf_file" <<EOF
        sub_filter "$ext_host" "$my_domain/$path_key";
        sub_filter "https://$ext_host" "https://$my_domain/$path_key";
        sub_filter "http://$ext_host" "https://$my_domain/$path_key";
EOF
            cat >> "$conf_file.locations" <<EOF
    location /$path_key/ { rewrite ^/$path_key/(.*) /\$1 break; proxy_pass $ext_url; proxy_set_header Host $ext_host; proxy_set_header Referer $ext_url; proxy_ssl_server_name on; proxy_set_header Accept-Encoding ""; }
EOF
            ((count++))
        done
        cat >> "$conf_file" <<EOF
        sub_filter_once off; sub_filter_types *;
    }
EOF
        [ -f "$conf_file.locations" ] && cat "$conf_file.locations" >> "$conf_file" && rm "$conf_file.locations"
        echo "}" >> "$conf_file"
    fi
}

# --- 5. 反向代理 (V49: 增加选项) ---
function create_proxy() {
    read -p "1. 主域名: " d; fd=$(validate_and_sanitize_domain "$d") || return
    read -p "2. 邮箱: " e; e=${e:-admin@$fd}
    sdir="$SITES_DIR/$fd"; mkdir -p "$sdir"
    
    echo -e "${YELLOW}请选择反代模式:${NC}"
    echo "1. 普通反代 (适合镜像站/API转发，速度快)"
    echo "2. 高级反代 (资源聚合/内容替换，解决防盗链/混合内容)"
    read -p "选择 [1-2]: " pmode
    
    read -p "主目标 URL (可省协议): " raw_tu; tu=$(normalize_url "$raw_tu")
    
    if [ "$pmode" == "1" ]; then
        generate_nginx_conf "$tu" "$fd" "simple"
    else
        generate_nginx_conf "$tu" "$fd" "advanced"
    fi
    
    cat > "$sdir/docker-compose.yml" <<EOF
services:
  proxy: {image: nginx:alpine, container_name: ${fd//./_}_worker, restart: always, volumes: [./nginx-proxy.conf:/etc/nginx/conf.d/default.conf], extra_hosts: ["host.docker.internal:host-gateway"], environment: {VIRTUAL_HOST: "$fd", LETSENCRYPT_HOST: "$fd", LETSENCRYPT_EMAIL: "$e"}, networks: [proxy-net]}
networks: {proxy-net: {external: true}}
EOF
    cd "$sdir" && docker compose up -d >/dev/null 2>&1; echo -e "${GREEN}✔ 启动成功${NC}"; check_ssl_status "$fd"
}

# --- 10. 修复代理 ---
function repair_proxy() {
    ls -1 "$SITES_DIR"; read -p "输入要修复的域名: " d; sdir="$SITES_DIR/$d"; [ ! -d "$sdir" ] && return
    echo -e "${YELLOW}1. 普通反代  2. 高级反代${NC}"; read -p "模式: " pmode
    read -p "主目标 URL: " raw_tu; tu=$(normalize_url "$raw_tu")
    
    if [ "$pmode" == "1" ]; then
        generate_nginx_conf "$tu" "$d" "simple"
    else
        generate_nginx_conf "$tu" "$d" "advanced"
    fi
    cd "$sdir" && docker compose restart >/dev/null 2>&1; echo -e "${GREEN}✔ 修复完成${NC}"; read -p "按回车返回..."
}

# --- 16. 备份与还原 (V49: 优化路径显示与智能扫描) ---
function backup_restore_ops() {
    while true; do
        clear; echo "=== 💾 备份与还原 ==="; echo "1. 备份网站 (整站)"; echo "2. 还原网站 (智能扫描)"; echo "0. 返回"; read -p "选: " br
        case $br in
            0) return ;;
            1)
                ls -1 "$SITES_DIR"; read -p "备份域名: " d; [ "$d" == "0" ] && continue
                s="$SITES_DIR/$d"; [ ! -d "$s" ] && continue
                
                backup_name="$(date +%Y%m%d_%H%M%S)"
                b="$s/backups/$backup_name"; mkdir -p "$b"
                
                echo -e "${YELLOW}正在导出数据库...${NC}"
                pwd=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml"|awk -F': ' '{print $2}'|tr -d ' ')
                cd "$s" && docker compose exec -T db mysqldump -u root -p"$pwd" --all-databases > "$b/db.sql"
                
                echo -e "${YELLOW}正在打包文件...${NC}"
                wp_c=$(docker compose ps -q wordpress); docker run --rm --volumes-from $wp_c -v "$b":/backup alpine tar czf /backup/files.tar.gz /var/www/html/wp-content
                cp *.conf docker-compose.yml "$b/"
                
                echo -e "${GREEN}✔ 备份成功!${NC}"
                echo -e "${CYAN}备份路径: $b${NC}"
                echo -e "${CYAN}备份名称: $backup_name${NC}"
                read -p "按回车继续..."
                ;;
            2)
                ls -1 "$SITES_DIR"; read -p "还原域名: " d; s="$SITES_DIR/$d"; b_root="$s/backups"
                if [ ! -d "$b_root" ]; then echo -e "${RED}无备份记录${NC}"; read -p "..."; continue; fi
                
                # 智能扫描最新备份
                latest=$(ls -1t "$b_root" | head -n 1)
                if [ -z "$latest" ]; then echo -e "${RED}备份目录为空${NC}"; read -p "..."; continue; fi
                
                echo -e "${YELLOW}发现最近备份: ${CYAN}$latest${NC}"
                read -p "是否还原此备份? (y/n/手动输入m): " choice
                
                if [ "$choice" == "m" ]; then
                    ls "$b_root"; read -p "输入备份目录名: " latest
                elif [ "$choice" != "y" ]; then
                    continue
                fi
                
                bp="$b_root/$latest"
                if [ ! -d "$bp" ]; then echo -e "${RED}备份不存在${NC}"; read -p "..."; continue; fi
                
                echo -e "${YELLOW}正在还原...${NC}"
                cd "$s" && docker compose down
                vol=$(docker volume ls -q|grep "${d//./_}_wp_data")
                docker run --rm -v $vol:/var/www/html -v "$bp":/backup alpine tar xzf /backup/files.tar.gz -C /
                docker compose up -d db; sleep 10
                pwd=$(grep MYSQL_ROOT_PASSWORD docker-compose.yml|awk -F': ' '{print $2}'|tr -d ' ')
                docker compose exec -T db mysql -u root -p"$pwd" < "$bp/db.sql"
                docker compose up -d
                echo -e "${GREEN}✔ 还原完成${NC}"; read -p "按回车继续..."
                ;;
        esac
    done
}

# --- 其他功能 (保持不变) ---
function create_redirect() { read -p "源域名: " s; s=$(validate_and_sanitize_domain "$s") || return; read -p "目标: " t; t=$(normalize_url "$t"); e="admin@$s"; sdir="$SITES_DIR/$s"; mkdir -p "$sdir"; echo "server { listen 80; server_name localhost; location / { return 301 $t\$request_uri; } }" > "$sdir/redirect.conf"; cat > "$sdir/docker-compose.yml" <<EOF
services: {redirector: {image: nginx:alpine, container_name: ${s//./_}_redirect, restart: always, volumes: [./redirect.conf:/etc/nginx/conf.d/default.conf], environment: {VIRTUAL_HOST: "$s", LETSENCRYPT_HOST: "$s", LETSENCRYPT_EMAIL: "$e"}, networks: [proxy-net]}}
networks: {proxy-net: {external: true}}
EOF
cd "$sdir" && docker compose up -d >/dev/null 2>&1; check_ssl_status "$s"; }

function delete_site() { while true; do clear; echo "=== 🗑️ 删除网站 ==="; ls -1 "$SITES_DIR"; echo "----------------"; echo "输入域名(0返回):"; read d; [ "$d" == "0" ] && return; if [ -d "$SITES_DIR/$d" ]; then read -p "确认删除 $d? (y/n): " c; if [ "$c" == "y" ]; then cd "$SITES_DIR/$d" && docker compose down -v >/dev/null 2>&1; cd .. && rm -rf "$SITES_DIR/$d"; echo -e "${GREEN}✔ 已删除${NC}"; fi; else echo "❌ 找不到"; fi; read -p "按回车继续..."; done; }
function list_sites() { clear; echo "=== 📂 站点列表 ==="; ls -1 "$SITES_DIR"; echo "----------------"; read -p "按回车返回..."; }
function container_ops() { while true; do clear; echo "=== 📊 状态 ==="; cd "$GATEWAY_DIR"; if docker compose ps | grep -q "Up"; then echo -e "${GREEN}● Gateway${NC}"; else echo -e "${RED}● Gateway${NC}"; fi; for d in "$SITES_DIR"/*; do [ -d "$d" ] && (cd "$d"; if docker compose ps | grep -q "Up"; then echo -e "${GREEN}● $(basename "$d")${NC}"; else echo -e "${RED}● $(basename "$d")${NC}"; fi); done; echo "1.全启 2.全停 3.全重启 4.指定启 5.指定停 6.指定重启 0.返回"; read -p "选: " c; case $c in 0) return;; 1) cd "$GATEWAY_DIR" && docker compose up -d >/dev/null 2>&1; for d in "$SITES_DIR"/*; do cd "$d" && docker compose up -d >/dev/null 2>&1; done;; 2) for d in "$SITES_DIR"/*; do cd "$d" && docker compose stop >/dev/null 2>&1; done; cd "$GATEWAY_DIR" && docker compose stop >/dev/null 2>&1;; 3) cd "$GATEWAY_DIR" && docker compose restart >/dev/null 2>&1; for d in "$SITES_DIR"/*; do cd "$d" && docker compose restart >/dev/null 2>&1; done;; 4|5|6) read -p "域名: " d; [ -d "$SITES_DIR/$d" ] && cd "$SITES_DIR/$d" && ([ "$c" == "4" ] && docker compose up -d || ([ "$c" == "5" ] && docker compose stop) || docker compose restart) >/dev/null 2>&1;; esac; [ "$c" != "0" ] && read -p "按回车确定..."; done; }
function manage_firewall() { while true; do clear; echo "1.加黑 2.加白 3.封国 4.重载Nginx 5.防DOS 6.开端口 7.关端口 8.看端口 0.返回"; read -p "选: " f; case $f in 0) return;; 1|2) t="deny"; [ "$f" == "2" ] && t="allow"; read -p "IP: " i; echo "$t $i;" >> "$FW_DIR/${t/deny/black}list.conf";; 3) read -p "代码(cn): " c; wget -qO- "http://www.ipdeny.com/ipblocks/data/countries/$c.zone" | while read l; do echo "deny $l;" >> "$FW_DIR/country_block.conf"; done;; 4) docker exec gateway_proxy nginx -s reload >/dev/null 2>&1;; 5) read -p "1.宽松 2.标准 3.严格 4.关: " d; if [ "$d" == "4" ]; then rm -f "$FW_DIR/dos_zones.conf" "$GATEWAY_DIR/vhost/default"; else r="10r/s"; b="15"; [ "$d" == "1" ] && r="20r/s"; echo "limit_req_zone \$binary_remote_addr zone=one:10m rate=$r; limit_conn_zone \$binary_remote_addr zone=addr:10m;" > "$FW_DIR/dos_zones.conf"; mkdir -p "$GATEWAY_DIR/vhost"; echo "limit_req zone=one burst=$b nodelay; limit_conn addr ${b%0};" > "$GATEWAY_DIR/vhost/default"; fi; cd "$GATEWAY_DIR" && docker compose up -d >/dev/null 2>&1 && docker exec gateway_proxy nginx -s reload >/dev/null 2>&1;; 6|7) read -p "Port: " p; a="allow"; [ "$f" == "7" ] && a="delete allow"; if command -v ufw >/dev/null; then ufw $a $p/tcp >/dev/null 2>&1; elif command -v firewall-cmd >/dev/null; then firewall-cmd --${a/delete /remove-}port=$p/tcp --permanent >/dev/null 2>&1; firewall-cmd --reload >/dev/null 2>&1; fi;; 8) if command -v ufw >/dev/null; then ufw status; else firewall-cmd --list-ports; fi;; esac; [ "$f" != "0" ] && read -p "按回车确定..."; done; }
function cert_management() { while true; do clear; echo "1.看证书 2.上传 3.重置 4.续签 5.诊断 6.切换CA 0.返回"; read -p "选: " c; case $c in 0) return;; 1) docker exec gateway_proxy ls -lh /etc/nginx/certs | grep ".crt";; 2) ls -1 "$SITES_DIR"; read -p "域名: " d; read -p "crt: " c; read -p "key: " k; docker cp "$c" gateway_acme:"/etc/nginx/certs/$d.crt"; docker cp "$k" gateway_acme:"/etc/nginx/certs/$d.key"; docker exec gateway_proxy nginx -s reload;; 3) ls -1 "$SITES_DIR"; read -p "域名: " d; docker exec gateway_acme rm -f "/etc/nginx/certs/$d.crt" "/etc/nginx/certs/$d.key"; docker restart gateway_acme;; 4) docker exec gateway_acme /app/force_renew;; 5) docker logs --tail 30 gateway_acme; echo "---"; netstat -tuln|grep :80 || ss -tuln|grep :80;; 6) echo "1.LE 2.Zero"; read -p "选: " ca; [ "$ca" == "1" ] && s="letsencrypt" || s="zerossl"; docker exec gateway_acme acme.sh --set-default-ca --server $s; echo "OK";; esac; [ "$c" != "0" ] && read -p "按回车确定..."; done; }
function ssh_key_manager() { while true; do clear; echo "1.导入公钥 2.开密码 3.关密码 4.装Fail2Ban 5.生成密钥 0.返回"; read -p "选: " s; f="/root/.ssh/authorized_keys"; c="/etc/ssh/sshd_config"; case $s in 0) return;; 1) mkdir -p /root/.ssh; read -p "Key: " k; echo "$k" >> "$f"; chmod 600 "$f";; 2) sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' "$c";; 3) [ -s "$f" ] && sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' "$c" || echo "无密钥";; 4) apt-get install -y fail2ban || yum install -y fail2ban;; 5) k="/root/.ssh/id_rsa_auto_$(date +%s)"; ssh-keygen -t rsa -b 4096 -f "$k" -N "" -q; cat "$k.pub" >> "$f"; echo "Private Key:"; cat "$k";; esac; [ "$s" != "5" ] && systemctl restart sshd; read -p "按回车确定..."; done; }
function db_manager() { while true; do clear; echo "1.导出 2.导入 3.开Adminer 4.关Adminer 0.返回"; read -p "选: " c; case $c in 0) return;; 1) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; pwd=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml"|awk -F': ' '{print $2}'); docker compose -f "$s/docker-compose.yml" exec -T db mysqldump -u root -p"$pwd" --all-databases > "$s/${d}.sql"; echo "OK: $s/${d}.sql";; 2) ls -1 "$SITES_DIR"; read -p "域名: " d; read -p "SQL: " f; s="$SITES_DIR/$d"; pwd=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml"|awk -F': ' '{print $2}'); cat "$f" | docker compose -f "$s/docker-compose.yml" exec -T db mysql -u root -p"$pwd"; echo "OK";; 3) docker run --name temp_adminer -p 8888:8080 --network proxy-net -d adminer; echo "Port 8888";; 4) docker rm -f temp_adminer;; esac; read -p "按回车确定..."; done; }
function change_domain() { while true; do clear; ls -1 "$SITES_DIR"; echo "输入旧域名(0返回):"; read o; [ "$o" == "0" ] && return; [ ! -d "$SITES_DIR/$o" ] && continue; read -p "新域名: " n; cd "$SITES_DIR/$o" && docker compose down >/dev/null 2>&1; cd .. && mv "$o" "$n" && cd "$n"; sed -i "s/$o/$n/g" docker-compose.yml; docker compose up -d; wp_c=$(docker compose ps -q wordpress); docker run --rm --volumes-from $wp_c --network container:$wp_c wordpress:cli wp search-replace "$o" "$n" --all-tables --skip-columns=guid; docker exec gateway_proxy nginx -s reload; echo "OK"; read -p "按回车继续..."; done; }
function manage_hotlink() { while true; do clear; echo "1.开防盗链 2.关防盗链 0.返回"; read -p "选: " h; case $h in 0) return;; 1) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; if [ -f "$s/nginx.conf" ]; then read -p "白名单(空格隔开): " w; cat > "$s/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M;
location ~* \.(gif|jpg|jpeg|png|bmp|swf|webp)$ { valid_referers none blocked server_names $d *.$d $w; if (\$invalid_referer) { return 403; } try_files \$uri \$uri/ /index.php?\$args; }
location / { try_files \$uri \$uri/ /index.php?\$args; }
location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; } }
EOF
cd "$s" && docker compose restart nginx; echo "OK"; fi;; 2) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; if [ -f "$s/nginx.conf" ]; then cat > "$s/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M;
location / { try_files \$uri \$uri/ /index.php?\$args; }
location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; } }
EOF
cd "$s" && docker compose restart nginx; echo "OK"; fi;; esac; read -p "按回车返回..."; done; }

# --- 主程序 ---
check_and_install_docker
install_shortcut
if ! docker ps --format '{{.Names}}' | grep -q "^gateway_proxy$"; then echo -e "${YELLOW}后台初始化...${NC}"; init_gateway "auto"; fi
while true; do show_menu; case $option in 1) init_gateway "force"; read -p "按回车返回...";; 2) container_ops;; 3) ssh_key_manager;; 4) create_site;; 5) create_proxy;; 6) create_redirect;; 7) list_sites;; 8) delete_site;; 9) change_domain;; 10) repair_proxy;; 11) fix_upload_limit;; 12) manage_firewall;; 13) cert_management;; 14) manage_hotlink;; 15) db_manager;; 16) backup_restore_ops;; 17) uninstall_cluster;; 0) exit 0;; esac; done
