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

# ================= 菜单系统 (V48) =================
function show_menu() {
    clear
    echo -e "${GREEN}=== WordPress Docker 集群管理 (V48 完美卸载版) ===${NC}"
    echo -e "${CYAN}数据根目录: $BASE_DIR${NC}"
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
    echo " 11. 解除上传限制 (一键扩容)"
    echo ""
    echo -e "${YELLOW}[安全防御]${NC}"
    echo " 12. 防火墙配置 (端口/黑白名单)"
    echo " 13. HTTPS 证书管理 (诊断/续签)"
    echo " 14. 防盗链设置"
    echo ""
    echo -e "${YELLOW}[数据管理]${NC}"
    echo " 15. 数据库 导出/导入"
    echo " 16. 整站 备份与还原"
    echo "-----------------------------------------"
    echo -e "${RED} 17. [危险] 彻底卸载脚本与数据${NC}"
    echo " 0. 退出"
    echo "-----------------------------------------"
    echo -n "请选择操作 [1-17]: "
    read option
}

# --- 17. 卸载功能 (V48 新增) ---
function uninstall_cluster() {
    clear
    echo -e "${RED}======================================${NC}"
    echo -e "${RED}⚠️  危险警告：彻底卸载  ⚠️${NC}"
    echo -e "${RED}======================================${NC}"
    echo "此操作将执行以下毁灭性动作："
    echo "1. 停止并删除所有由本脚本创建的 WordPress 网站容器。"
    echo "2. 停止并删除网关 (Nginx Gateway)。"
    echo "3. 永久删除所有数据文件 ($BASE_DIR)，包括数据库和网站文件！"
    echo "4. 移除 'wp' 快捷指令。"
    echo ""
    echo -e "${YELLOW}如果您只想删除某个网站，请使用菜单 '8. 销毁指定站点'。${NC}"
    echo ""
    read -p "请输入 'DELETE' (大写) 以确认卸载: " confirm
    
    if [ "$confirm" != "DELETE" ]; then
        echo "操作已取消。"
        read -p "按回车返回..."
        return
    fi

    echo -e "\n${YELLOW}>>> 1. 正在停止所有站点容器...${NC}"
    if [ -d "$SITES_DIR" ]; then
        for d in "$SITES_DIR"/*; do
            if [ -d "$d" ]; then
                cd "$d" && docker compose down -v 2>/dev/null
                echo " - 已停止: $(basename "$d")"
            fi
        done
    fi

    echo -e "${YELLOW}>>> 2. 正在停止网关...${NC}"
    if [ -d "$GATEWAY_DIR" ]; then
        cd "$GATEWAY_DIR" && docker compose down -v 2>/dev/null
    fi
    docker network rm proxy-net 2>/dev/null

    echo -e "${YELLOW}>>> 3. 正在粉碎数据文件...${NC}"
    cd /root
    rm -rf "$BASE_DIR"
    
    echo -e "${YELLOW}>>> 4. 移除快捷指令...${NC}"
    rm -f "/usr/bin/wp"

    echo -e "${GREEN}✔ 卸载完成。江湖路远，有缘再见！${NC}"
    echo "脚本文件 ($0) 依然保留，您可以手动删除它。"
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

# --- 4. 创建WP ---
function create_site() {
    read -p "1. 主域名: " fd; host_ip=$(curl -s4 ifconfig.me)
    if command -v dig >/dev/null; then dip=$(dig +short $fd | head -1); else dip=$(getent hosts $fd | awk '{print $1}'); fi
    if [ ! -z "$dip" ] && [ "$dip" != "$host_ip" ]; then echo -e "${RED}⚠️ IP不符: $dip vs $host_ip${NC}"; read -p "强制继续? (y/n): " f; [ "$f" != "y" ] && return; fi
    read -p "2. 邮箱: " email; read -p "3. DB密码: " db_pass
    pname=$(echo $fd | tr '.' '_'); sdir="$SITES_DIR/$fd"; [ -d "$sdir" ] && echo -e "${RED}❌ 已存在${NC}" && read -p "..." && return
    mkdir -p "$sdir"
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
    cd "$sdir" && docker compose up -d >/dev/null 2>&1
    check_ssl_status "$fd"
}

# --- 11. 修复上传限制 ---
function fix_upload_limit() {
    ls -1 "$SITES_DIR"; read -p "输入要优化的域名: " d; sdir="$SITES_DIR/$d"
    if [ ! -d "$sdir" ]; then echo -e "${RED}❌ 找不到${NC}"; read -p "..."; return; fi
    cat > "$sdir/uploads.ini" <<EOF
file_uploads = On
memory_limit = 512M
upload_max_filesize = 512M
post_max_size = 512M
max_execution_time = 600
EOF
    if [ -f "$sdir/nginx.conf" ]; then
        cat > "$sdir/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M;
location / { try_files \$uri \$uri/ /index.php?\$args; }
location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } }
EOF
    fi
    cd "$sdir" && docker compose restart >/dev/null 2>&1
    echo -e "${GREEN}✔ 优化完成${NC}"; read -p "按回车返回..."
}

# --- Nginx 生成器 ---
function generate_nginx_conf() {
    local target_url=$1; local my_domain=$2
    local target_host=$(echo $target_url | awk -F/ '{print $3}')
    local conf_file="$SITES_DIR/$my_domain/nginx-proxy.conf"
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
}

# --- 5. 反向代理 ---
function create_proxy() {
    read -p "1. 主域名: " d; fd="$d"; read -p "2. 邮箱: " e; sdir="$SITES_DIR/$d"; mkdir -p "$sdir"
    read -p "主目标 URL (可省协议): " raw_tu; tu=$(normalize_url "$raw_tu"); echo -e "${CYAN}>>> 目标: $tu${NC}"
    generate_nginx_conf "$tu" "$d"
    cat > "$sdir/docker-compose.yml" <<EOF
services:
  proxy: {image: nginx:alpine, container_name: ${d//./_}_worker, restart: always, volumes: [./nginx-proxy.conf:/etc/nginx/conf.d/default.conf], extra_hosts: ["host.docker.internal:host-gateway"], environment: {VIRTUAL_HOST: "$fd", LETSENCRYPT_HOST: "$fd", LETSENCRYPT_EMAIL: "$e"}, networks: [proxy-net]}
networks: {proxy-net: {external: true}}
EOF
    cd "$sdir" && docker compose up -d >/dev/null 2>&1; echo -e "${GREEN}✔ 启动成功${NC}"; check_ssl_status "$d"
}

# --- 10. 修复代理 ---
function repair_proxy() {
    ls -1 "$SITES_DIR"; read -p "输入要修复的域名: " d; sdir="$SITES_DIR/$d"; [ ! -d "$sdir" ] && return
    echo -e "${YELLOW}重新配置 Nginx 规则...${NC}"; read -p "主目标 URL: " raw_tu; tu=$(normalize_url "$raw_tu")
    generate_nginx_conf "$tu" "$d"
    cd "$sdir" && docker compose restart >/dev/null 2>&1; echo -e "${GREEN}✔ 修复完成${NC}"; read -p "按回车返回..."
}

# --- 其他功能 ---
function create_redirect() { read -p "源域名: " s; read -p "目标URL: " t; t=$(normalize_url "$t"); read -p "邮箱: " e; sdir="$SITES_DIR/$s"; mkdir -p "$sdir"; echo "server { listen 80; server_name localhost; location / { return 301 $t\$request_uri; } }" > "$sdir/redirect.conf"; echo "services: {redirector: {image: nginx:alpine, container_name: ${s//./_}_redirect, restart: always, volumes: [./redirect.conf:/etc/nginx/conf.d/default.conf], environment: {VIRTUAL_HOST: \"$s\", LETSENCRYPT_HOST: \"$s\", LETSENCRYPT_EMAIL: \"$e\"}, networks: [proxy-net]}}" > "$sdir/docker-compose.yml"; echo "networks: {proxy-net: {external: true}}" >> "$sdir/docker-compose.yml"; cd "$sdir" && docker compose up -d >/dev/null 2>&1; echo -e "${GREEN}✔ 完成${NC}"; check_ssl_status "$s"; }
function delete_site() { while true; do clear; echo "=== 🗑️ 删除网站 ==="; ls -1 "$SITES_DIR"; echo "----------------"; echo "输入域名(0返回):"; read d; [ "$d" == "0" ] && return; if [ -d "$SITES_DIR/$d" ]; then read -p "确认删除 $d? (y/n): " c; if [ "$c" == "y" ]; then cd "$SITES_DIR/$d" && docker compose down -v >/dev/null 2>&1; cd .. && rm -rf "$SITES_DIR/$d"; echo -e "${GREEN}✔ 已删除${NC}"; fi; else echo "❌ 找不到"; fi; read -p "按回车继续..."; done; }
function list_sites() { clear; echo "=== 📂 站点列表 ==="; ls -1 "$SITES_DIR"; echo "----------------"; read -p "按回车返回..."; }
function container_ops() { while true; do clear; echo "=== 📊 状态 ==="; cd "$GATEWAY_DIR"; if docker compose ps | grep -q "Up"; then echo -e "${GREEN}● Gateway${NC}"; else echo -e "${RED}● Gateway${NC}"; fi; for d in "$SITES_DIR"/*; do [ -d "$d" ] && (cd "$d"; if docker compose ps | grep -q "Up"; then echo -e "${GREEN}● $(basename "$d")${NC}"; else echo -e "${RED}● $(basename "$d")${NC}"; fi); done; echo "1.全启 2.全停 3.全重启 4.指定启 5.指定停 6.指定重启 0.返回"; read -p "选: " c; case $c in 0) return;; 1) cd "$GATEWAY_DIR" && docker compose up -d >/dev/null 2>&1; for d in "$SITES_DIR"/*; do cd "$d" && docker compose up -d >/dev/null 2>&1; done;; 2) for d in "$SITES_DIR"/*; do cd "$d" && docker compose stop >/dev/null 2>&1; done; cd "$GATEWAY_DIR" && docker compose stop >/dev/null 2>&1;; 3) cd "$GATEWAY_DIR" && docker compose restart >/dev/null 2>&1; for d in "$SITES_DIR"/*; do cd "$d" && docker compose restart >/dev/null 2>&1; done;; 4|5|6) read -p "域名: " d; [ -d "$SITES_DIR/$d" ] && cd "$SITES_DIR/$d" && ([ "$c" == "4" ] && docker compose up -d || ([ "$c" == "5" ] && docker compose stop) || docker compose restart) >/dev/null 2>&1;; esac; [ "$c" != "0" ] && read -p "按回车确定..."; done; }
function manage_firewall() { while true; do clear; echo "1.加黑 2.加白 3.封国 4.重载Nginx 5.防DOS 6.开端口 7.关端口 8.看端口 0.返回"; read -p "选: " f; case $f in 0) return;; 1|2) t="deny"; [ "$f" == "2" ] && t="allow"; read -p "IP: " i; echo "$t $i;" >> "$FW_DIR/${t/deny/black}list.conf";; 3) read -p "代码(cn): " c; wget -qO- "http://www.ipdeny.com/ipblocks/data/countries/$c.zone" | while read l; do echo "deny $l;" >> "$FW_DIR/country_block.conf"; done;; 4) docker exec gateway_proxy nginx -s reload >/dev/null 2>&1;; 5) read -p "1.宽松 2.标准 3.严格 4.关: " d; if [ "$d" == "4" ]; then rm -f "$FW_DIR/dos_zones.conf" "$GATEWAY_DIR/vhost/default"; else r="10r/s"; b="15"; [ "$d" == "1" ] && r="20r/s"; echo "limit_req_zone \$binary_remote_addr zone=one:10m rate=$r; limit_conn_zone \$binary_remote_addr zone=addr:10m;" > "$FW_DIR/dos_zones.conf"; mkdir -p "$GATEWAY_DIR/vhost"; echo "limit_req zone=one burst=$b nodelay; limit_conn addr ${b%0};" > "$GATEWAY_DIR/vhost/default"; fi; cd "$GATEWAY_DIR" && docker compose up -d >/dev/null 2>&1 && docker exec gateway_proxy nginx -s reload >/dev/null 2>&1;; 6|7) read -p "Port: " p; a="allow"; [ "$f" == "7" ] && a="delete allow"; if command -v ufw >/dev/null; then ufw $a $p/tcp >/dev/null 2>&1; elif command -v firewall-cmd >/dev/null; then firewall-cmd --${a/delete /remove-}port=$p/tcp --permanent >/dev/null 2>&1; firewall-cmd --reload >/dev/null 2>&1; fi;; 8) if command -v ufw >/dev/null; then ufw status; else firewall-cmd --list-ports; fi;; esac; [ "$f" != "0" ] && read -p "按回车确定..."; done; }
function cert_management() { while true; do clear; echo "1.看证书 2.上传 3.重置 4.续签 5.诊断 6.切换CA 0.返回"; read -p "选: " c; case $c in 0) return;; 1) docker exec gateway_proxy ls -lh /etc/nginx/certs | grep ".crt";; 2) ls -1 "$SITES_DIR"; read -p "域名: " d; read -p "crt: " c; read -p "key: " k; docker cp "$c" gateway_acme:"/etc/nginx/certs/$d.crt"; docker cp "$k" gateway_acme:"/etc/nginx/certs/$d.key"; docker exec gateway_proxy nginx -s reload;; 3) ls -1 "$SITES_DIR"; read -p "域名: " d; docker exec gateway_acme rm -f "/etc/nginx/certs/$d.crt" "/etc/nginx/certs/$d.key"; docker restart gateway_acme;; 4) docker exec gateway_acme /app/force_renew;; 5) docker logs --tail 30 gateway_acme; echo "---"; netstat -tuln|grep :80 || ss -tuln|grep :80;; 6) echo "1.LE 2.Zero"; read -p "选: " ca; [ "$ca" == "1" ] && s="letsencrypt" || s="zerossl"; docker exec gateway_acme acme.sh --set-default-ca --server $s; echo "OK";; esac; [ "$c" != "0" ] && read -p "按回车确定..."; done; }
function ssh_key_manager() { while true; do clear; echo "1.导入公钥 2.开密码 3.关密码 4.装Fail2Ban 5.生成密钥 0.返回"; read -p "选: " s; f="/root/.ssh/authorized_keys"; c="/etc/ssh/sshd_config"; case $s in 0) return;; 1) mkdir -p /root/.ssh; read -p "Key: " k; echo "$k" >> "$f"; chmod 600 "$f";; 2) sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' "$c";; 3) [ -s "$f" ] && sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' "$c" || echo "无密钥";; 4) apt-get install -y fail2ban || yum install -y fail2ban;; 5) k="/root/.ssh/id_rsa_auto_$(date +%s)"; ssh-keygen -t rsa -b 4096 -f "$k" -N "" -q; cat "$k.pub" >> "$f"; echo "Private Key:"; cat "$k";; esac; [ "$s" != "5" ] && systemctl restart sshd; read -p "按回车确定..."; done; }
function db_manager() { while true; do clear; echo "1.导出 2.导入 3.开Adminer 4.关Adminer 0.返回"; read -p "选: " c; case $c in 0) return;; 1) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; pwd=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml"|awk -F': ' '{print $2}'); docker compose -f "$s/docker-compose.yml" exec -T db mysqldump -u root -p"$pwd" --all-databases > "$s/${d}.sql"; echo "OK: $s/${d}.sql";; 2) ls -1 "$SITES_DIR"; read -p "域名: " d; read -p "SQL: " f; s="$SITES_DIR/$d"; pwd=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml"|awk -F': ' '{print $2}'); cat "$f" | docker compose -f "$s/docker-compose.yml" exec -T db mysql -u root -p"$pwd"; echo "OK";; 3) docker run --name temp_adminer -p 8888:8080 --network proxy-net -d adminer; echo "Port 8888";; 4) docker rm -f temp_adminer;; esac; read -p "按回车确定..."; done; }
function change_domain() { while true; do clear; ls -1 "$SITES_DIR"; echo "输入旧域名(0返回):"; read o; [ "$o" == "0" ] && return; [ ! -d "$SITES_DIR/$o" ] && continue; read -p "新域名: " n; cd "$SITES_DIR/$o" && docker compose down >/dev/null 2>&1; cd .. && mv "$o" "$n" && cd "$n"; sed -i "s/$o/$n/g" docker-compose.yml; docker compose up -d; wp_c=$(docker compose ps -q wordpress); docker run --rm --volumes-from $wp_c --network container:$wp_c wordpress:cli wp search-replace "$o" "$n" --all-tables --skip-columns=guid; docker exec gateway_proxy nginx -s reload; echo "OK"; read -p "按回车继续..."; done; }
function backup_restore_ops() {
    while true; do clear; echo "1. 备份网站 (整站)" ; echo "2. 还原网站 (整站)"; echo "0. 返回"; read -p "选: " br; case $br in
        0) return;;
        1) ls -1 "$SITES_DIR"; echo "备份域名(0返回):"; read d; [ "$d" == "0" ] && continue; s="$SITES_DIR/$d"; b="$s/backups/$(date +%Y%m%d)"; mkdir -p "$b"; if [ -d "$s" ]; then cd "$s"; pwd=$(grep MYSQL_ROOT_PASSWORD docker-compose.yml|awk -F': ' '{print $2}'); docker compose exec -T db mysqldump -u root -p"$pwd" --all-databases > "$b/db.sql"; wp_c=$(docker compose ps -q wordpress); docker run --rm --volumes-from $wp_c -v "$b":/backup alpine tar czf /backup/files.tar.gz /var/www/html/wp-content; cp *.conf docker-compose.yml "$b/"; echo "OK: $b"; else echo "No"; fi; read -p "按回车继续...";;
        2) ls -1 "$SITES_DIR"; echo "还原域名(0返回):"; read d; [ "$d" == "0" ] && continue; s="$SITES_DIR/$d"; b="$s/backups"; if [ -d "$b" ]; then ls "$b"; read -p "备份名: " n; bp="$b/$n"; if [ -d "$bp" ]; then cd "$s" && docker compose down; vol=$(docker volume ls -q|grep "${d//./_}_wp_data"); docker run --rm -v $vol:/var/www/html -v "$bp":/backup alpine tar xzf /backup/files.tar.gz -C /; docker compose up -d db; sleep 10; pwd=$(grep MYSQL_ROOT_PASSWORD docker-compose.yml|awk -F': ' '{print $2}'); docker compose exec -T db mysql -u root -p"$pwd" < "$bp/db.sql"; docker compose up -d; echo "OK"; else echo "No Backup"; fi; else echo "No Dir"; fi; read -p "按回车继续...";;
    esac; done
}
function manage_hotlink() { while true; do clear; echo "1.开防盗链 2.关防盗链 0.返回"; read -p "选: " h; case $h in 0) return;; 1) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; if [ -f "$s/nginx.conf" ]; then read -p "白名单(空格隔开): " w; cat > "$s/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M;
location ~* \.(gif|jpg|jpeg|png|bmp|swf|webp)$ { valid_referers none blocked server_names $d *.$d $w; if (\$invalid_referer) { return 403; } try_files \$uri \$uri/ /index.php?\$args; }
location / { try_files \$uri \$uri/ /index.php?\$args; }
location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } }
EOF
cd "$s" && docker compose restart nginx; echo "OK"; fi;; 2) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; if [ -f "$s/nginx.conf" ]; then cat > "$s/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M;
location / { try_files \$uri \$uri/ /index.php?\$args; }
location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } }
EOF
cd "$s" && docker compose restart nginx; echo "OK"; fi;; esac; read -p "按回车返回..."; done; }

# --- 主程序 ---
check_and_install_docker
install_shortcut
if ! docker ps --format '{{.Names}}' | grep -q "^gateway_proxy$"; then echo -e "${YELLOW}后台初始化...${NC}"; init_gateway "auto"; fi
while true; do show_menu; case $option in 1) init_gateway "force"; read -p "按回车返回...";; 2) container_ops;; 3) ssh_key_manager;; 4) create_site;; 5) create_proxy;; 6) create_redirect;; 7) list_sites;; 8) delete_site;; 9) change_domain;; 10) repair_proxy;; 11) fix_upload_limit;; 12) manage_firewall;; 13) cert_management;; 14) manage_hotlink;; 15) db_manager;; 16) backup_restore_ops;; 17) uninstall_cluster;; 0) exit 0;; esac; done
