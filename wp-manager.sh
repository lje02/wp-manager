#!/bin/bash

# ================= 配置区域 =================
# 脚本版本号
VERSION="V55 (Sec-Hardened)"

# 数据存储路径
BASE_DIR="/root/wp-cluster"
SITES_DIR="$BASE_DIR/sites"
GATEWAY_DIR="$BASE_DIR/gateway"
FW_DIR="$BASE_DIR/firewall"

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

# ================= 核心工具函数 =================

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

# --- 防火墙自动检测与安装 ---
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
        echo -e "${RED}❌ 系统不支持自动安装防火墙${NC}"; return 1
    fi
    echo -e "${GREEN}✔ 防火墙就绪${NC}"; sleep 1
}

function check_ssl_status() {
    local d=$1; echo -e "${CYAN}>>> [SSL] 申请证书中...${NC}"; for ((i=1; i<=20; i++)); do if docker exec gateway_acme test -f "/etc/nginx/certs/$d.crt"; then echo -e "${GREEN}✔ SSL 成功: https://$d${NC}"; read -p "按回车返回..."; return 0; fi; echo -n "."; sleep 5; done; echo -e "\n${YELLOW}⚠️ 证书暂未生成 (请检查DNS)${NC}"; read -p "按回车返回...";
}

function normalize_url() {
    local url=$1; url=${url%/}; if [[ "$url" != http* ]]; then echo "https://$url"; else echo "$url"; fi
}

function update_script() {
    clear; echo -e "${GREEN}=== 脚本自动更新 ===${NC}"; echo -e "版本: $VERSION"; echo -e "源: github.com/lje02/wp-manager"
    temp_file="/tmp/wp_manager_new.sh"
    if curl -L -s -o "$temp_file" "$UPDATE_URL" && head -n 1 "$temp_file" | grep -q "/bin/bash"; then
        mv "$temp_file" "$0"; chmod +x "$0"; echo -e "${GREEN}✔ 更新成功，重启中...${NC}"; sleep 1; exec "$0"
    else echo -e "${RED}❌ 更新失败${NC}"; rm -f "$temp_file"; fi; read -p "..."
}

# ================= 安全防御中心 (V55 重构) =================

# --- 1. Fail2Ban 管理 ---
function fail2ban_manager() {
    while true; do
        clear; echo -e "${YELLOW}=== 👮 Fail2Ban SSH 防护专家 ===${NC}"
        # 检测状态
        if systemctl is-active fail2ban >/dev/null 2>&1; then 
            f2b_status="${GREEN}运行中${NC}"
            banned_count=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $4}')
        else 
            f2b_status="${RED}未运行${NC}"
            banned_count="N/A"
        fi
        echo -e "状态: $f2b_status | 当前封禁IP数: ${RED}$banned_count${NC}"
        echo "--------------------------"
        echo " 1. 安装并配置 (加强版策略)"
        echo " 2. 查看被封禁 IP 列表"
        echo " 3. 手动解封 IP"
        echo " 4. 卸载/停止 Fail2Ban"
        echo " 0. 返回"
        read -p "选择: " op
        case $op in
            0) return;;
            1) 
                echo -e "${BLUE}>>> 正在安装 Fail2Ban...${NC}"
                if [ -f /etc/debian_version ]; then apt-get update && apt-get install -y fail2ban; logpath="/var/log/auth.log";
                elif [ -f /etc/redhat-release ]; then yum install -y epel-release && yum install -y fail2ban; logpath="/var/log/secure"; fi
                
                echo -e "${BLUE}>>> 应用加强版配置 (5次失败封禁24小时)...${NC}"
                cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = 127.0.0.1/8
bantime  = 86400
findtime = 3600
maxretry = 5

[sshd]
enabled = true
port    = ssh
logpath = $logpath
backend = systemd
EOF
                systemctl enable fail2ban; systemctl restart fail2ban
                echo -e "${GREEN}✔ Fail2Ban 已启动且策略已加强${NC}"; read -p "...";;
            2) 
                echo -e "${CYAN}=== 黑名单 IP ===${NC}"
                fail2ban-client status sshd 2>/dev/null | grep "Banned IP list"
                read -p "按回车返回...";;
            3)
                read -p "输入要解封的 IP: " uip
                fail2ban-client set sshd unbanip $uip
                echo "操作已提交"; read -p "...";;
            4)
                systemctl stop fail2ban; systemctl disable fail2ban
                echo "已停止"; read -p "...";;
        esac
    done
}

# --- 2. 全局 WAF 管理 ---
function waf_manager() {
    while true; do
        clear; echo -e "${YELLOW}=== 🛡️ WAF 网站防火墙 ===${NC}"
        echo " 1. 部署/更新 WAF 规则到所有网站 (强制)"
        echo " 2. 查看当前 WAF 规则内容"
        echo " 0. 返回"
        read -p "选择: " op
        case $op in
            0) return;;
            1)
                echo -e "${BLUE}>>> 正在生成增强型 WAF 配置文件...${NC}"
                # 创建临时 WAF 文件
                cat > /tmp/waf_strict.conf <<EOF
# --- V55 增强型 WAF 规则 ---
# 1. 保护敏感文件
location ~* /\.(git|svn|hg|env|bak|config|sql|db|key|pem) { deny all; return 403; }
location ~* \.(sql|bak|conf|ini|log|sh|yaml|yml|swp)$ { deny all; return 403; }

# 2. 拦截 SQL 注入特征 (简易版)
if (\$query_string ~* "union.*select.*\(") { return 403; }
if (\$query_string ~* "concat.*\(") { return 403; }

# 3. 拦截恶意脚本特征
if (\$query_string ~* "base64_decode\(") { return 403; }
if (\$query_string ~* "eval\(") { return 403; }

# 4. 拦截恶意 User-Agent
if (\$http_user_agent ~* (netcralwer|nikto|wikto|sf|sqlmap|bsqlbf|w3af|acunetix|havij|appscan)) { return 403; }
EOF
                echo -e "${BLUE}>>> 正在分发到所有站点...${NC}"
                count=0
                for d in "$SITES_DIR"/*; do
                    if [ -d "$d" ]; then
                        cp /tmp/waf_strict.conf "$d/waf.conf"
                        echo " - 已更新: $(basename "$d")"
                        # 重载配置
                        cd "$d" && docker compose exec -T nginx nginx -s reload >/dev/null 2>&1
                        ((count++))
                    fi
                done
                rm -f /tmp/waf_strict.conf
                echo -e "${GREEN}✔ 操作完成，已保护 $count 个网站${NC}"; read -p "...";;
            2)
                echo -e "${CYAN}--- WAF 规则预览 ---${NC}"
                cat > /tmp/waf_preview.conf <<EOF
location ~* /\.(git|env|sql...) { deny all; }  # 敏感文件
if (\$query_string ~* "union.*select") { return 403; } # SQL注入
if (\$query_string ~* "eval\(") { return 403; } # 恶意脚本
if (\$http_user_agent ~* (sqlmap|nikto...)) { return 403; } # 扫描器
EOF
                cat /tmp/waf_preview.conf
                echo -e "${CYAN}--------------------${NC}"
                read -p "按回车返回...";;
        esac
    done
}

# --- 3. 防火墙与端口 (原 manage_firewall) ---
function port_manager() {
    ensure_firewall_installed || return
    while true; do
        clear; echo -e "${YELLOW}=== 🧱 端口与流量控制 ===${NC}"
        if command -v ufw >/dev/null; then FW="UFW"; STAT=$(ufw status | grep Status); else FW="Firewalld"; STAT=$(firewall-cmd --state); fi
        echo -e "系统: $FW | 状态: $STAT"
        echo "--------------------------"
        echo " 1. 查看开放端口"
        echo " 2. 开放/关闭 端口"
        echo " 3. 防 DOS 攻击配置"
        echo " 4. 一键全开 / 一键全锁"
        echo " 0. 返回"
        read -p "选择: " f
        case $f in
            0) return;;
            1) if [ "$FW" == "UFW" ]; then ufw status; else firewall-cmd --list-ports; fi; read -p "...";;
            2) 
                read -p "端口号: " p; read -p "1.开放 2.关闭: " a
                if [ "$FW" == "UFW" ]; then [ "$a" == "1" ] && ufw allow $p/tcp || ufw delete allow $p/tcp
                else act=$([ "$a" == "1" ] && echo "add" || echo "remove"); firewall-cmd --zone=public --${act}-port=${p}/tcp --permanent; firewall-cmd --reload; fi
                echo "OK"; sleep 1;;
            3)
                read -p "1.开启(标准) 2.关闭: " d
                if [ "$d" == "1" ]; then
                    echo "limit_req_zone \$binary_remote_addr zone=one:10m rate=10r/s; limit_conn_zone \$binary_remote_addr zone=addr:10m;" > "$FW_DIR/dos_zones.conf"
                    mkdir -p "$GATEWAY_DIR/vhost"; echo "limit_req zone=one burst=15 nodelay; limit_conn addr 15;" > "$GATEWAY_DIR/vhost/default"
                    cd "$GATEWAY_DIR" && docker compose up -d >/dev/null 2>&1 && docker exec gateway_proxy nginx -s reload
                    echo -e "${GREEN}✔ 防DOS已开启${NC}"
                else
                    rm -f "$FW_DIR/dos_zones.conf" "$GATEWAY_DIR/vhost/default"
                    cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload
                    echo -e "${GREEN}✔ 防DOS已关闭${NC}"
                fi
                read -p "...";;
            4)
                read -p "1.允许所有 2.封锁所有(保留SSH): " m
                if [ "$m" == "1" ]; then
                    [ "$FW" == "UFW" ] && ufw default allow incoming || firewall-cmd --set-default-zone=trusted
                else
                    if [ "$FW" == "UFW" ]; then ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp; ufw default deny incoming; ufw enable
                    else firewall-cmd --permanent --add-service={ssh,http,https}; firewall-cmd --set-default-zone=drop; firewall-cmd --reload; fi
                fi
                echo "设置完成"; read -p "...";;
        esac
    done
}

# --- 安全中心总入口 ---
function security_center() {
    while true; do
        clear; echo -e "${YELLOW}=== 🛡️ 安全防御中心 ===${NC}"
        echo " 1. 端口与防火墙 (Firewall)"
        echo " 2. SSH 防暴力破解 (Fail2Ban)"
        echo " 3. 网站防火墙 (WAF)"
        echo " 4. HTTPS 证书管理"
        echo " 5. 防盗链设置"
        echo " 0. 返回主菜单"
        read -p "选择: " s
        case $s in
            0) return;;
            1) port_manager;;
            2) fail2ban_manager;;
            3) waf_manager;;
            4) cert_management;;
            5) manage_hotlink;;
        esac
    done
}

# ================= 菜单系统 (V55) =================
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
    echo " 9. 解除上传限制 (一键扩容)"
    echo ""
    echo -e "${YELLOW}[数据管理]${NC}"
    echo " 10. 数据库 导出/导入"
    echo " 11. 整站 备份与还原"
    echo ""
    echo -e "${RED}[安全中心]${NC}"
    echo " 12. 进入安全防御中心 (Firewall/WAF/Fail2Ban...)"
    echo "-----------------------------------------"
    echo -e "${BLUE} u. 检查更新${NC} | ${RED}x. 卸载${NC} | 0. 退出"
    echo -n "请选择: "
    read option
}

# --- 其他未变动的核心功能函数 ---
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
function create_site() {
    read -p "1. 主域名: " fd; host_ip=$(curl -s4 ifconfig.me)
    if command -v dig >/dev/null; then dip=$(dig +short $fd | head -1); else dip=$(getent hosts $fd | awk '{print $1}'); fi
    if [ ! -z "$dip" ] && [ "$dip" != "$host_ip" ]; then echo -e "${RED}⚠️ IP不符: $dip vs $host_ip${NC}"; read -p "强制继续? (y/n): " f; [ "$f" != "y" ] && return; fi
    read -p "2. 邮箱: " email; read -p "3. DB密码: " db_pass
    pname=$(echo $fd | tr '.' '_'); sdir="$SITES_DIR/$fd"; [ -d "$sdir" ] && echo -e "${RED}❌ 目录已存在${NC}" && read -p "..." && return
    echo -e "\n${BLUE}>>> [1/4] 创建目录...${NC}"; mkdir -p "$sdir"
    echo -e "${BLUE}>>> [2/4] 生成配置...${NC}"
    # 默认写入新版加强 WAF
    cat > "$sdir/waf.conf" <<EOF
location ~* /\.(git|svn|hg|env|bak|config|sql|db|key|pem) { deny all; return 403; }
location ~* \.(sql|bak|conf|ini|log|sh|yaml|yml|swp)$ { deny all; return 403; }
if (\$query_string ~* "union.*select.*\(") { return 403; }
if (\$query_string ~* "concat.*\(") { return 403; }
if (\$query_string ~* "base64_decode\(") { return 403; }
if (\$query_string ~* "eval\(") { return 403; }
if (\$http_user_agent ~* (netcralwer|nikto|wikto|sf|sqlmap|bsqlbf|w3af|acunetix|havij|appscan)) { return 403; }
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
    echo -e "${BLUE}>>> [3/4] 编排容器...${NC}"
    cat > "$sdir/docker-compose.yml" <<EOF
services:
  db: {image: mysql:8.0, container_name: ${pname}_db, restart: always, command: --default-authentication-plugin=mysql_native_password, environment: {MYSQL_ROOT_PASSWORD: $db_pass, MYSQL_DATABASE: wordpress, MYSQL_USER: wp_user, MYSQL_PASSWORD: $db_pass}, volumes: [db_data:/var/lib/mysql], networks: [default]}
  redis: {image: redis:alpine, container_name: ${pname}_redis, restart: always, networks: [default]}
  wordpress: {image: wordpress:php8.2-fpm-alpine, container_name: ${pname}_app, restart: always, depends_on: [db, redis], environment: {WORDPRESS_DB_HOST: db, WORDPRESS_DB_USER: wp_user, WORDPRESS_DB_PASSWORD: $db_pass, WORDPRESS_DB_NAME: wordpress, WORDPRESS_CONFIG_EXTRA: "define('WP_REDIS_HOST','redis');define('WP_REDIS_PORT',6379);define('WP_HOME','https://'.\$\$_SERVER['HTTP_HOST']);define('WP_SITEURL','https://'.\$\$_SERVER['HTTP_HOST']);if(isset(\$\$_SERVER['HTTP_X_FORWARDED_PROTO'])&&strpos(\$\$_SERVER['HTTP_X_FORWARDED_PROTO'],'https')!==false){\$\$_SERVER['HTTPS']='on';}"}, volumes: [wp_data:/var/www/html, ./uploads.ini:/usr/local/etc/php/conf.d/uploads.ini], networks: [default]}
  nginx: {image: nginx:alpine, container_name: ${pname}_nginx, restart: always, volumes: [wp_data:/var/www/html, ./nginx.conf:/etc/nginx/conf.d/default.conf, ./waf.conf:/etc/nginx/waf.conf], environment: {VIRTUAL_HOST: "$fd", LETSENCRYPT_HOST: "$fd", LETSENCRYPT_EMAIL: "$email"}, networks: [default, proxy-net]}
volumes: {db_data: , wp_data: }
networks: {proxy-net: {external: true}}
EOF
    echo -e "${BLUE}>>> [4/4] 启动...${NC}"; cd "$sdir" && docker compose up -d; check_ssl_status "$fd"
}
function generate_nginx_conf() {
    local target_url=$1; local my_domain=$2; local mode=$3; local target_host=$(echo $target_url | awk -F/ '{print $3}')
    local conf_file="$SITES_DIR/$my_domain/nginx-proxy.conf"
    echo "server { listen 80; server_name localhost; resolver 8.8.8.8;" > "$conf_file"
    echo "location / {" >> "$conf_file"
    if [ "$mode" == "2" ]; then
        echo "    proxy_pass $target_url; proxy_set_header Host $target_host; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_ssl_server_name on;" >> "$conf_file"
    else
        echo "    proxy_pass $target_url; proxy_set_header Host $target_host; proxy_set_header Referer $target_url; proxy_ssl_server_name on; proxy_set_header Accept-Encoding \"\";" >> "$conf_file"
        echo "    sub_filter \"</head>\" \"<meta name='referrer' content='no-referrer'></head>\"; sub_filter \"$target_host\" \"$my_domain\"; sub_filter \"https://$target_host\" \"https://$my_domain\"; sub_filter \"http://$target_host\" \"https://$my_domain\";" >> "$conf_file"
        echo "    sub_filter_once off; sub_filter_types *;" >> "$conf_file"
    fi
    echo "}}" >> "$conf_file"
}
function create_proxy() {
    read -p "1. 主域名: " d; fd="$d"; read -p "2. 邮箱: " e; sdir="$SITES_DIR/$d"; mkdir -p "$sdir"
    echo -e "${YELLOW}目标类型:${NC} 1. 域名/URL (如 google.com)  2. IP:端口 (如 127.0.0.1:8080)"
    read -p "选择: " type
    if [ "$type" == "2" ]; then
        read -p "目标 IP (回车默认 127.0.0.1): " input_ip; [ -z "$input_ip" ] && input_ip="127.0.0.1"
        read -p "目标 端口: " input_port; [ -z "$input_port" ] && { echo -e "${RED}❌ 端口不能为空${NC}"; read -p "..."; return; }
        tu="http://$input_ip:$input_port"; echo -e "${CYAN}>>> 目标设置为: $tu${NC}"; pmode="2"
    else
        read -p "主目标 URL: " raw_tu; tu=$(normalize_url "$raw_tu"); echo -e "${YELLOW}代理模式:${NC} 1. 高级替换 (镜像站) 2. 普通代理 (透传)"; read -p "选择 [1-2]: " pmode; [ -z "$pmode" ] && pmode="1"
    fi
    generate_nginx_conf "$tu" "$d" "$pmode"
    cat > "$sdir/docker-compose.yml" <<EOF
services:
  proxy: {image: nginx:alpine, container_name: ${d//./_}_worker, restart: always, volumes: [./nginx-proxy.conf:/etc/nginx/conf.d/default.conf], extra_hosts: ["host.docker.internal:host-gateway"], environment: {VIRTUAL_HOST: "$fd", LETSENCRYPT_HOST: "$fd", LETSENCRYPT_EMAIL: "$e"}, networks: [proxy-net]}
networks: {proxy-net: {external: true}}
EOF
    cd "$sdir" && docker compose up -d >/dev/null 2>&1; echo -e "${GREEN}✔ 启动成功${NC}"; check_ssl_status "$d"
}
function repair_proxy() {
    ls -1 "$SITES_DIR"; read -p "输入域名: " d; sdir="$SITES_DIR/$d"; [ ! -d "$sdir" ] && return
    read -p "新目标 URL (或 http://IP:Port): " raw_tu; tu=$(normalize_url "$raw_tu")
    read -p "模式 (1.高级替换 2.普通代理): " pmode; [ -z "$pmode" ] && pmode="1"
    generate_nginx_conf "$tu" "$d" "$pmode"
    cd "$sdir" && docker compose restart >/dev/null 2>&1; echo -e "${GREEN}✔ 完成${NC}"; read -p "..."
}
function backup_restore_ops() {
    while true; do 
        clear; echo -e "${YELLOW}=== 备份与还原系统 ===${NC}"
        echo "1. 备份网站 (整站)" ; echo "2. 还原网站 (整站)"; echo "0. 返回"; read -p "选: " br 
        case $br in
            0) return;;
            1) ls -1 "$SITES_DIR"; echo "----------------"; read -p "输入要备份的域名: " d; s="$SITES_DIR/$d"
                if [ ! -d "$s" ]; then echo -e "${RED}❌ 找不到${NC}"; sleep 1; continue; fi
                timestamp=$(date +%Y%m%d_%H%M%S); bdir="$s/backups/$timestamp"; mkdir -p "$bdir"
                echo -e "${CYAN}>>> 正在导出数据库...${NC}"; cd "$s"; pwd=$(grep MYSQL_ROOT_PASSWORD docker-compose.yml|awk -F': ' '{print $2}')
                docker compose exec -T db mysqldump -u root -p"$pwd" --all-databases > "$bdir/db.sql"
                echo -e "${CYAN}>>> 正在打包文件...${NC}"
                wp_c=$(docker compose ps -q wordpress 2>/dev/null)
                if [ ! -z "$wp_c" ]; then docker run --rm --volumes-from $wp_c -v "$bdir":/backup alpine tar czf /backup/files.tar.gz /var/www/html/wp-content; fi
                cp *.conf docker-compose.yml "$bdir/" 2>/dev/null
                echo -e "${GREEN}✔ 备份成功! 路径: ${YELLOW}$bdir${NC}"; read -p "按回车继续...";;
            2) ls -1 "$SITES_DIR"; echo "----------------"; read -p "输入要还原的域名: " d; s="$SITES_DIR/$d"; backup_root="$s/backups"
                if [ ! -d "$backup_root" ]; then echo -e "${RED}❌ 无备份${NC}"; sleep 2; continue; fi
                latest_backup=$(ls -t "$backup_root" | head -n 1)
                if [ ! -z "$latest_backup" ]; then echo -e "最新备份: ${CYAN}$latest_backup${NC}"; read -p "使用此备份? (y/n): " use_latest; [ "$use_latest" == "y" ] && target_backup="$latest_backup"; fi
                if [ -z "$target_backup" ]; then ls -1 "$backup_root"; read -p "输入文件夹名: " target_backup; fi
                bp="$backup_root/$target_backup"; [ ! -d "$bp" ] && continue
                echo -e "${YELLOW}>>> 正在还原...${NC}"; cd "$s" && docker compose down
                vol=$(docker volume ls -q | grep "${d//./_}_wp_data"); [ ! -z "$vol" ] && docker run --rm -v $vol:/var/www/html -v "$bp":/backup alpine tar xzf /backup/files.tar.gz -C /
                docker compose up -d db; echo "等待DB..."; sleep 15; pwd=$(grep MYSQL_ROOT_PASSWORD docker-compose.yml|awk -F': ' '{print $2}')
                docker compose exec -T db mysql -u root -p"$pwd" < "$bp/db.sql"
                docker compose up -d; echo -e "${GREEN}✔ 还原完成${NC}"; read -p "按回车继续...";;
        esac
    done
}
function fix_upload_limit() { ls -1 "$SITES_DIR"; read -p "域名: " d; sdir="$SITES_DIR/$d"; [ ! -d "$sdir" ] && return; cat > "$sdir/uploads.ini" <<EOF
file_uploads=On
memory_limit=512M
upload_max_filesize=512M
post_max_size=512M
max_execution_time=600
EOF
if [ -f "$sdir/nginx.conf" ]; then sed -i 's/client_max_body_size .*/client_max_body_size 512M;/g' "$sdir/nginx.conf"; fi; cd "$sdir" && docker compose restart >/dev/null 2>&1; echo "OK"; read -p "..."; }
function create_redirect() { read -p "源域名: " s; read -p "目标URL: " t; t=$(normalize_url "$t"); read -p "邮箱: " e; sdir="$SITES_DIR/$s"; mkdir -p "$sdir"; echo "server { listen 80; server_name localhost; location / { return 301 $t\$request_uri; } }" > "$sdir/redirect.conf"; echo "services: {redirector: {image: nginx:alpine, container_name: ${s//./_}_redirect, restart: always, volumes: [./redirect.conf:/etc/nginx/conf.d/default.conf], environment: {VIRTUAL_HOST: \"$s\", LETSENCRYPT_HOST: \"$s\", LETSENCRYPT_EMAIL: \"$e\"}, networks: [proxy-net]}}" > "$sdir/docker-compose.yml"; echo "networks: {proxy-net: {external: true}}" >> "$sdir/docker-compose.yml"; cd "$sdir" && docker compose up -d >/dev/null 2>&1; echo -e "${GREEN}✔ 完成${NC}"; check_ssl_status "$s"; }
function delete_site() { while true; do clear; echo "=== 🗑️ 删除网站 ==="; ls -1 "$SITES_DIR"; echo "----------------"; echo "输入域名(0返回):"; read d; [ "$d" == "0" ] && return; if [ -d "$SITES_DIR/$d" ]; then read -p "确认删除 $d? (y/n): " c; if [ "$c" == "y" ]; then cd "$SITES_DIR/$d" && docker compose down -v >/dev/null 2>&1; cd .. && rm -rf "$SITES_DIR/$d"; echo -e "${GREEN}✔ 已删除${NC}"; fi; else echo "❌ 找不到"; fi; read -p "按回车继续..."; done; }
function list_sites() { clear; echo "=== 📂 站点列表 ==="; ls -1 "$SITES_DIR"; echo "----------------"; read -p "按回车返回..."; }
function container_ops() { while true; do clear; echo "=== 📊 状态 ==="; cd "$GATEWAY_DIR"; if docker compose ps | grep -q "Up"; then echo -e "${GREEN}● Gateway${NC}"; else echo -e "${RED}● Gateway${NC}"; fi; for d in "$SITES_DIR"/*; do [ -d "$d" ] && (cd "$d"; if docker compose ps | grep -q "Up"; then echo -e "${GREEN}● $(basename "$d")${NC}"; else echo -e "${RED}● $(basename "$d")${NC}"; fi); done; echo "1.全启 2.全停 3.全重启 4.指定启 5.指定停 6.指定重启 0.返回"; read -p "选: " c; case $c in 0) return;; 1) cd "$GATEWAY_DIR" && docker compose up -d >/dev/null 2>&1; for d in "$SITES_DIR"/*; do cd "$d" && docker compose up -d >/dev/null 2>&1; done;; 2) for d in "$SITES_DIR"/*; do cd "$d" && docker compose stop >/dev/null 2>&1; done; cd "$GATEWAY_DIR" && docker compose stop >/dev/null 2>&1;; 3) cd "$GATEWAY_DIR" && docker compose restart >/dev/null 2>&1; for d in "$SITES_DIR"/*; do cd "$d" && docker compose restart >/dev/null 2>&1; done;; 4|5|6) read -p "域名: " d; [ -d "$SITES_DIR/$d" ] && cd "$SITES_DIR/$d" && ([ "$c" == "4" ] && docker compose up -d || ([ "$c" == "5" ] && docker compose stop) || docker compose restart) >/dev/null 2>&1;; esac; [ "$c" != "0" ] && read -p "按回车确定..."; done; }
function cert_management() { while true; do clear; echo "1.看证书 2.上传 3.重置 4.续签 5.诊断 6.切换CA 0.返回"; read -p "选: " c; case $c in 0) return;; 1) docker exec gateway_proxy ls -lh /etc/nginx/certs | grep ".crt";; 2) ls -1 "$SITES_DIR"; read -p "域名: " d; read -p "crt: " c; read -p "key: " k; docker cp "$c" gateway_acme:"/etc/nginx/certs/$d.crt"; docker cp "$k" gateway_acme:"/etc/nginx/certs/$d.key"; docker exec gateway_proxy nginx -s reload;; 3) ls -1 "$SITES_DIR"; read -p "域名: " d; docker exec gateway_acme rm -f "/etc/nginx/certs/$d.crt" "/etc/nginx/certs/$d.key"; docker restart gateway_acme;; 4) docker exec gateway_acme /app/force_renew;; 5) docker logs --tail 30 gateway_acme; echo "---"; netstat -tuln|grep :80 || ss -tuln|grep :80;; 6) echo "1.LE 2.Zero"; read -p "选: " ca; [ "$ca" == "1" ] && s="letsencrypt" || s="zerossl"; docker exec gateway_acme acme.sh --set-default-ca --server $s; echo "OK";; esac; [ "$c" != "0" ] && read -p "按回车确定..."; done; }
function db_manager() { while true; do clear; echo "1.导出 2.导入 3.开Adminer 4.关Adminer 0.返回"; read -p "选: " c; case $c in 0) return;; 1) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; pwd=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml"|awk -F': ' '{print $2}'); docker compose -f "$s/docker-compose.yml" exec -T db mysqldump -u root -p"$pwd" --all-databases > "$s/${d}.sql"; echo "OK: $s/${d}.sql";; 2) ls -1 "$SITES_DIR"; read -p "域名: " d; read -p "SQL: " f; s="$SITES_DIR/$d"; pwd=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml"|awk -F': ' '{print $2}'); cat "$f" | docker compose -f "$s/docker-compose.yml" exec -T db mysql -u root -p"$pwd"; echo "OK";; 3) docker run --name temp_adminer -p 8888:8080 --network proxy-net -d adminer; echo "Port 8888";; 4) docker rm -f temp_adminer;; esac; read -p "按回车确定..."; done; }
function change_domain() { while true; do clear; ls -1 "$SITES_DIR"; echo "输入旧域名(0返回):"; read o; [ "$o" == "0" ] && return; [ ! -d "$SITES_DIR/$o" ] && continue; read -p "新域名: " n; cd "$SITES_DIR/$o" && docker compose down >/dev/null 2>&1; cd .. && mv "$o" "$n" && cd "$n"; sed -i "s/$o/$n/g" docker-compose.yml; docker compose up -d; wp_c=$(docker compose ps -q wordpress); docker run --rm --volumes-from $wp_c --network container:$wp_c wordpress:cli wp search-replace "$o" "$n" --all-tables --skip-columns=guid; docker exec gateway_proxy nginx -s reload; echo "OK"; read -p "按回车继续..."; done; }
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
function uninstall_cluster() {
    clear; echo -e "${RED}⚠️  危险警告：彻底卸载 ⚠️${NC}"; echo "这将删除所有网站数据！"; read -p "输入 'DELETE' 确认: " c
    [ "$c" != "DELETE" ] && return
    echo "1. 停止容器..."; ls "$SITES_DIR" | while read d; do cd "$SITES_DIR/$d" && docker compose down -v 2>/dev/null; done
    cd "$GATEWAY_DIR" && docker compose down -v 2>/dev/null
    docker network rm proxy-net 2>/dev/null
    echo "2. 删除文件..."; rm -rf "$BASE_DIR"; rm -f "/usr/bin/wp"
    echo -e "${GREEN}✔ 已卸载${NC}"; exit 0
}

# --- 主程序 ---
check_and_install_docker
install_shortcut
if ! docker ps --format '{{.Names}}' | grep -q "^gateway_proxy$"; then echo -e "${YELLOW}后台初始化...${NC}"; init_gateway "auto"; fi
while true; do show_menu; case $option in u|U) update_script;; 1) create_site;; 2) create_proxy;; 3) create_redirect;; 4) list_sites;; 5) container_ops;; 6) delete_site;; 7) change_domain;; 8) repair_proxy;; 9) fix_upload_limit;; 10) db_manager;; 11) backup_restore_ops;; 12) security_center;; x|X) uninstall_cluster;; 0) exit 0;; esac; done
