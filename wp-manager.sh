#!/bin/bash

# ================= 配置区域 =================
# 脚本版本号
VERSION="V60 (Telegram+ProxyFix)"

# 数据存储路径
BASE_DIR="/root/wp-cluster"
SITES_DIR="$BASE_DIR/sites"
GATEWAY_DIR="$BASE_DIR/gateway"
FW_DIR="$BASE_DIR/firewall"
TG_CONF="$BASE_DIR/telegram.conf"

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

# --- Telegram 发送工具 ---
function send_tg_msg() {
    local msg=$1
    if [ -f "$TG_CONF" ]; then
        source "$TG_CONF"
        if [ ! -z "$TG_BOT_TOKEN" ] && [ ! -z "$TG_CHAT_ID" ]; then
            curl -s -X POST "https://api.telegram.org/bot$TG_BOT_TOKEN/sendMessage" -d chat_id="$TG_CHAT_ID" -d text="$msg" >/dev/null
        fi
    fi
}

# ================= 核心功能模块 =================

# --- 1. 容器监控 (V60: 增强显示) ---
function container_ops() {
    while true; do
        clear; echo -e "${YELLOW}=== 📊 容器状态监控 (V60) ===${NC}"
        
        # 检查网关
        cd "$GATEWAY_DIR"
        echo "---------------------------------------------------"
        echo -e "网关 (Gateway):"
        docker compose ps --format "table {{.Service}}\t{{.State}}\t{{.Status}}" | tail -n +2 | while read line; do
            if echo "$line" | grep -q "running"; then echo -e "${GREEN}  $line${NC}"; else echo -e "${RED}  $line${NC}"; fi
        done

        # 检查所有站点
        for d in "$SITES_DIR"/*; do
            if [ -d "$d" ]; then
                site_name=$(basename "$d")
                echo "---------------------------------------------------"
                echo -e "站点: ${CYAN}$site_name${NC}"
                cd "$d"
                # 显示所有容器状态，不仅仅是 Up 的
                docker compose ps --all --format "table {{.Service}}\t{{.State}}\t{{.Status}}" | tail -n +2 | while read line; do
                    if echo "$line" | grep -q "running"; then 
                        echo -e "${GREEN}  $line${NC}"
                    elif echo "$line" | grep -q "exited"; then
                        echo -e "${RED}  $line (已停止)${NC}"
                    else
                        echo -e "${YELLOW}  $line (状态异常)${NC}"
                    fi
                done
            fi
        done
        echo "---------------------------------------------------"
        echo " 1. 全部启动 (Start All)"
        echo " 2. 全部停止 (Stop All)"
        echo " 3. 全部重启 (Restart All)"
        echo " 4. 指定站点操作"
        echo " 0. 返回"
        read -p "选择: " c
        
        case $c in
            0) return;;
            1) cd "$GATEWAY_DIR" && docker compose up -d; for d in "$SITES_DIR"/*; do cd "$d" && docker compose up -d; done; echo "已全部启动"; read -p "...";;
            2) for d in "$SITES_DIR"/*; do cd "$d" && docker compose stop; done; cd "$GATEWAY_DIR" && docker compose stop; echo "已全部停止"; read -p "...";;
            3) cd "$GATEWAY_DIR" && docker compose restart; for d in "$SITES_DIR"/*; do cd "$d" && docker compose restart; done; echo "已全部重启"; read -p "...";;
            4) 
                ls -1 "$SITES_DIR"
                read -p "输入域名: " d; sdir="$SITES_DIR/$d"
                if [ -d "$sdir" ]; then
                    cd "$sdir"
                    read -p "1.启动 2.停止 3.重启: " a
                    case $a in 1) docker compose up -d;; 2) docker compose stop;; 3) docker compose restart;; esac
                    echo "操作完成"
                else echo "找不到站点"; fi
                read -p "..."
                ;;
        esac
    done
}

# --- 2. Telegram 通知中心 (V60: 回归) ---
function notify_manager() {
    while true; do
        clear; echo -e "${YELLOW}=== 📢 通知中心 (Telegram) ===${NC}"
        if [ -f "$TG_CONF" ]; then source "$TG_CONF"; fi
        echo -e "当前 Token: ${CYAN}${TG_BOT_TOKEN:0:10}******${NC}"
        echo -e "当前 ChatID: ${CYAN}$TG_CHAT_ID${NC}"
        echo "--------------------------"
        echo " 1. 配置 机器人 Token"
        echo " 2. 配置 Chat ID"
        echo " 3. 发送测试消息"
        echo " 0. 返回"
        read -p "选择: " n
        case $n in
            0) return;;
            1) read -p "输入 Bot Token: " t; echo "TG_BOT_TOKEN=\"$t\"" > "$TG_CONF"; [ ! -z "$TG_CHAT_ID" ] && echo "TG_CHAT_ID=\"$TG_CHAT_ID\"" >> "$TG_CONF";;
            2) read -p "输入 Chat ID: " c; [ ! -z "$TG_BOT_TOKEN" ] && echo "TG_BOT_TOKEN=\"$TG_BOT_TOKEN\"" > "$TG_CONF"; echo "TG_CHAT_ID=\"$c\"" >> "$TG_CONF";;
            3) send_tg_msg "🔔 [WP-Cluster] 这是一条来自服务器的测试消息。"; echo "已发送，请检查手机。"; read -p "...";;
        esac
    done
}

# --- 3. 组件版本管理 ---
function component_manager() {
    while true; do
        clear; echo -e "${YELLOW}=== 🆙 组件版本升降级 ===${NC}"
        ls -1 "$SITES_DIR"
        echo "--------------------------"
        read -p "请输入要操作的域名 (0返回): " d; [ "$d" == "0" ] && return
        sdir="$SITES_DIR/$d"; if [ ! -d "$sdir" ]; then echo -e "${RED}❌ 站点不存在${NC}"; sleep 1; continue; fi
        
        cur_wp=$(grep "image: wordpress" "$sdir/docker-compose.yml" | awk '{print $2}')
        cur_db=$(grep "image: .*sql" "$sdir/docker-compose.yml" | awk '{print $2}')
        echo -e "当前: PHP=[$cur_wp] DB=[$cur_db]"
        echo "--------------------------"
        echo " 1. 切换 PHP 版本 (7.4/8.0/8.1/8.2/Latest)"
        echo " 2. 切换 数据库 版本 (MySQL/MariaDB)"
        echo " 3. 切换 Redis 版本"
        echo " 4. 切换 Nginx 版本"
        echo " 0. 返回"
        read -p "选择: " op
        case $op in
            0) break;;
            1)
                echo "1.PHP 7.4  2.PHP 8.0  3.PHP 8.1  4.PHP 8.2  5.Latest"
                read -p "选: " p
                case $p in 1) t="php7.4-fpm-alpine";; 2) t="php8.0-fpm-alpine";; 3) t="php8.1-fpm-alpine";; 4) t="php8.2-fpm-alpine";; 5) t="fpm-alpine";; *) continue;; esac
                sed -i "s|image: wordpress:.*|image: wordpress:$t|g" "$sdir/docker-compose.yml"
                cd "$sdir" && docker compose up -d; echo "OK"; read -p "...";;
            2)
                echo -e "${RED}⚠️ 数据库降级需谨慎!${NC}"; echo "1.MySQL 5.7  2.MySQL 8.0  3.MySQL Latest  4.MariaDB 10.6  5.MariaDB Latest"
                read -p "选: " v
                case $v in 1) i="mysql:5.7";; 2) i="mysql:8.0";; 3) i="mysql:latest";; 4) i="mariadb:10.6";; 5) i="mariadb:latest";; *) continue;; esac
                sed -i "s|image: .*sql:.*|image: $i|g" "$sdir/docker-compose.yml"; sed -i "s|image: mariadb:.*|image: $i|g" "$sdir/docker-compose.yml"
                cd "$sdir" && docker compose up -d; echo "OK"; read -p "...";;
            3)
                echo "1.Redis 6.2  2.Redis 7.0  3.Redis Latest"
                read -p "选: " r
                case $r in 1) rt="6.2-alpine";; 2) rt="7.0-alpine";; 3) rt="alpine";; *) continue;; esac
                sed -i "s|image: redis:.*|image: redis:$rt|g" "$sdir/docker-compose.yml"
                cd "$sdir" && docker compose up -d; echo "OK"; read -p "...";;
            4)
                echo "1.Nginx Alpine  2.Nginx Latest"
                read -p "选: " n; [ "$n" == "2" ] && nt="latest" || nt="alpine"
                sed -i "s|image: nginx:.*|image: nginx:$nt|g" "$sdir/docker-compose.yml"
                cd "$sdir" && docker compose up -d; echo "OK"; read -p "...";;
        esac
    done
}

# --- 4. 生成器 (V60: 修复资源聚合循环) ---
function generate_nginx_conf() {
    local target_url=$1; local my_domain=$2; local mode=$3; local target_host=$(echo $target_url | awk -F/ '{print $3}')
    local conf_file="$SITES_DIR/$my_domain/nginx-proxy.conf"
    
    echo "server { listen 80; server_name localhost; resolver 8.8.8.8;" > "$conf_file"
    echo "location / {" >> "$conf_file"
    
    if [ "$mode" == "2" ]; then
        # 普通代理
        echo "    proxy_pass $target_url; proxy_set_header Host $target_host; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_ssl_server_name on;" >> "$conf_file"
    else
        # 高级代理 (带内容替换)
        echo "    proxy_pass $target_url; proxy_set_header Host $target_host; proxy_set_header Referer $target_url; proxy_ssl_server_name on; proxy_set_header Accept-Encoding \"\";" >> "$conf_file"
        echo "    sub_filter \"</head>\" \"<meta name='referrer' content='no-referrer'></head>\";" >> "$conf_file"
        echo "    sub_filter \"$target_host\" \"$my_domain\";" >> "$conf_file"
        echo "    sub_filter \"https://$target_host\" \"https://$my_domain\";" >> "$conf_file"
        echo "    sub_filter \"http://$target_host\" \"https://$my_domain\";" >> "$conf_file"
        
        # --- V60 恢复：外部资源聚合循环 ---
        echo -e "${YELLOW}--- [V60 特性] 外部资源聚合 ---${NC}"
        echo "可以输入外部资源的URL（如CDN图片、字体），脚本会自动将其映射到本地域名下，解决跨域/防盗链问题。"
        local count=1
        while true; do
            read -p "输入外部资源URL (回车结束): " raw_ext
            [ -z "$raw_ext" ] && break
            
            local ext_url=$(normalize_url "$raw_ext")
            local ext_host=$(echo $ext_url | awk -F/ '{print $3}')
            local path_key="_res_${count}"
            
            echo -e "${GREEN}>>> 映射建立: $ext_host -> $my_domain/$path_key/${NC}"
            
            # 1. 在主 location 中添加替换规则
            cat >> "$conf_file" <<EOF
    sub_filter "$ext_host" "$my_domain/$path_key";
    sub_filter "https://$ext_host" "https://$my_domain/$path_key";
    sub_filter "http://$ext_host" "https://$my_domain/$path_key";
EOF
            # 2. 生成对应的 location 块 (追加到临时文件，最后合并)
            cat >> "$conf_file.locations" <<EOF
location /$path_key/ {
    rewrite ^/$path_key/(.*) /\$1 break;
    proxy_pass $ext_url;
    proxy_set_header Host $ext_host;
    proxy_set_header Referer $ext_url;
    proxy_ssl_server_name on;
    proxy_set_header Accept-Encoding "";
}
EOF
            ((count++))
        done
        
        echo "    sub_filter_once off; sub_filter_types *;" >> "$conf_file"
    fi
    echo "}" >> "$conf_file"
    
    # 合并 location 块
    if [ -f "$conf_file.locations" ]; then
        cat "$conf_file.locations" >> "$conf_file"
        rm "$conf_file.locations"
    fi
    
    echo "}" >> "$conf_file"
}

# --- 5. 反向代理 (创建) ---
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

# --- 6. 防火墙 ---
function port_manager() {
    ensure_firewall_installed || return
    if command -v ufw >/dev/null && ! ufw status | grep -q "active"; then ufw allow 22/tcp >/dev/null; ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null; echo "y" | ufw enable >/dev/null; fi
    while true; do
        clear; echo -e "${YELLOW}=== 🧱 端口防火墙 ===${NC}"
        if command -v ufw >/dev/null; then FW="UFW"; if ufw status | grep -q "active"; then STAT="${GREEN}Active${NC}"; else STAT="${RED}Inactive${NC}"; fi; else FW="Firewalld"; STAT="${GREEN}Running${NC}"; fi
        echo -e "防火墙: $FW | 状态: $STAT"
        echo "--------------------------"
        echo " 1. 查看开放端口"; echo " 2. 开放/关闭 端口"; echo " 3. 防 DOS (标准/关闭)"; echo " 4. 一键全开 / 一键全锁"; echo " 0. 返回"; read -p "选: " f
        case $f in
            0) return;;
            1) if [ "$FW" == "UFW" ]; then ufw status; else firewall-cmd --list-ports; fi; read -p "按回车返回...";;
            2) read -p "端口: " p; echo "1.开放 2.关闭"; read -p "选: " a; if [ "$FW" == "UFW" ]; then [ "$a" == "1" ] && ufw allow $p/tcp || ufw delete allow $p/tcp; else act=$([ "$a" == "1" ] && echo "add" || echo "remove"); firewall-cmd --zone=public --${act}-port=${p}/tcp --permanent; firewall-cmd --reload; fi; echo -e "${GREEN}✔ 配置成功!${NC}"; read -p "按回车返回...";;
            3) echo "1.开启防DOS(标准) 2.关闭"; read -p "选: " d; if [ "$d" == "1" ]; then echo "limit_req_zone \$binary_remote_addr zone=one:10m rate=10r/s; limit_conn_zone \$binary_remote_addr zone=addr:10m;" > "$FW_DIR/dos_zones.conf"; mkdir -p "$GATEWAY_DIR/vhost"; echo "limit_req zone=one burst=15 nodelay; limit_conn addr 15;" > "$GATEWAY_DIR/vhost/default"; cd "$GATEWAY_DIR" && docker compose up -d >/dev/null 2>&1 && docker exec gateway_proxy nginx -s reload; echo -e "${GREEN}✔ 已开启${NC}"; else rm -f "$FW_DIR/dos_zones.conf" "$GATEWAY_DIR/vhost/default"; cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload; echo -e "${GREEN}✔ 已关闭${NC}"; fi; read -p "...";;
            4) echo "1.允许所有 2.封锁所有(保SSH)"; read -p "选: " m; if [ "$m" == "1" ]; then [ "$FW" == "UFW" ] && ufw default allow incoming || firewall-cmd --set-default-zone=trusted; else if [ "$FW" == "UFW" ]; then ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp; ufw default deny incoming; else firewall-cmd --permanent --add-service={ssh,http,https}; firewall-cmd --set-default-zone=drop; firewall-cmd --reload; fi; fi; echo -e "${GREEN}✔ 配置成功!${NC}"; read -p "...";;
        esac
    done
}

# --- 其他模块保持精简 ---
function security_center() {
    while true; do
        clear; echo -e "${YELLOW}=== 🛡️ 安全防御中心 ===${NC}"
        echo " 1. 端口防火墙 (Layer 4)"; echo " 2. 流量访问控制 (Layer 7)"; echo " 3. SSH 防暴破 (Fail2Ban)"; echo " 4. 网站防火墙 (WAF)"; echo " 5. HTTPS 证书"; echo " 6. 防盗链"; echo " 0. 返回"; read -p "选: " s
        case $s in 0) return;; 1) port_manager;; 2) traffic_manager;; 3) fail2ban_manager;; 4) waf_manager;; 5) cert_management;; 6) manage_hotlink;; esac
    done
}
function fail2ban_manager() {
    while true; do
        clear; echo -e "${YELLOW}=== 👮 Fail2Ban ===${NC}"
        echo " 1. 安装(5次封24h) 2. 列表 3. 解封 0. 返回"; read -p "选: " o; case $o in
            0) return;;
            1) echo "安装中..."; if [ -f /etc/debian_version ]; then apt-get install -y fail2ban; lp="/var/log/auth.log"; else yum install -y fail2ban; lp="/var/log/secure"; fi; cat >/etc/fail2ban/jail.local <<EOF
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
            systemctl enable fail2ban; systemctl restart fail2ban; echo "OK"; read -p "...";;
            2) fail2ban-client status sshd|grep Banned; read -p "...";;
            3) read -p "IP: " i; fail2ban-client set sshd unbanip $i; echo "OK"; read -p "...";;
        esac
    done
}
function waf_manager() {
    while true; do clear; echo -e "${YELLOW}=== WAF ===${NC}"; echo "1. 部署 2. 查看 0. 返回"; read -p "选: " o; case $o in 0) return;; 1) echo "部署..."; cat >/tmp/w <<EOF
location ~* /\.(git|svn|env|sql) { deny all; return 403; }
if (\$query_string ~* "(union.*select|eval\()") { return 403; }
EOF
    for d in "$SITES_DIR"/*; do [ -d "$d" ] && cp /tmp/w "$d/waf.conf" && cd "$d" && docker compose exec -T nginx nginx -s reload; done; rm /tmp/w; echo "OK"; read -p "...";; 2) cat "$SITES_DIR/"*"/waf.conf" 2>/dev/null|head -5; read -p "...";; esac; done
}
function traffic_manager() {
    while true; do clear; echo -e "${YELLOW}=== ACL ===${NC}"; echo "1.黑名单 2.白名单 3.国家 4.清空 0.返回"; read -p "选: " t; case $t in 0) return;; 1|2) tp="deny"; [ "$t" == "2" ] && tp="allow"; read -p "IP: " i; echo "$tp $i;" >> "$FW_DIR/access.conf"; cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload; echo "OK"; read -p "...";; 3) read -p "Code(cn): " c; wget -qO- "http://www.ipdeny.com/ipblocks/data/countries/$c.zone" | while read l; do echo "deny $l;" >> "$FW_DIR/geo.conf"; done; cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload; echo "OK"; read -p "...";; 4) echo "" > "$FW_DIR/access.conf"; echo "" > "$FW_DIR/geo.conf"; cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload; echo "OK"; read -p "...";; esac; done
}
function cert_management() { while true; do clear; echo "1.列表 2.上传 3.重置 4.续签 0.返回"; read -p "选: " c; case $c in 0) return;; 1) docker exec gateway_proxy ls -lh /etc/nginx/certs|grep .crt; read -p "...";; 2) ls -1 "$SITES_DIR"; read -p "Domain: " d; read -p "crt: " c; read -p "key: " k; docker cp "$c" gateway_acme:"/etc/nginx/certs/$d.crt"; docker cp "$k" gateway_acme:"/etc/nginx/certs/$d.key"; docker exec gateway_proxy nginx -s reload; echo "OK"; read -p "...";; 3) read -p "Domain: " d; docker exec gateway_acme rm -f "/etc/nginx/certs/$d.crt" "/etc/nginx/certs/$d.key"; docker restart gateway_acme; echo "OK"; read -p "...";; 4) docker exec gateway_acme /app/force_renew; echo "OK"; read -p "...";; esac; done; }
function manage_hotlink() { while true; do clear; echo "1.开 2.关 0.返"; read -p "选: " h; case $h in 0) return;; 1) ls -1 "$SITES_DIR"; read -p "Domain: " d; s="$SITES_DIR/$d"; if [ -f "$s/nginx.conf" ]; then read -p "白名单(空格隔开): " w; cat > "$s/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M;
location ~* \.(gif|jpg|png|webp)$ { valid_referers none blocked server_names $d *.$d $w; if (\$invalid_referer) { return 403; } try_files \$uri \$uri/ /index.php?\$args; }
location / { try_files \$uri \$uri/ /index.php?\$args; }
location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } }
EOF
cd "$s" && docker compose restart nginx; echo -e "${GREEN}✔ 成功${NC}"; fi;; 2) ls -1 "$SITES_DIR"; read -p "Domain: " d; s="$SITES_DIR/$d"; if [ -f "$s/nginx.conf" ]; then cat > "$s/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M;
location / { try_files \$uri \$uri/ /index.php?\$args; }
location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } }
EOF
cd "$s" && docker compose restart nginx; echo -e "${GREEN}✔ 成功${NC}"; fi;; esac; read -p "..."; done; }

# --- 初始化与创建 ---
function init_gateway() { local m=$1; if ! docker network ls|grep -q proxy-net; then docker network create proxy-net >/dev/null; fi; mkdir -p "$GATEWAY_DIR"; cd "$GATEWAY_DIR"; echo "client_max_body_size 1024m;" > upload_size.conf; echo "proxy_read_timeout 600s;" >> upload_size.conf; echo "proxy_send_timeout 600s;" >> upload_size.conf; cat > docker-compose.yml <<EOF
services:
  nginx-proxy: {image: nginxproxy/nginx-proxy, container_name: gateway_proxy, ports: ["80:80", "443:443"], volumes: [conf:/etc/nginx/conf.d, vhost:/etc/nginx/vhost.d, html:/usr/share/nginx/html, certs:/etc/nginx/certs:ro, /var/run/docker.sock:/tmp/docker.sock:ro, ../firewall/access.conf:/etc/nginx/conf.d/z_access.conf:ro, ../firewall/geo.conf:/etc/nginx/conf.d/z_geo.conf:ro, ./upload_size.conf:/etc/nginx/conf.d/upload_size.conf:ro], networks: ["proxy-net"], restart: always, environment: ["TRUST_DOWNSTREAM_PROXY=true"]}
  acme-companion: {image: nginxproxy/acme-companion, container_name: gateway_acme, volumes: [conf:/etc/nginx/conf.d, vhost:/etc/nginx/vhost.d, html:/usr/share/nginx/html, certs:/etc/nginx/certs:rw, acme:/etc/acme.sh, /var/run/docker.sock:/var/run/docker.sock:ro], environment: ["DEFAULT_EMAIL=admin@localhost.com", "NGINX_PROXY_CONTAINER=gateway_proxy", "ACME_CA_URI=https://acme-v02.api.letsencrypt.org/directory"], networks: ["proxy-net"], depends_on: ["nginx-proxy"], restart: always}
volumes: {conf: , vhost: , html: , certs: , acme: }
networks: {proxy-net: {external: true}}
EOF
if docker compose up -d --remove-orphans >/dev/null 2>&1; then [ "$m" == "force" ] && echo -e "${GREEN}✔ 网关启动成功${NC}"; else echo -e "${RED}✘ 网关启动失败${NC}"; [ "$m" == "force" ] && docker compose up -d; fi; }

function create_site() {
    read -p "1. Domain: " fd; host_ip=$(curl -s4 ifconfig.me); if command -v dig >/dev/null; then dip=$(dig +short $fd|head -1); else dip=$(getent hosts $fd|awk '{print $1}'); fi; if [ ! -z "$dip" ] && [ "$dip" != "$host_ip" ]; then echo -e "${RED}IP Error${NC}"; read -p "Force? (y/n): " f; [ "$f" != "y" ] && return; fi
    read -p "2. Email: " email; read -p "3. DB Pass: " db_pass
    echo -e "${YELLOW}使用自定义版本? (Default: PHP8.2/MySQL8.0/Redis7)${NC}"; read -p "y/n: " cust
    pt="php8.2-fpm-alpine"; di="mysql:8.0"; rt="7.0-alpine"
    if [ "$cust" == "y" ]; then
        echo "PHP: 1.7.4 2.8.0 3.8.1 4.8.2 5.8.3 6.Latest"; read -p "Select: " p; case $p in 1) pt="php7.4-fpm-alpine";; 2) pt="php8.0-fpm-alpine";; 3) pt="php8.1-fpm-alpine";; 4) pt="php8.2-fpm-alpine";; 5) pt="php8.3-fpm-alpine";; 6) pt="fpm-alpine";; esac
        echo "DB: 1.MySQL5.7 2.MySQL8.0 3.Latest 4.MariaDB10.6 5.Latest"; read -p "Select: " d; case $d in 1) di="mysql:5.7";; 2) di="mysql:8.0";; 3) di="mysql:latest";; 4) di="mariadb:10.6";; 5) di="mariadb:latest";; esac
        echo "Redis: 1.6.2 2.7.0 3.Latest"; read -p "Select: " r; case $r in 1) rt="6.2-alpine";; 2) rt="7.0-alpine";; 3) rt="alpine";; esac
    fi
    pname=$(echo $fd|tr '.' '_'); sdir="$SITES_DIR/$fd"; [ -d "$sdir" ] && return; mkdir -p "$sdir"
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
    cd "$sdir" && docker compose up -d; check_ssl_status "$fd"
}

# --- 其他辅助功能 ---
function list_sites() { clear; echo "=== 📂 站点列表 ==="; ls -1 "$SITES_DIR"; echo "----------------"; read -p "按回车返回..."; }
function delete_site() { while true; do clear; echo "=== 🗑️ 删除网站 ==="; ls -1 "$SITES_DIR"; echo "----------------"; echo "输入域名(0返回):"; read d; [ "$d" == "0" ] && return; if [ -d "$SITES_DIR/$d" ]; then read -p "确认删除 $d? (y/n): " c; if [ "$c" == "y" ]; then cd "$SITES_DIR/$d" && docker compose down -v >/dev/null 2>&1; cd .. && rm -rf "$SITES_DIR/$d"; echo -e "${GREEN}✔ 已删除${NC}"; fi; else echo "❌ 找不到"; fi; read -p "按回车继续..."; done; }
function repair_proxy() { ls -1 "$SITES_DIR"; read -p "输入域名: " d; sdir="$SITES_DIR/$d"; [ ! -d "$sdir" ] && return; read -p "新目标URL: " tu; tu=$(normalize_url "$tu"); generate_nginx_conf "$tu" "$d" "1"; cd "$sdir" && docker compose restart >/dev/null 2>&1; echo "OK"; read -p "..."; }
function fix_upload_limit() { ls -1 "$SITES_DIR"; read -p "域名: " d; sdir="$SITES_DIR/$d"; [ ! -d "$sdir" ] && return; cat > "$sdir/uploads.ini" <<EOF
file_uploads=On; memory_limit=512M; upload_max_filesize=512M; post_max_size=512M; max_execution_time=600;
EOF
if [ -f "$sdir/nginx.conf" ]; then sed -i 's/client_max_body_size .*/client_max_body_size 512M;/g' "$sdir/nginx.conf"; fi; cd "$sdir" && docker compose restart >/dev/null 2>&1; echo "OK"; read -p "..."; }
function change_domain() { ls -1 "$SITES_DIR"; echo "输入旧域名(0返回):"; read o; [ "$o" == "0" ] && return; [ ! -d "$SITES_DIR/$o" ] && continue; read -p "新域名: " n; cd "$SITES_DIR/$o" && docker compose down >/dev/null 2>&1; cd .. && mv "$o" "$n" && cd "$n"; sed -i "s/$o/$n/g" docker-compose.yml; docker compose up -d; wp_c=$(docker compose ps -q wordpress); docker run --rm --volumes-from $wp_c --network container:$wp_c wordpress:cli wp search-replace "$o" "$n" --all-tables --skip-columns=guid; docker exec gateway_proxy nginx -s reload; echo "OK"; read -p "..."; }
function backup_restore_ops() { while true; do clear; echo "=== 备份/还原 ==="; echo "1.备份 2.还原 0.返回"; read -p "选: " b; case $b in 0) return;; 1) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; [ ! -d "$s" ] && continue; bd="$s/backups/$(date +%Y%m%d%H%M)"; mkdir -p "$bd"; cd "$s"; pwd=$(grep MYSQL_ROOT_PASSWORD docker-compose.yml|awk -F': ' '{print $2}'); docker compose exec -T db mysqldump -u root -p"$pwd" --all-databases > "$bd/db.sql"; wp_c=$(docker compose ps -q wordpress); docker run --rm --volumes-from $wp_c -v "$bd":/backup alpine tar czf /backup/files.tar.gz /var/www/html/wp-content; cp *.conf docker-compose.yml "$bd/"; echo "OK: $bd"; read -p "...";; 2) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; bd="$s/backups"; [ ! -d "$bd" ] && continue; ls -1 "$bd"; read -p "备份名: " n; bp="$bd/$n"; [ ! -d "$bp" ] && continue; cd "$s" && docker compose down; vol=$(docker volume ls -q|grep "${d//./_}_wp_data"); docker run --rm -v $vol:/var/www/html -v "$bp":/backup alpine tar xzf /backup/files.tar.gz -C /; docker compose up -d db; sleep 15; pwd=$(grep MYSQL_ROOT_PASSWORD docker-compose.yml|awk -F': ' '{print $2}'); docker compose exec -T db mysql -u root -p"$pwd" < "$bp/db.sql"; docker compose up -d; echo "OK"; read -p "...";; esac; done; }
function uninstall_cluster() { echo "⚠️ 危险: 输入 DELETE 确认卸载"; read -p "> " c; [ "$c" == "DELETE" ] && (ls "$SITES_DIR"|while read d; do cd "$SITES_DIR/$d" && docker compose down -v; done; cd "$GATEWAY_DIR" && docker compose down -v; docker network rm proxy-net; rm -rf "$BASE_DIR" /usr/bin/wp; echo "已卸载"); }

# --- 主程序 ---
check_and_install_docker
install_shortcut
if ! docker ps --format '{{.Names}}' | grep -q "^gateway_proxy$"; then echo -e "${YELLOW}后台初始化...${NC}"; init_gateway "auto"; fi
while true; do show_menu; case $option in u|U) update_script;; 1) create_site;; 2) create_proxy;; 3) create_redirect;; 4) list_sites;; 5) container_ops;; 6) delete_site;; 7) change_domain;; 8) repair_proxy;; 9) component_manager;; 10) fix_upload_limit;; 11) db_manager;; 12) backup_restore_ops;; 13) security_center;; 14) notify_manager;; x|X) uninstall_cluster;; 0) exit 0;; esac; done
