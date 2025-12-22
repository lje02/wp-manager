
---

Docker-Web
轻量级 Docker 运维管理工具，支持 WordPress 集群部署、反向代理、应用商店、安全防护、备份还原，并集成 Telegram 通知 和 WAF规则。

---

功能亮点
• WordPress一键部署：自动配置 Nginx + SSL，支持 PHP/MySQL/Redis 版本切换
• 应用商店：云端安装 Portainer、Alist 等热门应用
• 安全防护：防火墙、Fail2Ban、WAF规则、主机安全审计
• Telegram Bot：资源报警、指令交互
• 运维工具：容器监控、日志查看、WP-CLI工具箱、备份还原

---

安装
curl -sL https://raw.githubusercontent.com/lje02/wp-manager/main/wp-manager.sh -o wp-manager.sh
chmod +x wp-manager.sh
./wp-manager.sh

首次运行会自动安装依赖并初始化网关，创建快捷命令 wp。

---

快速使用
• 部署 WordPress：菜单 1
• 应用商店安装：菜单 4
• 查看站点：菜单 10
• 备份还原：菜单 23
• 安全防御中心：菜单 30
• Telegram通知：菜单 31

---

更新与卸载
• 更新脚本：wp u
• 卸载脚本：wp x（输入 DELETE 确认）

---

注意事项
• 系统要求：Linux，需 root 权限
• 确保 80/443 端口未被占用
• 建议结合防火墙和 Fail2Ban，避免公网暴露
