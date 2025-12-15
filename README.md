# 🐳 WordPress Docker 集群一键管家 (V49)

这是一个专为 VPS 设计的轻量级运维脚本，旨在帮助用户通过 Docker 快速构建、管理和保护 WordPress 站点。

## ✨ 核心亮点

* **🚀 极速部署**：一键自动化安装 Docker、WordPress、MySQL 8.0、Redis。
* **🔒 自动 HTTPS**：自动申请 Let's Encrypt / ZeroSSL 证书，支持到期监控与自动续签。
* **⚡ 性能优化**：内置 Redis 对象缓存配置，一键解除 Nginx/PHP 上传限制 (支持 1GB+)。
* **🛡️ 安全防御**：集成防火墙管理（端口/IP黑白名单）、防 DOS 攻击、防盗链设置。
* **🔄 反向代理**：内置强大的反代功能，支持外部资源聚合（解决混合内容/防盗链问题）。
* **💾 数据无忧**：支持数据库独立导出、整站打包备份与秒级还原。
* **⌨️ 全局指令**：安装后输入 `wp` 即可随时唤醒管理面板。

## 🖥️ 一键安装

无需复杂的配置，使用 SSH 连接服务器（需要 Root 权限）后执行以下命令：

```bash
curl -O [https://cdn.jsdelivr.net/gh/lje02/wp-manager@main/manager.sh](https://cdn.jsdelivr.net/gh/lje02/wp-manager@main/manager.sh) && chmod +x manager.sh && bash manager.sh

