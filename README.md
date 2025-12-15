# 🐳 WordPress Docker 集群一键管家 (V49)

这是一个专为 VPS 设计的轻量级运维脚本，一键解决 WordPress 建站的所有痛点。

## ✨ 核心亮点
* **🚀 极速部署**：一键安装 Docker、WordPress、MySQL、Redis。
* **🔒 自动 HTTPS**：自动申请、续签 SSL 证书，支持证书监控。
* **🛡️ 安全防御**：内置防火墙、防盗链、防 DOS 攻击配置。
* **⚡ 性能优化**：一键解除上传限制（支持 1GB+），集成反代资源聚合。
* **💾 数据无忧**：整站备份与秒级还原，支持数据库独立导出。

## 🖥️ 一键安装 脚本调出快捷指令"wp"
无需复杂的配置，SSH 连接服务器（Root 权限）后执行：

```bash
curl -O [https://cdn.jsdelivr.net/gh/lje02/wp-manager@main/manager.sh](https://cdn.jsdelivr.net/gh/lje02/wp-manager@main/manager.sh) && chmod +x manager.sh && bash manager.sh
