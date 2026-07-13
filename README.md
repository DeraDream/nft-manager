# nft-manager

一个基于 `nftables` 的交互式端口转发管理脚本，支持 TCP/UDP DNAT + SNAT、目标主机别名、转发规则别名、systemd 保活和在线更新。
适合在 VPS 上快速配置和维护端口转发。

## 功能

- 交互式管理端口转发规则
- 自动安装和初始化 `nftables`
- 自动开启 IPv4 转发
- 自动尝试启用 BBR + fq
- 支持 TCP + UDP 同时转发
- 支持目标主机库，可为 IP 设置中文别名
- 支持为每条转发规则设置别名
- 查看和删除规则时按目标主机分区
- 安装后提供全局命令 `nft` 唤起菜单
- 安装后自动创建 systemd 保活服务
- 安装后自动创建 Web 面板，默认端口 `5555`
- Web 面板支持一次添加多个单端口
- Web 面板支持上传、下载、总计流量统计、24 小时趋势和规则开关
- 支持在线检查和更新脚本

## 安装

海外服务器或可直接访问 GitHub 的机器：

```bash
curl -L https://raw.githubusercontent.com/DeraDream/nft-manager/main/nft.sh -o nft.sh
chmod +x nft.sh
sudo ./nft.sh
```

国内服务器可使用 jsDelivr CDN：

```bash
curl -L https://cdn.jsdelivr.net/gh/DeraDream/nft-manager@main/nft.sh -o nft.sh
head -3 nft.sh
chmod +x nft.sh
sudo ./nft.sh
```

正常情况下，`head -3 nft.sh` 应显示：

```bash
#!/usr/bin/env bash
#
# nftables 端口转发管理工具 v2.3
```

如果看到 `<!DOCTYPE html>`、`Cloudflare`、`403`、`404` 等内容，说明下载到的是网页错误页，不要执行。

进入菜单后选择：

```text
1) 安装 nftables / 管理器
```

安装完成后，可直接使用全局命令打开菜单：

```bash
sudo nft
```

Web 面板默认地址：

```text
http://服务器出口IPv4:5555
```

默认账号和密码：

```text
admin / admin
```

首次登录后建议在 Web 面板的系统设置中修改密码。

## 菜单

```text
1) 安装/卸载 nftables 管理器
2) 更新脚本
3) 查看现有端口转发
4) 新增端口转发
5) 删除端口转发
6) 目标主机管理
7) 一键清空所有转发
8) 诊断/自检
0) 退出
```

## Web 面板

Web 面板默认监听 `0.0.0.0:5555`，安装完成后 SSH 菜单顶部会显示：

```text
Web 面板: http://当前VPS出口IPv4:5555
```

Web 面板包含：

- 仪表板
- 转发管理
- 主机管理
- 系统设置

新增转发时，入口端口输入框仅支持单个端口；可用空格或英文逗号一次输入多个端口：

```text
80 443 10000
80,443,10000
```

不支持端口段，例如 `100-200` 会直接提示错误。单次最多添加 1000 个端口。

出口端口支持：

- 与入口端口一致
- 指定出口起始端口

选择出口起始端口时，多个入口端口会按输入顺序依次映射到连续的出口端口。Web 面板使用 nftables counter 统计流量，活跃状态根据流量计数是否增长判断。

默认账号密码为：

```text
admin / admin
```

请在公网使用前修改默认密码，并确认服务器安全组/防火墙只向可信来源开放 `5555` 端口。

## 配置更新源

如果需要使用菜单里的更新功能，请将 GitHub Raw 地址写入：

```bash
sudo mkdir -p /etc/nftables.d
echo 'https://raw.githubusercontent.com/DeraDream/nft-manager/main/nft.sh' | sudo tee /etc/nftables.d/update-url
```

国内服务器可将代理后的地址写入更新源：

```bash
sudo mkdir -p /etc/nftables.d
echo 'https://cdn.jsdelivr.net/gh/DeraDream/nft-manager@main/nft.sh' | sudo tee /etc/nftables.d/update-url
```

之后进入菜单选择：

```text
2) 更新脚本
```

也可以临时使用环境变量指定更新源：

```bash
sudo NFT_FORWARD_UPDATE_URL='https://raw.githubusercontent.com/DeraDream/nft-manager/main/nft.sh' ./nft.sh
```

## 文件位置

安装后主要文件：

```text
/usr/local/lib/nft-forward/nft.sh
/usr/local/lib/nft-forward/web_panel.py
/usr/local/bin/nft
/etc/systemd/system/nft-forward-keepalive.service
/etc/systemd/system/nft-manager-web.service
/etc/nftables.conf
/etc/nftables.d/port-forward.conf
/etc/nftables.d/targets.conf
/etc/nftables.d/update-url
/etc/nftables.d/web-auth.conf
/etc/nftables.d/web-stats.json
/etc/nftables.d/web-history.json
/etc/sysctl.d/99-nft-forward.conf
/var/log/nft-forward.log
```

## 卸载

进入菜单选择：

```text
1) 卸载 nftables 管理器
```

卸载为完整卸载，会删除：

- 全局命令 `/usr/local/bin/nft`
- 安装目录 `/usr/local/lib/nft-forward`
- systemd 保活服务
- Web 面板服务
- 端口转发配置
- 目标主机库
- 更新源配置
- Web 面板账号文件
- Web 面板流量采样文件
- 脚本日志
- 脚本写入的 sysctl 配置
- 脚本写入的 logrotate 配置

卸载过程中会询问是否清空当前全部 nftables 运行规则。脚本不会卸载系统的 `nftables` 软件包。

## 注意

安装初始化时，脚本会接管 `/etc/nftables.conf` 和 `/etc/nftables.d/*.conf`。如果服务器已有复杂防火墙规则，请先备份：

```bash
sudo nft list ruleset > nftables.rules.backup
sudo cp -a /etc/nftables.conf /etc/nftables.conf.backup 2>/dev/null || true
sudo cp -a /etc/nftables.d /etc/nftables.d.backup 2>/dev/null || true
```

建议先在新 VPS 或测试环境验证后再用于生产服务器。
