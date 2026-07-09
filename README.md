# nft-manager

一个基于 `nftables` 的交互式端口转发管理脚本，支持 TCP/UDP DNAT + SNAT、目标主机别名、转发规则别名、systemd 保活和在线更新。

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
- 支持在线检查和更新脚本

## 安装

海外服务器或可直接访问 GitHub 的机器：

```bash
curl -L https://raw.githubusercontent.com/DeraDream/nft-manager/main/nft.sh -o nft.sh
chmod +x nft.sh
sudo ./nft.sh
```

国内服务器可使用 GitHub 代理：

```bash
curl -L https://gh-proxy.com/https://raw.githubusercontent.com/DeraDream/nft-manager/main/nft.sh -o nft.sh
chmod +x nft.sh
sudo ./nft.sh
```

进入菜单后选择：

```text
1) 安装 nftables / 管理器
```

安装完成后，可直接使用全局命令打开菜单：

```bash
sudo nft
```

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

## 配置更新源

如果需要使用菜单里的更新功能，请将 GitHub Raw 地址写入：

```bash
sudo mkdir -p /etc/nftables.d
echo 'https://raw.githubusercontent.com/DeraDream/nft-manager/main/nft.sh' | sudo tee /etc/nftables.d/update-url
```

国内服务器可将代理后的地址写入更新源：

```bash
sudo mkdir -p /etc/nftables.d
echo 'https://gh-proxy.com/https://raw.githubusercontent.com/DeraDream/nft-manager/main/nft.sh' | sudo tee /etc/nftables.d/update-url
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
/usr/local/bin/nft
/etc/systemd/system/nft-forward-keepalive.service
/etc/nftables.conf
/etc/nftables.d/port-forward.conf
/etc/nftables.d/targets.conf
/etc/nftables.d/update-url
/etc/sysctl.d/99-nft-forward.conf
/var/log/nft-forward.log
```

## 卸载管理器

进入菜单选择：

```text
1) 卸载 nftables 管理器
```

卸载会移除全局命令和 systemd 保活服务，但不会自动清空已有转发规则，也不会卸载系统的 `nftables` 软件包。

## 注意

安装初始化时，脚本会接管 `/etc/nftables.conf` 和 `/etc/nftables.d/*.conf`。如果服务器已有复杂防火墙规则，请先备份：

```bash
sudo nft list ruleset > nftables.rules.backup
sudo cp -a /etc/nftables.conf /etc/nftables.conf.backup 2>/dev/null || true
sudo cp -a /etc/nftables.d /etc/nftables.d.backup 2>/dev/null || true
```

建议先在新 VPS 或测试环境验证后再用于生产服务器。
