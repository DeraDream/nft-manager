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
- 安装后提供全局命令 `nftm` 唤起菜单，不占用系统 nftables 的 `nft` 命令
- 安装后自动创建 systemd 保活服务
- 安装后自动创建 Web 面板，默认端口 `5555`
- Web 面板自适应桌面与手机，手机端使用固定底部 Tab Bar，列表、表单和弹窗均支持触屏布局
- 提供独立的 nftables 入站防火墙模块，默认保底开放当前 SSH 端口、`5555/tcp` 和 ICMP/ICMPv6
- 新增转发默认同步放行入口端口，删除转发默认同步关闭入口端口，SSH 和 Web 均可取消该操作
- Web 面板支持一次添加多个单端口
- Web 面板支持持久化上传、下载、总计流量统计、24 小时趋势和规则开关
- 端口在最近 20 秒内产生转发流量时标记为活跃，后台每 10 秒采样一次规则计数器
- 首页和转发管理页为活跃端口显示每秒更新的实时上传、下载速率
- 系统设置支持导出 `.nftm` 配置并在其他 VPS 追加导入主机与转发规则，导入后自动同步转发端口防火墙
- 仪表板结合默认出口网卡与 nftables 转发方向计数器统计实时上传/下载带宽，避免单网卡转发流量在 RX/TX 中重复而导致两条曲线重合；折线图固定展示从现在到过去 24 小时的真实时间范围，横轴每格 1 小时。首页可见时，实时速率和曲线最右端的当前速率点每秒同步更新，分钟结束后以该分钟峰值保存为历史点；未打开 Web 或离开首页后，自动恢复为每 10 秒后台采样，并仅按该节奏持久化带宽历史
- 流量与带宽折线图支持悬停查看对应时间的数据明细
- 转发与主机列表支持按流量、连通性或延迟持久化排序，并可一键恢复默认顺序
- 主机管理支持批量延迟检测，转发管理支持批量连通性检查
- 仪表板每次进入时自动检测全部转发端口连通性
- Web 面板支持日间、夜间和跟随系统三种显示模式
- 管理页使用右下角悬浮操作按钮，手机列表采用高对比度独立 item 布局
- 主机管理按目标汇总所有端口的上传、下载与总计流量，规则数支持点击查看全部转发
- 系统设置支持自定义 Web 面板顶部标题
- 系统设置支持在线检查并确认升级，升级进度会持续显示，Web 服务重启恢复后自动刷新页面
- 主机管理支持使用 NextTrace 查看本机到目标主机的路由
- 项目内置 NextTrace Tiny 的 Linux amd64/arm64 离线文件，并提供 SSH 安装与在线升级菜单
- 支持在线检查和更新脚本
- 更新时自动在当前配置源、GitHub Raw、GitHub API 和 jsDelivr 镜像之间切换，兼容海外和大陆 VPS

## 安装

海外服务器或可直接访问 GitHub 的机器：

```bash
curl -fsSL https://raw.githubusercontent.com/DeraDream/nft-manager/main/install.sh | sudo bash
```

国内服务器可使用 jsDelivr CDN：

```bash
curl -fsSL https://cdn.jsdelivr.net/gh/DeraDream/nft-manager@main/install.sh | sudo bash
```

引导安装器会在 `/tmp/nft-manager-install.*` 创建临时目录，下载并校验同版本的脚本、Web 面板和当前架构的 NextTrace，然后进入安装菜单。退出菜单后临时目录会自动删除；正式运行文件统一安装到 `/opt/nft-manager`，不会在 `/root` 留下 `nft.sh`。

进入菜单后选择：

```text
1) 安装 nftables / 管理器
```

安装完成后，可直接使用全局命令打开菜单：

```bash
sudo nftm
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

## 从旧 SSH 版升级

纯 SSH 菜单版本升级到 Web 版本时，只需在旧菜单中选择 `2) 更新脚本`。新版会先把运行文件迁移到 `/opt/nft-manager`，再停止管理服务、补装缺失的 Web 面板与 NextTrace、更新 systemd 路径并迁移配置，最后重启服务。服务和路径同步成功后，才会清理旧目录 `/usr/local/lib/nft-forward` 以及可识别的 `/root/nft.sh`；不会执行菜单 `1)` 的清空安装流程，也不会删除 `/etc/nftables.d` 中的规则、主机和流量统计数据。

升级到 v3.24 或更高版本时，会先创建新的全局菜单命令 `/usr/local/bin/nftm`，成功后自动删除旧版项目生成的 `/usr/local/bin/nft`，把 `nft` 命令还给系统 nftables。

如果服务器没有 systemd 或保活服务启动失败，再手动执行一次 `sudo nftm` 即可触发相同的补装检测。

对于已部署 Web 的版本更新，脚本会比较已安装的 Web 文件版本；版本一致时不下载或覆盖 Web 文件。更新会短暂停止 Web 和保活服务，校验配置结构是否需要迁移，最后统一重启。nftables 规则与配置不会被清空。

升级过程中不要选择 `1) 安装/卸载 nftables 管理器`，该选项用于全新安装或完整卸载，不适合保留旧转发的升级场景。

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
9) 防火墙端口管理
10) 从 /root/nft-manager-main.zip 离线更新
11) NextTrace 管理
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
- 防火墙管理
- 系统设置

项目内置 NextTrace Tiny `v1.7.1` 的 Linux `amd64` 与 `arm64` 文件。首次安装时会按 VPS 架构自动关联为 `/usr/local/bin/nexttrace`；只有单独下载 `nft.sh` 且本地没有内置文件时，才会尝试从本项目下载对应架构文件。Web 主机管理可点击“NextTrace 路由”，SSH 目标主机管理可选择 `5) NextTrace 路由检测`。主菜单 `11) NextTrace 管理` 支持从项目内置文件安装/修复，以及从 NextTrace 官方 Release 在线升级；也可以直接执行 `sudo nftm --nexttrace-update`。

新增转发时，入口端口输入框仅支持单个端口；可用空格或英文逗号一次输入多个端口：

```text
80 443 10000
80,443,10000
```

不支持端口段，例如 `100-200` 会直接提示错误。单次最多添加 1000 个端口。

出口端口支持：

- 与入口端口一致
- 指定出口起始端口

选择出口起始端口时，多个入口端口会按输入顺序依次映射到连续的出口端口。Web 面板使用 nftables counter 统计流量，活跃状态根据流量计数是否增长判断。内核计数每 30 秒结算到 `/etc/nftables.d/web-stats.json`，规则重载、Web 服务重启和正常关机前也会结算，累计流量不会因 nftables 计数器归零而清空。

默认账号密码为：

```text
admin / admin
```

请在公网使用前修改默认密码，并确认服务器安全组/防火墙只向可信来源开放 `5555` 端口。

## 防火墙端口管理

安装或更新到 `v3.9` 后，项目会创建独立的 nftables 入站防火墙配置：

- 默认拒绝未列出的入站连接。
- 无论何时都会保留当前检测到的 SSH 端口和 `5555/tcp`（Web 面板）两个保底端口。
- 新增端口转发时，SSH 菜单和 Web 面板都会默认同时开放入口端口；可在确认项中取消勾选。
- 删除端口转发时，默认同时关闭由该转发创建的入口端口；手动开放的端口不会被自动删除。
- Web 面板左侧的“防火墙管理”和 SSH 菜单 `9)` 可单独查看、开放或关闭端口。
- 防火墙默认自动检测当前生效的 SSH 端口；SSH 菜单可修改保底端口，输入与实际 SSH 端口不一致时会警告。
- 防火墙默认放行全部 IPv4 ICMP 和 ICMPv6，TCP/UDP 仍只放行端口清单中的端口。

该模块同时限制主机入站流量与 DNAT 转发流量。云厂商安全组仍在系统外层生效，安全组未放行时，本机规则无法绕过它。

## 配置更新源

更新检查会校验脚本内容和版本号，并在当前配置源、GitHub Raw、GitHub API 和 jsDelivr 之间自动回退；选择更新时会优先复用已经校验的新版文件。除 SSH 菜单外，也可以在 Web 面板“系统设置 → 在线更新”中完成检查和升级；升级任务独立于 Web 服务运行，服务重启期间页面会继续等待，恢复后自动刷新。

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

## 完全离线更新

在 GitHub 下载项目 ZIP 后，将其上传并固定命名为：

```text
/root/nft-manager-main.zip
```

执行 `nftm`，选择 `10) 从 /root/nft-manager-main.zip 离线更新`。脚本会将 ZIP 解压到 `/tmp` 下的随机临时目录，校验后直接更新 `/opt/nft-manager` 中的服务文件。更新成功后删除临时解压目录和 `/root/nft-manager-main.zip`，并清理旧版本遗留的 `/root/nft-manager-update` 后立即进入新版菜单；更新失败时删除临时目录并保留 ZIP，供排查或重试。该入口不影响 `2) 更新脚本` 的在线更新流程。

完整项目已经包含 Linux `amd64/arm64` 的 NextTrace，无需另外下载。若使用其他架构，也可以自行下载匹配的二进制并命名为 `nexttrace`，上传到以下任一位置：

```text
/opt/nft-manager/nexttrace
/root/nexttrace
```

再次选择菜单 `10)` 后，脚本会将它安装为 `/usr/local/bin/nexttrace` 并接入 Web 面板。Web 面板只通过系统命令 `nexttrace` 调用它，不需要额外配置。

内置文件来自 [NextTrace 官方项目](https://github.com/nxtrace/NTrace-core)，使用 GPL-3.0 许可证；对应许可证和 `v1.7.1` 完整源码包位于 `vendor/nexttrace`。

## 文件位置

安装后主要文件：

```text
/opt/nft-manager/nft.sh
/opt/nft-manager/web_panel.py
/opt/nft-manager/vendor/nexttrace/
/usr/local/bin/nftm
/usr/local/bin/nexttrace
/etc/systemd/system/nft-forward-keepalive.service
/etc/systemd/system/nft-manager-web.service
/etc/nftables.conf
/etc/nftables.d/port-forward.conf
/etc/nftables.d/targets.conf
/etc/nftables.d/firewall.conf
/etc/nftables.d/firewall-ports.db
/etc/nftables.d/update-url
/etc/nftables.d/web-auth.conf
/etc/nftables.d/web-stats.json
/etc/nftables.d/web-history.json
/etc/nftables.d/web-settings.json
/etc/sysctl.d/99-nft-forward.conf
/var/log/nft-forward.log
```

## 卸载

进入菜单选择：

```text
1) 卸载 nftables 管理器
```

卸载为完整卸载，会删除：

- 全局命令 `/usr/local/bin/nftm`（升级时自动清理旧版 `/usr/local/bin/nft` 管理入口）
- 安装目录 `/opt/nft-manager`（同时清理旧版 `/usr/local/lib/nft-forward`）
- systemd 保活服务
- Web 面板服务
- 端口转发配置
- 目标主机库
- 更新源配置
- Web 面板账号文件
- Web 面板流量采样文件
- 独立防火墙配置和端口清单
- 脚本日志
- 脚本写入的 sysctl 配置
- 脚本写入的 logrotate 配置

卸载只需在唯一一次 `[y/N]` 确认中输入 `y`，回车或其他输入均取消。确认后会直接完整卸载所有项目文件、服务和数据，并自动清空当前全部 nftables 运行规则；脚本不会卸载系统的 `nftables` 软件包。

## 注意

安装初始化时，脚本会接管 `/etc/nftables.conf` 和 `/etc/nftables.d/*.conf`。如果服务器已有复杂防火墙规则，请先备份：

```bash
sudo nft list ruleset > nftables.rules.backup
sudo cp -a /etc/nftables.conf /etc/nftables.conf.backup 2>/dev/null || true
sudo cp -a /etc/nftables.d /etc/nftables.d.backup 2>/dev/null || true
```

建议先在新 VPS 或测试环境验证后再用于生产服务器。
