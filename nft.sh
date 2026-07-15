#!/usr/bin/env bash
#
# nftables 端口转发管理工具 v3.24
# 交互式管理 DNAT 端口转发规则
#

# ============== 常量定义 ==============
SCRIPT_VERSION="3.24"
WEB_PANEL_VERSION="3.24"
CONF_DIR="/etc/nftables.d"
CONF_FILE="${CONF_DIR}/port-forward.conf"
TARGETS_FILE="${CONF_DIR}/targets.conf"
FIREWALL_CONF="${CONF_DIR}/firewall.conf"
FIREWALL_PORTS_FILE="${CONF_DIR}/firewall-ports.db"
FIREWALL_SSH_PORT_FILE="${CONF_DIR}/firewall-ssh-port"
FIREWALL_TABLE="nft_manager_firewall"
UPDATE_URL_FILE="${CONF_DIR}/update-url"
MAIN_CONF="/etc/nftables.conf"
SYSCTL_CONF="/etc/sysctl.d/99-nft-forward.conf"
LOG_FILE="/var/log/nft-forward.log"
LOGROTATE_CONF="/etc/logrotate.d/nft-forward"
TABLE_NAME="port_forward"
GLOBAL_CMD="/usr/local/bin/nftm"
LEGACY_GLOBAL_CMD="/usr/local/bin/nft"
SCRIPT_INSTALL_DIR="/opt/nft-manager"
SCRIPT_INSTALL_FILE="${SCRIPT_INSTALL_DIR}/nft.sh"
WEB_PANEL_FILE="${SCRIPT_INSTALL_DIR}/web_panel.py"
LEGACY_SCRIPT_INSTALL_DIR="/usr/local/lib/nft-forward"
OFFLINE_ZIP_FILE="/root/nft-manager-main.zip"
NEXTTRACE_MARKER="${SCRIPT_INSTALL_DIR}/nexttrace-managed"
NEXTTRACE_LOCAL_FILE="${SCRIPT_INSTALL_DIR}/nexttrace"
NEXTTRACE_INSTALL_FILE="/usr/local/bin/nexttrace"
NEXTTRACE_VENDOR_DIR="${SCRIPT_INSTALL_DIR}/vendor/nexttrace"
NEXTTRACE_BUNDLED_VERSION="1.7.1"
NEXTTRACE_PROJECT_RAW="https://raw.githubusercontent.com/DeraDream/nft-manager/main/vendor/nexttrace"
NEXTTRACE_PROJECT_CDN="https://cdn.jsdelivr.net/gh/DeraDream/nft-manager@main/vendor/nexttrace"
NEXTTRACE_RELEASE_BASE="https://github.com/nxtrace/NTrace-core/releases/latest/download"
WEB_PORT="5555"
WEB_AUTH_FILE="${CONF_DIR}/web-auth.conf"
WEB_PANEL_URL="${NFT_MANAGER_WEB_PANEL_URL:-https://cdn.jsdelivr.net/gh/DeraDream/nft-manager@main/web_panel.py}"
KEEPALIVE_SERVICE_NAME="nft-forward-keepalive.service"
KEEPALIVE_SERVICE_FILE="/etc/systemd/system/${KEEPALIVE_SERVICE_NAME}"
WEB_SERVICE_NAME="nft-manager-web.service"
WEB_SERVICE_FILE="/etc/systemd/system/${WEB_SERVICE_NAME}"
DEFAULT_UPDATE_URL="https://raw.githubusercontent.com/DeraDream/nft-manager/main/nft.sh"
FALLBACK_UPDATE_URL="https://cdn.jsdelivr.net/gh/DeraDream/nft-manager@main/nft.sh"
UPDATE_URL="${NFT_FORWARD_UPDATE_URL:-$DEFAULT_UPDATE_URL}"
UPDATE_DOWNLOADED_URL=""
SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || printf '%s\n' "$0")"
UPDATE_CHECKED=false
UPDATE_AVAILABLE=false
UPDATE_REMOTE_VERSION=""
UPDATE_STATUS_TEXT="未检查"

resolve_nft_bin() {
    local bin
    for bin in /usr/sbin/nft /sbin/nft /usr/bin/nft /bin/nft; do
        if [[ -x "$bin" && "$bin" != "$GLOBAL_CMD" && "$bin" != "$LEGACY_GLOBAL_CMD" ]]; then
            echo "$bin"
            return
        fi
    done
    bin=$(command -v nft 2>/dev/null || true)
    if [[ -n "$bin" && "$bin" != "$GLOBAL_CMD" && "$bin" != "$LEGACY_GLOBAL_CMD" ]]; then
        echo "$bin"
    fi
}

NFT_BIN="$(resolve_nft_bin)"

nft_available() {
    [[ -n "$NFT_BIN" && -x "$NFT_BIN" ]]
}

# ============== 日志函数 ==============
log_action() {
    local msg="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${msg}" >> "${LOG_FILE}" 2>/dev/null || true
}

# ============== 输出辅助（用 printf 避免 echo -e 转义副作用） ==============
info()    { printf '\033[32m[信息]\033[0m %s\n' "$1"; }
warn()    { printf '\033[33m[警告]\033[0m %s\n' "$1"; }
err()     { printf '\033[31m[错误]\033[0m %s\n' "$1"; }

# ============== root 权限检查 ==============
check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "此脚本需要 root 权限运行，请使用 sudo 或 root 用户执行。"
        exit 1
    fi
}

# ============== 输入验证 ==============
validate_port() {
    local port="$1"
    # 拒绝非纯数字、前导零（避免 bash 八进制歧义）、空串
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [[ "$port" =~ ^0[0-9] ]]; then
        return 1
    fi
    if (( port < 1 || port > 65535 )); then
        return 1
    fi
    return 0
}

validate_ip() {
    local ip="$1"
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi
    # 拒绝前导零（避免 bash 八进制解析歧义，如 010 != 10）
    if [[ "$ip" =~ (^|\.)0[0-9] ]]; then
        return 1
    fi
    local IFS='.'
    read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if (( octet > 255 )); then
            return 1
        fi
    done
    return 0
}

# ============== 自动获取本机 IP ==============
get_local_ip() {
    local ip
    # 优先取默认路由出口的 IP（最准确：这就是发包时实际使用的源 IP）
    ip=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1) || true
    if [[ -n "$ip" ]]; then
        echo "$ip"
        return
    fi
    # 回退：取第一个非 lo 接口的 IP
    ip=$(ip -4 addr show scope global 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1) || true
    if [[ -n "$ip" ]]; then
        echo "$ip"
        return
    fi
    # 最终回退
    hostname -I 2>/dev/null | awk '{print $1}' || true
}

# ============== 发行版检测 ==============
detect_pkg_manager() {
    if command -v apt-get &>/dev/null; then
        echo "apt"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v yum &>/dev/null; then
        echo "yum"
    elif command -v pacman &>/dev/null; then
        echo "pacman"
    else
        echo "unknown"
    fi
}

# ============== iptables 可用性检测 ==============
# 不依赖 systemd 服务，而是检测命令是否存在且能读取规则
has_iptables() {
    command -v iptables &>/dev/null && iptables -S &>/dev/null
}

# ============== iptables 规则持久化尝试 ==============
try_persist_iptables() {
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save >/dev/null 2>&1 && return 0
    fi
    if command -v iptables-save &>/dev/null; then
        if [[ -d /etc/iptables ]]; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null && return 0
        elif [[ -d /etc/sysconfig ]]; then
            iptables-save > /etc/sysconfig/iptables 2>/dev/null && return 0
        fi
    fi
    if command -v service &>/dev/null; then
        service iptables save >/dev/null 2>&1 && return 0
    fi
    return 1
}

# ============== 检查目标是否仍被其他规则使用 ==============
# 参数: $1=目标IP  $2=目标端口  $3=要排除的本机端口(即正在删除的那条)
dest_still_used() {
    local check_ip="$1" check_dport="$2" exclude_lport="$3"
    local rule lport dip dport alias
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport alias <<< "$rule"
        # 跳过正在删除的那条
        [[ "$lport" == "$exclude_lport" ]] && continue
        # 如果其他规则也指向同一 dest_ip:dport，返回 true
        if [[ "$dip" == "$check_ip" && "$dport" == "$check_dport" ]]; then
            return 0
        fi
    done
    return 1
}

# ============== firewalld / iptables 端口放行 ==============
# 参数: $1=本机监听端口  $2=目标IP  $3=目标端口
firewall_open_port() {
    local lport="$1" dest_ip="$2" dport="$3"

    # firewalld 优先：如果 firewalld 在运行，只用 firewall-cmd，不碰 iptables
    # （firewalld 可能以 iptables 为后端，手动插 iptables 规则会被 reload 冲掉）
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --add-port="${lport}/tcp" --permanent >/dev/null 2>&1 || true
        firewall-cmd --add-port="${lport}/udp" --permanent >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        info "已在 firewalld 中放行端口 ${lport} (tcp+udp)。"
        log_action "firewalld 放行端口 ${lport}"
        return
    fi

    # UFW: Ubuntu 小白最常见的防火墙
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qw "active"; then
        # INPUT: 放行进入本机的流量
        ufw allow "${lport}/tcp" >/dev/null 2>&1 || true
        ufw allow "${lport}/udp" >/dev/null 2>&1 || true
        # FORWARD: ufw allow 只管 INPUT，转发流量需要 route allow
        ufw route allow proto tcp to "${dest_ip}" port "${dport}" >/dev/null 2>&1 || true
        ufw route allow proto udp to "${dest_ip}" port "${dport}" >/dev/null 2>&1 || true
        info "已在 UFW 中放行端口 ${lport} 及转发到 ${dest_ip}:${dport} (tcp+udp)。"
        log_action "UFW 放行端口 ${lport} 转发到 ${dest_ip}:${dport}"
        return
    fi

    # 无 firewalld / UFW，检测 iptables
    if has_iptables; then
        # INPUT 链: 放行进入本机的流量（匹配 DNAT 前的本机端口）
        iptables -C INPUT -p tcp --dport "${lport}" -j ACCEPT 2>/dev/null || \
            iptables -I INPUT -p tcp --dport "${lport}" -j ACCEPT 2>/dev/null || true
        iptables -C INPUT -p udp --dport "${lport}" -j ACCEPT 2>/dev/null || \
            iptables -I INPUT -p udp --dport "${lport}" -j ACCEPT 2>/dev/null || true
        # FORWARD 链: DNAT 后包的目的地已改写为 dest_ip:dport，需按此匹配
        iptables -C FORWARD -d "${dest_ip}" -p tcp --dport "${dport}" -j ACCEPT 2>/dev/null || \
            iptables -I FORWARD -d "${dest_ip}" -p tcp --dport "${dport}" -j ACCEPT 2>/dev/null || true
        iptables -C FORWARD -d "${dest_ip}" -p udp --dport "${dport}" -j ACCEPT 2>/dev/null || \
            iptables -I FORWARD -d "${dest_ip}" -p udp --dport "${dport}" -j ACCEPT 2>/dev/null || true
        # FORWARD 链: 放行回程已建立连接的包（DNAT 转发场景标配）
        iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
            iptables -I FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
        info "已在 iptables 中放行: INPUT ${lport}, FORWARD → ${dest_ip}:${dport} (tcp+udp)。"
        log_action "iptables 放行 INPUT:${lport} FORWARD:${dest_ip}:${dport}"
        if ! try_persist_iptables; then
            warn "iptables 规则已生效但未能自动持久化，重启后可能丢失。"
            warn "如需持久化请安装 iptables-persistent / netfilter-persistent。"
        fi
    fi
}

# 参数: $1=本机监听端口  $2=目标IP  $3=目标端口  $4=是否跳过共享检查("force" 表示强制删除)
firewall_close_port() {
    local lport="$1" dest_ip="$2" dport="$3" force="${4:-}"

    # firewalld
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --remove-port="${lport}/tcp" --permanent >/dev/null 2>&1 || true
        firewall-cmd --remove-port="${lport}/udp" --permanent >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        info "已从 firewalld 中移除端口 ${lport} 的放行规则。"
        log_action "firewalld 移除端口 ${lport}"
        return
    fi

    # UFW（用 yes 管道防止 ufw delete 交互询问卡住脚本）
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qw "active"; then
        yes | ufw delete allow "${lport}/tcp" >/dev/null 2>&1 || true
        yes | ufw delete allow "${lport}/udp" >/dev/null 2>&1 || true
        # route 规则按目标匹配，只有在没有其他规则共享同一目标时才删除
        if [[ "$force" == "force" ]] || ! dest_still_used "$dest_ip" "$dport" "$lport"; then
            yes | ufw route delete allow proto tcp to "${dest_ip}" port "${dport}" >/dev/null 2>&1 || true
            yes | ufw route delete allow proto udp to "${dest_ip}" port "${dport}" >/dev/null 2>&1 || true
        fi
        info "已从 UFW 中移除端口 ${lport} 的放行规则。"
        log_action "UFW 移除端口 ${lport}"
        return
    fi

    # iptables
    if has_iptables; then
        # INPUT 链: 总是删除（lport 是唯一的）
        iptables -D INPUT -p tcp --dport "${lport}" -j ACCEPT 2>/dev/null || true
        iptables -D INPUT -p udp --dport "${lport}" -j ACCEPT 2>/dev/null || true
        # FORWARD 链: 只有在没有其他规则共享同一 dest_ip:dport 时才删除
        if [[ "$force" == "force" ]] || ! dest_still_used "$dest_ip" "$dport" "$lport"; then
            iptables -D FORWARD -d "${dest_ip}" -p tcp --dport "${dport}" -j ACCEPT 2>/dev/null || true
            iptables -D FORWARD -d "${dest_ip}" -p udp --dport "${dport}" -j ACCEPT 2>/dev/null || true
        fi
        # 注意: 不删除 ESTABLISHED,RELATED 规则，它是通用规则，其他转发可能还需要
        info "已从 iptables 中移除: INPUT ${lport}, FORWARD → ${dest_ip}:${dport}。"
        log_action "iptables 移除 INPUT:${lport} FORWARD:${dest_ip}:${dport}"
        try_persist_iptables || true
    fi
}

web_firewall_open() {
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --add-port="${WEB_PORT}/tcp" --permanent >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        return
    fi
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qw "active"; then
        ufw allow "${WEB_PORT}/tcp" >/dev/null 2>&1 || true
        return
    fi
    if has_iptables; then
        iptables -C INPUT -p tcp --dport "${WEB_PORT}" -j ACCEPT 2>/dev/null || \
            iptables -I INPUT -p tcp --dport "${WEB_PORT}" -j ACCEPT 2>/dev/null || true
        try_persist_iptables || true
    fi
}

web_firewall_close() {
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --remove-port="${WEB_PORT}/tcp" --permanent >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        return
    fi
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qw "active"; then
        yes | ufw delete allow "${WEB_PORT}/tcp" >/dev/null 2>&1 || true
        return
    fi
    if has_iptables; then
        iptables -D INPUT -p tcp --dport "${WEB_PORT}" -j ACCEPT 2>/dev/null || true
        try_persist_iptables || true
    fi
}

# ============== nft-manager 独立入站防火墙 ==============
# 防火墙逻辑由 Web 后端统一生成，避免 SSH 与 Web 写出不同格式的 nft 规则。
manager_firewall_call() {
    # 防火墙模块通过 Web 后端的 CLI 入口运行，但不依赖 Web 服务本身。
    # 这样即使面板暂时停止，SSH 菜单仍可管理入站端口。
    if ! command -v python3 &>/dev/null || [[ ! -f "${WEB_PANEL_FILE}" ]]; then
        err "防火墙模块不可用，模块文件缺失。请先执行菜单【更新脚本】。"
        return 1
    fi
    NFT_MANAGER_CONF_DIR="${CONF_DIR}" python3 "${WEB_PANEL_FILE}" "$@"
}

manager_firewall_ensure() {
    manager_firewall_call --firewall-ensure
}

manager_firewall_sync() {
    manager_firewall_call --firewall-sync
}

manager_firewall_add_forward() {
    # 与 Web 新增转发共用专用入口，确保写入转发端口记录并立即重载防火墙。
    manager_firewall_call --firewall-add-forward "$1"
}

manager_firewall_remove_forward() {
    manager_firewall_call --firewall-remove "$1"
}

do_firewall_menu() {
    while true; do
        echo ""
        echo "========================================"
        echo "            防火墙端口管理"
        echo "   当前 SSH 保底端口: $(manager_firewall_call --firewall-ssh-status 2>/dev/null || echo '检测失败')/tcp"
        echo "   Web 面板保底端口: ${WEB_PORT}/tcp"
        echo "========================================"
        echo "  1) 查看已开放端口"
        echo "  2) 手动开放端口"
        echo "  3) 关闭手动开放端口"
        echo "  4) 同步当前转发端口"
        echo "  5) 修改 SSH 防火墙保底端口"
        echo "  6) 恢复 SSH 端口自动检测"
        echo "  0) 返回上一层"
        echo "========================================"
        local choice port protocol detected
        read -rp "请选择操作 [0-6]: " choice
        case "$choice" in
            0) return ;;
            1) manager_firewall_call --firewall-list ;;
            2)
                read -rp "请输入要开放的端口 (1-65535): " port
                if ! validate_port "$port"; then
                    err "端口无效。"
                    continue
                fi
                read -rp "协议 [tcp+udp/tcp/udp，默认 tcp+udp]: " protocol
                protocol="${protocol:-tcp+udp}"
                if manager_firewall_call --firewall-add "$port" "$protocol" "手动开放"; then
                    info "已开放端口 ${port}/${protocol}。"
                fi
                ;;
            3)
                read -rp "请输入要关闭的端口 (1-65535): " port
                if ! validate_port "$port"; then
                    err "端口无效。"
                    continue
                fi
                if [[ "$port" == "${WEB_PORT}" ]]; then
                    warn "${port} 是 Web 面板保底端口，不允许关闭。"
                    continue
                fi
                detected=$(manager_firewall_call --firewall-ssh-status 2>/dev/null || true)
                if [[ ",${detected}," == *",${port},"* ]]; then
                    warn "${port} 是当前 SSH 端口，不允许关闭。"
                    continue
                fi
                read -rp "确认关闭端口 ${port}？[y/N]: " protocol
                [[ "$protocol" =~ ^[Yy]$ ]] || continue
                if manager_firewall_call --firewall-delete "$port"; then
                    info "已关闭端口 ${port}。"
                fi
                ;;
            4)
                if manager_firewall_sync; then
                    info "已将当前转发端口同步到防火墙。"
                fi
                ;;
            5)
                detected=$(manager_firewall_call --firewall-ssh-status 2>/dev/null || echo "未知")
                echo "当前系统检测到的 SSH 端口: ${detected}"
                read -rp "请输入要保留的 SSH 防火墙端口 (1-65535): " port
                if ! validate_port "$port"; then
                    err "端口无效。"
                    continue
                fi
                if [[ ",${detected}," != *",${port},"* ]]; then
                    warn "警告：输入端口 ${port} 与当前检测到的 SSH 端口 (${detected}) 不一致。"
                    read -rp "仍要将 ${port} 设置为 SSH 防火墙保底端口？[y/N]: " protocol
                    [[ "$protocol" =~ ^[Yy]$ ]] || { info "已取消。"; continue; }
                fi
                if manager_firewall_call --firewall-ssh-port "$port"; then
                    info "已设置 SSH 防火墙保底端口: ${port}/tcp"
                fi
                ;;
            6)
                if manager_firewall_call --firewall-ssh-auto; then
                    info "已恢复 SSH 端口自动检测。"
                fi
                ;;
            *) err "无效选择，请输入 0-6。" ;;
        esac
    done
}

# ============== 端口占用检测（TCP + UDP） ==============
check_port_conflict() {
    local port="$1"
    local conflict=""
    if ss -tlnp 2>/dev/null | grep -qE ":${port}\b"; then
        conflict="TCP"
    fi
    if ss -ulnp 2>/dev/null | grep -qE ":${port}\b"; then
        if [[ -n "$conflict" ]]; then
            conflict="TCP+UDP"
        else
            conflict="UDP"
        fi
    fi
    if [[ -n "$conflict" ]]; then
        warn "本机端口 ${port} 已被其他服务占用（${conflict}）。"
        warn "添加转发后，该端口的外部流量将被转发，本地服务可能无法从外部访问。"
        read -rp "是否仍要继续添加转发规则？[y/N]: " ans
        if [[ ! "$ans" =~ ^[Yy]$ ]]; then
            return 1
        fi
    fi
    return 0
}

# ============== 初始化配置文件结构 ==============
init_conf() {
    mkdir -p "${CONF_DIR}" 2>/dev/null || {
        err "无法创建配置目录 ${CONF_DIR}，请检查权限。"
        return 1
    }

    # 确保日志文件存在
    touch "${LOG_FILE}" 2>/dev/null || true

    # 创建 logrotate 配置
    if [[ ! -f "${LOGROTATE_CONF}" ]]; then
        cat > "${LOGROTATE_CONF}" <<'LOGROTATE'
/var/log/nft-forward.log {
    monthly
    rotate 6
    compress
    missingok
    notifempty
}
LOGROTATE
    fi

    # 确保主配置存在且包含 include
    if [[ ! -f "${MAIN_CONF}" ]]; then
        # 极简系统可能没有 nftables.conf，创建最小文件确保重启后规则自动加载
        cat > "${MAIN_CONF}" <<'NFTCONF'
#!/usr/sbin/nft -f
flush ruleset
include "/etc/nftables.d/*.conf"
NFTCONF
        info "已创建 ${MAIN_CONF}（系统中不存在该文件）。"
        log_action "创建 ${MAIN_CONF}"
    elif ! grep -qF 'include "/etc/nftables.d/*.conf"' "${MAIN_CONF}" 2>/dev/null; then
        echo 'include "/etc/nftables.d/*.conf"' >> "${MAIN_CONF}"
        info "已在 ${MAIN_CONF} 中添加 include 指令。"
        log_action "在 ${MAIN_CONF} 中添加 include 指令"
    fi

    # 如果转发配置文件不存在，创建初始结构
    if [[ ! -f "${CONF_FILE}" ]]; then
        write_conf_file || return 1
    fi

    touch "${TARGETS_FILE}" 2>/dev/null || true
}

# ============== 写出配置文件（基于当前 RULES 数组） ==============
# RULES 数组格式: "本机端口|目标IP|目标端口|转发别名"
declare -a RULES=()
declare -a TARGETS=()

clean_label() {
    local label="$1"
    label="${label//$'\r'/ }"
    label="${label//$'\n'/ }"
    label="${label//|/ }"
    label=$(printf '%s' "$label" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
    while [[ "$label" == \#* ]]; do
        label="${label#\#}"
    done
    printf '%s' "$label" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//'
}

load_targets() {
    TARGETS=()
    [[ -f "${TARGETS_FILE}" ]] || return
    local line alias ip
    while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        IFS='|' read -r alias ip <<< "$line"
        alias=$(clean_label "$alias")
        if [[ -n "$alias" && "$alias" != "0" ]] && validate_ip "$ip"; then
            TARGETS+=("${alias}|${ip}")
        fi
    done < "${TARGETS_FILE}"
}

write_targets_file() {
    mkdir -p "${CONF_DIR}" 2>/dev/null || return 1
    local tmp_file="${TARGETS_FILE}.tmp.$$"
    {
        echo "# alias|ip"
        local target alias ip
        for target in "${TARGETS[@]}"; do
            IFS='|' read -r alias ip <<< "$target"
            echo "${alias}|${ip}"
        done
    } > "${tmp_file}" || return 1
    mv -f "${tmp_file}" "${TARGETS_FILE}" 2>/dev/null || {
        rm -f "${tmp_file}" 2>/dev/null || true
        return 1
    }
}

target_alias_by_ip() {
    local find_ip="$1" target alias ip
    load_targets
    for target in "${TARGETS[@]}"; do
        IFS='|' read -r alias ip <<< "$target"
        if [[ "$ip" == "$find_ip" ]]; then
            echo "$alias"
            return
        fi
    done
}

target_display() {
    local ip="$1" alias
    alias=$(target_alias_by_ip "$ip")
    if [[ -n "$alias" ]]; then
        printf '%s (%s)' "$alias" "$ip"
    else
        printf '%s' "$ip"
    fi
}

find_target_index_by_ip() {
    local find_ip="$1" idx target alias ip
    for idx in "${!TARGETS[@]}"; do
        target="${TARGETS[$idx]}"
        IFS='|' read -r alias ip <<< "$target"
        if [[ "$ip" == "$find_ip" ]]; then
            echo "$idx"
            return 0
        fi
    done
    return 1
}

find_target_index_by_alias() {
    local find_alias="$1" exclude_idx="${2:-}" idx target alias ip
    for idx in "${!TARGETS[@]}"; do
        [[ -n "$exclude_idx" && "$idx" == "$exclude_idx" ]] && continue
        target="${TARGETS[$idx]}"
        IFS='|' read -r alias ip <<< "$target"
        if [[ "$alias" == "$find_alias" ]]; then
            echo "$idx"
            return 0
        fi
    done
    return 1
}

choose_or_input_target_ip() {
    local __result_var="$1"
    local selected_ip choice idx target alias ip save_alias
    load_targets

    if [[ ${#TARGETS[@]} -gt 0 ]]; then
        while true; do
            echo ""
            echo "请选择目标 IP 来源:"
            echo "  1) 从目标主机库选择"
            echo "  2) 手动输入 IP"
            read -rp "请选择 [1-2，默认 1]: " choice
            choice="${choice:-1}"
            [[ "$choice" == "1" || "$choice" == "2" ]] && break
            err "无效选择，请输入 1 或 2。"
        done
    else
        choice="2"
    fi

    if [[ "$choice" == "1" ]]; then
        echo ""
        printf "\033[1m%-6s %-24s %-16s\033[0m\n" "序号" "别名" "IP"
        echo "────────────────────────────────────────────"
        for idx in "${!TARGETS[@]}"; do
            IFS='|' read -r alias ip <<< "${TARGETS[$idx]}"
            printf "%-6s %-24s %-16s\n" "$((idx + 1))" "$alias" "$ip"
        done
        while true; do
            read -rp "请选择目标主机序号 (0 手动输入): " choice
            if [[ "$choice" == "0" || -z "$choice" ]]; then
                break
            fi
            if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#TARGETS[@]} )); then
                target="${TARGETS[$((choice - 1))]}"
                IFS='|' read -r alias selected_ip <<< "$target"
                printf -v "$__result_var" '%s' "$selected_ip"
                return 0
            fi
            err "无效的序号。"
        done
    fi

    while true; do
        read -rp "请输入目标 IP 地址: " selected_ip
        if validate_ip "$selected_ip"; then
            break
        fi
        err "IP 地址格式无效，请重新输入（如 192.168.1.100，不含前导零）。"
    done

    idx=$(find_target_index_by_ip "$selected_ip" || true)
    if [[ -n "$idx" ]]; then
        IFS='|' read -r alias ip <<< "${TARGETS[$idx]}"
        info "该 IP 已存在于目标主机库: ${alias} (${ip})"
    else
        read -rp "是否将当前 IP 保存到目标主机库？[y/N]: " choice
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            while true; do
                read -rp "请输入目标主机别名（支持中文，输入 0 或回车取消保存）: " save_alias
                save_alias=$(clean_label "$save_alias")
                if [[ -z "$save_alias" || "$save_alias" == "0" ]]; then
                    info "已跳过保存目标主机。"
                    break
                fi
                idx=$(find_target_index_by_alias "$save_alias" || true)
                if [[ -n "$idx" ]]; then
                    warn "该别名已存在，请换一个别名。"
                    continue
                fi
                TARGETS+=("${save_alias}|${selected_ip}")
                if write_targets_file; then
                    info "已保存目标主机: ${save_alias} (${selected_ip})"
                else
                    warn "目标主机保存失败，但会继续创建转发。"
                fi
                break
            done
        fi
    fi

    printf -v "$__result_var" '%s' "$selected_ip"
}

load_rules() {
    RULES=()
    if [[ ! -f "${CONF_FILE}" ]]; then
        return
    fi
    if grep -qE '^[[:space:]]*#[[:space:]]*META_RULE\|' "${CONF_FILE}" 2>/dev/null; then
        local line lport dip dport alias _group _desc
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*#[[:space:]]*META_RULE\| ]] || continue
            line="${line#*META_RULE|}"
            IFS='|' read -r lport dip dport alias _group _desc <<< "$line"
            if validate_port "$lport" && validate_ip "$dip" && validate_port "$dport"; then
                alias=$(clean_label "$alias")
                RULES+=("${lport}|${dip}|${dport}|${alias}")
            fi
        done < "${CONF_FILE}"
        return
    fi
    while IFS= read -r line; do
        # 跳过注释行
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        # 只解析 tcp 的 dnat 行（每对 tcp/udp 只记录一次）
        if [[ "$line" =~ tcp\ dport\ ([0-9]+)\ dnat\ to\ ([0-9.]+):([0-9]+) ]]; then
            RULES+=("${BASH_REMATCH[1]}|${BASH_REMATCH[2]}|${BASH_REMATCH[3]}|")
        fi
    done < "${CONF_FILE}"
}

write_conf_file() {
    local local_ip
    local_ip=$(get_local_ip)

    if [[ -z "$local_ip" ]]; then
        err "无法获取本机 IP 地址，请检查网络配置。"
        return 1
    fi

    # 先写入临时文件，成功后原子替换，避免写到一半断电导致配置损坏
    local tmp_file="${CONF_FILE}.tmp.$$"

    cat > "${tmp_file}" <<EOF
#!/usr/sbin/nft -f

# WEB_META|4

# --- 本机 IP（自动获取，用于 SNAT 回源）
define LOCAL_IP = ${local_ip}

table ip ${TABLE_NAME} {
    # --- PREROUTING (DNAT) ---
    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
EOF

    local rule lport dip dport alias
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport alias <<< "$rule"
        alias=$(clean_label "$alias")
        cat >> "${tmp_file}" <<EOF

        # META_RULE|${lport}|${dip}|${dport}|${alias}|||total|1
        # 转发: 本机:${lport} -> ${dip}:${dport}${alias:+ (${alias})}
        tcp dport ${lport} counter dnat to ${dip}:${dport}
        udp dport ${lport} counter dnat to ${dip}:${dport}
EOF
    done

    cat >> "${tmp_file}" <<EOF
    }

    # --- POSTROUTING (SNAT) ---
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
EOF

    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport alias <<< "$rule"
        cat >> "${tmp_file}" <<EOF

        # 回源: 发往 ${dip}:${dport} 的已 DNAT 流量, SNAT 为本机 IP
        ip daddr ${dip} tcp dport ${dport} ct status dnat snat to \$LOCAL_IP
        ip daddr ${dip} udp dport ${dport} ct status dnat snat to \$LOCAL_IP
EOF
    done

    cat >> "${tmp_file}" <<EOF
    }

    # --- FORWARD (Web 流量统计) ---
    chain forward {
        type filter hook forward priority filter; policy accept;
EOF

    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport alias <<< "$rule"
        cat >> "${tmp_file}" <<EOF

        ct original protocol tcp ct original proto-dst ${lport} ip daddr ${dip} tcp dport ${dport} ct status dnat counter comment "META_COUNTER_UPLOAD|${lport}|${dip}|${dport}"
        ct original protocol udp ct original proto-dst ${lport} ip daddr ${dip} udp dport ${dport} ct status dnat counter comment "META_COUNTER_UPLOAD|${lport}|${dip}|${dport}"
        ct original protocol tcp ct original proto-dst ${lport} ip saddr ${dip} tcp sport ${dport} ct status dnat counter comment "META_COUNTER_DOWNLOAD|${lport}|${dip}|${dport}"
        ct original protocol udp ct original proto-dst ${lport} ip saddr ${dip} udp sport ${dport} ct status dnat counter comment "META_COUNTER_DOWNLOAD|${lport}|${dip}|${dport}"
EOF
    done

    cat >> "${tmp_file}" <<EOF
    }
}
EOF

    # 原子替换
    mv -f "${tmp_file}" "${CONF_FILE}" 2>/dev/null || {
        err "无法写入配置文件 ${CONF_FILE}"
        rm -f "${tmp_file}" 2>/dev/null || true
        return 1
    }
}

# ============== 重新加载规则 ==============
snapshot_traffic() {
    if command -v python3 &>/dev/null && [[ -f "${WEB_PANEL_FILE}" ]] && grep -q -- '--snapshot-traffic' "${WEB_PANEL_FILE}" 2>/dev/null; then
        python3 "${WEB_PANEL_FILE}" --snapshot-traffic >/dev/null 2>&1 || true
    fi
}

reload_rules() {
    snapshot_traffic
    "$NFT_BIN" flush table ip "${TABLE_NAME}" 2>/dev/null || true
    "$NFT_BIN" delete table ip "${TABLE_NAME}" 2>/dev/null || true
    if ! "$NFT_BIN" -f "${CONF_FILE}"; then
        err "加载配置文件失败，请检查 ${CONF_FILE}"
        return 1
    fi
    return 0
}

# ============== 开启内核参数：IP 转发 + BBR/fq ==============
enable_ip_forward() {
    local current
    current=$(sysctl -n net.ipv4.ip_forward 2>/dev/null) || current="0"
    if [[ "$current" != "1" ]]; then
        if sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
            info "已开启 IPv4 转发。"
        else
            warn "无法开启 IPv4 转发，请手动执行: sysctl -w net.ipv4.ip_forward=1"
        fi
    fi

    # 持久化：统一替换所有匹配行为 =1，没有则追加（避免重复项导致后值覆盖前值的误判）
    mkdir -p "$(dirname "${SYSCTL_CONF}")" 2>/dev/null || true
    touch "${SYSCTL_CONF}" 2>/dev/null || true

    if grep -qE '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=' "${SYSCTL_CONF}" 2>/dev/null; then
        sed -i -E 's|^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=.*|net.ipv4.ip_forward=1|' "${SYSCTL_CONF}" 2>/dev/null || true
    else
        echo "net.ipv4.ip_forward=1" >> "${SYSCTL_CONF}" 2>/dev/null || true
    fi

    sysctl -p "${SYSCTL_CONF}" >/dev/null 2>&1 || true
}

enable_bbr_fq() {
    # 1) 内核是否支持 bbr
    modprobe tcp_bbr 2>/dev/null || true
    if ! grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
        warn "内核不支持 BBR（tcp_available_congestion_control 中未找到 bbr），已跳过。"
        return 0
    fi

    # 2) 读取当前配置
    local cur_cc cur_qd
    cur_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null) || cur_cc=""
    cur_qd=$(sysctl -n net.core.default_qdisc 2>/dev/null) || cur_qd=""

    # 3) 判断是否已经开启
    if [[ "$cur_cc" == "bbr" && "$cur_qd" == "fq" ]]; then
        info "BBR + fq 已启用（无需修改）。"
        return 0
    fi

    # 4) 没开则开启（立即生效）
    sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true

    # 再读一次确认
    cur_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null) || cur_cc=""
    cur_qd=$(sysctl -n net.core.default_qdisc 2>/dev/null) || cur_qd=""

    if [[ "$cur_cc" == "bbr" && "$cur_qd" == "fq" ]]; then
        info "已开启 BBR + fq。"
        log_action "开启 BBR+fq"
    else
        warn "尝试开启 BBR+fq 后未确认生效（当前: cc=${cur_cc:-?}, qdisc=${cur_qd:-?}），可能被系统配置覆盖。"
    fi

    # 5) 持久化：写入 SYSCTL_CONF（用“替换/追加”避免覆盖别的项）
    mkdir -p "$(dirname "${SYSCTL_CONF}")" 2>/dev/null || true
    touch "${SYSCTL_CONF}" 2>/dev/null || true

    if grep -qE '^[[:space:]]*net\.core\.default_qdisc[[:space:]]*=' "${SYSCTL_CONF}"; then
        sed -i -E 's|^[[:space:]]*net\.core\.default_qdisc[[:space:]]*=.*|net.core.default_qdisc=fq|' "${SYSCTL_CONF}" 2>/dev/null || true
    else
        echo "net.core.default_qdisc=fq" >> "${SYSCTL_CONF}" 2>/dev/null || true
    fi

    if grep -qE '^[[:space:]]*net\.ipv4\.tcp_congestion_control[[:space:]]*=' "${SYSCTL_CONF}"; then
        sed -i -E 's/^[[:space:]]*net\.ipv4\.tcp_congestion_control[[:space:]]*=.*/net.ipv4.tcp_congestion_control=bbr/' "${SYSCTL_CONF}" 2>/dev/null || true
    else
        echo "net.ipv4.tcp_congestion_control=bbr" >> "${SYSCTL_CONF}" 2>/dev/null || true
    fi

    sysctl -p "${SYSCTL_CONF}" >/dev/null 2>&1 || true
    info "已持久化 BBR + fq 到 ${SYSCTL_CONF}。"
    log_action "持久化 BBR+fq 到 ${SYSCTL_CONF}"
}

# ============== 检测防火墙状态（仅提示） ==============
check_firewall_status() {
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        info "检测到 firewalld 正在运行，添加转发规则时将自动放行对应端口。"
    elif command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qw "active"; then
        info "检测到 UFW 正在运行，添加转发规则时将自动放行对应端口。"
    elif has_iptables; then
        info "检测到 iptables 规则集存在，添加转发规则时将自动放行对应端口。"
    fi
}

# ============== 更新检查 / 在线更新 ==============
load_update_url() {
    if [[ -n "${NFT_FORWARD_UPDATE_URL:-}" ]]; then
        printf '%s' "$NFT_FORWARD_UPDATE_URL"
        return
    fi
    if [[ -f "$UPDATE_URL_FILE" ]]; then
        sed -nE '/^[[:space:]]*#/d; s/^[[:space:]]+//; s/[[:space:]]+$//; /^$/d; 1p' "$UPDATE_URL_FILE" 2>/dev/null
        return
    fi
    printf '%s' "$DEFAULT_UPDATE_URL"
}

persist_update_url() {
    local url
    url=$(load_update_url)
    [[ -n "$url" ]] || return 0
    mkdir -p "$CONF_DIR" 2>/dev/null || return 0
    printf '%s\n' "$url" > "$UPDATE_URL_FILE" 2>/dev/null || true
}

extract_script_version() {
    local file="$1"
    sed -nE 's/^[[:space:]]*SCRIPT_VERSION="([^"]+)".*/\1/p' "$file" 2>/dev/null | head -1
}

version_gt() {
    local newer="$1" current="$2"
    [[ "$newer" != "$current" ]] && [[ "$(printf '%s\n%s\n' "$current" "$newer" | sort -V | tail -1)" == "$newer" ]]
}

download_update_script() {
    local dest="$1" requested_url source_url
    requested_url=$(load_update_url)
    if [[ -z "$requested_url" ]]; then
        return 2
    fi

    # 按当前配置源、GitHub Raw、jsDelivr 顺序尝试。每个源都要通过脚本校验，
    # 防止代理返回 HTML 错误页后被误判为下载成功。
    local -a candidates=("$requested_url" "$DEFAULT_UPDATE_URL" "$FALLBACK_UPDATE_URL")
    local candidate
    for candidate in "${candidates[@]}"; do
        [[ -n "$candidate" ]] || continue
        [[ "$candidate" == "$source_url" ]] && continue
        source_url="$candidate"
        if download_remote_file "$source_url" "$dest" 8 && is_valid_update_script "$dest"; then
            UPDATE_URL="$source_url"
            UPDATE_DOWNLOADED_URL="$source_url"
            return 0
        fi
        rm -f "$dest" 2>/dev/null || true
    done
    return 1
}

is_valid_update_script() {
    local file="$1"
    [[ -s "$file" ]] || return 1
    [[ "$(head -1 "$file" 2>/dev/null)" == "#!/usr/bin/env bash" ]] || return 1
    [[ -n "$(extract_script_version "$file")" ]] || return 1
    bash -n "$file" >/dev/null 2>&1
}

cache_busted_url() {
    local url="$1" sep="?"
    case "$url" in
        http://*|https://*) ;;
        *) printf '%s' "$url"; return ;;
    esac
    [[ "$url" == *\?* ]] && sep="&"
    printf '%s%snft_manager_cache=%s%s' "$url" "$sep" "$(date +%s)" "$RANDOM"
}

download_remote_file() {
    local source_url="$1" dest="$2" timeout="${3:-30}" request_url
    request_url=$(cache_busted_url "$source_url")
    if command -v curl &>/dev/null; then
        curl -fsSL --retry 0 --connect-timeout 3 --max-time "$timeout" "$request_url" -o "$dest"
    elif command -v wget &>/dev/null; then
        wget -q --tries=1 --timeout="$timeout" -O "$dest" "$request_url"
    else
        return 3
    fi
}

load_web_panel_url() {
    if [[ -n "${NFT_MANAGER_WEB_PANEL_URL:-}" ]]; then
        printf '%s' "$NFT_MANAGER_WEB_PANEL_URL"
        return
    fi

    local update_url update_base update_query
    update_url="${UPDATE_DOWNLOADED_URL:-$UPDATE_URL}"
    [[ -n "$update_url" ]] || update_url=$(load_update_url)
    update_base="${update_url%%\?*}"
    update_query="${update_url#*\?}"
    if [[ "$update_base" == */nft.sh ]]; then
        if [[ "$update_url" == *\?* ]]; then
            printf '%s?%s' "${update_base%/nft.sh}/web_panel.py" "$update_query"
        else
            printf '%s' "${update_base%/nft.sh}/web_panel.py"
        fi
        return
    fi

    printf '%s' "$WEB_PANEL_URL"
}

check_update_status() {
    local force="${1:-}"
    if [[ "$UPDATE_CHECKED" == "true" && "$force" != "force" ]]; then
        return
    fi

    UPDATE_CHECKED=true
    UPDATE_AVAILABLE=false
    UPDATE_REMOTE_VERSION=""
    UPDATE_URL=$(load_update_url)

    if [[ -z "$UPDATE_URL" ]]; then
        UPDATE_STATUS_TEXT="未配置更新源"
        return
    fi

    local tmp_file remote_version
    tmp_file=$(mktemp 2>/dev/null || echo "/tmp/nft-forward-update.$$") || true
    if ! download_update_script "$tmp_file" >/dev/null 2>&1; then
        rm -f "$tmp_file" 2>/dev/null || true
        UPDATE_STATUS_TEXT="检查失败"
        return
    fi

    remote_version=$(extract_script_version "$tmp_file")
    rm -f "$tmp_file" 2>/dev/null || true

    if [[ -z "$remote_version" ]]; then
        UPDATE_STATUS_TEXT="远程版本无效"
        return
    fi

    UPDATE_REMOTE_VERSION="$remote_version"
    if version_gt "$remote_version" "$SCRIPT_VERSION"; then
        UPDATE_AVAILABLE=true
        UPDATE_STATUS_TEXT="可升级到 v${remote_version}"
    else
        UPDATE_STATUS_TEXT="已是最新"
    fi
}

do_update() {
    echo ""
    UPDATE_URL=$(load_update_url)
    if [[ -z "$UPDATE_URL" ]]; then
        warn "未配置更新源，无法在线更新。"
        warn "请将 GitHub raw 地址写入 ${UPDATE_URL_FILE}，或运行前设置环境变量 NFT_FORWARD_UPDATE_URL。"
        return
    fi

    info "当前版本: v${SCRIPT_VERSION}"
    info "更新源: ${UPDATE_URL}"

    local tmp_file remote_version install_target
    tmp_file=$(mktemp 2>/dev/null || echo "/tmp/nft-forward-update.$$") || true
    if ! download_update_script "$tmp_file"; then
        rm -f "$tmp_file" 2>/dev/null || true
        err "下载更新失败，请检查网络或 UPDATE_URL。"
        return
    fi

    remote_version=$(extract_script_version "$tmp_file")
    if [[ -z "$remote_version" ]]; then
        rm -f "$tmp_file" 2>/dev/null || true
        err "远程脚本没有有效版本号，已取消更新。"
        return
    fi

    if ! bash -n "$tmp_file"; then
        rm -f "$tmp_file" 2>/dev/null || true
        err "远程脚本语法检查失败，已取消更新。"
        return
    fi

    if version_gt "$remote_version" "$SCRIPT_VERSION"; then
        info "发现新版本: v${remote_version}"
    elif [[ "$remote_version" == "$SCRIPT_VERSION" ]]; then
        info "当前已是最新版本，未执行更新。"
        rm -f "$tmp_file" 2>/dev/null || true
        return
    else
        info "远程版本: v${remote_version}"
        warn "远程版本低于当前版本，已取消更新。"
        rm -f "$tmp_file" 2>/dev/null || true
        return
    fi

    if manager_installed || [[ "$SCRIPT_PATH" == "$SCRIPT_INSTALL_FILE" ]]; then
        install_target="$SCRIPT_INSTALL_FILE"
    else
        install_target="$SCRIPT_PATH"
    fi

    mkdir -p "$(dirname "$install_target")" 2>/dev/null || {
        rm -f "$tmp_file" 2>/dev/null || true
        err "无法创建安装目录: $(dirname "$install_target")"
        return
    }

    install -m 755 "$tmp_file" "$install_target" 2>/dev/null || {
        rm -f "$tmp_file" 2>/dev/null || true
        err "写入新版脚本失败。"
        return
    }
    rm -f "$tmp_file" 2>/dev/null || true

    if [[ "$install_target" == "$SCRIPT_INSTALL_FILE" ]]; then
        cat > "${GLOBAL_CMD}" <<EOF
#!/usr/bin/env bash
exec "${SCRIPT_INSTALL_FILE}" "\$@"
EOF
        chmod +x "${GLOBAL_CMD}" 2>/dev/null || true
        if ! NFT_MANAGER_WEB_PANEL_URL="$(load_web_panel_url)" "${SCRIPT_INSTALL_FILE}" --post-update; then
            err "运行时同步未完整完成，请检查服务状态后重试更新。"
            return
        fi
    fi

    info "更新完成: v${SCRIPT_VERSION} → v${remote_version}"
    persist_update_url
    if [[ "$install_target" == "$SCRIPT_INSTALL_FILE" ]]; then
        info "已同步更新 Web 面板并重启相关服务。"
    fi
    log_action "更新脚本: ${SCRIPT_VERSION} -> ${remote_version}"
    exit 0
}

# ============== 管理器安装 / 卸载 / 保活 ==============
manager_installed() {
    [[ -x "${SCRIPT_INSTALL_FILE}" && -x "${GLOBAL_CMD}" ]]
}

web_panel_installed() {
    [[ -x "${WEB_PANEL_FILE}" && -f "${WEB_SERVICE_FILE}" ]]
}

web_panel_version() {
    local file="$1"
    sed -nE 's/^WEB_PANEL_VERSION[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$file" 2>/dev/null | head -1
}

web_panel_needs_sync() {
    [[ ! -x "${WEB_PANEL_FILE}" ]] && return 0
    [[ "$(web_panel_version "${WEB_PANEL_FILE}")" != "${WEB_PANEL_VERSION}" ]]
}

is_manager_global_command() {
    local file="$1"
    [[ -f "$file" ]] || return 1
    grep -qE 'exec[[:space:]]+"(/opt/nft-manager|/usr/local/lib/nft-forward)/nft\.sh"' "$file" 2>/dev/null ||
        grep -qF 'nftables 端口转发管理工具' "$file" 2>/dev/null
}

remove_legacy_global_command() {
    [[ "${LEGACY_GLOBAL_CMD}" != "${GLOBAL_CMD}" && -e "${LEGACY_GLOBAL_CMD}" ]] || return 0
    if ! is_manager_global_command "${LEGACY_GLOBAL_CMD}"; then
        warn "检测到非本项目管理的 ${LEGACY_GLOBAL_CMD}，已保留该文件。"
        return 0
    fi
    rm -f "${LEGACY_GLOBAL_CMD}" 2>/dev/null || {
        err "无法删除旧版全局命令 ${LEGACY_GLOBAL_CMD}"
        return 1
    }
    info "已删除旧版全局命令: ${LEGACY_GLOBAL_CMD}"
}

install_manager_files() {
    local source_vendor target_vendor
    mkdir -p "${SCRIPT_INSTALL_DIR}" 2>/dev/null || {
        err "无法创建 ${SCRIPT_INSTALL_DIR}"
        return 1
    }

    if [[ "${SCRIPT_PATH}" != "${SCRIPT_INSTALL_FILE}" ]]; then
        install -m 755 "${SCRIPT_PATH}" "${SCRIPT_INSTALL_FILE}" 2>/dev/null || {
            err "无法安装脚本到 ${SCRIPT_INSTALL_FILE}"
            return 1
        }
    else
        chmod +x "${SCRIPT_INSTALL_FILE}" 2>/dev/null || true
    fi

    source_vendor="$(dirname "${SCRIPT_PATH}")/vendor/nexttrace"
    target_vendor="${NEXTTRACE_VENDOR_DIR}"
    if [[ -d "$source_vendor" && "$(readlink -f "$source_vendor" 2>/dev/null || realpath "$source_vendor" 2>/dev/null)" != "$(readlink -f "$target_vendor" 2>/dev/null || realpath "$target_vendor" 2>/dev/null)" ]]; then
        rm -rf "$target_vendor" 2>/dev/null || true
        mkdir -p "$(dirname "$target_vendor")" 2>/dev/null || return 1
        cp -a "$source_vendor" "$target_vendor" 2>/dev/null || {
            err "无法安装项目内置 NextTrace 文件。"
            return 1
        }
    fi

    if [[ -e "${GLOBAL_CMD}" ]] && ! grep -qF "exec \"${SCRIPT_INSTALL_FILE}\"" "${GLOBAL_CMD}" 2>/dev/null; then
        warn "检测到已有 ${GLOBAL_CMD}，将直接覆盖为 nft-manager 入口。"
    fi

    cat > "${GLOBAL_CMD}" <<EOF
#!/usr/bin/env bash
exec "${SCRIPT_INSTALL_FILE}" "\$@"
EOF
    chmod +x "${GLOBAL_CMD}" 2>/dev/null || {
        err "无法创建全局命令 ${GLOBAL_CMD}"
        return 1
    }

    remove_legacy_global_command || return 1

    info "已安装全局命令: ${GLOBAL_CMD}"
}

is_nft_manager_script() {
    local file="$1"
    [[ -f "$file" ]] || return 1
    grep -qF 'nftables 端口转发管理工具' "$file" 2>/dev/null &&
        grep -qE '^[[:space:]]*SCRIPT_VERSION=' "$file" 2>/dev/null
}

cleanup_legacy_runtime() {
    local legacy_root_script="/root/nft.sh"
    local legacy_offline_dir="/root/nft-manager-update"

    # 只有全局命令和两个 systemd 服务均已指向新目录，才清理旧运行文件。
    grep -qF "exec \"${SCRIPT_INSTALL_FILE}\"" "${GLOBAL_CMD}" 2>/dev/null || return 1
    if command -v systemctl &>/dev/null; then
        [[ ! -f "${KEEPALIVE_SERVICE_FILE}" ]] || grep -qF "${SCRIPT_INSTALL_FILE} --keepalive" "${KEEPALIVE_SERVICE_FILE}" 2>/dev/null || return 1
        [[ ! -f "${WEB_SERVICE_FILE}" ]] || grep -qF "${WEB_PANEL_FILE}" "${WEB_SERVICE_FILE}" 2>/dev/null || return 1
    fi

    if [[ "${LEGACY_SCRIPT_INSTALL_DIR}" != "${SCRIPT_INSTALL_DIR}" && -d "${LEGACY_SCRIPT_INSTALL_DIR}" ]]; then
        rm -rf "${LEGACY_SCRIPT_INSTALL_DIR}" 2>/dev/null || {
            warn "旧运行目录清理失败: ${LEGACY_SCRIPT_INSTALL_DIR}"
            return 1
        }
        info "已迁移并清理旧运行目录: ${LEGACY_SCRIPT_INSTALL_DIR}"
    fi

    if [[ "$legacy_root_script" != "${SCRIPT_INSTALL_FILE}" ]] && is_nft_manager_script "$legacy_root_script"; then
        rm -f "$legacy_root_script" 2>/dev/null || {
            warn "旧启动脚本清理失败: ${legacy_root_script}"
            return 1
        }
        info "已清理旧启动脚本: ${legacy_root_script}"
    fi

    if [[ -d "$legacy_offline_dir" ]]; then
        rm -rf "$legacy_offline_dir" 2>/dev/null || {
            warn "旧离线暂存目录清理失败: ${legacy_offline_dir}"
            return 1
        }
        info "已清理旧离线暂存目录: ${legacy_offline_dir}"
    fi
}

install_keepalive_service() {
    local start_mode="${1:-start}"
    if ! command -v systemctl &>/dev/null; then
        warn "未检测到 systemd，已跳过保活服务安装。"
        return 0
    fi

    cat > "${KEEPALIVE_SERVICE_FILE}" <<EOF
[Unit]
Description=nftables port-forward keepalive
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${SCRIPT_INSTALL_FILE} --keepalive
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload >/dev/null 2>&1 || true
    if systemctl enable "${KEEPALIVE_SERVICE_NAME}" >/dev/null 2>&1 && { [[ "$start_mode" == "defer" ]] || systemctl restart "${KEEPALIVE_SERVICE_NAME}" >/dev/null 2>&1; }; then
        info "已安装并启用 systemd 保活服务: ${KEEPALIVE_SERVICE_NAME}"
        log_action "安装并启用保活服务 ${KEEPALIVE_SERVICE_NAME}"
    else
        warn "保活服务启用失败，请手动执行: systemctl enable ${KEEPALIVE_SERVICE_NAME} && systemctl restart ${KEEPALIVE_SERVICE_NAME}"
        return 1
    fi
}

install_web_panel_file() {
    local force_download="${1:-}"
    mkdir -p "${SCRIPT_INSTALL_DIR}" 2>/dev/null || {
        err "无法创建 ${SCRIPT_INSTALL_DIR}"
        return 1
    }

    local source_dir tmp_file web_panel_url
    source_dir="$(dirname "${SCRIPT_PATH}")"
    if [[ "$force_download" != "force" && -f "${source_dir}/web_panel.py" ]]; then
        if ! python3 -m py_compile "${source_dir}/web_panel.py" >/dev/null 2>&1; then
            err "本地 Web 面板文件校验失败: ${source_dir}/web_panel.py"
            return 1
        fi
        if [[ "$(readlink -f "${source_dir}/web_panel.py" 2>/dev/null || realpath "${source_dir}/web_panel.py" 2>/dev/null)" == "$(readlink -f "${WEB_PANEL_FILE}" 2>/dev/null || realpath "${WEB_PANEL_FILE}" 2>/dev/null)" ]]; then
            chmod 755 "${WEB_PANEL_FILE}" 2>/dev/null || return 1
            return 0
        fi
        cp -f "${source_dir}/web_panel.py" "${WEB_PANEL_FILE}" 2>/dev/null && chmod 755 "${WEB_PANEL_FILE}" 2>/dev/null || {
            err "无法安装 Web 面板文件到 ${WEB_PANEL_FILE}"
            return 1
        }
        return 0
    fi

    tmp_file=$(mktemp 2>/dev/null || echo "/tmp/nft-manager-web.$$") || true
    web_panel_url=$(load_web_panel_url)
    if ! download_remote_file "$web_panel_url" "$tmp_file" 30; then
        rm -f "$tmp_file" 2>/dev/null || true
        err "下载 Web 面板失败: ${web_panel_url}"
        return 1
    fi

    if ! python3 -m py_compile "$tmp_file" >/dev/null 2>&1; then
        rm -f "$tmp_file" 2>/dev/null || true
        err "Web 面板文件校验失败。"
        return 1
    fi

    cp -f "$tmp_file" "${WEB_PANEL_FILE}" 2>/dev/null && chmod 755 "${WEB_PANEL_FILE}" 2>/dev/null || {
        rm -f "$tmp_file" 2>/dev/null || true
        err "无法安装 Web 面板文件到 ${WEB_PANEL_FILE}"
        return 1
    }
    rm -f "$tmp_file" 2>/dev/null || true
}

install_web_service() {
    local force_download="${1:-}"
    local start_mode="${2:-start}"
    if ! command -v python3 &>/dev/null; then
        warn "未检测到 python3，无法安装 Web 面板。"
        return 1
    fi
    install_web_panel_file "$force_download" || return 1
    mkdir -p "${CONF_DIR}" 2>/dev/null || true

    if ! command -v systemctl &>/dev/null; then
        warn "未检测到 systemd，已跳过 Web 面板服务安装。"
        return 0
    fi

    cat > "${WEB_SERVICE_FILE}" <<EOF
[Unit]
Description=nft-manager web panel
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/env python3 ${WEB_PANEL_FILE}
Restart=always
RestartSec=3
Environment=NFT_MANAGER_WEB_PORT=${WEB_PORT}
ExecStop=/usr/bin/env python3 ${WEB_PANEL_FILE} --snapshot-traffic

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload >/dev/null 2>&1 || true
    if systemctl enable "${WEB_SERVICE_NAME}" >/dev/null 2>&1 && { [[ "$start_mode" == "defer" ]] || systemctl restart "${WEB_SERVICE_NAME}" >/dev/null 2>&1; }; then
        web_firewall_open
        info "已安装并启用 Web 面板服务: ${WEB_SERVICE_NAME}"
        info "Web 面板地址: http://$(get_local_ip):${WEB_PORT}"
        info "默认账号/密码: admin / admin"
        log_action "安装并启用 Web 面板服务 ${WEB_SERVICE_NAME}"
    else
        warn "Web 面板服务启用失败，请手动执行: systemctl enable ${WEB_SERVICE_NAME} && systemctl restart ${WEB_SERVICE_NAME}"
        return 1
    fi
}

nexttrace_arch() {
    case "$(uname -m 2>/dev/null)" in
        x86_64|amd64) printf 'amd64' ;;
        aarch64|arm64) printf 'arm64' ;;
        *) return 1 ;;
    esac
}

nexttrace_version_text() {
    local bin="${1:-$(command -v nexttrace 2>/dev/null || true)}" output=""
    [[ -n "$bin" && -x "$bin" ]] || return 1
    if command -v timeout &>/dev/null; then
        output=$(NO_COLOR=1 timeout 5 "$bin" --version 2>&1 | head -1) || true
    else
        output=$(NO_COLOR=1 "$bin" --version 2>&1 | head -1) || true
    fi
    [[ -n "$output" ]] && printf '%s' "$output" || printf '%s' "$bin"
}

validate_nexttrace_binary() {
    local file="$1"
    [[ -s "$file" ]] || return 1
    chmod 755 "$file" 2>/dev/null || return 1
    if command -v timeout &>/dev/null; then
        timeout 8 "$file" --version >/dev/null 2>&1 || timeout 8 "$file" -h >/dev/null 2>&1
    else
        "$file" --version >/dev/null 2>&1 || "$file" -h >/dev/null 2>&1
    fi
}

activate_nexttrace_binary() {
    local source="$1" temp_target="${NEXTTRACE_INSTALL_FILE}.new.$$"
    validate_nexttrace_binary "$source" || {
        err "NextTrace 文件无效或与当前 VPS 架构不匹配: ${source}"
        return 1
    }
    install -m 755 "$source" "$temp_target" 2>/dev/null && mv -f "$temp_target" "${NEXTTRACE_INSTALL_FILE}" 2>/dev/null || {
        rm -f "$temp_target" 2>/dev/null || true
        err "无法写入 ${NEXTTRACE_INSTALL_FILE}"
        return 1
    }
    printf '%s\n' "${NEXTTRACE_INSTALL_FILE}" > "$NEXTTRACE_MARKER" 2>/dev/null || true
}

download_project_nexttrace() {
    local arch="$1" dest="$2" name="nexttrace_linux_${arch}" url
    for url in "${NEXTTRACE_PROJECT_RAW}/${name}" "${NEXTTRACE_PROJECT_CDN}/${name}"; do
        if download_remote_file "$url" "$dest" 120 && validate_nexttrace_binary "$dest"; then
            return 0
        fi
        rm -f "$dest" 2>/dev/null || true
    done
    return 1
}

install_nexttrace() {
    local mode="${1:-online}" force="${2:-}" nexttrace_bin candidate arch name temp_file
    nexttrace_bin=$(command -v nexttrace 2>/dev/null || true)
    if [[ -n "$nexttrace_bin" && "$force" != "force" ]]; then
        info "NextTrace 已就绪: $(nexttrace_version_text "$nexttrace_bin")"
        return 0
    fi
    arch=$(nexttrace_arch 2>/dev/null || true)
    if [[ -n "$arch" ]]; then
        name="nexttrace_linux_${arch}"
        for candidate in "$(dirname "${SCRIPT_PATH}")/vendor/nexttrace/${name}" "${NEXTTRACE_VENDOR_DIR}/${name}"; do
            [[ -f "$candidate" ]] || continue
            if activate_nexttrace_binary "$candidate"; then
                info "已接入项目内置 NextTrace v${NEXTTRACE_BUNDLED_VERSION}: ${candidate}"
                log_action "安装项目内置 NextTrace: ${candidate}"
                return 0
            fi
        done
    fi
    for candidate in "$(dirname "${SCRIPT_PATH}")/nexttrace" "${NEXTTRACE_LOCAL_FILE}" "/root/nexttrace"; do
        [[ -f "$candidate" ]] || continue
        if activate_nexttrace_binary "$candidate"; then
            info "已接入本地 NextTrace: ${candidate}"
            log_action "安装本地 NextTrace: ${candidate}"
            return 0
        fi
    done

    if [[ -z "$arch" ]]; then
        warn "当前架构没有项目内置 NextTrace，请将官方二进制上传为 ${NEXTTRACE_LOCAL_FILE}。"
        return 1
    fi

    if [[ "$mode" == "offline" ]]; then
        warn "未找到适用于 ${arch} 的项目内置 NextTrace；请一并上传 vendor/nexttrace 目录。"
        return 1
    fi
    temp_file=$(mktemp 2>/dev/null || echo "/tmp/nexttrace-project.$$") || true
    info "正在下载项目内置 NextTrace v${NEXTTRACE_BUNDLED_VERSION} (${arch})..."
    if ! download_project_nexttrace "$arch" "$temp_file" || ! activate_nexttrace_binary "$temp_file"; then
        rm -f "$temp_file" 2>/dev/null || true
        warn "项目内置 NextTrace 下载失败，路由追踪暂不可用。"
        return 1
    fi
    mkdir -p "${NEXTTRACE_VENDOR_DIR}" 2>/dev/null || true
    install -m 755 "$temp_file" "${NEXTTRACE_VENDOR_DIR}/${name}" 2>/dev/null || true
    rm -f "$temp_file" 2>/dev/null || true
    info "NextTrace 已安装: $(nexttrace_version_text "${NEXTTRACE_INSTALL_FILE}")"
    log_action "下载并安装项目内置 NextTrace v${NEXTTRACE_BUNDLED_VERSION}"
}

update_nexttrace_online() {
    local arch name temp_file vendor_target
    arch=$(nexttrace_arch) || {
        err "当前架构暂不支持菜单在线升级，请使用 NextTrace 官方安装方式。"
        return 1
    }
    name="nexttrace-tiny_linux_${arch}"
    temp_file=$(mktemp 2>/dev/null || echo "/tmp/nexttrace-update.$$") || true
    info "正在从 NextTrace 官方 Release 检查并下载最新 ${arch} 版本..."
    if ! download_remote_file "${NEXTTRACE_RELEASE_BASE}/${name}" "$temp_file" 180; then
        rm -f "$temp_file" 2>/dev/null || true
        err "NextTrace 下载失败，请检查 GitHub 连接。"
        return 1
    fi
    if ! activate_nexttrace_binary "$temp_file"; then
        rm -f "$temp_file" 2>/dev/null || true
        return 1
    fi
    vendor_target="${NEXTTRACE_VENDOR_DIR}/nexttrace_linux_${arch}"
    mkdir -p "${NEXTTRACE_VENDOR_DIR}" 2>/dev/null || true
    install -m 755 "$temp_file" "$vendor_target" 2>/dev/null || warn "已更新运行命令，但未能同步项目安装目录中的副本。"
    rm -f "$temp_file" 2>/dev/null || true
    info "NextTrace 升级完成: $(nexttrace_version_text "${NEXTTRACE_INSTALL_FILE}")"
    log_action "在线升级 NextTrace"
}

do_nexttrace_menu() {
    while true; do
        echo ""
        echo "========================================"
        echo "          NextTrace 管理"
        echo "========================================"
        if command -v nexttrace &>/dev/null; then
            echo "  当前状态: $(nexttrace_version_text)"
        else
            echo "  当前状态: 未安装"
        fi
        echo "  1) 从项目内置文件安装 / 修复"
        echo "  2) 从官方 Release 在线升级"
        echo "  0) 返回主菜单"
        echo "========================================"
        local choice
        read -rp "请选择操作 [0-2]: " choice
        case "$choice" in
            0) return ;;
            1) install_nexttrace offline force ;;
            2) update_nexttrace_online ;;
            *) err "无效选择，请输入 0-2。" ;;
        esac
    done
}

install_manager_runtime() {
    install_manager_files || return 1
    persist_update_url
    install_web_service || return 1
    install_nexttrace || true
    install_keepalive_service
}

restart_runtime_services() {
    local restart_ok=true
    if ! command -v systemctl &>/dev/null; then
        return 0
    fi
    systemctl daemon-reload >/dev/null 2>&1 || true
    if [[ -f "${KEEPALIVE_SERVICE_FILE}" ]]; then
        if ! systemctl enable "${KEEPALIVE_SERVICE_NAME}" >/dev/null 2>&1; then
            restart_ok=false
            warn "保活服务启用失败: ${KEEPALIVE_SERVICE_NAME}"
        fi
        if ! systemctl restart "${KEEPALIVE_SERVICE_NAME}" >/dev/null 2>&1; then
            restart_ok=false
            warn "保活服务重启失败: ${KEEPALIVE_SERVICE_NAME}"
        fi
    fi
    if [[ -x "${WEB_PANEL_FILE}" && -f "${WEB_SERVICE_FILE}" ]]; then
        if ! systemctl enable "${WEB_SERVICE_NAME}" >/dev/null 2>&1; then
            restart_ok=false
            warn "Web 面板服务启用失败: ${WEB_SERVICE_NAME}"
        fi
        if ! systemctl restart "${WEB_SERVICE_NAME}" >/dev/null 2>&1; then
            restart_ok=false
            warn "Web 面板服务重启失败: ${WEB_SERVICE_NAME}"
        fi
    fi
    [[ "$restart_ok" == "true" ]]
}

sync_updated_runtime() {
    local needs_web=false migration_ok=true sync_ok=true
    if ! web_panel_installed || web_panel_needs_sync; then
        needs_web=true
    fi

    if command -v systemctl &>/dev/null; then
        systemctl stop "${WEB_SERVICE_NAME}" >/dev/null 2>&1 || true
        systemctl stop "${KEEPALIVE_SERVICE_NAME}" >/dev/null 2>&1 || true
    fi

    if [[ "$needs_web" == "true" ]]; then
        info "检测到 Web 面板缺失或版本不一致，正在同步 v${WEB_PANEL_VERSION}..."
        if ! install_web_service force defer; then
            sync_ok=false
            warn "Web 面板同步失败，已保留当前文件并将在最后恢复已有服务。"
        fi
    else
        info "Web 面板版本 v${WEB_PANEL_VERSION} 已匹配，跳过文件部署。"
    fi

    if [[ "$sync_ok" == "true" ]]; then
        install_nexttrace || warn "NextTrace 未能完成安装，路由追踪功能暂不可用。"
    fi
    if ! install_keepalive_service defer; then
        sync_ok=false
        warn "保活服务同步失败，已在最后尝试恢复已有服务。"
    fi

    if [[ "$sync_ok" == "true" ]] && command -v python3 &>/dev/null && [[ -x "${WEB_PANEL_FILE}" ]]; then
        if ! python3 "${WEB_PANEL_FILE}" --migrate-only; then
            migration_ok=false
            warn "配置迁移未完成，已保留原配置；服务仍会恢复运行。"
        fi
    fi

    if ! restart_runtime_services; then
        sync_ok=false
    fi

    [[ "$sync_ok" == "true" && "$migration_ok" == "true" ]]
}

do_local_redeploy() {
    echo ""
    info "开始使用本机文件离线重部署，不会访问任何下载源。"
    local source_dir source_web sync_ok=true
    source_dir="$(dirname "${SCRIPT_PATH}")"
    source_web="${source_dir}/web_panel.py"

    if ! bash -n "${SCRIPT_PATH}" >/dev/null 2>&1; then
        err "当前 nft.sh 语法校验失败，已取消重部署。"
        return 1
    fi
    if [[ ! -f "$source_web" ]]; then
        err "缺少 ${source_web}。请将 nft.sh 与 web_panel.py 放在同一目录后重试。"
        return 1
    fi
    if ! command -v python3 &>/dev/null || ! python3 -m py_compile "$source_web" >/dev/null 2>&1; then
        err "本地 web_panel.py 校验失败，已取消重部署。"
        return 1
    fi

    if grep -q -- '--snapshot-traffic' "$source_web" 2>/dev/null; then
        python3 "$source_web" --snapshot-traffic >/dev/null 2>&1 || warn "服务停止前的流量快照未完成，将继续重部署。"
    fi
    if command -v systemctl &>/dev/null; then
        systemctl stop "${WEB_SERVICE_NAME}" >/dev/null 2>&1 || true
        systemctl stop "${KEEPALIVE_SERVICE_NAME}" >/dev/null 2>&1 || true
    fi

    install_manager_files || sync_ok=false
    if [[ "$sync_ok" == "true" ]]; then
        install_web_service "" defer || sync_ok=false
    fi
    install_nexttrace offline || warn "NextTrace 暂不可用，其余服务继续部署。"
    install_keepalive_service defer || sync_ok=false

    if [[ "$sync_ok" == "true" ]]; then
        python3 "${WEB_PANEL_FILE}" --migrate-only || sync_ok=false
    fi
    restart_runtime_services || sync_ok=false

    if [[ "$sync_ok" == "true" ]]; then
        cleanup_legacy_runtime || warn "新版服务已运行，但旧运行文件未能全部清理。"
        info "离线重部署完成，配置与流量统计数据均已保留。"
        info "Web 面板地址: http://$(get_local_ip):${WEB_PORT}"
        log_action "使用本机文件离线重部署 v${SCRIPT_VERSION}"
        return 0
    else
        err "离线重部署未完整完成，已尝试恢复并重启现有服务，请执行诊断/自检。"
        return 1
    fi
}

do_offline_zip_update() {
    echo ""
    info "离线更新包: ${OFFLINE_ZIP_FILE}"

    if [[ ! -f "${OFFLINE_ZIP_FILE}" ]]; then
        err "未找到离线更新包，请将 GitHub 下载的 ZIP 上传为 ${OFFLINE_ZIP_FILE}"
        return 1
    fi
    if ! command -v python3 &>/dev/null; then
        err "未安装 python3，无法解压和校验离线更新包。"
        return 1
    fi

    local unpack_dir source_script source_dir candidate
    unpack_dir="$(mktemp -d /tmp/nft-manager-offline.XXXXXX 2>/dev/null)" || {
        err "无法创建临时解压目录。"
        return 1
    }

    if ! python3 -m zipfile -e "${OFFLINE_ZIP_FILE}" "$unpack_dir" >/dev/null 2>&1; then
        rm -rf "$unpack_dir" 2>/dev/null || true
        err "ZIP 解压失败，请重新下载完整的 GitHub 项目压缩包。"
        return 1
    fi

    source_script=""
    while IFS= read -r candidate; do
        if [[ -f "$(dirname "$candidate")/web_panel.py" ]]; then
            source_script="$candidate"
            break
        fi
    done < <(find "$unpack_dir" -type f -name nft.sh -print 2>/dev/null)

    if [[ -z "$source_script" ]]; then
        rm -rf "$unpack_dir" 2>/dev/null || true
        err "ZIP 中未找到同目录的 nft.sh 和 web_panel.py。"
        return 1
    fi
    source_dir="$(dirname "$source_script")"
    if ! bash -n "$source_script" >/dev/null 2>&1 || ! python3 -m py_compile "$source_dir/web_panel.py" >/dev/null 2>&1; then
        rm -rf "$unpack_dir" 2>/dev/null || true
        err "ZIP 中的脚本校验失败，未修改当前运行文件。"
        return 1
    fi

    chmod +x "$source_script" 2>/dev/null || true
    info "已读取离线版本: v$(sed -nE 's/^[[:space:]]*SCRIPT_VERSION="([^"]+)".*/\1/p' "$source_script" | head -1)"
    if bash "$source_script" --offline-redeploy; then
        rm -rf "$unpack_dir" 2>/dev/null || warn "更新成功，但无法删除临时解压目录: ${unpack_dir}"
        rm -f "${OFFLINE_ZIP_FILE}" 2>/dev/null || warn "更新成功，但无法删除 ${OFFLINE_ZIP_FILE}"
        info "临时解压目录和离线更新包已删除。"
        if [[ -x "${SCRIPT_INSTALL_FILE}" ]]; then
            info "正在进入新版菜单..."
            exec "${SCRIPT_INSTALL_FILE}"
        fi
        err "新版脚本不存在或不可执行: ${SCRIPT_INSTALL_FILE}"
        return 1
    fi

    rm -rf "$unpack_dir" 2>/dev/null || true
    err "离线更新失败，ZIP 已保留: ${OFFLINE_ZIP_FILE}"
    return 1
}

do_post_update() {
    check_root
    local source_web
    source_web="$(dirname "${SCRIPT_PATH}")/web_panel.py"

    # 从旧运行目录启动升级时，先结算一次流量，再切换服务路径。
    if [[ -f "$source_web" ]] && grep -q -- '--snapshot-traffic' "$source_web" 2>/dev/null; then
        python3 "$source_web" --snapshot-traffic >/dev/null 2>&1 || warn "升级前的流量快照未完成，将继续迁移。"
    fi

    info "正在将运行文件同步到 ${SCRIPT_INSTALL_DIR}..."
    install_manager_files || return 1
    if sync_updated_runtime; then
        cleanup_legacy_runtime || warn "新版服务已运行，但旧启动文件未能全部清理。"
        return 0
    fi
    return 1
}

bootstrap_legacy_web_panel() {
    if ! manager_installed || web_panel_installed; then
        return 0
    fi

    info "检测到旧版 SSH 管理器，正在补装 Web 面板，不会清空现有转发配置。"
    if install_web_service force; then
        install_nexttrace || warn "NextTrace 未能完成安装，路由追踪功能暂不可用。"
        info "Web 面板补装完成。旧规则将在 Web 服务启动时校验并迁移。"
    else
        warn "Web 面板补装失败；现有 SSH 转发未被改动。请检查网络后重新执行 nftm。"
    fi
}

do_uninstall_manager() {
    echo ""
    warn "即将完整卸载 nftables 端口转发管理器。"
    warn "将删除全局命令、安装目录、systemd 保活服务、转发配置、目标主机库、更新源、日志、脚本写入的 sysctl 配置以及本脚本安装的 NextTrace。"
    warn "不会卸载系统 nftables 软件包。"
    read -rp "确认卸载？[y/N]: " confirm1
    if [[ ! "$confirm1" =~ ^[Yy]$ ]]; then
        info "已取消。"
        return
    fi
    read -rp "请再次输入 UNINSTALL 确认完整卸载: " confirm2
    if [[ "$confirm2" != "UNINSTALL" ]]; then
        info "已取消。"
        return
    fi

    local clear_ruleset managed_nexttrace=""
    if [[ -f "${NEXTTRACE_MARKER}" ]]; then
        managed_nexttrace=$(cat "${NEXTTRACE_MARKER}" 2>/dev/null || true)
    fi

    if command -v systemctl &>/dev/null; then
        systemctl disable --now "${WEB_SERVICE_NAME}" >/dev/null 2>&1 || true
        systemctl disable --now "${KEEPALIVE_SERVICE_NAME}" >/dev/null 2>&1 || true
    fi
    rm -f "${WEB_SERVICE_FILE}" 2>/dev/null || true
    rm -f "${KEEPALIVE_SERVICE_FILE}" 2>/dev/null || true
    if command -v systemctl &>/dev/null; then
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi

    rm -f "${GLOBAL_CMD}" 2>/dev/null || true
    rm -f "${GLOBAL_CMD}.bak."* 2>/dev/null || true
    if is_manager_global_command "${LEGACY_GLOBAL_CMD}"; then
        rm -f "${LEGACY_GLOBAL_CMD}" 2>/dev/null || true
    fi
    rm -rf "${SCRIPT_INSTALL_DIR}" 2>/dev/null || true
    rm -rf "${LEGACY_SCRIPT_INSTALL_DIR}" 2>/dev/null || true
    if is_nft_manager_script /root/nft.sh; then
        rm -f /root/nft.sh 2>/dev/null || true
    fi
    if [[ -n "$managed_nexttrace" && -x "$managed_nexttrace" ]]; then
        rm -f "$managed_nexttrace" 2>/dev/null || true
    fi
    web_firewall_close

    if nft_available; then
        "$NFT_BIN" flush table ip "${TABLE_NAME}" 2>/dev/null || true
        "$NFT_BIN" delete table ip "${TABLE_NAME}" 2>/dev/null || true
        "$NFT_BIN" flush table inet "${FIREWALL_TABLE}" 2>/dev/null || true
        "$NFT_BIN" delete table inet "${FIREWALL_TABLE}" 2>/dev/null || true
        read -rp "是否清空当前全部 nftables 运行规则？[y/N]: " clear_ruleset
        if [[ "$clear_ruleset" =~ ^[Yy]$ ]]; then
            "$NFT_BIN" flush ruleset 2>/dev/null || true
            info "已清空当前 nftables 运行规则。"
        fi
    fi

    rm -f "${CONF_FILE}" 2>/dev/null || true
    rm -f "${TARGETS_FILE}" 2>/dev/null || true
    rm -f "${FIREWALL_CONF}" "${FIREWALL_PORTS_FILE}" "${FIREWALL_SSH_PORT_FILE}" 2>/dev/null || true
    rm -f "${UPDATE_URL_FILE}" 2>/dev/null || true
    rm -f "${WEB_AUTH_FILE}" 2>/dev/null || true
    rm -f "${CONF_DIR}/web-stats.json" "${CONF_DIR}/web-history.json" "${CONF_DIR}/web-bandwidth.db" "${CONF_DIR}/web-bandwidth.db-wal" "${CONF_DIR}/web-bandwidth.db-shm" "${CONF_DIR}/web-settings.json" "${CONF_DIR}/.web-stats.lock" 2>/dev/null || true
    rm -f "${CONF_DIR}"/*.conf.bak.* 2>/dev/null || true
    rm -rf "${CONF_DIR}/backups" 2>/dev/null || true
    rmdir "${CONF_DIR}" 2>/dev/null || true

    rm -f "${SYSCTL_CONF}" 2>/dev/null || true
    rm -f "${LOGROTATE_CONF}" 2>/dev/null || true
    rm -f "${LOG_FILE}" 2>/dev/null || true
    rm -rf /root/nft-manager-uninstall-backup-* 2>/dev/null || true

    if [[ -f "${MAIN_CONF}" ]] && grep -qF 'include "/etc/nftables.d/*.conf"' "${MAIN_CONF}" 2>/dev/null; then
        rm -f "${MAIN_CONF}" 2>/dev/null || true
    fi
    rm -f "${MAIN_CONF}.bak."* 2>/dev/null || true

    info "nftables 端口转发管理器已完整卸载。"
    exit 0
}

do_keepalive() {
    check_root
    if ! nft_available; then
        err "nftables 未安装，保活失败。"
        exit 1
    fi
    init_conf || exit 1
    enable_ip_forward
    reload_rules || exit 1
    # 旧版菜单更新会重启本服务；在旧规则已成功恢复后补装 Web，避免并发重载规则。
    bootstrap_legacy_web_panel
    manager_firewall_ensure || warn "独立防火墙初始化失败，请检查 nftables 状态。"
    log_action "保活服务已确认规则加载"
}

# ============== 诊断/自检 ==============
do_diagnose() {
    echo ""
    echo "========================================"
    echo "           诊断 / 自检"
    echo "========================================"

    # 1. IP 转发
    local ip_fwd
    ip_fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null) || ip_fwd="未知"
    if [[ "$ip_fwd" == "1" ]]; then
        info "IPv4 转发: 已开启"
    else
        err  "IPv4 转发: 未开启 (当前值: ${ip_fwd})"
        echo "  → 修复: 选择菜单【安装 nftables】会自动开启"
    fi

    # 2. nftables 状态
    if nft_available; then
        info "nftables: 已安装 ($("$NFT_BIN" --version 2>/dev/null || echo '未知版本'))"
    else
        err  "nftables: 未安装"
        echo "  → 修复: 选择菜单【安装 nftables】"
    fi

    local svc_enabled svc_active
    svc_enabled=$(systemctl is-enabled nftables 2>/dev/null) || svc_enabled="unknown"
    svc_active=$(systemctl is-active nftables 2>/dev/null) || svc_active="unknown"

    if [[ "$svc_enabled" == "enabled" ]]; then
        info "nftables 开机启动: 是"
    else
        warn "nftables 开机启动: 否（重启后规则可能丢失）"
        echo "  → 修复: systemctl enable nftables"
    fi

    if [[ "$svc_active" == "active" ]]; then
        info "nftables 服务状态: 运行中"
    else
        warn "nftables 服务状态: 未运行"
        echo "  → 修复: systemctl start nftables"
    fi

    # 3. 转发规则是否加载
    if "$NFT_BIN" list table ip "${TABLE_NAME}" &>/dev/null; then
        load_rules
        info "转发规则表: 已加载（${#RULES[@]} 条转发规则）"
    else
        warn "转发规则表: 未加载（可能无规则或服务未启动）"
    fi

    # 4. 防火墙检测
    echo ""
    echo "--- 防火墙状态 ---"
    local fw_found=false

    if systemctl is-active --quiet firewalld 2>/dev/null; then
        fw_found=true
        info "firewalld: 活跃"
    fi

    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qw "active"; then
        fw_found=true
        warn "UFW: 活跃（默认会阻止入站连接，可能影响转发）"
    fi

    if ! $fw_found && has_iptables; then
        fw_found=true
        local fwd_policy
        fwd_policy=$(iptables -S FORWARD 2>/dev/null | grep -- '^-P FORWARD' | awk '{print $3}') || fwd_policy=""
        if [[ "$fwd_policy" == "DROP" || "$fwd_policy" == "REJECT" ]]; then
            warn "iptables FORWARD 默认策略: ${fwd_policy}（可能阻止转发流量）"
        else
            info "iptables FORWARD 默认策略: ${fwd_policy:-ACCEPT}"
        fi
    fi

    if ! $fw_found; then
        info "未检测到活跃的防火墙 (firewalld / UFW / iptables)"
    fi

    # 5. nftables forward 链检测
    echo ""
    echo "--- nftables forward 链 ---"
    local fwd_chains
    fwd_chains=$("$NFT_BIN" list chains 2>/dev/null | grep -B1 "hook forward" || true)
    if [[ -n "$fwd_chains" ]]; then
        if echo "$fwd_chains" | grep -qi "drop"; then
            warn "检测到 nftables 存在 forward 链默认策略为 drop"
            echo "  这会阻止所有转发流量，需手动添加放行规则。"
            echo "  查看详情: nft list ruleset | grep -A5 'hook forward'"
        else
            info "nftables forward 链: 未发现 drop 策略"
        fi
    else
        info "未检测到 nftables forward 链（正常，不影响转发）"
    fi

    # 6. 配置持久化
    echo ""
    echo "--- 配置持久化 ---"
    if [[ -f "${MAIN_CONF}" ]]; then
        if grep -qF 'include "/etc/nftables.d/*.conf"' "${MAIN_CONF}" 2>/dev/null; then
            info "主配置 ${MAIN_CONF}: 已包含 include 指令"
        else
            warn "主配置 ${MAIN_CONF}: 缺少 include 指令（重启后规则可能丢失）"
            echo "  → 修复: 选择菜单【安装 nftables】会自动添加"
        fi
    else
        warn "主配置 ${MAIN_CONF}: 不存在（重启后规则可能丢失）"
        echo "  → 修复: 选择菜单【安装 nftables】会自动创建"
    fi

    if [[ -f "${CONF_FILE}" ]]; then
        info "转发配置文件: ${CONF_FILE} 存在"
    else
        info "转发配置文件: 尚未创建（添加首条规则时自动生成）"
    fi

    # 7. 目标连通性测试（可选）
    echo ""
    load_rules
    if [[ ${#RULES[@]} -gt 0 ]]; then
        read -rp "是否测试目标连通性？[y/N]: " test_conn
        if [[ "$test_conn" =~ ^[Yy]$ ]]; then
            local rule lport dip dport alias
            for rule in "${RULES[@]}"; do
                IFS='|' read -r lport dip dport alias <<< "$rule"
                printf "  测试 %s:%s (TCP) ... " "$dip" "$dport"
                if timeout 3 bash -c ">/dev/tcp/${dip}/${dport}" 2>/dev/null; then
                    printf "\033[32m通\033[0m\n"
                else
                    printf "\033[31m不通或超时\033[0m\n"
                fi
            done
        fi
    fi
    echo ""
}

# ====================================================
# 功能 1：安装 nftables
# ====================================================
do_install() {
    echo ""
    if nft_available; then
        info "nftables 已安装。"
        "$NFT_BIN" --version 2>/dev/null || true
        echo ""
        warn "安装将清空所有已有 nftables 配置，由本脚本统一接管。"
        read -rp "是否继续？[y/N]: " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            info "已取消，退出脚本。"
            exit 0
        fi

        rm -f "${MAIN_CONF}" 2>/dev/null || true
        rm -f "${CONF_FILE}" "${TARGETS_FILE}" "${UPDATE_URL_FILE}" 2>/dev/null || true
        rm -rf "${CONF_DIR}/backups" 2>/dev/null || true

        # 清空当前运行中的规则
        "$NFT_BIN" flush ruleset 2>/dev/null || true
        info "已清空当前 nftables 规则集。"
        log_action "清空已有配置并由脚本接管"

        enable_ip_forward
        enable_bbr_fq
        check_firewall_status
        init_conf

        # 加载主配置（flush + include），验证整条配置链路
        if ! "$NFT_BIN" -f "${MAIN_CONF}"; then
            err "加载 ${MAIN_CONF} 失败，请检查配置。"
            return
        fi

        # 确保服务开机启动且当前正在运行
        if systemctl enable --now nftables 2>/dev/null; then
            info "已启用 nftables 服务。"
        else
            warn "nftables 服务启用失败，重启后规则可能丢失。"
            warn "请手动执行: systemctl enable --now nftables"
        fi

        install_manager_runtime || return
        cleanup_legacy_runtime || warn "安装已完成，但旧启动文件未能全部清理。"
        info "初始化完成，所有配置已由本脚本接管。"
        return
    fi

    info "未检测到 nftables，准备安装..."
    local pkg_mgr
    pkg_mgr=$(detect_pkg_manager)

    case "$pkg_mgr" in
        apt)
            apt-get update -y && apt-get install -y nftables
            ;;
        dnf)
            dnf install -y nftables
            ;;
        yum)
            yum install -y nftables
            ;;
        pacman)
            pacman -Sy --noconfirm nftables
            ;;
        *)
            err "无法识别包管理器，请手动安装 nftables。"
            return
            ;;
    esac

    NFT_BIN="$(resolve_nft_bin)"
    if ! nft_available; then
        err "安装失败，请手动安装 nftables。"
        return
    fi

    info "nftables 安装成功。"
    "$NFT_BIN" --version 2>/dev/null || true
    log_action "安装 nftables"

    enable_ip_forward
    enable_bbr_fq
    check_firewall_status
    init_conf
    # 先写好配置，再启用服务，确保服务启动时直接加载我们的配置
    if systemctl enable --now nftables 2>/dev/null; then
        info "已启用 nftables 服务。"
    else
        warn "nftables 服务启用失败，重启后规则可能丢失。"
        warn "请手动执行: systemctl enable --now nftables"
    fi

    install_manager_runtime || return
    cleanup_legacy_runtime || warn "安装已完成，但旧启动文件未能全部清理。"
    info "安装与初始化完成。"
}

# ====================================================
# 功能 2：目标主机管理
# ====================================================
do_targets_list() {
    echo ""
    load_targets
    if [[ ${#TARGETS[@]} -eq 0 ]]; then
        info "当前没有保存目标主机。"
        return 1
    fi

    printf "\n\033[1m%-6s %-24s %-16s\033[0m\n" "序号" "别名" "IP"
    echo "────────────────────────────────────────────"
    local idx target alias ip
    for idx in "${!TARGETS[@]}"; do
        IFS='|' read -r alias ip <<< "${TARGETS[$idx]}"
        printf "%-6s %-24s %-16s\n" "$((idx + 1))" "$alias" "$ip"
    done
    echo ""
    return 0
}

do_targets_add() {
    echo ""
    init_conf || return
    load_targets

    local ip alias idx alias_idx
    while true; do
        read -rp "请输入目标 IP 地址: " ip
        if validate_ip "$ip"; then
            break
        fi
        err "IP 地址格式无效，请重新输入。"
    done

    idx=$(find_target_index_by_ip "$ip" || true)
    if [[ -n "$idx" ]]; then
        IFS='|' read -r alias _ <<< "${TARGETS[$idx]}"
        warn "该 IP 已存在: ${alias} (${ip})"
        return
    fi

    while true; do
        read -rp "请输入目标主机别名（支持中文）: " alias
        alias=$(clean_label "$alias")
        if [[ -z "$alias" || "$alias" == "0" ]]; then
            err "别名不能为空，也不能为 0。"
            continue
        fi
        alias_idx=$(find_target_index_by_alias "$alias" || true)
        if [[ -n "$alias_idx" ]]; then
            warn "该别名已存在，请换一个别名。"
            continue
        fi
        break
    done

    TARGETS+=("${alias}|${ip}")
    if write_targets_file; then
        info "目标主机已添加: ${alias} (${ip})"
    else
        err "目标主机保存失败。"
    fi
}

do_targets_edit() {
    echo ""
    init_conf || return
    do_targets_list || return

    local choice edit_idx target old_alias old_ip new_alias new_ip alias_idx ip_idx dup_alias dup_ip
    read -rp "请输入要修改的序号 (0 取消): " choice
    if [[ "$choice" == "0" || -z "$choice" ]]; then
        info "已取消。"
        return
    fi
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#TARGETS[@]} )); then
        err "无效的序号。"
        return
    fi

    edit_idx=$((choice - 1))
    target="${TARGETS[$edit_idx]}"
    IFS='|' read -r old_alias old_ip <<< "$target"

    read -rp "请输入新别名 [当前: ${old_alias}]: " new_alias
    new_alias=$(clean_label "${new_alias:-$old_alias}")
    if [[ -z "$new_alias" || "$new_alias" == "0" ]]; then
        err "别名不能为空，也不能为 0。"
        return
    fi
    alias_idx=$(find_target_index_by_alias "$new_alias" "$edit_idx" || true)
    if [[ -n "$alias_idx" ]]; then
        IFS='|' read -r dup_alias dup_ip <<< "${TARGETS[$alias_idx]}"
        err "别名已存在: ${dup_alias} (${dup_ip})"
        return
    fi

    while true; do
        read -rp "请输入新 IP [当前: ${old_ip}]: " new_ip
        new_ip="${new_ip:-$old_ip}"
        if validate_ip "$new_ip"; then
            break
        fi
        err "IP 地址格式无效，请重新输入。"
    done
    ip_idx=$(find_target_index_by_ip "$new_ip" || true)
    if [[ -n "$ip_idx" && "$ip_idx" != "$edit_idx" ]]; then
        IFS='|' read -r dup_alias dup_ip <<< "${TARGETS[$ip_idx]}"
        err "IP 已存在: ${dup_alias} (${dup_ip})"
        return
    fi

    TARGETS[$edit_idx]="${new_alias}|${new_ip}"
    if write_targets_file; then
        info "目标主机已修改: ${new_alias} (${new_ip})"
        if [[ "$old_ip" != "$new_ip" ]]; then
            warn "已有转发规则仍指向旧 IP，如需迁移请删除后重新添加。"
        fi
    else
        err "目标主机保存失败。"
    fi
}

do_targets_delete() {
    echo ""
    init_conf || return
    do_targets_list || return

    local choice delete_idx target alias ip
    read -rp "请输入要删除的序号 (0 取消): " choice
    if [[ "$choice" == "0" || -z "$choice" ]]; then
        info "已取消。"
        return
    fi
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#TARGETS[@]} )); then
        err "无效的序号。"
        return
    fi

    delete_idx=$((choice - 1))
    target="${TARGETS[$delete_idx]}"
    IFS='|' read -r alias ip <<< "$target"
    warn "即将删除目标主机: ${alias} (${ip})"
    warn "这不会删除已有转发规则，只是不再显示该目标别名。"
    read -rp "确认删除？[y/N]: " choice
    if [[ ! "$choice" =~ ^[Yy]$ ]]; then
        info "已取消。"
        return
    fi

    unset "TARGETS[$delete_idx]"
    TARGETS=("${TARGETS[@]}")
    if write_targets_file; then
        info "目标主机已删除: ${alias} (${ip})"
    else
        err "目标主机保存失败。"
    fi
}

do_targets_trace() {
    echo ""
    init_conf || return
    do_targets_list || return
    if ! command -v nexttrace &>/dev/null; then
        err "NextTrace 未安装，请先返回主菜单进入【NextTrace 管理】安装。"
        return
    fi

    local choice target alias ip
    read -rp "请选择要检测路由的主机序号 (0 取消): " choice
    if [[ "$choice" == "0" || -z "$choice" ]]; then
        info "已取消。"
        return
    fi
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#TARGETS[@]} )); then
        err "无效的序号。"
        return
    fi
    target="${TARGETS[$((choice - 1))]}"
    IFS='|' read -r alias ip <<< "$target"
    echo ""
    info "正在执行本机到 ${alias} (${ip}) 的 NextTrace 路由..."
    echo "────────────────────────────────────────────"
    nexttrace "$ip"
    local status=$?
    echo "────────────────────────────────────────────"
    if (( status != 0 )); then
        err "NextTrace 执行失败，退出码: ${status}"
    fi
}

do_targets_menu() {
    while true; do
        echo ""
        echo "========================================"
        echo "           目标主机管理"
        echo "========================================"
        echo "  1) 查看目标主机"
        echo "  2) 新增目标主机"
        echo "  3) 修改目标主机"
        echo "  4) 删除目标主机"
        echo "  5) NextTrace 路由检测"
        echo "  0) 返回主菜单"
        echo "========================================"
        local choice
        read -rp "请选择操作 [0-5]: " choice
        case "$choice" in
            0) return ;;
            1) do_targets_list ;;
            2) do_targets_add ;;
            3) do_targets_edit ;;
            4) do_targets_delete ;;
            5) do_targets_trace ;;
            *) err "无效选择，请输入 0-5。" ;;
        esac
    done
}

# ====================================================
# 功能 3：查看现有端口转发
# ====================================================
do_list() {
    echo ""
    init_conf || return
    load_rules

    if [[ ${#RULES[@]} -eq 0 ]]; then
        info "当前没有端口转发规则。"
        return
    fi

    local -a group_ips=()
    local rule lport dip dport alias ip exists
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport alias <<< "$rule"
        exists=false
        for ip in "${group_ips[@]}"; do
            [[ "$ip" == "$dip" ]] && exists=true && break
        done
        $exists || group_ips+=("$dip")
    done

    for ip in "${group_ips[@]}"; do
        echo ""
        printf "\033[1m目标: %s\033[0m\n" "$(target_display "$ip")"
        printf "\033[1m%-6s %-10s %-10s %-10s %-24s\033[0m\n" "序号" "协议" "入口端口" "出口端口" "转发别名"
        echo "────────────────────────────────────────────────────────────"
        local idx=1
        for rule in "${RULES[@]}"; do
            IFS='|' read -r lport dip dport alias <<< "$rule"
            [[ "$dip" == "$ip" ]] || continue
            [[ -n "$alias" ]] || alias="-"
            printf "%-6s %-10s %-10s %-10s %-24s\n" \
                "$idx" "tcp+udp" "$lport" "$dport" "$alias"
            ((idx++))
        done
    done
    echo ""
}

# ====================================================
# 功能 4：新增端口转发
# ====================================================
do_add() {
    echo ""
    if ! nft_available; then
        err "nftables 未安装，请先选择 [1] 安装。"
        return
    fi

    init_conf || return
    enable_ip_forward
    load_rules

    local local_ip
    local_ip=$(get_local_ip)
    if [[ -z "$local_ip" ]]; then
        err "无法获取本机 IP 地址，请检查网络配置。"
        return
    fi

    local dip
    choose_or_input_target_ip dip
    if ! validate_ip "$dip"; then
        err "目标 IP 为空或无效，已取消添加。"
        return
    fi

    # 输入入口端口（本机监听端口）
    local lport
    while true; do
        read -rp "请输入入口端口/本机监听端口 (1-65535): " lport
        if validate_port "$lport"; then
            break
        fi
        err "端口无效，请输入 1-65535 之间的数字。"
    done

    # 检查端口是否已有转发规则
    local rule rp _dip _dport _alias
    for rule in "${RULES[@]}"; do
        IFS='|' read -r rp _dip _dport _alias <<< "$rule"
        if [[ "$rp" == "$lport" ]]; then
            err "本机端口 ${lport} 已存在转发规则，请先删除后再添加。"
            return
        fi
    done

    # 检查端口占用（TCP + UDP）
    if ! check_port_conflict "$lport"; then
        info "已取消。"
        return
    fi

    # 输入出口端口（目标端口）
    local dport
    while true; do
        read -rp "请输入出口端口/目标端口 (1-65535) [默认: ${lport}]: " dport
        dport="${dport:-$lport}"
        if validate_port "$dport"; then
            break
        fi
        err "端口无效，请输入 1-65535 之间的数字。"
    done

    local rule_alias
    read -rp "请输入本条转发别名（支持中文，输入 0 或回车跳过）: " rule_alias
    rule_alias=$(clean_label "$rule_alias")
    if [[ "$rule_alias" == "0" ]]; then
        rule_alias=""
    fi

    # 确认
    echo ""
    echo "即将添加转发规则:"
    echo "  目标主机: $(target_display "$dip")"
    echo "  入口端口: 本机 ${lport} (tcp+udp)"
    echo "  出口端口: 目标 ${dport}"
    if [[ -n "$rule_alias" ]]; then
        echo "  转发别名: ${rule_alias}"
    fi
    local open_firewall
    read -rp "同时开放本机入口端口 ${lport}？[Y/n]: " open_firewall
    if [[ "$open_firewall" =~ ^[Nn]$ ]]; then
        open_firewall=false
    else
        open_firewall=true
    fi
    read -rp "确认添加？[Y/n]: " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        info "已取消。"
        return
    fi

    # 写入
    local -a old_rules=("${RULES[@]}")
    RULES+=("${lport}|${dip}|${dport}|${rule_alias}")
    if ! write_conf_file; then
        RULES=("${old_rules[@]}")
        write_conf_file >/dev/null 2>&1 || true
        return
    fi

    if reload_rules; then
        if [[ "$open_firewall" == "true" ]] && ! manager_firewall_add_forward "$lport"; then
            err "防火墙端口开放失败，已回滚本次新增。"
            RULES=("${old_rules[@]}")
            write_conf_file >/dev/null 2>&1 || true
            reload_rules >/dev/null 2>&1 || true
            return
        fi
        info "转发规则添加成功: ${lport} → ${dip}:${dport}"
        log_action "新增转发: ${lport} -> ${dip}:${dport}${rule_alias:+ (${rule_alias})}"
        info "若转发不通，请使用菜单中的【诊断/自检】排查。"
    else
        err "规则加载失败，请检查配置。"
        warn "已回滚本次新增，保留原有规则。"
        RULES=("${old_rules[@]}")
        write_conf_file >/dev/null 2>&1 || true
        reload_rules >/dev/null 2>&1 || true
    fi
}

# ====================================================
# 功能 5：删除端口转发
# ====================================================
do_delete() {
    echo ""
    if ! nft_available; then
        err "nftables 未安装，请先选择 [1] 安装。"
        return
    fi

    load_rules

    if [[ ${#RULES[@]} -eq 0 ]]; then
        info "当前没有端口转发规则，无需删除。"
        return
    fi

    local -a group_ips=()
    local rule lport dip dport alias ip exists
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport alias <<< "$rule"
        exists=false
        for ip in "${group_ips[@]}"; do
            [[ "$ip" == "$dip" ]] && exists=true && break
        done
        $exists || group_ips+=("$dip")
    done

    echo ""
    printf "\033[1m%-6s %-32s %-8s\033[0m\n" "序号" "目标" "规则数"
    echo "────────────────────────────────────────────────────"
    local idx count
    for idx in "${!group_ips[@]}"; do
        ip="${group_ips[$idx]}"
        count=0
        for rule in "${RULES[@]}"; do
            IFS='|' read -r lport dip dport alias <<< "$rule"
            [[ "$dip" == "$ip" ]] && ((count++))
        done
        printf "%-6s %-32s %-8s\n" "$((idx + 1))" "$(target_display "$ip")" "$count"
    done
    echo ""

    local group_choice
    read -rp "请选择目标分区 (0 取消): " group_choice

    if [[ "$group_choice" == "0" ]] || [[ -z "$group_choice" ]]; then
        info "已取消。"
        return
    fi

    if [[ ! "$group_choice" =~ ^[0-9]+$ ]] || (( group_choice < 1 || group_choice > ${#group_ips[@]} )); then
        err "无效的序号。"
        return
    fi

    local selected_ip="${group_ips[$((group_choice - 1))]}"
    local -a match_indexes=()
    echo ""
    printf "\033[1m目标: %s\033[0m\n" "$(target_display "$selected_ip")"
    printf "\033[1m%-6s %-10s %-10s %-10s %-24s\033[0m\n" "序号" "协议" "入口端口" "出口端口" "转发别名"
    echo "────────────────────────────────────────────────────────────"
    local display_idx=1
    for idx in "${!RULES[@]}"; do
        rule="${RULES[$idx]}"
        IFS='|' read -r lport dip dport alias <<< "$rule"
        [[ "$dip" == "$selected_ip" ]] || continue
        match_indexes+=("$idx")
        [[ -n "$alias" ]] || alias="-"
        printf "%-6s %-10s %-10s %-10s %-24s\n" \
            "$display_idx" "tcp+udp" "$lport" "$dport" "$alias"
        ((display_idx++))
    done
    echo ""

    local rule_choice
    read -rp "请输入要删除的规则序号 (0 取消): " rule_choice
    if [[ "$rule_choice" == "0" ]] || [[ -z "$rule_choice" ]]; then
        info "已取消。"
        return
    fi
    if [[ ! "$rule_choice" =~ ^[0-9]+$ ]] || (( rule_choice < 1 || rule_choice > ${#match_indexes[@]} )); then
        err "无效的序号。"
        return
    fi

    local rule_index="${match_indexes[$((rule_choice - 1))]}"
    local target="${RULES[$rule_index]}"
    IFS='|' read -r lport dip dport alias <<< "$target"

    echo "即将删除转发规则:"
    echo "  目标主机: $(target_display "$dip")"
    echo "  入口端口: 本机 ${lport} (tcp+udp)"
    echo "  出口端口: 目标 ${dport}"
    if [[ -n "$alias" ]]; then
        echo "  转发别名: ${alias}"
    fi
    local close_firewall
    read -rp "删除后同时关闭本机入口端口 ${lport}？[Y/n]: " close_firewall
    if [[ "$close_firewall" =~ ^[Nn]$ ]]; then
        close_firewall=false
    else
        close_firewall=true
    fi
    read -rp "确认删除？[Y/n]: " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        info "已取消。"
        return
    fi

    # 移除
    local -a old_rules=("${RULES[@]}")
    unset "RULES[$rule_index]"
    RULES=("${RULES[@]}")

    if ! write_conf_file; then
        return
    fi

    if reload_rules; then
        if [[ "$close_firewall" == "true" ]] && ! manager_firewall_remove_forward "$lport"; then
            err "防火墙端口关闭失败，已回滚本次删除。"
            RULES=("${old_rules[@]}")
            write_conf_file >/dev/null 2>&1 || true
            reload_rules >/dev/null 2>&1 || true
            return
        fi
        info "转发规则已删除: ${lport} → ${dip}:${dport}"
        log_action "删除转发: ${lport} -> ${dip}:${dport}"
    else
        err "规则加载失败，请检查配置。"
    fi
}

# ====================================================
# 功能 6：一键清空所有转发
# ====================================================
do_clear_all() {
    echo ""
    if ! nft_available; then
        err "nftables 未安装，请先选择 [1] 安装。"
        return
    fi

    load_rules

    if [[ ${#RULES[@]} -eq 0 ]]; then
        info "当前没有端口转发规则，无需清空。"
        return
    fi

    warn "即将清空全部 ${#RULES[@]} 条转发规则！"
    read -rp "确认清空？[y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        info "已取消。"
        return
    fi

    local -a old_rules=("${RULES[@]}")
    RULES=()
    if ! write_conf_file; then
        return
    fi

    if reload_rules; then
        local rule lport dip dport alias
        for rule in "${old_rules[@]}"; do
            IFS='|' read -r lport dip dport alias <<< "$rule"
            if ! manager_firewall_remove_forward "$lport"; then
                warn "端口 ${lport} 的防火墙放行未能自动关闭，请到【防火墙端口管理】处理。"
            fi
        done
        info "所有转发规则已清空。"
        log_action "清空所有转发规则"
    else
        err "规则加载失败，请检查配置。"
    fi
}

# ====================================================
# 主菜单
# ====================================================
main_menu() {
    while true; do
        local install_label
        if manager_installed; then
            install_label="卸载 nftables 管理器"
        else
            install_label="安装 nftables / 管理器"
        fi
        check_update_status

        echo ""
        echo "========================================"
        echo "   nftables 端口转发管理工具 v${SCRIPT_VERSION}"
        echo "   更新状态: ${UPDATE_STATUS_TEXT}"
        if manager_installed; then
            echo "   Web 面板: http://$(get_local_ip):${WEB_PORT}"
        fi
        echo "========================================"
        echo "  1) ${install_label}"
        echo "  2) 更新脚本"
        echo "  3) 查看现有端口转发"
        echo "  4) 新增端口转发"
        echo "  5) 删除端口转发"
        echo "  6) 目标主机管理"
        echo "  7) 一键清空所有转发"
        echo "  8) 诊断/自检"
        echo "  9) 防火墙端口管理"
        echo " 10) 从 /root/nft-manager-main.zip 离线更新"
        echo " 11) NextTrace 管理"
        echo "  0) 退出"
        echo "========================================"
        read -rp "请选择操作 [0-11]: " choice

        case "$choice" in
            0)
                info "再见！"
                exit 0
                ;;
            1)
                if manager_installed; then
                    do_uninstall_manager
                else
                    do_install
                fi
                ;;
            2)
                check_update_status force
                do_update
                ;;
            3) do_list ;;
            4) do_add ;;
            5) do_delete ;;
            6) do_targets_menu ;;
            7) do_clear_all ;;
            8) do_diagnose ;;
            9) do_firewall_menu ;;
            10) do_offline_zip_update ;;
            11) do_nexttrace_menu ;;
            *)
                err "无效选择，请输入 0-11。"
                ;;
        esac
    done
}

# ============== 入口 ==============
if [[ "${1:-}" == "--post-update" ]]; then
    do_post_update
    exit $?
fi

if [[ "${1:-}" == "--keepalive" ]]; then
    do_keepalive
    exit 0
fi

if [[ "${1:-}" == "--offline-redeploy" ]]; then
    check_root
    do_local_redeploy
    exit $?
fi

if [[ "${1:-}" == "--nexttrace-update" ]]; then
    check_root
    update_nexttrace_online
    exit $?
fi

check_root
bootstrap_legacy_web_panel
main_menu
