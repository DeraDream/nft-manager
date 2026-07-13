#!/usr/bin/env bash
#
# nftables 端口转发管理工具 v2.0
# 交互式管理 DNAT 端口转发规则
#

# ============== 常量定义 ==============
SCRIPT_VERSION="2.0"
CONF_DIR="/etc/nftables.d"
CONF_FILE="${CONF_DIR}/port-forward.conf"
TARGETS_FILE="${CONF_DIR}/targets.conf"
UPDATE_URL_FILE="${CONF_DIR}/update-url"
MAIN_CONF="/etc/nftables.conf"
SYSCTL_CONF="/etc/sysctl.d/99-nft-forward.conf"
LOG_FILE="/var/log/nft-forward.log"
LOGROTATE_CONF="/etc/logrotate.d/nft-forward"
TABLE_NAME="port_forward"
GLOBAL_CMD="/usr/local/bin/nft"
SCRIPT_INSTALL_DIR="/usr/local/lib/nft-forward"
SCRIPT_INSTALL_FILE="${SCRIPT_INSTALL_DIR}/nft.sh"
WEB_PANEL_FILE="${SCRIPT_INSTALL_DIR}/web_panel.py"
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
        if [[ -x "$bin" && "$bin" != "$GLOBAL_CMD" ]]; then
            echo "$bin"
            return
        fi
    done
    bin=$(command -v nft 2>/dev/null || true)
    if [[ -n "$bin" && "$bin" != "$GLOBAL_CMD" ]]; then
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

# WEB_META|1

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

        # META_RULE|${lport}|${dip}|${dport}|${alias}
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
reload_rules() {
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
    local dest="$1" source_url
    source_url=$(load_update_url)
    if [[ -z "$source_url" ]]; then
        return 2
    fi

    if download_remote_file "$source_url" "$dest" 20; then
        UPDATE_URL="$source_url"
        UPDATE_DOWNLOADED_URL="$source_url"
        return 0
    fi

    # 默认 GitHub raw 在部分网络环境不可用时，自动尝试官方 jsDelivr 镜像。
    if [[ "$source_url" == "$DEFAULT_UPDATE_URL" ]] && download_remote_file "$FALLBACK_UPDATE_URL" "$dest" 20; then
        UPDATE_URL="$FALLBACK_UPDATE_URL"
        UPDATE_DOWNLOADED_URL="$FALLBACK_UPDATE_URL"
        return 0
    fi

    return 1
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
        curl -fsSL --retry 2 --retry-delay 1 --connect-timeout 8 --max-time "$timeout" "$request_url" -o "$dest"
    elif command -v wget &>/dev/null; then
        wget -q --tries=3 --timeout="$timeout" -O "$dest" "$request_url"
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

    local services_stopped=false
    if [[ "$install_target" == "$SCRIPT_INSTALL_FILE" ]] && command -v systemctl &>/dev/null; then
        info "正在停止 nft-forward-keepalive 和 nft-manager-web 服务..."
        systemctl stop "${KEEPALIVE_SERVICE_NAME}" >/dev/null 2>&1 || true
        systemctl stop "${WEB_SERVICE_NAME}" >/dev/null 2>&1 || true
        services_stopped=true
    fi

    install -m 755 "$tmp_file" "$install_target" 2>/dev/null || {
        rm -f "$tmp_file" 2>/dev/null || true
        if [[ "$services_stopped" == "true" ]]; then
            systemctl restart "${KEEPALIVE_SERVICE_NAME}" >/dev/null 2>&1 || true
            systemctl restart "${WEB_SERVICE_NAME}" >/dev/null 2>&1 || true
        fi
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
        install_keepalive_service
        if ! install_web_service force; then
            if [[ "$services_stopped" == "true" ]]; then
                systemctl restart "${KEEPALIVE_SERVICE_NAME}" >/dev/null 2>&1 || true
                systemctl restart "${WEB_SERVICE_NAME}" >/dev/null 2>&1 || true
            fi
            err "Web 面板更新失败，脚本已写入但服务未完整同步。请检查网络后重新执行更新。"
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

install_manager_files() {
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

    info "已安装全局命令: ${GLOBAL_CMD}"
}

install_keepalive_service() {
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
    if systemctl enable "${KEEPALIVE_SERVICE_NAME}" >/dev/null 2>&1 && systemctl restart "${KEEPALIVE_SERVICE_NAME}" >/dev/null 2>&1; then
        info "已安装并启用 systemd 保活服务: ${KEEPALIVE_SERVICE_NAME}"
        log_action "安装并启用保活服务 ${KEEPALIVE_SERVICE_NAME}"
    else
        warn "保活服务启用失败，请手动执行: systemctl enable ${KEEPALIVE_SERVICE_NAME} && systemctl restart ${KEEPALIVE_SERVICE_NAME}"
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
    if ! command -v python3 &>/dev/null; then
        warn "未检测到 python3，已跳过 Web 面板安装。"
        return 0
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

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload >/dev/null 2>&1 || true
    if systemctl enable "${WEB_SERVICE_NAME}" >/dev/null 2>&1 && systemctl restart "${WEB_SERVICE_NAME}" >/dev/null 2>&1; then
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

install_manager_runtime() {
    install_manager_files || return 1
    persist_update_url
    install_keepalive_service
    install_web_service
}

do_uninstall_manager() {
    echo ""
    warn "即将完整卸载 nftables 端口转发管理器。"
    warn "将删除全局命令、安装目录、systemd 保活服务、转发配置、目标主机库、更新源、日志和脚本写入的 sysctl 配置。"
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

    local clear_ruleset

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
    rm -rf "${SCRIPT_INSTALL_DIR}" 2>/dev/null || true
    web_firewall_close

    if nft_available; then
        "$NFT_BIN" flush table ip "${TABLE_NAME}" 2>/dev/null || true
        "$NFT_BIN" delete table ip "${TABLE_NAME}" 2>/dev/null || true
        read -rp "是否清空当前全部 nftables 运行规则？[y/N]: " clear_ruleset
        if [[ "$clear_ruleset" =~ ^[Yy]$ ]]; then
            "$NFT_BIN" flush ruleset 2>/dev/null || true
            info "已清空当前 nftables 运行规则。"
        fi
    fi

    rm -f "${CONF_FILE}" 2>/dev/null || true
    rm -f "${TARGETS_FILE}" 2>/dev/null || true
    rm -f "${UPDATE_URL_FILE}" 2>/dev/null || true
    rm -f "${WEB_AUTH_FILE}" 2>/dev/null || true
    rm -f "${CONF_DIR}/web-stats.json" 2>/dev/null || true
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
        echo "  0) 返回主菜单"
        echo "========================================"
        local choice
        read -rp "请选择操作 [0-4]: " choice
        case "$choice" in
            0) return ;;
            1) do_targets_list ;;
            2) do_targets_add ;;
            3) do_targets_edit ;;
            4) do_targets_delete ;;
            *) err "无效选择，请输入 0-4。" ;;
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
        firewall_open_port "$lport" "$dip" "$dport"
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
    read -rp "确认删除？[Y/n]: " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        info "已取消。"
        return
    fi

    # 移除
    unset "RULES[$rule_index]"
    RULES=("${RULES[@]}")

    if ! write_conf_file; then
        return
    fi

    if reload_rules; then
        # nft 规则已成功更新后，再清理防火墙放行（RULES 已移除该条，dest_still_used 能正确判断）
        firewall_close_port "$lport" "$dip" "$dport"
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

    # 先清理所有防火墙规则（清空场景用 force，无需检查共享）
    local rule lport dip dport alias
    for rule in "${RULES[@]}"; do
        IFS='|' read -r lport dip dport alias <<< "$rule"
        firewall_close_port "$lport" "$dip" "$dport" "force"
    done

    RULES=()
    if ! write_conf_file; then
        return
    fi

    if reload_rules; then
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
        echo "  0) 退出"
        echo "========================================"
        read -rp "请选择操作 [0-8]: " choice

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
            *)
                err "无效选择，请输入 0-8。"
                ;;
        esac
    done
}

# ============== 入口 ==============
if [[ "${1:-}" == "--keepalive" ]]; then
    do_keepalive
    exit 0
fi

check_root
main_menu
