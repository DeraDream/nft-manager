#!/usr/bin/env bash
set -Eeuo pipefail

INSTALLER_VERSION="3.27"
RAW_BASE="https://raw.githubusercontent.com/DeraDream/nft-manager/main"
CDN_BASE="https://cdn.jsdelivr.net/gh/DeraDream/nft-manager@main"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "[错误] 请使用 root 运行，或执行: curl ... | sudo bash" >&2
    exit 1
fi

if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    echo "[错误] 未找到 curl 或 wget。" >&2
    exit 1
fi

WORK_DIR=$(mktemp -d /tmp/nft-manager-install.XXXXXX)
cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

download_file() {
    local relative="$1" destination="$2" base url
    for base in "$RAW_BASE" "$CDN_BASE"; do
        url="${base}/${relative}?nft_manager_install=$(date +%s)${RANDOM}"
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL --retry 1 --connect-timeout 5 --max-time 180 "$url" -o "$destination" && return 0
        else
            wget -q --tries=2 --timeout=180 -O "$destination" "$url" && return 0
        fi
        rm -f "$destination"
    done
    return 1
}

echo "[信息] 临时安装目录: ${WORK_DIR}"
echo "[信息] 正在获取 nft-manager v${INSTALLER_VERSION} 安装文件..."

download_file "nft.sh" "${WORK_DIR}/nft.sh" || {
    echo "[错误] nft.sh 下载失败，请检查 GitHub 或 jsDelivr 连接。" >&2
    exit 1
}
download_file "web_panel.py" "${WORK_DIR}/web_panel.py" || {
    echo "[错误] web_panel.py 下载失败。" >&2
    exit 1
}

if [[ "$(head -1 "${WORK_DIR}/nft.sh" 2>/dev/null)" != "#!/usr/bin/env bash" ]] || ! bash -n "${WORK_DIR}/nft.sh"; then
    echo "[错误] nft.sh 文件校验失败，已取消安装。" >&2
    exit 1
fi
downloaded_script_version=$(sed -nE 's/^[[:space:]]*SCRIPT_VERSION="([^"]+)".*/\1/p' "${WORK_DIR}/nft.sh" | head -1)
downloaded_web_version=$(sed -nE 's/^WEB_PANEL_VERSION[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "${WORK_DIR}/web_panel.py" | head -1)
if [[ "$downloaded_script_version" != "$INSTALLER_VERSION" || "$downloaded_web_version" != "$INSTALLER_VERSION" ]]; then
    echo "[错误] 下载源文件版本不一致（安装器 ${INSTALLER_VERSION}，脚本 ${downloaded_script_version:-未知}，Web ${downloaded_web_version:-未知}）。" >&2
    echo "[错误] 请稍后重试，避免混合安装不同版本。" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1 || ! python3 -m py_compile "${WORK_DIR}/web_panel.py" >/dev/null 2>&1; then
    echo "[错误] web_panel.py 校验失败，或系统未安装 python3。" >&2
    exit 1
fi

case "$(uname -m 2>/dev/null)" in
    x86_64|amd64) NEXTTRACE_ARCH="amd64" ;;
    aarch64|arm64) NEXTTRACE_ARCH="arm64" ;;
    *) NEXTTRACE_ARCH="" ;;
esac

if [[ -n "$NEXTTRACE_ARCH" ]]; then
    mkdir -p "${WORK_DIR}/vendor/nexttrace"
    if download_file "vendor/nexttrace/nexttrace_linux_${NEXTTRACE_ARCH}" "${WORK_DIR}/vendor/nexttrace/nexttrace_linux_${NEXTTRACE_ARCH}"; then
        chmod 755 "${WORK_DIR}/vendor/nexttrace/nexttrace_linux_${NEXTTRACE_ARCH}"
        echo "[信息] 已准备 NextTrace (${NEXTTRACE_ARCH})。"
    else
        echo "[警告] NextTrace 未能预先下载，主安装流程会再次尝试。"
    fi
fi

chmod 755 "${WORK_DIR}/nft.sh" "${WORK_DIR}/web_panel.py"
echo "[信息] 文件校验通过，正在启动安装菜单。"

if [[ -r /dev/tty ]]; then
    bash "${WORK_DIR}/nft.sh" </dev/tty
else
    echo "[错误] 当前环境没有可交互终端，请在 SSH 终端中执行安装命令。" >&2
    exit 1
fi
