#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import concurrent.futures
import fcntl
import hashlib
import hmac
import http.cookies
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from contextlib import closing, contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

CONF_DIR = os.environ.get("NFT_MANAGER_CONF_DIR", "/etc/nftables.d")
CONF_FILE = os.path.join(CONF_DIR, "port-forward.conf")
TARGETS_FILE = os.path.join(CONF_DIR, "targets.conf")
AUTH_FILE = os.path.join(CONF_DIR, "web-auth.conf")
STATS_FILE = os.path.join(CONF_DIR, "web-stats.json")
STATS_LOCK_FILE = os.path.join(CONF_DIR, ".web-stats.lock")
HISTORY_FILE = os.path.join(CONF_DIR, "web-history.json")
BANDWIDTH_DB = os.path.join(CONF_DIR, "web-bandwidth.db")
SETTINGS_FILE = os.path.join(CONF_DIR, "web-settings.json")
FIREWALL_CONF = os.path.join(CONF_DIR, "firewall.conf")
FIREWALL_PORTS_FILE = os.path.join(CONF_DIR, "firewall-ports.db")
FIREWALL_SSH_PORT_FILE = os.path.join(CONF_DIR, "firewall-ssh-port")
TABLE_NAME = "port_forward"
FIREWALL_TABLE = "nft_manager_firewall"
HOST = os.environ.get("NFT_MANAGER_WEB_HOST", "0.0.0.0")
PORT = int(os.environ.get("NFT_MANAGER_WEB_PORT", "5555"))
MAX_BATCH_RULES = int(os.environ.get("NFT_MANAGER_MAX_BATCH", "1000"))
SESSION_MAX_AGE = 86400
WEB_PANEL_VERSION = "3.31"
FIREWALL_LOCK = threading.Lock()
STATS_LOCK = threading.Lock()
BANDWIDTH_LOCK = threading.Lock()
BANDWIDTH_STATE = {
    "interface": "",
    "timestamp": 0.0,
    "rx": 0,
    "tx": 0,
    "forwardCounters": {},
    "forwardCountersAvailable": False,
    "downloadMbps": 0.0,
    "uploadMbps": 0.0,
    "bucketTimestamp": 0,
    "bucketDownloadMax": 0.0,
    "bucketUploadMax": 0.0,
}
BANDWIDTH_RETENTION = 24 * 60 * 60
BANDWIDTH_SAMPLE_INTERVAL = 10
BANDWIDTH_LIVE_MIN_INTERVAL = 0.8
BANDWIDTH_BUCKET_SECONDS = 60
BANDWIDTH_SCHEMA_VERSION = "3"
DEFAULT_PANEL_TITLE = "nft-manager"
DEFAULT_DASHBOARD_POLL_SECONDS = 10


def resolve_nft_bin():
    for path in ("/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"):
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    path = shutil.which("nft")
    if path and os.path.realpath(path) != "/usr/local/bin/nft":
        return path
    return ""


NFT_BIN = resolve_nft_bin()


def run(cmd, timeout=8):
    try:
        return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except FileNotFoundError:
        class Result:
            returncode = 127
            stdout = ""
            stderr = f"command not found: {cmd[0]}"
        return Result()
    except subprocess.TimeoutExpired:
        class Result:
            returncode = 124
            stdout = ""
            stderr = f"command timed out: {' '.join(cmd)}"
        return Result()


def run_nft(args, timeout=8):
    if not NFT_BIN:
        class Result:
            returncode = 127
            stdout = ""
            stderr = "未找到系统 nftables 命令"
        return Result()
    return run([NFT_BIN, *args], timeout=timeout)


def command_output(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def nexttrace_route(ip):
    if not valid_ip(ip):
        raise ValueError("目标 IP 无效")
    nexttrace = shutil.which("nexttrace")
    if not nexttrace:
        return "未检测到 nexttrace 命令。请在 SSH 菜单选择“更新脚本”，由安装流程自动安装 NextTrace。"
    try:
        result = subprocess.run(
            [nexttrace, ip], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120
        )
        output = command_output(result.stdout).rstrip()
        if not output:
            output = "NextTrace 未返回输出。"
        if result.returncode:
            output += f"\n\n[NextTrace 退出码: {result.returncode}]"
        return output
    except subprocess.TimeoutExpired as e:
        output = command_output(e.stdout).rstrip()
        if output:
            output += "\n\n"
        return output + "[NextTrace 执行超时：已停止，最长等待 120 秒]"


def ping_target(ip):
    if not valid_ip(ip):
        return {"reachable": False, "latency": None}
    try:
        result = run(["ping", "-n", "-c", "1", "-W", "2", ip], timeout=4)
    except Exception:
        return {"reachable": False, "latency": None}
    if result.returncode != 0:
        return {"reachable": False, "latency": None}
    match = re.search(r"time[=<]\s*([0-9.]+)\s*ms", result.stdout)
    return {"reachable": True, "latency": float(match.group(1)) if match else 0.0}


def tcp_connect_target(ip, port):
    if not valid_ip(ip) or not valid_port(port):
        return {"reachable": False, "latency": None}
    started = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=3):
            latency = round((time.perf_counter() - started) * 1000, 1)
            return {"reachable": True, "latency": latency}
    except OSError:
        return {"reachable": False, "latency": None}


def parallel_probes(items, probe):
    if not items:
        return {}
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(items))) as pool:
        future_map = {pool.submit(probe, value): key for key, value in items.items()}
        for future in concurrent.futures.as_completed(future_map):
            key = future_map[future]
            try:
                results[key] = future.result()
            except Exception:
                results[key] = {"reachable": False, "latency": None}
    return results


def target_latency_checks():
    return parallel_probes({target["ip"]: target["ip"] for target in read_targets()}, ping_target)


def rule_connectivity_checks():
    checks = {}
    for rule in parse_rules():
        if rule.get("enabled", True):
            checks[str(rule["lport"])] = (rule["ip"], rule["dport"])
        else:
            checks[str(rule["lport"])] = None

    def probe(value):
        if value is None:
            return {"reachable": False, "latency": None, "skipped": True}
        return tcp_connect_target(*value)

    return parallel_probes(checks, probe)


def local_ip():
    out = run(["bash", "-lc", "ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \\K[0-9.]+' | head -1"], timeout=2).stdout.strip()
    if out:
        return out
    out = run(["bash", "-lc", "hostname -I 2>/dev/null | awk '{print $1}'"], timeout=2).stdout.strip()
    return out or "127.0.0.1"


def normalize_firewall_protocol(protocol):
    protocol = str(protocol or "tcp+udp").lower()
    if protocol not in ("tcp", "udp", "tcp+udp"):
        raise ValueError("协议仅支持 tcp、udp 或 tcp+udp")
    return protocol


def detected_ssh_ports():
    ports = []
    for command in (("sshd", "-T"), ("/usr/sbin/sshd", "-T"), ("/usr/local/sbin/sshd", "-T")):
        if command[0] != "sshd" and not os.path.isfile(command[0]):
            continue
        result = run(list(command), timeout=3)
        if result.returncode == 0:
            ports = [int(m.group(1)) for m in re.finditer(r"(?m)^port\s+(\d+)\s*$", result.stdout)]
            if ports:
                break
    if not ports:
        for path in ("/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d"):
            if os.path.isfile(path):
                paths = [path]
            elif os.path.isdir(path):
                paths = [os.path.join(path, name) for name in os.listdir(path) if name.endswith(".conf")]
            else:
                paths = []
            for config in paths:
                try:
                    for line in open(config, encoding="utf-8", errors="ignore"):
                        match = re.match(r"^\s*Port\s+(\d+)\s*$", line, re.I)
                        if match:
                            ports.append(int(match.group(1)))
                except OSError:
                    pass
    ports = sorted({port for port in ports if valid_port(port)})
    return ports or [22]


def configured_ssh_ports():
    if os.path.exists(FIREWALL_SSH_PORT_FILE):
        try:
            port = int(open(FIREWALL_SSH_PORT_FILE, encoding="utf-8").read().strip())
            if valid_port(port):
                return [port]
        except (OSError, TypeError, ValueError):
            pass
    return detected_ssh_ports()


def firewall_baseline_ports():
    return [
        *[{"port": port, "protocol": "tcp", "label": "SSH 保底"} for port in configured_ssh_ports()],
        {"port": PORT, "protocol": "tcp", "label": "Web 面板保底"},
    ]


def read_firewall_ports():
    ports = []
    if not os.path.exists(FIREWALL_PORTS_FILE):
        return ports
    for line in open(FIREWALL_PORTS_FILE, encoding="utf-8", errors="ignore"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|", 2)
        if len(parts) < 2:
            continue
        try:
            port = int(parts[0])
            protocol = normalize_firewall_protocol(parts[1])
        except (TypeError, ValueError):
            continue
        if valid_port(port):
            ports.append({"port": port, "protocol": protocol, "label": clean_label(parts[2] if len(parts) > 2 else "")})
    return ports


def normalize_firewall_ports(ports):
    normalized = {}
    for item in [*firewall_baseline_ports(), *ports]:
        port = int(item.get("port", 0))
        protocol = normalize_firewall_protocol(item.get("protocol"))
        if not valid_port(port):
            raise ValueError(f"端口无效: {port}")
        key = (port, protocol)
        label = clean_label(item.get("label", ""))
        if label.startswith("SSH 保底") or label.startswith("Web 面板保底"):
            # 旧版保底端口不应在自动切换 SSH 端口后继续残留开放。
            continue
        if key not in normalized or label.startswith("SSH 保底") or label.startswith("Web 面板保底"):
            normalized[key] = {"port": port, "protocol": protocol, "label": label}
    for item in firewall_baseline_ports():
        key = (item["port"], item["protocol"])
        normalized[key] = item
    return sorted(normalized.values(), key=lambda item: (item["port"], item["protocol"]))


def firewall_config_text(ports):
    tcp_ports = sorted({item["port"] for item in ports if item["protocol"] in ("tcp", "tcp+udp")})
    udp_ports = sorted({item["port"] for item in ports if item["protocol"] in ("udp", "tcp+udp")})
    lines = [
        "#!/usr/sbin/nft -f",
        "",
        "# NFT_MANAGER_FIREWALL|1",
        "",
        f"table inet {FIREWALL_TABLE} {{",
        "    chain input {",
        "        type filter hook input priority filter; policy drop;",
        "        ct state established,related accept",
        "        iifname \"lo\" accept",
        "        ip protocol icmp accept",
        "        meta l4proto ipv6-icmp accept",
    ]
    if tcp_ports:
        lines.append("        tcp dport { " + ", ".join(map(str, tcp_ports)) + " } accept")
    if udp_ports:
        lines.append("        udp dport { " + ", ".join(map(str, udp_ports)) + " } accept")
    lines.extend([
        "    }",
        "",
        "    chain forward {",
        "        type filter hook forward priority filter; policy drop;",
        "        ct state established,related accept",
    ])
    if tcp_ports:
        lines.append("        ct original protocol tcp ct original proto-dst { " + ", ".join(map(str, tcp_ports)) + " } ct status dnat accept")
    if udp_ports:
        lines.append("        ct original protocol udp ct original proto-dst { " + ", ".join(map(str, udp_ports)) + " } ct status dnat accept")
    lines.extend(["    }", "}", ""])
    return "\n".join(lines)


def atomic_write(path, content):
    ensure_dirs()
    temp = f"{path}.tmp.{secrets.token_hex(8)}"
    try:
        with open(temp, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def firewall_ports_text(ports):
    lines = ["# port|protocol|label"]
    lines.extend(f"{item['port']}|{item['protocol']}|{clean_label(item['label'])}" for item in ports)
    return "\n".join(lines) + "\n"


def reload_firewall():
    run_nft(["flush", "table", "inet", FIREWALL_TABLE])
    run_nft(["delete", "table", "inet", FIREWALL_TABLE])
    result = run_nft(["-f", FIREWALL_CONF], timeout=15)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "防火墙规则加载失败")


def apply_firewall_ports(ports):
    ports = normalize_firewall_ports(ports)
    config = firewall_config_text(ports)
    temp = f"{FIREWALL_CONF}.check.{secrets.token_hex(8)}"
    old_conf = open(FIREWALL_CONF, encoding="utf-8").read() if os.path.exists(FIREWALL_CONF) else None
    old_ports = open(FIREWALL_PORTS_FILE, encoding="utf-8").read() if os.path.exists(FIREWALL_PORTS_FILE) else None
    try:
        with open(temp, "w", encoding="utf-8") as f:
            f.write(config)
        check = run_nft(["-c", "-f", temp], timeout=15)
        if check.returncode != 0:
            raise RuntimeError(check.stderr.strip() or "防火墙配置校验失败")
        atomic_write(FIREWALL_CONF, config)
        atomic_write(FIREWALL_PORTS_FILE, firewall_ports_text(ports))
        reload_firewall()
        return ports
    except Exception:
        if old_conf is not None:
            atomic_write(FIREWALL_CONF, old_conf)
            try:
                reload_firewall()
            except Exception:
                pass
        elif os.path.exists(FIREWALL_CONF):
            os.unlink(FIREWALL_CONF)
        if old_ports is not None:
            atomic_write(FIREWALL_PORTS_FILE, old_ports)
        elif os.path.exists(FIREWALL_PORTS_FILE):
            os.unlink(FIREWALL_PORTS_FILE)
        raise
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def ensure_firewall_configuration(sync_existing=False):
    with FIREWALL_LOCK:
        current = read_firewall_ports()
        first_setup = not os.path.exists(FIREWALL_PORTS_FILE)
        if first_setup or sync_existing:
            known = {(item["port"], item["protocol"]) for item in current}
            for rule in parse_rules():
                if not rule.get("enabled", True):
                    continue
                key = (rule["lport"], "tcp+udp")
                if key not in known:
                    current.append({"port": rule["lport"], "protocol": "tcp+udp", "label": "转发端口"})
                    known.add(key)
        return apply_firewall_ports(current)


def add_firewall_port(port, protocol="tcp+udp", label="手动开放"):
    port = int(port)
    if not valid_port(port):
        raise ValueError("端口无效")
    with FIREWALL_LOCK:
        current = read_firewall_ports()
        current.append({"port": port, "protocol": normalize_firewall_protocol(protocol), "label": label})
        return apply_firewall_ports(current)


def add_forward_firewall_ports(ports):
    with FIREWALL_LOCK:
        current = read_firewall_ports()
        existing = {(item["port"], item["protocol"]) for item in current}
        for port in ports:
            port = int(port)
            if not valid_port(port):
                raise ValueError("端口无效")
            if (port, "tcp+udp") not in existing:
                current.append({"port": port, "protocol": "tcp+udp", "label": "转发端口"})
                existing.add((port, "tcp+udp"))
        return apply_firewall_ports(current)


def remove_firewall_port(port, protocol=None):
    port = int(port)
    baseline_ports = {item["port"] for item in firewall_baseline_ports()}
    if port in baseline_ports:
        raise ValueError(f"保底端口 {port} 不允许关闭")
    with FIREWALL_LOCK:
        current = read_firewall_ports()
        if protocol:
            protocol = normalize_firewall_protocol(protocol)
            current = [item for item in current if not (item["port"] == port and item["protocol"] == protocol)]
        else:
            current = [item for item in current if item["port"] != port]
        return apply_firewall_ports(current)


def remove_forward_firewall_ports(ports):
    with FIREWALL_LOCK:
        wanted = {int(port) for port in ports if int(port) not in (22, PORT)}
        current = [item for item in read_firewall_ports() if not (item["port"] in wanted and item["label"] == "转发端口")]
        return apply_firewall_ports(current)


def set_firewall_ssh_port(port):
    port = int(port)
    if not valid_port(port):
        raise ValueError("SSH 保底端口无效")
    old_override = open(FIREWALL_SSH_PORT_FILE, encoding="utf-8").read() if os.path.exists(FIREWALL_SSH_PORT_FILE) else None
    atomic_write(FIREWALL_SSH_PORT_FILE, f"{port}\n")
    try:
        return apply_firewall_ports(read_firewall_ports())
    except Exception:
        if old_override is None:
            if os.path.exists(FIREWALL_SSH_PORT_FILE):
                os.unlink(FIREWALL_SSH_PORT_FILE)
        else:
            atomic_write(FIREWALL_SSH_PORT_FILE, old_override)
        raise


def restore_automatic_ssh_port():
    old_override = open(FIREWALL_SSH_PORT_FILE, encoding="utf-8").read() if os.path.exists(FIREWALL_SSH_PORT_FILE) else None
    if os.path.exists(FIREWALL_SSH_PORT_FILE):
        os.unlink(FIREWALL_SSH_PORT_FILE)
    try:
        return apply_firewall_ports(read_firewall_ports())
    except Exception:
        if old_override is not None:
            atomic_write(FIREWALL_SSH_PORT_FILE, old_override)
        raise


def valid_ip(ip):
    parts = ip.split(".")
    return len(parts) == 4 and all(p.isdigit() and str(int(p)) == p and 0 <= int(p) <= 255 for p in parts)


def valid_port(p):
    return isinstance(p, int) and 1 <= p <= 65535


def clean_label(s):
    return str(s or "").replace("|", " ").replace("\n", " ").replace("\r", " ").strip().lstrip("#").strip()


def ensure_dirs():
    os.makedirs(CONF_DIR, exist_ok=True)


@contextmanager
def stats_file_lock():
    ensure_dirs()
    with open(STATS_LOCK_FILE, "a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def read_settings():
    settings = {"panelTitle": DEFAULT_PANEL_TITLE, "dashboardPollSeconds": DEFAULT_DASHBOARD_POLL_SECONDS}
    if os.path.exists(SETTINGS_FILE):
        try:
            saved = json.load(open(SETTINGS_FILE, encoding="utf-8"))
            title = clean_label(saved.get("panelTitle", ""))[:64]
            if title:
                settings["panelTitle"] = title
            interval = int(saved.get("dashboardPollSeconds", DEFAULT_DASHBOARD_POLL_SECONDS))
            if 2 <= interval <= 300:
                settings["dashboardPollSeconds"] = interval
        except Exception:
            pass
    return settings


def save_settings(payload):
    settings = read_settings()
    if "panelTitle" in payload:
        title = clean_label(payload.get("panelTitle", ""))[:64]
        if not title:
            raise ValueError("顶部标题不能为空")
        settings["panelTitle"] = title
    if "dashboardPollSeconds" in payload:
        raw_interval = payload.get("dashboardPollSeconds")
        try:
            interval = int(raw_interval)
        except (TypeError, ValueError):
            raise ValueError("首页轮询间隔必须是整数秒")
        if isinstance(raw_interval, bool) or isinstance(raw_interval, float) and not raw_interval.is_integer():
            raise ValueError("首页轮询间隔必须是整数秒")
        if not 2 <= interval <= 300:
            raise ValueError("首页轮询间隔必须在 2-300 秒之间")
        settings["dashboardPollSeconds"] = interval
    atomic_write(SETTINGS_FILE, json.dumps(settings, ensure_ascii=False) + "\n")


def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 160000)
    return base64.b64encode(salt).decode(), base64.b64encode(digest).decode()


def ensure_auth():
    ensure_dirs()
    if os.path.exists(AUTH_FILE):
        return
    salt, digest = password_hash("admin")
    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        f.write(f"admin|{salt}|{digest}\n")
    os.chmod(AUTH_FILE, 0o600)


def read_auth():
    ensure_auth()
    line = open(AUTH_FILE, encoding="utf-8").read().strip()
    user, salt, digest = line.split("|", 2)
    return user, salt, digest


def verify_password(username, password):
    user, salt_b64, digest_b64 = read_auth()
    if username != user:
        return False
    salt = base64.b64decode(salt_b64)
    _, digest = password_hash(password, salt)
    return hmac.compare_digest(digest, digest_b64)


def set_password(old_password, new_password):
    user, _, _ = read_auth()
    if not verify_password(user, old_password):
        raise ValueError("旧密码错误")
    if len(new_password) < 4:
        raise ValueError("新密码至少 4 位")
    salt, digest = password_hash(new_password)
    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        f.write(f"{user}|{salt}|{digest}\n")
    os.chmod(AUTH_FILE, 0o600)


def sign_session(username, ts):
    _, _, digest_b64 = read_auth()
    msg = f"{username}|{ts}"
    sig = hmac.new(digest_b64.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{msg}|{sig}".encode()).decode()


def verify_session(token):
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        username, ts_text, sig = raw.split("|", 2)
        ts = int(ts_text)
    except Exception:
        return False
    if time.time() - ts > SESSION_MAX_AGE:
        return False
    user, _, digest_b64 = read_auth()
    if username != user:
        return False
    expected = hmac.new(digest_b64.encode(), f"{username}|{ts}".encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)


def read_targets():
    targets = []
    if not os.path.exists(TARGETS_FILE):
        return targets
    for line in open(TARGETS_FILE, encoding="utf-8", errors="ignore"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        alias, _, ip = line.partition("|")
        alias, ip = clean_label(alias), ip.strip()
        if alias and valid_ip(ip):
            targets.append({"alias": alias, "ip": ip})
    return targets


def write_targets(targets):
    ensure_dirs()
    with open(TARGETS_FILE, "w", encoding="utf-8") as f:
        f.write("# alias|ip\n")
        for t in targets:
            f.write(f"{clean_label(t['alias'])}|{t['ip']}\n")


def parse_rules():
    rules = []
    if not os.path.exists(CONF_FILE):
        return rules
    text = open(CONF_FILE, encoding="utf-8", errors="ignore").read().splitlines()
    seen_lports = set()
    for line in text:
        if "META_RULE|" in line:
            meta = line.split("META_RULE|", 1)[1]
            parts = (meta.split("|") + [""] * 8)[:8]
            try:
                lport, ip, dport = int(parts[0]), parts[1], int(parts[2])
            except ValueError:
                continue
            if valid_port(lport) and valid_ip(ip) and valid_port(dport):
                rules.append({
                    "lport": lport,
                    "ip": ip,
                    "dport": dport,
                    "alias": clean_label(parts[3]),
                    "desc": clean_label(parts[5] if len(parts) > 5 else ""),
                    "statsMode": parts[6] if parts[6] in ("upload", "download", "total") else "total",
                    "enabled": parts[7] != "0",
                })
                seen_lports.add(lport)
    for line in text:
        m = re.search(r"tcp dport (\d+).*dnat to ([0-9.]+):(\d+)", line)
        if not m:
            continue
        lport = int(m.group(1))
        if lport in seen_lports:
            continue
        rules.append({"lport": lport, "ip": m.group(2), "dport": int(m.group(3)), "alias": "", "desc": "", "statsMode": "total", "enabled": True})
        seen_lports.add(lport)
    return rules


def write_rules_file(path, rules):
    lip = local_ip()
    with open(path, "w", encoding="utf-8") as f:
        f.write("#!/usr/sbin/nft -f\n\n")
        f.write("# WEB_META|4\n\n")
        f.write(f"define LOCAL_IP = {lip}\n\n")
        f.write(f"table ip {TABLE_NAME} {{\n")
        f.write("    chain prerouting {\n        type nat hook prerouting priority -100; policy accept;\n")
        for r in rules:
            alias = clean_label(r.get("alias", ""))
            desc = clean_label(r.get("desc", ""))
            stats_mode = r.get("statsMode", "total")
            enabled = "1" if r.get("enabled", True) else "0"
            f.write(f"\n        # META_RULE|{r['lport']}|{r['ip']}|{r['dport']}|{alias}||{desc}|{stats_mode}|{enabled}\n")
            if not r.get("enabled", True):
                continue
            f.write(f"        tcp dport {r['lport']} counter dnat to {r['ip']}:{r['dport']}\n")
            f.write(f"        udp dport {r['lport']} counter dnat to {r['ip']}:{r['dport']}\n")
        f.write("    }\n\n")
        f.write("    chain postrouting {\n        type nat hook postrouting priority 100; policy accept;\n")
        for r in rules:
            if not r.get("enabled", True):
                continue
            f.write(f"\n        ip daddr {r['ip']} tcp dport {r['dport']} ct status dnat snat to $LOCAL_IP\n")
            f.write(f"        ip daddr {r['ip']} udp dport {r['dport']} ct status dnat snat to $LOCAL_IP\n")
        f.write("    }\n\n")
        f.write("    chain forward {\n        type filter hook forward priority filter; policy accept;\n")
        for r in rules:
            if not r.get("enabled", True):
                continue
            upload_marker = f"META_COUNTER_UPLOAD|{r['lport']}|{r['ip']}|{r['dport']}"
            download_marker = f"META_COUNTER_DOWNLOAD|{r['lport']}|{r['ip']}|{r['dport']}"
            f.write(f"        ct original protocol tcp ct original proto-dst {r['lport']} ip daddr {r['ip']} tcp dport {r['dport']} ct status dnat counter comment \"{upload_marker}\"\n")
            f.write(f"        ct original protocol udp ct original proto-dst {r['lport']} ip daddr {r['ip']} udp dport {r['dport']} ct status dnat counter comment \"{upload_marker}\"\n")
            f.write(f"        ct original protocol tcp ct original proto-dst {r['lport']} ip saddr {r['ip']} tcp sport {r['dport']} ct status dnat counter comment \"{download_marker}\"\n")
            f.write(f"        ct original protocol udp ct original proto-dst {r['lport']} ip saddr {r['ip']} udp sport {r['dport']} ct status dnat counter comment \"{download_marker}\"\n")
        f.write("    }\n}\n")


def write_rules(rules):
    ensure_dirs()
    temp_file = f"{CONF_FILE}.tmp.{secrets.token_hex(8)}"
    try:
        write_rules_file(temp_file, rules)
        os.replace(temp_file, CONF_FILE)
    finally:
        if os.path.exists(temp_file):
            os.unlink(temp_file)


def reload_rules():
    try:
        nft_counters()
    except Exception:
        pass
    run_nft(["flush", "table", "ip", TABLE_NAME])
    run_nft(["delete", "table", "ip", TABLE_NAME])
    res = run_nft(["-f", CONF_FILE], timeout=15)
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip() or "nft 规则加载失败")


def migrate_legacy_data():
    ensure_dirs()
    rules = parse_rules()
    targets = read_targets()

    target_ips = {t["ip"] for t in targets}
    changed_targets = False
    for r in rules:
        if r["ip"] not in target_ips:
            targets.append({"alias": f"目标-{r['ip'].replace('.', '-')}", "ip": r["ip"]})
            target_ips.add(r["ip"])
            changed_targets = True
    if changed_targets:
        write_targets(targets)

    if not os.path.exists(CONF_FILE) or not rules:
        return True

    try:
        text = open(CONF_FILE, encoding="utf-8", errors="ignore").read()
    except OSError:
        return False

    needs_migration = "WEB_META|4" not in text or 'comment "META_COUNTER_UPLOAD|' not in text
    if not needs_migration:
        return True

    original_text = text
    temp_file = f"{CONF_FILE}.migrate.{secrets.token_hex(8)}"
    try:
        write_rules_file(temp_file, rules)
        check = run_nft(["-c", "-f", temp_file], timeout=15)
        if check.returncode != 0:
            print(f"nft-manager: 旧规则迁移校验失败，已保留原配置：{check.stderr.strip()}")
            return False
        os.replace(temp_file, CONF_FILE)
        reload_rules()
        return True
    except Exception as e:
        restore_file = f"{CONF_FILE}.restore.{secrets.token_hex(8)}"
        try:
            with open(restore_file, "w", encoding="utf-8") as f:
                f.write(original_text)
            os.replace(restore_file, CONF_FILE)
            reload_rules()
        except Exception as restore_error:
            print(f"nft-manager: 旧规则迁移失败，且原规则恢复失败：{restore_error}")
        finally:
            if os.path.exists(restore_file):
                os.unlink(restore_file)
        print(f"nft-manager: 旧规则迁移失败，已尝试恢复原配置：{e}")
        return False
    finally:
        if os.path.exists(temp_file):
            os.unlink(temp_file)


def hourly_history(delta):
    now_hour = int(time.time() // 3600) * 3600
    hours = {}
    if os.path.exists(HISTORY_FILE):
        try:
            hours = json.load(open(HISTORY_FILE, encoding="utf-8")).get("hours", {})
        except Exception:
            hours = {}
    hours = {str(k): int(v) for k, v in hours.items() if int(k) >= now_hour - 23 * 3600}
    key = str(now_hour)
    hours[key] = int(hours.get(key, 0)) + max(0, int(delta))
    atomic_write(HISTORY_FILE, json.dumps({"hours": hours}, ensure_ascii=False) + "\n")
    return [{"hour": stamp, "bytes": int(hours.get(str(stamp), 0))} for stamp in range(now_hour - 23 * 3600, now_hour + 1, 3600)]


def default_network_interface():
    result = run(["ip", "-o", "route", "show", "default"], timeout=2)
    for line in result.stdout.splitlines():
        match = re.search(r"(?:^|\s)dev\s+(\S+)", line)
        if match:
            return match.group(1)
    try:
        with open("/proc/net/route", encoding="utf-8") as route_file:
            for line in route_file.readlines()[1:]:
                fields = line.split()
                if len(fields) >= 4 and fields[1] == "00000000" and int(fields[3], 16) & 2:
                    return fields[0]
    except (OSError, ValueError):
        pass
    try:
        for interface in sorted(os.listdir("/sys/class/net")):
            if interface == "lo":
                continue
            state_file = f"/sys/class/net/{interface}/operstate"
            if os.path.isfile(state_file):
                with open(state_file, encoding="utf-8") as state_handle:
                    if state_handle.read().strip() == "up":
                        return interface
    except OSError:
        pass
    return ""


def interface_byte_counters(interface):
    if not re.fullmatch(r"[A-Za-z0-9_.:@-]+", interface or ""):
        raise ValueError("默认出口网卡名称无效")
    base = f"/sys/class/net/{interface}/statistics"
    with open(f"{base}/rx_bytes", encoding="utf-8") as rx_file:
        rx_bytes = int(rx_file.read().strip())
    with open(f"{base}/tx_bytes", encoding="utf-8") as tx_file:
        tx_bytes = int(tx_file.read().strip())
    return rx_bytes, tx_bytes


def bandwidth_connection():
    os.makedirs(CONF_DIR, exist_ok=True)
    connection = sqlite3.connect(BANDWIDTH_DB, timeout=5)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute(
        "CREATE TABLE IF NOT EXISTS samples ("
        "timestamp INTEGER PRIMARY KEY, download_mbps REAL NOT NULL, upload_mbps REAL NOT NULL)"
    )
    connection.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    row = connection.execute("SELECT value FROM metadata WHERE key = 'schema_version'").fetchone()
    if not row or row[0] != BANDWIDTH_SCHEMA_VERSION:
        # Earlier schemas stored raw samples. They cannot be converted safely to
        # corrected, per-minute peak buckets, so reset only the bandwidth history.
        connection.execute("DELETE FROM samples")
        connection.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES('schema_version', ?)",
            (BANDWIDTH_SCHEMA_VERSION,),
        )
    return connection


def bandwidth_history(connection, now):
    cutoff = ((int(now) - BANDWIDTH_RETENTION) // BANDWIDTH_BUCKET_SECONDS) * BANDWIDTH_BUCKET_SECONDS
    connection.execute("DELETE FROM samples WHERE timestamp < ?", (cutoff,))
    rows = connection.execute(
        "SELECT timestamp, download_mbps, upload_mbps "
        "FROM samples WHERE timestamp >= ? ORDER BY timestamp",
        (cutoff,),
    ).fetchall()
    return [
        {
            "timestamp": int(stamp) + BANDWIDTH_BUCKET_SECONDS,
            "bucketTimestamp": int(stamp),
            "downloadMbps": round(float(download), 3),
            "uploadMbps": round(float(upload), 3),
        }
        for stamp, download, upload in rows
    ]


def forwarding_byte_deltas(previous, current):
    deltas = {"upload": 0, "download": 0}
    previous = previous if isinstance(previous, dict) else {}
    current = current if isinstance(current, dict) else {}
    for key, value in current.items():
        old_value = previous.get(key, {})
        for direction in ("upload", "download"):
            now_bytes = nonnegative_int((value.get(direction, {}) if isinstance(value, dict) else {}).get("bytes", 0))
            old_bytes = nonnegative_int((old_value.get(direction, {}) if isinstance(old_value, dict) else {}).get("bytes", 0))
            # nftables counters return to zero when rules are reloaded. Treat the
            # new value as the post-reset delta instead of producing a negative rate.
            deltas[direction] += now_bytes - old_bytes if now_bytes >= old_bytes else now_bytes
    return deltas


def classify_bandwidth_bytes(rx_delta, tx_delta, forward_upload_delta, forward_download_delta):
    rx_delta = nonnegative_int(rx_delta)
    tx_delta = nonnegative_int(tx_delta)
    forward_upload_delta = nonnegative_int(forward_upload_delta)
    forward_download_delta = nonnegative_int(forward_download_delta)
    forwarded_total = forward_upload_delta + forward_download_delta

    # A forwarded packet is counted once on RX and once on TX by a single-NIC
    # gateway. Remove that duplicated aggregate, then add each nftables direction
    # back to the matching client-facing download/upload side. Any remaining bytes
    # are traffic generated or consumed by the server itself.
    local_download_delta = max(0, rx_delta - forwarded_total)
    local_upload_delta = max(0, tx_delta - forwarded_total)
    return (
        local_download_delta + forward_download_delta,
        local_upload_delta + forward_upload_delta,
    )


def persist_bandwidth_bucket(bucket_timestamp, download_mbps, upload_mbps):
    if not bucket_timestamp:
        return
    try:
        with closing(bandwidth_connection()) as connection:
            with connection:
                connection.execute(
                    "INSERT INTO samples(timestamp, download_mbps, upload_mbps) VALUES(?, ?, ?) "
                    "ON CONFLICT(timestamp) DO UPDATE SET "
                    "download_mbps = MAX(download_mbps, excluded.download_mbps), "
                    "upload_mbps = MAX(upload_mbps, excluded.upload_mbps)",
                    (int(bucket_timestamp), float(download_mbps), float(upload_mbps)),
                )
    except sqlite3.Error:
        pass


def bandwidth_point_locked(now):
    bucket_timestamp = int(BANDWIDTH_STATE.get("bucketTimestamp", 0) or 0)
    if not bucket_timestamp:
        return None
    sampled_at = float(BANDWIDTH_STATE.get("timestamp", 0) or now)
    return {
        "timestamp": int(sampled_at),
        "bucketTimestamp": bucket_timestamp,
        "downloadMbps": round(float(BANDWIDTH_STATE.get("downloadMbps", 0.0)), 3),
        "uploadMbps": round(float(BANDWIDTH_STATE.get("uploadMbps", 0.0)), 3),
        "provisional": True,
    }


def bandwidth_response_locked(now, include_history=False):
    point = bandwidth_point_locked(now)
    history = []
    if include_history:
        try:
            with closing(bandwidth_connection()) as connection:
                with connection:
                    history = bandwidth_history(connection, now)
        except sqlite3.Error:
            history = []
        if point:
            history = [item for item in history if item.get("bucketTimestamp") != point["bucketTimestamp"]]
            history.append(point)
    return {
        "available": bool(BANDWIDTH_STATE.get("interface")),
        "interface": str(BANDWIDTH_STATE.get("interface", "")),
        "downloadMbps": round(float(BANDWIDTH_STATE.get("downloadMbps", 0.0)), 3),
        "uploadMbps": round(float(BANDWIDTH_STATE.get("uploadMbps", 0.0)), 3),
        "sampledAt": int(BANDWIDTH_STATE.get("timestamp", 0) or now),
        "point": point,
        "history": history,
    }


def bandwidth_status(include_history=True):
    with BANDWIDTH_LOCK:
        return bandwidth_response_locked(time.time(), include_history=include_history)


def bandwidth_snapshot(persist=False, include_history=False):
    with BANDWIDTH_LOCK:
        now = time.time()
        previous = dict(BANDWIDTH_STATE)
        elapsed = now - float(previous.get("timestamp", 0) or 0)

        # Several visible dashboards may poll together. Reuse the latest sample so
        # they never multiply system counter reads beyond roughly once per second.
        if previous.get("timestamp") and elapsed < BANDWIDTH_LIVE_MIN_INTERVAL:
            if persist:
                persist_bandwidth_bucket(
                    previous.get("bucketTimestamp", 0),
                    previous.get("bucketDownloadMax", 0.0),
                    previous.get("bucketUploadMax", 0.0),
                )
            return bandwidth_response_locked(now, include_history=include_history)

        interface = str(previous.get("interface", ""))
        if not interface:
            interface = default_network_interface()
        if not interface:
            return bandwidth_response_locked(now, include_history=include_history)
        try:
            rx_bytes, tx_bytes = interface_byte_counters(interface)
        except (OSError, ValueError):
            interface = default_network_interface()
            try:
                rx_bytes, tx_bytes = interface_byte_counters(interface)
            except (OSError, ValueError):
                BANDWIDTH_STATE["interface"] = ""
                return bandwidth_response_locked(now, include_history=include_history)

        forward_available, forward_counters = read_kernel_counters_with_status()
        valid_delta = (
            previous.get("interface") == interface
            and 0.5 <= elapsed <= BANDWIDTH_SAMPLE_INTERVAL * 4
            and rx_bytes >= int(previous.get("rx", 0))
            and tx_bytes >= int(previous.get("tx", 0))
        )
        download_mbps = float(previous.get("downloadMbps", 0.0))
        upload_mbps = float(previous.get("uploadMbps", 0.0))
        if valid_delta:
            rx_delta = rx_bytes - int(previous["rx"])
            tx_delta = tx_bytes - int(previous["tx"])
            if forward_available and previous.get("forwardCountersAvailable"):
                forward_deltas = forwarding_byte_deltas(previous.get("forwardCounters", {}), forward_counters)
                download_delta, upload_delta = classify_bandwidth_bytes(
                    rx_delta,
                    tx_delta,
                    forward_deltas["upload"],
                    forward_deltas["download"],
                )
            else:
                download_delta, upload_delta = rx_delta, tx_delta
            download_mbps = download_delta * 8 / elapsed / 1_000_000
            upload_mbps = upload_delta * 8 / elapsed / 1_000_000

        bucket_timestamp = (int(now) // BANDWIDTH_BUCKET_SECONDS) * BANDWIDTH_BUCKET_SECONDS
        previous_bucket = int(previous.get("bucketTimestamp", 0) or 0)
        if previous_bucket != bucket_timestamp:
            persist_bandwidth_bucket(
                previous_bucket,
                previous.get("bucketDownloadMax", 0.0),
                previous.get("bucketUploadMax", 0.0),
            )
            bucket_download_max = download_mbps if valid_delta else 0.0
            bucket_upload_max = upload_mbps if valid_delta else 0.0
        else:
            bucket_download_max = max(float(previous.get("bucketDownloadMax", 0.0)), download_mbps) if valid_delta else float(previous.get("bucketDownloadMax", 0.0))
            bucket_upload_max = max(float(previous.get("bucketUploadMax", 0.0)), upload_mbps) if valid_delta else float(previous.get("bucketUploadMax", 0.0))

        BANDWIDTH_STATE.update(
            {
                "interface": interface,
                "timestamp": now,
                "rx": rx_bytes,
                "tx": tx_bytes,
                "forwardCounters": forward_counters if forward_available else {},
                "forwardCountersAvailable": forward_available,
                "downloadMbps": download_mbps,
                "uploadMbps": upload_mbps,
                "bucketTimestamp": bucket_timestamp,
                "bucketDownloadMax": bucket_download_max,
                "bucketUploadMax": bucket_upload_max,
            }
        )
        if persist:
            persist_bandwidth_bucket(bucket_timestamp, bucket_download_max, bucket_upload_max)
        return bandwidth_response_locked(now, include_history=include_history)


def empty_counter():
    return {"upload": {"packets": 0, "bytes": 0}, "download": {"packets": 0, "bytes": 0}}


def nonnegative_int(value):
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def normalize_counter(value):
    result = empty_counter()
    if not isinstance(value, dict):
        return result
    for direction in ("upload", "download"):
        source = value.get(direction, {})
        if isinstance(source, dict):
            result[direction]["packets"] = nonnegative_int(source.get("packets", 0))
            result[direction]["bytes"] = nonnegative_int(source.get("bytes", 0))
    return result


def parse_kernel_counters(out):
    counters = {}
    current = None
    direction = None
    for line in out.splitlines():
        marker = re.search(r"META_COUNTER_(UPLOAD|DOWNLOAD)\|(\d+)\|([0-9.]+)\|(\d+)", line)
        if marker:
            current = f"{marker.group(2)}|{marker.group(3)}|{marker.group(4)}"
            direction = "upload" if marker.group(1) == "UPLOAD" else "download"
        if current and direction and "counter packets" in line:
            m = re.search(r"counter packets (\d+) bytes (\d+)", line)
            if m:
                item = counters.setdefault(current, empty_counter())[direction]
                item["packets"] += int(m.group(1))
                item["bytes"] += int(m.group(2))
    return counters


def read_kernel_counters_with_status():
    result = run_nft(["list", "table", "ip", TABLE_NAME], timeout=2)
    if result.returncode != 0:
        return False, {}
    return True, parse_kernel_counters(result.stdout)


def read_kernel_counters():
    _, counters = read_kernel_counters_with_status()
    return counters


def read_stats_state(current):
    saved = {}
    if os.path.exists(STATS_FILE):
        try:
            saved = json.load(open(STATS_FILE, encoding="utf-8"))
        except Exception:
            saved = {}
    if isinstance(saved, dict) and saved.get("version") == 2:
        saved_kernel = saved.get("lastKernel", {})
        saved_totals = saved.get("totals", {})
        saved_activity = saved.get("activity", {})
        if not isinstance(saved_kernel, dict):
            saved_kernel = {}
        if not isinstance(saved_totals, dict):
            saved_totals = {}
        if not isinstance(saved_activity, dict):
            saved_activity = {}
        return {
            "lastKernel": {key: normalize_counter(value) for key, value in saved_kernel.items()},
            "totals": {key: normalize_counter(value) for key, value in saved_totals.items()},
            "activity": {key: nonnegative_int(value) for key, value in saved_activity.items()},
        }

    # v1 only stored the previous kernel snapshot. Preserve it during upgrade,
    # including a reset that may already have happened before v2 starts.
    previous = saved if isinstance(saved, dict) else {}
    totals = {}
    for key in set(previous) | set(current):
        old = normalize_counter(previous.get(key, {}))
        now = normalize_counter(current.get(key, {}))
        total = empty_counter()
        for direction in ("upload", "download"):
            for metric in ("packets", "bytes"):
                old_value = old[direction][metric]
                now_value = now[direction][metric]
                total[direction][metric] = now_value if now_value >= old_value else old_value + now_value
        totals[key] = total
    return {"lastKernel": current, "totals": totals, "activity": {}}


def nft_counters():
    with STATS_LOCK, stats_file_lock():
        current = read_kernel_counters()
        state = read_stats_state(current)
        previous = state["lastKernel"]
        totals = state["totals"]
        activity = state["activity"]
        now = int(time.time())
        result = {}
        delta_total = 0
        for key, val in current.items():
            old = normalize_counter(previous.get(key, {}))
            total = normalize_counter(totals.get(key, {}))
            rule_delta = 0
            for direction in ("upload", "download"):
                for metric in ("packets", "bytes"):
                    value = val[direction][metric]
                    old_value = old[direction][metric]
                    delta = value - old_value if value >= old_value else value
                    total[direction][metric] += max(0, delta)
                    if metric == "bytes":
                        rule_delta += max(0, delta)
                        delta_total += max(0, delta)
            totals[key] = total
            if rule_delta > 0:
                activity[key] = now
            result[key] = {**total, "active": now - int(activity.get(key, 0)) <= 60, "sampled_at": now}

        # Disabled rules have no live nft counter but retain their accumulated traffic.
        for key, total in totals.items():
            if key not in result:
                result[key] = {**normalize_counter(total), "active": False, "sampled_at": now}

        payload = {"version": 2, "lastKernel": current, "totals": totals, "activity": activity, "updatedAt": now}
        atomic_write(STATS_FILE, json.dumps(payload, ensure_ascii=False) + "\n")
        return result, hourly_history(delta_total)


def parse_port_tokens(tokens):
    ports = []
    seen = set()
    for token in tokens:
        token = str(token).strip()
        if not token:
            continue
        if not token.isdigit():
            raise ValueError(f"端口无效: {token}；仅支持单个端口，请使用空格或英文逗号分隔多个端口")
        port = int(token)
        if not valid_port(port):
            raise ValueError(f"端口无效: {token}")
        if port in seen:
            raise ValueError(f"端口重复: {port}")
        seen.add(port)
        ports.append(port)
    if not ports:
        raise ValueError("请至少输入一个入口端口")
    if len(ports) > MAX_BATCH_RULES:
        raise ValueError(f"单次最多添加 {MAX_BATCH_RULES} 条规则")
    return ports


def expand_forward(payload):
    ip = payload.get("ip", "")
    if not valid_ip(ip):
        raise ValueError("目标 IP 无效")
    in_ports = parse_port_tokens(payload.get("ports", []))
    mode = payload.get("mode", "same")
    if mode == "same":
        out_ports = list(in_ports)
    elif mode == "start":
        start = int(payload.get("outStart", 0))
        if not valid_port(start) or start + len(in_ports) - 1 > 65535:
            raise ValueError("出口起始端口无效")
        out_ports = [start + i for i in range(len(in_ports))]
    else:
        raise ValueError("映射方式无效，仅支持与入口端口一致或指定出口起始端口")
    prefix = clean_label(payload.get("alias", ""))
    desc = clean_label(payload.get("desc", ""))
    stats_mode = payload.get("statsMode", "total")
    if stats_mode not in ("upload", "download", "total"):
        raise ValueError("统计口径无效")
    batch = len(in_ports) > 1
    target_alias = next((target["alias"] for target in read_targets() if target["ip"] == ip), ip)
    rules = []
    for lp, dp in zip(in_ports, out_ports):
        alias = f"{prefix}-{lp}" if prefix and batch else prefix or f"{target_alias}:{lp}"
        rules.append({"lport": lp, "ip": ip, "dport": dp, "alias": alias, "desc": desc, "statsMode": stats_mode, "enabled": True})
    return rules


def add_rules(payload):
    existing = parse_rules()
    new_rules = expand_forward(payload)
    used = {r["lport"] for r in existing}
    conflict = [r["lport"] for r in new_rules if r["lport"] in used]
    if conflict:
        raise ValueError("入口端口已存在: " + ", ".join(map(str, conflict[:20])))
    open_firewall = payload.get("openFirewall", True)
    if isinstance(open_firewall, str):
        open_firewall = open_firewall.lower() not in ("0", "false", "no")
    try:
        write_rules(existing + new_rules)
        reload_rules()
        if open_firewall:
            add_forward_firewall_ports([rule["lport"] for rule in new_rules])
    except Exception:
        write_rules(existing)
        try:
            reload_rules()
        except Exception:
            pass
        raise
    return len(new_rules)


def update_rule(payload):
    old_lport = int(payload.get("oldLport", 0))
    rules = parse_rules()
    old_rule = next((r for r in rules if r["lport"] == old_lport), None)
    rest = [r for r in rules if r["lport"] != old_lport]
    new_rules = expand_forward(payload)
    if len(new_rules) != 1:
        raise ValueError("编辑时只能保存为单条规则")
    if any(r["lport"] == new_rules[0]["lport"] for r in rest):
        raise ValueError("入口端口已存在")
    if old_rule:
        new_rules[0]["enabled"] = old_rule.get("enabled", True)
    try:
        write_rules(rest + new_rules)
        reload_rules()
        if old_rule and old_rule["lport"] != new_rules[0]["lport"]:
            add_forward_firewall_ports([new_rules[0]["lport"]])
            if old_rule["lport"] not in (22, PORT):
                remove_forward_firewall_ports([old_rule["lport"]])
    except Exception:
        write_rules(rules)
        try:
            reload_rules()
        except Exception:
            pass
        raise


def delete_rules(payload):
    ports = {int(p) for p in payload.get("lports", [])}
    existing = parse_rules()
    close_firewall = payload.get("closeFirewall", True)
    if isinstance(close_firewall, str):
        close_firewall = close_firewall.lower() not in ("0", "false", "no")
    try:
        write_rules([r for r in existing if r["lport"] not in ports])
        reload_rules()
        if close_firewall:
            remove_forward_firewall_ports(ports)
    except Exception:
        write_rules(existing)
        try:
            reload_rules()
        except Exception:
            pass
        raise


def toggle_rule(payload):
    lport = int(payload.get("lport", 0))
    enabled = bool(payload.get("enabled"))
    rules = parse_rules()
    for rule in rules:
        if rule["lport"] == lport:
            rule["enabled"] = enabled
            write_rules(rules)
            reload_rules()
            return
    raise ValueError("未找到转发规则")


def dashboard():
    targets = read_targets()
    rules = parse_rules()
    counters, history = nft_counters()
    enriched = []
    total_bytes = 0
    active = 0
    aliases = {t["ip"]: t["alias"] for t in targets}
    for r in rules:
        key = f"{r['lport']}|{r['ip']}|{r['dport']}"
        c = counters.get(key, {"upload": {"packets": 0, "bytes": 0}, "download": {"packets": 0, "bytes": 0}, "active": False})
        upload_bytes, download_bytes = c["upload"]["bytes"], c["download"]["bytes"]
        both_bytes = upload_bytes + download_bytes
        selected = r.get("statsMode", "total")
        selected_bytes = upload_bytes if selected == "upload" else download_bytes if selected == "download" else both_bytes
        total_bytes += both_bytes
        active += 1 if c.get("active") else 0
        enriched.append({**r, "targetAlias": aliases.get(r["ip"], ""), "uploadBytes": upload_bytes, "downloadBytes": download_bytes, "totalBytes": both_bytes, "bytes": selected_bytes, "active": c["active"]})
    return {"targets": targets, "rules": enriched, "history": history, "bandwidth": bandwidth_status(include_history=True), "settings": read_settings(), "firewall": {"ports": read_firewall_ports(), "baselinePorts": [item["port"] for item in firewall_baseline_ports()], "enabled": os.path.exists(FIREWALL_CONF)}, "stats": {"totalBytes": total_bytes, "ruleCount": len(rules), "targetCount": len(targets), "activeCount": active, "localIp": local_ip(), "port": PORT}}


HTML = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>nft-manager</title>
<style>
:root{color-scheme:dark;--bg:#050607;--panel:#17181c;--panel2:#1f2026;--surface:#111318;--surface2:#101217;--sidebar:#020303;--line:#343640;--line-soft:#2a2d35;--item-bg:#10141a;--item-border:#3d4552;--text:#f5f7fb;--muted:#8e96a3;--nav-text:#d9dde7;--nav-active-bg:#112846;--nav-active-text:#55a8ff;--nav-hover-bg:#0d1b2d;--button-bg:#243b63;--button-text:#fff;--trace-bg:#222b2e;--trace-text:#e3dac5;--glass:rgba(5,6,7,.94);--tab-glass:rgba(9,10,12,.96);--pill-bg:#11351f;--pill-text:#68f0a4;--upload:#46a6ff;--download:#20d98a;--traffic-line:#9b7cff;--traffic-fill:rgba(155,124,255,.16);--bandwidth-upload:#c084fc;--bandwidth-download:#2dd4bf;--total:#b779ff;--blue:#0877ff;--green:#1ddb78;--orange:#ff9f1a;--purple:#8e4cff;--danger:#ff5a66}
:root[data-theme=light]{color-scheme:light;--bg:#f4f6f9;--panel:#fff;--panel2:#fff;--surface:#f8fafc;--surface2:#fff;--sidebar:#fff;--line:#d7dde7;--line-soft:#e6eaf0;--item-bg:#fff;--item-border:#c8d1df;--text:#172033;--muted:#697487;--nav-text:#3f4a5c;--nav-active-bg:#e8f1ff;--nav-active-text:#075fbd;--nav-hover-bg:#f1f5fb;--button-bg:#e7eef8;--button-text:#25334a;--trace-bg:#152126;--trace-text:#f1eadb;--glass:rgba(255,255,255,.94);--tab-glass:rgba(255,255,255,.96);--pill-bg:#e4f6ec;--pill-text:#087a4d;--upload:#176fc1;--download:#087a4d;--traffic-line:#6d3bd1;--traffic-fill:rgba(109,59,209,.12);--bandwidth-upload:#7e22ce;--bandwidth-download:#0f766e;--total:#7138c7;--green:#087a4d;--purple:#7138c7;--danger:#e23f4d}
@media(prefers-color-scheme:light){:root[data-theme=system]{color-scheme:light;--bg:#f4f6f9;--panel:#fff;--panel2:#fff;--surface:#f8fafc;--surface2:#fff;--sidebar:#fff;--line:#d7dde7;--line-soft:#e6eaf0;--item-bg:#fff;--item-border:#c8d1df;--text:#172033;--muted:#697487;--nav-text:#3f4a5c;--nav-active-bg:#e8f1ff;--nav-active-text:#075fbd;--nav-hover-bg:#f1f5fb;--button-bg:#e7eef8;--button-text:#25334a;--trace-bg:#152126;--trace-text:#f1eadb;--glass:rgba(255,255,255,.94);--tab-glass:rgba(255,255,255,.96);--pill-bg:#e4f6ec;--pill-text:#087a4d;--upload:#176fc1;--download:#087a4d;--traffic-line:#6d3bd1;--traffic-fill:rgba(109,59,209,.12);--bandwidth-upload:#7e22ce;--bandwidth-download:#0f766e;--total:#7138c7;--green:#087a4d;--purple:#7138c7;--danger:#e23f4d}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 -apple-system,BlinkMacSystemFont,Segoe UI,Arial,"Microsoft YaHei",sans-serif}
button,input,select,textarea{font:inherit}button{cursor:pointer;border:0;border-radius:6px;background:#243b63;color:#fff;padding:9px 14px}button:disabled{cursor:not-allowed;opacity:.65}button.primary{background:var(--blue)}button.danger{background:var(--danger)}button.ghost{background:#2b2d35}.login{height:100vh;display:grid;place-items:center}.login form{width:360px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:28px}.login input{width:100%;margin:8px 0 14px;padding:12px;border-radius:6px;border:1px solid var(--line);background:#111318;color:#fff}
.app{display:flex;min-height:100vh}.side{width:238px;background:#020303;border-right:1px solid #2a2d35;padding:28px 16px;position:fixed;inset:0 auto 0 0}.brand{font-weight:800;font-size:18px;margin-bottom:2px}.ver{font-size:12px;color:var(--muted);margin-bottom:34px}.nav button{width:100%;text-align:left;margin:5px 0;background:transparent;color:var(--nav-text);transition:background .16s,color .16s,box-shadow .16s}.nav button:hover{background:var(--nav-hover-bg)}.nav button.active{background:var(--nav-active-bg);color:var(--nav-active-text);box-shadow:inset 3px 0 0 var(--nav-active-text);font-weight:700}.foot{position:absolute;bottom:18px;color:#737b89;font-size:12px;left:70px}
.main{margin-left:238px;flex:1;min-width:0}.top{height:54px;border-bottom:1px solid #2a2d35;display:flex;align-items:center;justify-content:flex-end;padding:0 26px}.user{font-weight:700}.mobile-brand{display:none;font-weight:800;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.nav-icon{display:none}
.content{padding:18px 24px 40px}.page-with-fabs{min-height:calc(100vh - 112px);padding-bottom:190px}.cards{display:grid;grid-template-columns:repeat(4,minmax(160px,1fr));gap:14px}.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px}.card h3{font-size:14px;margin:0 0 14px}.big{font-size:25px;font-weight:800}.bar{height:5px;background:linear-gradient(90deg,var(--blue),#b54cff);border-radius:10px;margin-top:14px}.panel{margin-top:20px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}.panel h2{margin:0 0 14px;font-size:22px}.chart-pair{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.chart-pair>.panel{min-width:0}.chart-panel-head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px}.bandwidth-live{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:6px 12px;font-size:12px;font-weight:700}.bandwidth-live .download{color:var(--bandwidth-download)}.bandwidth-live .upload{color:var(--bandwidth-upload)}.bandwidth-interface{width:100%;color:var(--muted);font-weight:500;text-align:right}.chart-legend{display:flex;justify-content:flex-end;gap:14px;margin:-4px 2px 4px;color:var(--muted);font-size:12px}.chart-legend span{display:inline-flex;align-items:center;gap:6px}.chart-legend i{width:16px;height:3px;border-radius:3px}.chart-legend .download i{background:var(--bandwidth-download)}.chart-legend .upload i{background:var(--bandwidth-upload)}.toolbar{display:flex;gap:10px;align-items:center;margin-bottom:14px}.rule-table-wrap{border:1px solid var(--line);border-radius:8px;overflow:auto}.table{width:100%;border-collapse:collapse}.table th,.table td{border-bottom:1px solid #2a2d35;padding:10px;text-align:left}.table tr:last-child td{border-bottom:0}.muted{color:var(--muted)}.pill{display:inline-flex;gap:6px;background:#11351f;color:#68f0a4;border-radius:5px;padding:4px 8px;font-weight:700}.status{color:var(--muted)}.status.on{color:var(--green);font-weight:700}.metric.upload{color:#46a6ff}.metric.download{color:#20d98a}.metric.total{color:#b779ff}.actions{display:flex;align-items:center;gap:8px}.actions .switch{margin-right:12px}.actions button{padding:6px 10px;margin:0}.hidden{display:none!important}.view-switch{display:flex;border:1px solid var(--line);border-radius:6px;overflow:hidden}.view-switch button{border-radius:0;background:#17181c;padding:7px 11px}.view-switch button.active{background:#1d4d8a}.switch{position:relative;display:inline-flex;width:38px;height:22px;vertical-align:middle;flex:none}.switch input{opacity:0;width:0;height:0}.slider{position:absolute;inset:0;background:#4a252a;border-radius:22px}.slider:before{content:'';position:absolute;width:16px;height:16px;left:3px;top:3px;border-radius:50%;background:#fff;transition:.2s}.switch input:checked+.slider{background:#16855b}.switch input:checked+.slider:before{transform:translateX(16px)}.rule-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px}.rule-card{border:1px solid var(--line);background:#111318;padding:14px;border-radius:8px}.rule-card.disabled{opacity:.6}.rule-card-top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.rule-card h3{font-size:15px;margin:0 0 8px}.rule-card .route{color:#cdd4e0;margin:7px 0}.rule-card .metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;border-top:1px solid #2a2d35;padding-top:10px;margin-top:10px}.rule-card .metrics span{font-size:12px}.rule-card .actions{margin-top:14px}.chart-wrap{position:relative;touch-action:pan-y}.chart-svg{display:block;width:100%;height:300px}.chart-grid{stroke:var(--line);stroke-dasharray:3 4}.chart-axis{stroke:var(--muted);stroke-width:1.4}.chart-line{fill:none;stroke:var(--traffic-line);stroke-width:3}.chart-line.bandwidth-download{stroke:var(--bandwidth-download);stroke-width:2.5}.chart-line.bandwidth-upload{stroke:var(--bandwidth-upload);stroke-width:2.5}.chart-fill{fill:var(--traffic-fill)}.chart-label{fill:var(--muted);font-size:11px}.chart-axis-title{fill:var(--text);font-size:12px;font-weight:700}.chart-hover-guide{display:none;stroke:var(--muted);stroke-width:1;stroke-dasharray:4 3;pointer-events:none}.chart-hover-dot{display:none;stroke:var(--panel);stroke-width:3;pointer-events:none}.chart-hover-dot.traffic{fill:var(--traffic-line)}.chart-hover-dot.download{fill:var(--bandwidth-download)}.chart-hover-dot.upload{fill:var(--bandwidth-upload)}.chart-tooltip{position:absolute;z-index:3;display:none;min-width:150px;max-width:230px;padding:9px 11px;border:1px solid var(--line);border-radius:7px;background:var(--panel2);color:var(--text);box-shadow:0 10px 26px rgba(0,0,0,.28);font-size:12px;line-height:1.55;pointer-events:none}.chart-tooltip.show{display:block}.chart-tooltip-time{margin-bottom:3px;color:var(--muted);font-weight:700}.chart-tooltip-row{display:flex;justify-content:space-between;gap:16px;white-space:nowrap}.chart-tooltip-row b{font-variant-numeric:tabular-nums}.chart-tooltip-row.traffic b{color:var(--traffic-line)}.chart-tooltip-row.download b{color:var(--bandwidth-download)}.chart-tooltip-row.upload b{color:var(--bandwidth-upload)}.fab-stack{position:fixed;z-index:7;right:24px;bottom:24px;display:flex;flex-direction:column;align-items:flex-end;gap:10px}.fab{min-width:112px;height:46px;padding:0 15px;border:1px solid rgba(105,173,255,.45);border-radius:23px;background:rgba(17,40,70,.94);color:#eaf3ff;display:flex;align-items:center;justify-content:flex-start;gap:9px;box-shadow:0 10px 28px rgba(0,0,0,.3);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)}.fab:hover{background:#164b83}.fab.primary{border-color:rgba(8,119,255,.72);background:var(--blue)}.fab-icon{display:grid;place-items:center;width:20px;height:20px;font-size:18px;font-weight:800;line-height:1}.fab-label{font-size:13px;font-weight:700;white-space:nowrap}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.58);display:grid;place-items:center;z-index:20}.dialog{width:min(720px,92vw);max-height:88vh;overflow:auto;background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:20px}.dialog.trace-dialog{width:min(980px,95vw)}.dialog.rules-dialog{width:min(1240px,96vw)}.dialog-copy{margin:0 0 22px;color:#d7dde8}.dialog-actions{text-align:right}.trace-output{margin:12px 0 18px;max-height:62vh;overflow:auto;padding:14px;border:1px solid var(--line);border-radius:6px;background:#222b2e;color:#e3dac5;white-space:pre-wrap;tab-size:4;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}.trace-output a{color:#68c8d6;text-decoration:underline;text-underline-offset:2px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.field{margin-bottom:12px}.field label{display:block;color:#cbd1dc;margin-bottom:6px}.field input,.field select,.field textarea{width:100%;padding:10px;border-radius:6px;border:1px solid var(--line);background:#101217;color:#fff}.firewall-check{display:flex!important;align-items:center;gap:9px;padding:11px 12px;border:1px solid #356aa0;border-radius:6px;background:rgba(8,119,255,.1);color:#dbeafe!important;cursor:pointer}.firewall-check input{width:16px!important;height:16px;margin:0;accent-color:var(--blue)}.error-box{display:none;margin:0 0 12px;padding:10px 12px;border:1px solid rgba(255,90,102,.55);border-radius:6px;background:rgba(255,90,102,.12);color:#ff9aa3}.error-box.show{display:block}.toast{position:fixed;right:22px;top:18px;z-index:30;max-width:min(460px,calc(100vw - 44px));padding:12px 14px;border:1px solid rgba(255,90,102,.55);border-radius:8px;background:#2a1116;color:#ffd7dc;box-shadow:0 12px 30px rgba(0,0,0,.35)}.count-button{padding:2px 8px;background:rgba(8,119,255,.14);color:#69adff;border:1px solid rgba(8,119,255,.35)}.tags{min-height:42px;border:1px solid var(--line);background:#101217;border-radius:6px;padding:5px;display:flex;gap:6px;flex-wrap:wrap}.tag{background:#e9eef8;color:#243040;border-radius:4px;padding:4px 8px}.tag button{background:transparent;color:#667085;padding:0 0 0 6px}.tag-input{min-width:120px;flex:1;border:0!important;background:transparent!important;padding:5px!important}.preview{background:#101217;border:1px solid var(--line);border-radius:6px;padding:10px;max-height:160px;overflow:auto;color:#d7dde8}.chart{height:260px;border:1px dashed #3c414d;border-radius:8px;background:linear-gradient(180deg,rgba(128,76,255,.18),transparent)}.probe-pill{display:inline-flex;align-items:center;gap:6px;min-width:96px;padding:4px 9px;border-radius:999px;background:rgba(142,150,163,.14);color:#aeb5c0;white-space:nowrap}.probe-pill i{width:7px;height:7px;border-radius:50%;background:currentColor;box-shadow:0 0 0 0 currentColor;animation:probe-pulse 1.8s infinite}.probe-pill b{font-variant-numeric:tabular-nums}.probe-pill.good{background:rgba(29,219,120,.14);color:#58e69d}.probe-pill.warn{background:rgba(255,205,65,.15);color:#ffd262}.probe-pill.slow{background:rgba(255,159,26,.16);color:#ffae43}.probe-pill.bad{background:rgba(255,90,102,.16);color:#ff8791}.probe-pill.off{background:rgba(142,150,163,.12);color:#9aa2ae}.probe-pill.pending i{animation:none}@keyframes probe-pulse{0%,100%{box-shadow:0 0 0 0 currentColor}50%{box-shadow:0 0 0 4px transparent}}
button,button.ghost{background:var(--button-bg);color:var(--button-text)}button.primary,button.danger{color:#fff}.login input{background:var(--surface);color:var(--text)}.side{background:var(--sidebar);border-color:var(--line-soft)}.nav button{color:var(--nav-text)}.top{border-color:var(--line-soft)}.table th,.table td{border-color:var(--line-soft)}.view-switch button{background:var(--panel)}.rule-card{background:var(--surface)}.rule-card .route{color:var(--text)}.rule-card .metrics{border-color:var(--line-soft)}.pill{background:var(--pill-bg);color:var(--pill-text)}.metric.upload{color:var(--upload)}.metric.download{color:var(--download)}.metric.total{color:var(--total)}.trace-output{background:var(--trace-bg);color:var(--trace-text)}.dialog-copy{color:var(--text)}.field label{color:var(--text)}.field input,.field select,.field textarea{background:var(--surface2);color:var(--text)}.firewall-check{color:var(--text)!important}.tags,.preview{background:var(--surface2);color:var(--text)}.toast{display:flex;align-items:center;gap:10px;border:1px solid var(--line);background:var(--panel2);color:var(--text);box-shadow:0 14px 36px rgba(0,0,0,.22);animation:toast-in .2s ease-out}.toast-icon{display:grid;place-items:center;flex:none;width:24px;height:24px;border-radius:50%;background:rgba(8,119,255,.14);color:#3996ff;font-weight:800}.toast.success .toast-icon{background:rgba(29,219,120,.14);color:var(--green)}.toast.error .toast-icon{background:rgba(255,90,102,.14);color:var(--danger)}.toast.success{border-color:rgba(29,160,98,.42)}.toast.error{border-color:rgba(226,63,77,.48)}@keyframes toast-in{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:none}}.theme-switch{display:inline-grid;grid-template-columns:repeat(3,1fr);gap:3px;padding:3px;border:1px solid var(--line);border-radius:8px;background:var(--surface)}.theme-switch button{min-width:92px;background:transparent;color:var(--muted)}.theme-switch button.active{background:var(--blue);color:#fff}
.chart-svg{height:auto}
.sort-head{display:inline-flex;align-items:center;gap:5px;padding:2px 0;border-radius:0;background:transparent!important;color:inherit!important;font-weight:inherit}.sort-head:hover,.sort-head.active{color:var(--nav-active-text)!important}.sort-arrow{display:inline-block;min-width:10px;color:var(--muted);font-size:11px}.sort-head.active .sort-arrow{color:currentColor}.sort-strip{display:none;align-items:center;gap:7px;margin:0 0 12px;padding:8px;border:1px solid var(--line-soft);border-radius:7px;background:var(--surface)}.sort-strip.grid-sort{display:flex}.sort-strip-label{margin:0 3px;color:var(--muted);font-size:12px}.sort-strip button{padding:6px 9px;background:transparent;color:var(--muted);border:1px solid transparent}.sort-strip button.active{background:var(--nav-active-bg);color:var(--nav-active-text);border-color:var(--line)}
@media(max-width:1100px) and (min-width:761px){.cards{grid-template-columns:repeat(2,minmax(160px,1fr))}}
@media(max-width:760px){
body{font-size:14px;overflow-x:hidden}.app{display:block;min-height:100dvh}.side{position:fixed;z-index:8;inset:auto 0 0 0;width:auto;height:calc(66px + env(safe-area-inset-bottom));padding:0 8px env(safe-area-inset-bottom);border:0;border-top:1px solid var(--line-soft);background:var(--tab-glass);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px)}.brand,.ver,.foot{display:none}.nav{height:66px;display:grid;grid-template-columns:repeat(5,minmax(0,1fr));align-items:stretch}.nav button{min-width:0;width:auto;height:66px;margin:0;padding:7px 2px 6px;border-radius:0;display:flex;flex-direction:column;justify-content:center;align-items:center;gap:3px;text-align:center;color:var(--muted);font-size:11px;line-height:1.15;background:transparent}.nav button:hover{background:transparent}.nav button.active{background:transparent;color:#187ee8;box-shadow:none}.nav-icon{display:block;font-size:21px;line-height:22px;font-weight:500}.main{margin:0;min-width:0}.top{position:sticky;z-index:4;top:0;height:50px;padding:0 14px;justify-content:space-between;background:var(--glass);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px)}.mobile-brand{display:block;max-width:70%}.user{font-size:12px;color:var(--muted)}.content{padding:12px 12px calc(84px + env(safe-area-inset-bottom))}.page-with-fabs{min-height:calc(100dvh - 146px);padding-bottom:250px}.page-with-fabs>.panel{margin-top:0;padding:0;border:0;background:transparent}.cards{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.card{min-height:116px;padding:13px}.card h3{margin-bottom:10px;font-size:12px}.big{font-size:19px;overflow-wrap:anywhere}.bar{margin-top:11px}.panel{margin-top:12px;padding:12px;border-radius:8px}.panel h2{font-size:18px;margin-bottom:12px}.toolbar{align-items:stretch;flex-wrap:wrap;gap:8px;margin-bottom:12px}.toolbar h2{width:100%;margin:0!important}.toolbar button{min-height:42px;flex:1;padding:9px 8px}.grid{grid-template-columns:1fr;gap:0}.field>.actions{display:grid;grid-template-columns:1fr auto;align-items:stretch}.field>.actions button{min-height:44px}.rule-grid{grid-template-columns:1fr;gap:12px}.rule-card{padding:15px;border-color:var(--item-border);background:var(--item-bg);box-shadow:0 8px 22px rgba(0,0,0,.2)}.rule-card .actions{display:grid;grid-template-columns:1fr 1fr;gap:10px}.rule-card .actions button{min-height:40px}.chart-svg{height:230px}.chart-label{font-size:20px}.chart-axis-title{font-size:21px}.rule-table-wrap{border:0;overflow:visible}.table,.table tbody,.table tr,.table td{display:block;width:100%}.table thead{display:none}.table tbody{display:grid;gap:12px}.table tr{padding:14px;border:1px solid var(--item-border);border-radius:8px;background:var(--item-bg);box-shadow:0 8px 22px rgba(0,0,0,.2)}.table td{min-height:35px;padding:7px 0;border:0;display:grid;grid-template-columns:minmax(88px,36%) minmax(0,1fr);gap:12px;align-items:center;text-align:right;font-weight:600;overflow-wrap:anywhere}.table td:before{content:attr(data-label);color:var(--muted);font-size:12px;font-weight:500;text-align:left}.table td.actions{display:flex;justify-content:flex-end;flex-wrap:wrap;padding-top:12px;border-top:1px solid var(--line-soft);margin-top:6px}.table td.actions:before{margin-right:auto}.table td.actions button{min-height:40px}.table td[colspan]{display:block;text-align:center;color:var(--muted)}.table td[colspan]:before{display:none}.probe-pill{margin-left:auto}.fab-stack{right:14px;bottom:calc(80px + env(safe-area-inset-bottom));gap:9px}.fab{min-width:104px;height:44px;border-radius:22px;padding:0 13px}.dialog{width:calc(100vw - 24px);max-width:none;max-height:calc(100dvh - 28px);padding:16px;border-radius:9px;overscroll-behavior:contain}.dialog.trace-dialog,.dialog.rules-dialog{width:calc(100vw - 16px)}.dialog h2{font-size:20px;margin-top:0}.dialog-actions{position:sticky;bottom:-16px;margin:16px -16px -16px;padding:12px 16px calc(12px + env(safe-area-inset-bottom));display:flex;justify-content:flex-end;gap:9px;background:var(--panel2);border-top:1px solid var(--line)}.dialog-actions button{min-width:92px;min-height:42px}.trace-output{max-height:58dvh;padding:10px;font-size:11px}.field input,.field select,.field textarea{font-size:16px;min-height:44px}.field textarea{min-height:88px}.firewall-check{min-height:46px}.toast{left:12px;right:12px;top:auto;bottom:calc(78px + env(safe-area-inset-bottom));max-width:none}.theme-switch{display:grid;width:100%}.theme-switch button{min-width:0}.login{min-height:100dvh;height:auto;padding:18px}.login form{width:100%;max-width:360px;padding:22px}.login input{font-size:16px}.pill{max-width:100%;overflow-wrap:anywhere}.content>.panel:first-child{margin-top:0}
.chart-pair{grid-template-columns:1fr;gap:0}.chart-panel-head{display:block}.bandwidth-live{justify-content:flex-start;margin:-4px 0 8px}.bandwidth-interface{text-align:left}.chart-legend{justify-content:flex-start}
.sort-strip,.sort-strip.grid-sort{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px}.sort-strip-label{grid-column:1/-1}.sort-strip button{min-height:36px}
.chart-svg{height:auto}.chart-label{font-size:11px}.chart-axis-title{font-size:12px}
}
</style></head><body><div id="root"></div><script>
const appRoot=document.getElementById('root');
const authToken=()=>localStorage.getItem('nft_manager_token')||'';
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
window.addEventListener('error',e=>{if(appRoot&&!appRoot.innerHTML)appRoot.innerHTML=`<div class=login><form><h2>nft-manager</h2><p class=muted>前端加载失败</p><p>${e.message}</p><button type=button onclick="location.reload()" class=primary style="width:100%">刷新</button></form></div>`});
function savedSort(storageKey,allowed){try{let value=JSON.parse(localStorage.getItem(storageKey)||'{}');if(allowed.includes(value.key)&&['asc','desc'].includes(value.direction))return value}catch(e){}return {key:'',direction:''}}
let savedView=localStorage.getItem('nft_manager_view')||'dash';if(!['dash','rules','targets','firewall','settings'].includes(savedView))savedView='dash';let savedTheme=localStorage.getItem('nft_manager_theme')||'system';if(!['light','dark','system'].includes(savedTheme))savedTheme='system';let savedRuleSort=savedSort('nft_manager_rule_sort',['upload','download','total','connectivity']),savedTargetSort=savedSort('nft_manager_target_sort',['upload','download','total','latency']);document.documentElement.dataset.theme=savedTheme;let state={view:savedView,data:null,edit:null,ruleView:localStorage.getItem('nft_manager_rule_view')||'flat',theme:savedTheme,targetLatency:{},ruleConnectivity:{},ruleSort:savedRuleSort,targetSort:savedTargetSort,autoProbeView:'',publicTitle:'nft-manager',dashboardPollBusy:false,dashboardPollSeconds:0,dashboardPollTimer:null,bandwidthLiveBusy:false,bandwidthLiveTimer:null};
const api=(p,o={})=>{let {timeout=12000,...request}=o,headers={'Content-Type':'application/json',...(request.headers||{})};let token=authToken();if(token)headers.Authorization='Bearer '+token;let ctl=new AbortController();let timer=setTimeout(()=>ctl.abort(),timeout);return fetch(p,{credentials:'same-origin',...request,headers,signal:ctl.signal}).then(async r=>{let j=await r.json().catch(()=>({}));if(!r.ok){let e=new Error(j.error||'请求失败');e.status=r.status;throw e}return j}).catch(e=>{if(e.name==='AbortError')throw new Error('请求超时，请检查 Web 服务或 nftables 状态');throw e}).finally(()=>clearTimeout(timer))};
const fmt=b=>b>1073741824?(b/1073741824).toFixed(2)+' GB':b>1048576?(b/1048576).toFixed(2)+' MB':b>1024?(b/1024).toFixed(1)+' KB':b+' B';
const msg=e=>e?.message||String(e||'操作失败');
function toast(text,type='info'){document.querySelectorAll('.toast').forEach(x=>x.remove());let icon=type==='success'?'✓':type==='error'?'!':'i';document.body.insertAdjacentHTML('beforeend',`<div class="toast ${type}" role=status><span class=toast-icon>${icon}</span><span>${esc(text)}</span></div>`);setTimeout(()=>document.querySelector('.toast')?.remove(),4000)}
function setModalError(text){let box=document.querySelector('.modal .error-box');if(box){box.textContent=text;box.classList.add('show')}else toast(text,'error')}
function clearModalError(){let box=document.querySelector('.modal .error-box');if(box){box.textContent='';box.classList.remove('show')}}
function expireSession(){localStorage.removeItem('nft_manager_token');state.data=null;if(state.dashboardPollTimer)clearInterval(state.dashboardPollTimer);if(state.bandwidthLiveTimer)clearInterval(state.bandwidthLiveTimer);state.dashboardPollTimer=null;state.bandwidthLiveTimer=null;login()}
async function runAction(btn,fn){let old=btn?.textContent;if(btn){btn.disabled=true;btn.textContent='处理中...'}try{await fn()}catch(e){if(e.status===401)expireSession();else setModalError(msg(e))}finally{if(btn){btn.disabled=false;btn.textContent=old}}}
function loading(){appRoot.innerHTML=`<div class=login><form><h2>${esc(state.publicTitle)}</h2><p class=muted>正在加载...</p></form></div>`}
function login(){appRoot.innerHTML=`<div class=login><form onsubmit="doLogin(event)"><h2>${esc(state.publicTitle)}</h2><p class=muted>默认账号 admin / admin</p><input name=u value=admin placeholder=账号><input name=p type=password value=admin placeholder=密码><button class=primary style="width:100%">登录</button></form></div>`}
async function doLogin(e){e.preventDefault();let btn=e.submitter;let old=btn.textContent;btn.disabled=true;btn.textContent='登录中...';try{let res=await api('/api/login',{method:'POST',body:JSON.stringify({username:e.target.u.value,password:e.target.p.value})});if(res.token)localStorage.setItem('nft_manager_token',res.token);loading();load()}catch(err){toast(msg(err),'error')}finally{btn.disabled=false;btn.textContent=old}}
async function load(){try{state.data=await api('/api/state');document.title=state.data.settings?.panelTitle||'nft-manager';syncDashboardPoll();render();syncBandwidthLive();autoProbeCurrentView()}catch(e){if(e.status===401)expireSession();else appRoot.innerHTML=`<div class=login><form><h2>nft-manager</h2><p class=muted>加载失败</p><p>${msg(e)}</p><button type=button onclick="location.reload()" class=primary style="width:100%">刷新</button></form></div>`}}
function nav(v){if(state.view!==v)state.autoProbeView='';state.view=v;localStorage.setItem('nft_manager_view',v);render();syncBandwidthLive();autoProbeCurrentView();if(v==='dash')pollDashboard()}
function shell(content){let n=[['dash','仪表板','⌂'],['rules','转发管理','⇄'],['targets','主机管理','▣'],['firewall','防火墙','◫'],['settings','设置','⚙']].map(x=>`<button class="${state.view==x[0]?'active':''}" onclick="nav('${x[0]}')"><span class=nav-icon aria-hidden=true>${x[2]}</span><span>${x[1]}</span></button>`).join(''),title=esc(state.data.settings?.panelTitle||'nft-manager');appRoot.innerHTML=`<div class=app><aside class=side><div class=brand>${title}</div><div class=ver>v__WEB_PANEL_VERSION__</div><div class=nav>${n}</div><div class=foot>Powered by nft-manager</div></aside><main class=main><div class=top><span class=mobile-brand>${title}</span><span class=user>admin ▾</span></div><div class=content>${content}</div></main></div>`}
function hourText(stamp){return String(new Date(stamp*1000).getHours()).padStart(2,'0')+':00'}
function chartDateTime(stamp,hourOnly=false){let d=new Date(Number(stamp)*1000),pad=n=>String(n).padStart(2,'0');return `${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${hourOnly?'00':pad(d.getMinutes())}${hourOnly?'':':'+pad(d.getSeconds())}`}
function chartWrap(svg){return `<div class=chart-wrap>${svg}<div class=chart-tooltip role=status></div></div>`}
function trafficChart(){let mobile=window.matchMedia('(max-width:760px)').matches,w=mobile?390:700,ht=mobile?250:320,left=72,right=mobile?10:18,top=24,bottom=mobile?42:44,pw=w-left-right,ph=ht-top-bottom,max=Math.max(1,...(state.data.history||[]).map(x=>x.bytes)),h=state.data.history||[],den=Math.max(1,h.length-1),x=i=>left+i*pw/den,y=b=>top+(1-b/max)*ph,pts=h.map((item,i)=>`${x(i)},${y(item.bytes)}`),area=pts.length?`${left},${top+ph} ${pts.join(' ')} ${x(h.length-1)},${top+ph}`:'',yGrid=[0,1,2,3,4].map(i=>{let yy=top+i*ph/4,value=max*(4-i)/4;return `<line class=chart-grid x1="${left}" y1="${yy}" x2="${w-right}" y2="${yy}"/><text class=chart-label text-anchor=end x="${left-7}" y="${yy+4}">${fmt(value)}</text>`}).join(''),xGrid=h.map((item,i)=>i%3===0?`<line class=chart-grid x1="${x(i)}" y1="${top}" x2="${x(i)}" y2="${top+ph}"/><text class=chart-label text-anchor=middle x="${x(i)}" y="${top+ph+15}">${hourText(item.hour)}</text>`:'').join(''),svg=`<svg class=chart-svg viewBox="0 0 ${w} ${ht}" data-left="${left}" data-width="${pw}" data-top="${top}" data-height="${ph}" data-max="${max}" onpointermove="chartHover(event,'traffic')" onpointerleave="hideChartTooltip(event)" role="img" aria-label="最近24小时流量折线图"><g>${yGrid}${xGrid}</g><line class=chart-axis x1="${left}" y1="${top}" x2="${left}" y2="${top+ph}"/><line class=chart-axis x1="${left}" y1="${top+ph}" x2="${w-right}" y2="${top+ph}"/>${area?`<polygon class=chart-fill points="${area}"/><polyline class=chart-line points="${pts.join(' ')}"/>`:''}<line class=chart-hover-guide y1="${top}" y2="${top+ph}"/><circle class="chart-hover-dot traffic" r=5/><text class=chart-axis-title x="${left}" y="13">流量</text><text class=chart-axis-title text-anchor=middle x="${left+pw/2}" y="${ht-3}">时间（小时）</text></svg>`;return chartWrap(svg)}
function fmtBandwidth(value){let n=Number(value||0);return n>=1000?(n/1000).toFixed(n>=10000?1:2)+' Gbps':n.toFixed(n>=100?0:n>=10?1:2)+' Mbps'}
function bandwidthTime(stamp){let d=new Date(stamp*1000);return String(d.getHours()).padStart(2,'0')+':'+String(d.getMinutes()).padStart(2,'0')}
function bandwidthHour(stamp){return String(new Date(stamp*1000).getHours()).padStart(2,'0')}
function niceBandwidthMax(value){if(!Number.isFinite(value)||value<=0)return 1;let power=10**Math.floor(Math.log10(value)),scaled=value/power,factor=scaled<=1?1:scaled<=2?2:scaled<=5?5:10;return factor*power}
function bandwidthChart(){
 let b=state.data.bandwidth||{},end=Math.max(1,Number(b.sampledAt||Math.floor(Date.now()/1000))),start=end-24*60*60,h=[...(b.history||[])].filter(item=>Number(item.timestamp)>=start&&Number(item.timestamp)<=end).sort((a,c)=>Number(a.timestamp)-Number(c.timestamp)),mobile=window.matchMedia('(max-width:760px)').matches,w=mobile?390:700,ht=mobile?250:320,left=72,right=mobile?10:18,top=24,bottom=mobile?42:44,pw=w-left-right,ph=ht-top-bottom,max=niceBandwidthMax(Math.max(0,...h.flatMap(item=>[Number(item.downloadMbps||0),Number(item.uploadMbps||0)]))),x=stamp=>left+Math.max(0,Math.min(1,(Number(stamp)-start)/(end-start)))*pw,y=value=>top+(1-Number(value||0)/max)*ph;
 let seriesFor=key=>{let segments=[],current=[];h.forEach((item,index)=>{if(index&&Number(item.timestamp)-Number(h[index-1].timestamp)>120&&current.length){segments.push(current);current=[]}current.push([x(item.timestamp),y(item[key])])});if(current.length)segments.push(current);return segments},seriesMarkup=(segments,className,color)=>segments.map(points=>points.length>1?`<polyline class="chart-line ${className}" points="${points.map(point=>point.join(',')).join(' ')}"/>`:`<circle cx="${points[0][0]}" cy="${points[0][1]}" r="2.5" fill="var(${color})"/>`).join(''),download=seriesMarkup(seriesFor('downloadMbps'),'bandwidth-download','--bandwidth-download'),upload=seriesMarkup(seriesFor('uploadMbps'),'bandwidth-upload','--bandwidth-upload');
 let yGrid=[0,1,2,3,4].map(i=>{let yy=top+i*ph/4,value=max*(4-i)/4;return `<line class=chart-grid x1="${left}" y1="${yy}" x2="${w-right}" y2="${yy}"/><text class=chart-label text-anchor=end x="${left-7}" y="${yy+4}">${fmtBandwidth(value)}</text>`}).join(''),ticks=[],firstHour=Math.ceil(start/3600)*3600;for(let stamp=firstHour;stamp<=end;stamp+=3600)ticks.push(stamp);let labelEvery=mobile?4:1,xGrid=ticks.map((stamp,index)=>`<line class=chart-grid x1="${x(stamp)}" y1="${top}" x2="${x(stamp)}" y2="${top+ph}"/>${index%labelEvery===0?`<text class=chart-label text-anchor=middle x="${x(stamp)}" y="${top+ph+15}">${bandwidthHour(stamp)}</text>`:''}`).join(''),svg=`<svg class=chart-svg viewBox="0 0 ${w} ${ht}" data-left="${left}" data-width="${pw}" data-top="${top}" data-height="${ph}" data-max="${max}" data-start="${start}" data-end="${end}" onpointermove="chartHover(event,'bandwidth')" onpointerleave="hideChartTooltip(event)" role="img" aria-label="过去24小时上传下载带宽折线图，每格一小时"><g>${yGrid}${xGrid}</g><line class=chart-axis x1="${left}" y1="${top}" x2="${left}" y2="${top+ph}"/><line class=chart-axis x1="${left}" y1="${top+ph}" x2="${w-right}" y2="${top+ph}"/>${download}${upload}<line class=chart-hover-guide y1="${top}" y2="${top+ph}"/><circle class="chart-hover-dot download" r=5/><circle class="chart-hover-dot upload" r=5/><text class=chart-axis-title x="${left}" y="13">带宽</text><text class=chart-axis-title text-anchor=middle x="${left+pw/2}" y="${ht-3}">时间（过去24小时，每格1小时）</text></svg>`;return chartWrap(svg)
}
function hideChartTooltip(event){let svg=event.currentTarget,wrap=svg.closest('.chart-wrap');svg.querySelectorAll('.chart-hover-guide,.chart-hover-dot').forEach(node=>node.style.display='none');wrap?.querySelector('.chart-tooltip')?.classList.remove('show')}
function chartHover(event,type){
 let svg=event.currentTarget,wrap=svg.closest('.chart-wrap'),tip=wrap?.querySelector('.chart-tooltip'),history=type==='traffic'?(state.data?.history||[]):[...(state.data?.bandwidth?.history||[])].sort((a,b)=>Number(a.timestamp)-Number(b.timestamp));if(!tip||!history.length)return;
 let rect=svg.getBoundingClientRect(),box=wrap.getBoundingClientRect(),view=svg.viewBox.baseVal,left=Number(svg.dataset.left),width=Number(svg.dataset.width),top=Number(svg.dataset.top),height=Number(svg.dataset.height),max=Math.max(Number(svg.dataset.max),1),pointerX=(event.clientX-rect.left)*view.width/rect.width;if(pointerX<left-8||pointerX>left+width+8){hideChartTooltip(event);return}
 let index,item,vx;if(type==='bandwidth'){let start=Number(svg.dataset.start),end=Number(svg.dataset.end),pointerStamp=start+Math.max(0,Math.min(1,(pointerX-left)/width))*(end-start),low=0,high=history.length-1;while(low<high){let mid=Math.floor((low+high)/2);if(Number(history[mid].timestamp)<pointerStamp)low=mid+1;else high=mid}index=low;if(index>0&&Math.abs(Number(history[index-1].timestamp)-pointerStamp)<=Math.abs(Number(history[index].timestamp)-pointerStamp))index--;item=history[index];if(Math.abs(Number(item.timestamp)-pointerStamp)>300){hideChartTooltip(event);return}vx=left+Math.max(0,Math.min(1,(Number(item.timestamp)-start)/(end-start)))*width}else{index=history.length===1?0:Math.round((pointerX-left)/width*(history.length-1));index=Math.max(0,Math.min(history.length-1,index));item=history[index];vx=history.length===1?left:left+index*width/(history.length-1)}
 let toY=value=>top+(1-Number(value||0)/max)*height,guide=svg.querySelector('.chart-hover-guide');guide.setAttribute('x1',vx);guide.setAttribute('x2',vx);guide.style.display='block';if(type==='traffic'){let dot=svg.querySelector('.chart-hover-dot.traffic');dot.setAttribute('cx',vx);dot.setAttribute('cy',toY(item.bytes));dot.style.display='block';tip.innerHTML=`<div class=chart-tooltip-time>${chartDateTime(item.hour,true)}</div><div class="chart-tooltip-row traffic"><span>流量</span><b>${fmt(item.bytes)}</b></div>`}else{let down=svg.querySelector('.chart-hover-dot.download'),up=svg.querySelector('.chart-hover-dot.upload');down.setAttribute('cx',vx);down.setAttribute('cy',toY(item.downloadMbps));up.setAttribute('cx',vx);up.setAttribute('cy',toY(item.uploadMbps));down.style.display=up.style.display='block';tip.innerHTML=`<div class=chart-tooltip-time>${chartDateTime(item.timestamp)}</div><div class="chart-tooltip-row download"><span>下载</span><b>${fmtBandwidth(item.downloadMbps)}</b></div><div class="chart-tooltip-row upload"><span>上传</span><b>${fmtBandwidth(item.uploadMbps)}</b></div>`}tip.classList.add('show');let pointX=vx/view.width*rect.width+(rect.left-box.left),pointY=event.clientY-box.top,tipWidth=tip.offsetWidth,tipHeight=tip.offsetHeight,x=pointX+12;if(x+tipWidth>wrap.clientWidth-4)x=pointX-tipWidth-12;let y=pointY+12;if(y+tipHeight>wrap.clientHeight-4)y=pointY-tipHeight-12;tip.style.left=`${Math.max(4,x)}px`;tip.style.top=`${Math.max(4,y)}px`
}
function fabStack(buttons){return `<div class=fab-stack aria-label="页面操作">${buttons.join('')}</div>`}
function fabButton(icon,label,action,primary=false,title=''){return `<button class="fab ${primary?'primary':''}" onclick="${action}" title="${title||label}" aria-label="${title||label}"><span class=fab-icon aria-hidden=true>${icon}</span><span class=fab-label>${label}</span></button>`}
function render(){let d=state.data;if(state.view==='dash'){let b=d.bandwidth||{};return shell(`<div class=cards><div class=card><h3>总流量</h3><div class=big>无限制</div><div class=bar></div></div><div class=card><h3>已用流量</h3><div class=big>${fmt(d.stats.totalBytes)}</div><div class=bar></div></div><div class=card><h3>转发配额</h3><div class=big>无限制</div><div class=bar></div></div><div class=card><h3>已用转发</h3><div class=big>${d.stats.ruleCount}</div><div class=bar></div></div></div><div class=chart-pair><div class=panel><h2>24小时流量统计</h2>${trafficChart()}</div><div class=panel><div class=chart-panel-head><h2>24小时带宽统计</h2><div class=bandwidth-live><span class=download id=bandwidthLiveDownload>下载 ${fmtBandwidth(b.downloadMbps)}</span><span class=upload id=bandwidthLiveUpload>上传 ${fmtBandwidth(b.uploadMbps)}</span><span class=bandwidth-interface id=bandwidthLiveInterface>${b.available?esc(b.interface):'未检测到出口网卡'}</span></div></div><div class=chart-legend><span class=download><i></i>下载</span><span class=upload><i></i>上传</span></div><div id=bandwidthLiveChart>${bandwidthChart()}</div></div></div><div class=panel><h2>转发配置 <span class=muted>${d.stats.ruleCount}</span></h2>${rulesTable(true)}</div>`)}
 if(state.view==='rules'){let next=state.ruleView==='flat'?'grid':'flat',label=state.ruleView==='flat'?'平铺':'方块',icon=state.ruleView==='flat'?'☷':'▦';return shell(`<div class=page-with-fabs>${rulesTable(false)}${fabStack([fabButton(icon,label,`setRuleView('${next}')`,false,`切换为${next==='grid'?'方块':'平铺'}视图`),fabButton('⌁','连通性',`checkRuleConnectivity(this)`,false,'检查全部转发连通性'),fabButton('+','新增转发',`openRule()`,true),fabButton('↺','默认排序',`resetListSort('rule')`,false,'清除转发列表排序')])}</div>`)}
 if(state.view==='targets')return shell(`<div class=page-with-fabs><div class=panel><h2>主机管理</h2>${targetsTable()}</div>${fabStack([fabButton('◷','延迟检测',`checkTargetLatency(this)`),fabButton('+','新增主机',`openTarget()`,true),fabButton('↺','默认排序',`resetListSort('target')`,false,'清除主机列表排序')])}</div>`);
 if(state.view==='firewall')return shell(`<div class=page-with-fabs><div class=panel><h2>防火墙管理</h2><p class=muted>默认拒绝未列出的入站连接，始终保留当前 SSH 端口与 Web 面板 5555/tcp。</p>${firewallTable()}</div>${fabStack([fabButton('↻','同步端口',`syncFirewall(this)`),fabButton('+','开放端口',`openFirewall()`,true)])}</div>`);
 return shell(`<div class=panel><h2>系统设置</h2><div class=field style="max-width:520px"><label>顶部标题</label><div class=actions><input id=panelTitle maxlength=64 value="${esc(d.settings?.panelTitle||'nft-manager')}"><button class=primary onclick="savePanelTitle(this)">保存标题</button></div></div><div class=field style="max-width:520px"><label>首页轮询间隔（秒）</label><div class=actions><input id=dashboardPollSeconds type=number min=2 max=300 step=1 value="${Number(d.settings?.dashboardPollSeconds||10)}"><button class=primary onclick="savePollInterval(this)">保存间隔</button></div><p class=muted>控制流量、规则等完整首页数据刷新，范围 2-300 秒；带宽速率在首页可见时固定每秒刷新。</p></div><div class=field><label>显示模式</label><div class=theme-switch><button class="${state.theme==='light'?'active':''}" onclick="setTheme('light')">日间</button><button class="${state.theme==='dark'?'active':''}" onclick="setTheme('dark')">夜间</button><button class="${state.theme==='system'?'active':''}" onclick="setTheme('system')">跟随系统</button></div></div><p>Web 面板地址：<span class=pill>http://${d.stats.localIp}:${d.stats.port}</span></p><p>默认端口：5555</p><button onclick="openPassword()">修改密码</button> <button class=danger onclick="showInfo('完整卸载','请在 SSH 菜单执行完整卸载')">完整卸载</button></div>`)}
function setRuleView(view){state.ruleView=view;localStorage.setItem('nft_manager_rule_view',view);render()}
function setTheme(theme){if(!['light','dark','system'].includes(theme))return;state.theme=theme;localStorage.setItem('nft_manager_theme',theme);document.documentElement.dataset.theme=theme;render();toast('显示模式已切换','success')}
function ruleName(r){return r.alias||`${r.targetAlias||r.ip}:${r.lport}`}
function ruleSwitch(r){return `<label class=switch title="${r.enabled?'关闭转发':'开启转发'}"><input type=checkbox ${r.enabled?'checked':''} onchange="toggleRule(${r.lport},this.checked)"><span class=slider></span></label>`}
function ruleActions(r){return `<button onclick='openRule(${JSON.stringify(r)})'>编辑</button><button class=danger onclick="delRules([${r.lport}])">删除</button>`}
function listSort(kind){return kind==='rule'?state.ruleSort:state.targetSort}
function sortStorageKey(kind){return kind==='rule'?'nft_manager_rule_sort':'nft_manager_target_sort'}
function setListSort(kind,key){let sort=listSort(kind);if(sort.key===key)sort.direction=sort.direction==='asc'?'desc':'asc';else{sort.key=key;sort.direction='asc'}localStorage.setItem(sortStorageKey(kind),JSON.stringify(sort));render()}
function resetListSort(kind){let sort=listSort(kind);sort.key='';sort.direction='';localStorage.removeItem(sortStorageKey(kind));render();toast('已恢复默认排序','success')}
function sortButton(kind,key,label){let sort=listSort(kind),active=sort.key===key,arrow=active?(sort.direction==='asc'?'↑':'↓'):'↕';return `<button class="sort-head ${active?'active':''}" onclick="setListSort('${kind}','${key}')" title="按${label}${active&&sort.direction==='asc'?'降序':'升序'}排列">${label}<span class=sort-arrow>${arrow}</span></button>`}
function sortStrip(kind,items,grid=false){return `<div class="sort-strip ${grid?'grid-sort':''}" aria-label="列表排序"><span class=sort-strip-label>排序方式</span>${items.map(item=>sortButton(kind,item[0],item[1])).join('')}</div>`}
function probeSortValue(result){return result&&result.reachable&&!result.skipped?Number(result.latency||0):Number.POSITIVE_INFINITY}
function stableNumericSort(items,sort,valueOf){if(!sort.key)return items.slice();let factor=sort.direction==='desc'?-1:1;return items.map((item,index)=>({item,index,value:Number(valueOf(item,sort.key))})).sort((a,b)=>{let av=Number.isFinite(a.value)?a.value:Number.POSITIVE_INFINITY,bv=Number.isFinite(b.value)?b.value:Number.POSITIVE_INFINITY;if(av===bv)return a.index-b.index;return (av<bv?-1:1)*factor}).map(entry=>entry.item)}
function sortRules(rules){return stableNumericSort(rules,state.ruleSort,(r,key)=>key==='upload'?(r.uploadBytes||0):key==='download'?(r.downloadBytes||0):key==='total'?(r.totalBytes||0):probeSortValue(state.ruleConnectivity[r.lport]))}
function probePill(result,label){if(!result)return `<span class="probe-pill pending"><i></i>${label}<b>未检测</b></span>`;if(result.skipped)return `<span class="probe-pill off"><i></i>${label}<b>已关闭</b></span>`;if(!result.reachable)return `<span class="probe-pill bad"><i></i>${label}<b>不可达</b></span>`;let ms=Number(result.latency||0),level=ms<100?'good':ms<1000?'warn':'slow';return `<span class="probe-pill ${level}"><i></i>${label}<b>${ms.toFixed(ms<10?1:0)} ms</b></span>`}
function rulesTable(limit,sourceRules=null){let sortable=!limit&&!sourceRules,rules=(sourceRules||state.data.rules).slice();if(sortable)rules=sortRules(rules);rules=rules.slice(0,limit?8:9999);let controls=sortable?sortStrip('rule',[['upload','上传'],['download','下载'],['total','总计'],['connectivity','连通性']],state.ruleView==='grid'):'';if(sortable&&state.ruleView==='grid'){let cards=rules.map(r=>`<article class="rule-card ${r.enabled?'':'disabled'}"><div class=rule-card-top><h3>${ruleName(r)}</h3>${ruleSwitch(r)}</div><div class=muted>${r.targetAlias||'-'} / ${r.ip}</div><div class=route>${r.lport} → ${r.dport}</div><div class=metrics><span class="metric upload">上传<br>${fmt(r.uploadBytes)}</span><span class="metric download">下载<br>${fmt(r.downloadBytes)}</span><span class="metric total">总计<br>${fmt(r.totalBytes)}</span></div><p class="status ${r.active?'on':''}">状态：${r.enabled?(r.active?'活跃':'空闲'):'已关闭'}</p>${probePill(state.ruleConnectivity[r.lport],'连通性')}<div class=actions>${ruleActions(r)}</div></article>`).join('');return `${controls}<div class=rule-grid>${cards||'<span class=muted>暂无转发</span>'}</div>`}let rows=rules.map(r=>`<tr><td data-label="目标主机">${r.targetAlias||'-'}<br><span class=muted>${r.ip}</span></td><td data-label="别名">${ruleName(r)}</td><td data-label="入口">${r.lport}</td><td data-label="出口">${r.dport}</td><td data-label="上传" class="metric upload">${fmt(r.uploadBytes)}</td><td data-label="下载" class="metric download">${fmt(r.downloadBytes)}</td><td data-label="总计" class="metric total">${fmt(r.totalBytes)}</td><td data-label="统计口径">${r.statsMode==='upload'?'上传':r.statsMode==='download'?'下载':'总计'}</td><td data-label="连通性">${probePill(state.ruleConnectivity[r.lport],'连通性')}</td><td data-label="状态" class="status ${r.active?'on':''}">${r.enabled?(r.active?'活跃':'空闲'):'关闭'}</td><td data-label="操作" class=actions>${ruleSwitch(r)}${ruleActions(r)}</td></tr>`).join(''),upload=sortable?sortButton('rule','upload','上传'):'上传',download=sortable?sortButton('rule','download','下载'):'下载',total=sortable?sortButton('rule','total','总计'):'总计',connectivity=sortable?sortButton('rule','connectivity','连通性'):'连通性';return `${controls}<div class=rule-table-wrap><table class=table><thead><tr><th>目标主机</th><th>别名</th><th>入口</th><th>出口</th><th class="metric upload">${upload}</th><th class="metric download">${download}</th><th class="metric total">${total}</th><th>统计口径</th><th>${connectivity}</th><th>状态</th><th>操作</th></tr></thead><tbody>${rows||'<tr><td colspan=11 class=muted>暂无转发</td></tr>'}</tbody></table></div>`}
async function toggleRule(lport,enabled){try{await api('/api/rules/toggle',{method:'POST',body:JSON.stringify({lport,enabled}),timeout:30000});document.querySelector('.target-rules-layer')?.remove();await load()}catch(e){toast(msg(e),'error');await load()}}
function targetsTable(){let summary={};state.data.rules.forEach(r=>{let s=summary[r.ip]||(summary[r.ip]={count:0,upload:0,download:0,total:0});s.count++;s.upload+=r.uploadBytes||0;s.download+=r.downloadBytes||0;s.total+=r.totalBytes||0});let items=state.data.targets.map(target=>({target,summary:summary[target.ip]||{count:0,upload:0,download:0,total:0}}));items=stableNumericSort(items,state.targetSort,(item,key)=>key==='upload'?item.summary.upload:key==='download'?item.summary.download:key==='total'?item.summary.total:probeSortValue(state.targetLatency[item.target.ip]));let rows=items.map(item=>{let t=item.target,s=item.summary;return `<tr><td data-label="别名">${t.alias}</td><td data-label="IP">${t.ip}</td><td data-label="延迟">${probePill(state.targetLatency[t.ip],'延迟')}</td><td data-label="规则数">${s.count?`<button class=count-button onclick='openTargetRules(${JSON.stringify(t)})'>${s.count}</button>`:'0'}</td><td data-label="上传" class="metric upload">${fmt(s.upload)}</td><td data-label="下载" class="metric download">${fmt(s.download)}</td><td data-label="总计" class="metric total">${fmt(s.total)}</td><td data-label="操作" class=actions><button onclick='traceTarget(${JSON.stringify(t)})'>NextTrace 路由</button><button onclick='openTarget(${JSON.stringify(t)})'>编辑</button><button class=danger onclick='delTarget(${JSON.stringify(t)})'>删除</button></td></tr>`}).join(''),controls=sortStrip('target',[['latency','延迟'],['upload','上传'],['download','下载'],['total','总计']]),latency=sortButton('target','latency','延迟'),upload=sortButton('target','upload','上传'),download=sortButton('target','download','下载'),total=sortButton('target','total','总计');return `${controls}<div class=rule-table-wrap><table class=table><thead><tr><th>别名</th><th>IP</th><th>${latency}</th><th>规则数</th><th class="metric upload">${upload}</th><th class="metric download">${download}</th><th class="metric total">${total}</th><th>操作</th></tr></thead><tbody>${rows||'<tr><td colspan=8 class=muted>暂无主机</td></tr>'}</tbody></table></div>`}
function openTargetRules(t){let rules=state.data.rules.filter(r=>r.ip===t.ip),layer=modal(`<h2>${esc(t.alias)} 的转发规则</h2><p class=dialog-copy>${esc(t.ip)}，共 ${rules.length} 条</p>${rulesTable(false,rules)}<div class=dialog-actions style="margin-top:18px"><button class=primary data-close>关闭</button></div>`);layer.classList.add('target-rules-layer');layer.querySelector('.dialog').classList.add('rules-dialog');layer.querySelector('[data-close]').onclick=()=>layer.remove()}
function firewallTable(){let ports=state.data.firewall?.ports||[],baseline=state.data.firewall?.baselinePorts||[],rows=ports.map(p=>{let locked=baseline.includes(p.port);return `<tr><td data-label="端口">${p.port}</td><td data-label="协议">${p.protocol}</td><td data-label="来源/说明">${p.label||'-'}</td><td data-label="操作" class=actions>${locked?'<span class=muted>保底端口</span>':`<button class=danger onclick="delFirewall(${p.port},'${p.protocol}')">关闭</button>`}</td></tr>`}).join('');return `<div class=rule-table-wrap><table class=table><thead><tr><th>端口</th><th>协议</th><th>来源/说明</th><th>操作</th></tr></thead><tbody>${rows||'<tr><td colspan=4 class=muted>防火墙尚未初始化</td></tr>'}</tbody></table></div>`}
function openFirewall(){modal(`<h2>开放端口</h2><div class=grid><div class=field><label>端口</label><input id=fwPort placeholder="例如：8080"></div><div class=field><label>协议</label><select id=fwProtocol><option value=tcp+udp>TCP + UDP</option><option value=tcp>TCP</option><option value=udp>UDP</option></select></div></div><div class=field><label>说明</label><input id=fwLabel value="手动开放"></div><div class=dialog-actions><button class=ghost onclick="this.closest('.modal').remove()">取消</button><button class=primary onclick="saveFirewall(this)">开放</button></div>`)}
async function saveFirewall(btn){await runAction(btn,async()=>{await api('/api/firewall/add',{method:'POST',body:JSON.stringify({port:document.getElementById('fwPort').value,protocol:document.getElementById('fwProtocol').value,label:document.getElementById('fwLabel').value}),timeout:30000});document.querySelector('.modal').remove();await load()})}
function delFirewall(port,protocol){confirmDialog('关闭端口',`确认关闭 ${port}/${protocol}？`,async()=>{await api('/api/firewall/delete',{method:'POST',body:JSON.stringify({port,protocol}),timeout:30000});await load()})}
async function syncFirewall(btn){await runAction(btn,async()=>{await api('/api/firewall/sync',{method:'POST',body:'{}',timeout:30000});await load();toast('已同步现有转发端口','success')})}
async function checkTargetLatency(btn,quiet=false){await runAction(btn,async()=>{let result=await api('/api/targets/latency',{method:'POST',body:'{}',timeout:60000});state.targetLatency=result.results||{};render();if(!quiet)toast('延迟检测完成','success')})}
async function checkRuleConnectivity(btn,quiet=false){await runAction(btn,async()=>{let result=await api('/api/rules/connectivity',{method:'POST',body:'{}',timeout:60000});state.ruleConnectivity=result.results||{};render();if(!quiet)toast('连通性检查完成','success')})}
function autoProbeCurrentView(){if(!state.data||state.autoProbeView===state.view)return;if(state.view==='dash'){state.autoProbeView='dash';checkRuleConnectivity(null,true)}else if(state.view==='targets'){state.autoProbeView='targets';checkTargetLatency(null,true)}else if(state.view==='rules'){state.autoProbeView='rules';checkRuleConnectivity(null,true)}}
function ansiToHtml(text){let colors={30:'#111827',31:'#ff7b86',32:'#8bd49c',33:'#e6c27a',34:'#82b1ff',35:'#f38ac2',36:'#70d6e5',37:'#f1eadb',90:'#8a9499',91:'#ff8f9a',92:'#a4e5ae',93:'#f4d68f',94:'#9bc1ff',95:'#f5a5cf',96:'#91e2ed',97:'#ffffff'},fg='',bold=false,out='',last=0,re=/\x1b\[([0-9;]*)m/g,esc=s=>s.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),safe=s=>{let p=0,result='',urls=/https?:\/\/[^\s<>"']+/g,m;while((m=urls.exec(s))){result+=esc(s.slice(p,m.index));let url=esc(m[0]);result+=`<a href="${url}" target="_blank" rel="noopener noreferrer">${url}</a>`;p=urls.lastIndex}return result+esc(s.slice(p))},paint=s=>{if(!s)return;let style=[fg&&`color:${fg}`,bold&&'font-weight:700'].filter(Boolean).join(';'),content=safe(s);out+=style?`<span style="${style}">${content}</span>`:content},match;while((match=re.exec(text))){paint(text.slice(last,match.index));let codes=(match[1]||'0').split(';').map(Number);for(let i=0;i<codes.length;i++){let c=codes[i];if(c===0){fg='';bold=false}else if(c===1)bold=true;else if(c===22)bold=false;else if(c===39)fg='';else if(colors[c])fg=colors[c];else if(c===38&&codes[i+1]===2&&codes.length>=i+4){fg=`rgb(${codes[i+2]},${codes[i+3]},${codes[i+4]})`;i+=4}else if(c===38&&codes[i+1]===5&&codes.length>=i+2){let n=codes[i+2],v=n<16?(colors[[30,31,32,33,34,35,36,37,90,91,92,93,94,95,96,97][n]]||'#f1eadb'):n>=232?`rgb(${8+(n-232)*10},${8+(n-232)*10},${8+(n-232)*10})`:`rgb(${Math.floor((n-16)/36)*51},${Math.floor((n-16)%36/6)*51},${(n-16)%6*51})`;fg=v;i+=2}}last=re.lastIndex}paint(text.slice(last));return out}
function traceTarget(t){let layer=modal(`<h2>NextTrace 路由</h2><p class=dialog-copy data-trace-target></p><pre class=trace-output><code>正在从本机执行 nexttrace，请稍候...</code></pre><div class=dialog-actions><button class=primary data-close>关闭</button></div>`),code=layer.querySelector('code');layer.querySelector('.dialog').classList.add('trace-dialog');layer.querySelector('[data-trace-target]').textContent=`目标主机：${t.alias} (${t.ip})`;layer.querySelector('[data-close]').addEventListener('click',()=>layer.remove());api('/api/targets/trace',{method:'POST',body:JSON.stringify({ip:t.ip}),timeout:125000}).then(r=>{code.innerHTML=ansiToHtml((r.output||'NextTrace 未返回输出。').replace(/\r\n?/g,'\n'))}).catch(e=>{if(e.status===401){layer.remove();expireSession();return}code.textContent=`路由执行失败：${msg(e)}`})}
function modal(html){document.body.insertAdjacentHTML('beforeend',`<div class=modal><div class=dialog><div class=error-box></div>${html}</div></div>`);let layer=document.body.lastElementChild;layer.addEventListener('click',e=>{if(e.target===layer)layer.remove()});return layer}
function showInfo(title,text){let layer=modal(`<h2>${title}</h2><p class=dialog-copy>${text}</p><div class=dialog-actions><button class=primary data-confirm>确定</button></div>`);layer.querySelector('[data-confirm]').addEventListener('click',()=>layer.remove())}
function confirmDialog(title,text,action){let layer=modal(`<h2>${title}</h2><p class=dialog-copy>${text}</p><div class=dialog-actions><button class=ghost data-cancel>取消</button> <button class=primary data-confirm>确定</button></div>`),cancel=layer.querySelector('[data-cancel]'),confirmBtn=layer.querySelector('[data-confirm]');cancel.addEventListener('click',()=>layer.remove());confirmBtn.addEventListener('click',async()=>{let old=confirmBtn.textContent;confirmBtn.disabled=true;confirmBtn.textContent='处理中...';try{await action();layer.remove()}catch(e){if(e.status===401){layer.remove();expireSession()}else toast(msg(e),'error')}finally{confirmBtn.disabled=false;confirmBtn.textContent=old}})}
document.addEventListener('keydown',e=>{let layers=document.querySelectorAll('.modal'),layer=layers[layers.length-1];if(!layer)return;if(e.key==='Escape'){e.preventDefault();layer.remove();return}if(e.key==='Enter'&&!e.shiftKey&&e.target.tagName!=='TEXTAREA'){let button=layer.querySelector('[data-confirm],button.primary');if(button&&!button.disabled){e.preventDefault();button.click()}}})
function parsePorts(value){let ports=value.trim().split(/[ ,]+/).filter(Boolean);if(!ports.length)throw new Error('请至少输入一个入口端口');let seen=new Set;for(let port of ports){if(!/^[0-9]+$/.test(port)||Number(port)<1||Number(port)>65535)throw new Error(`端口无效: ${port}；仅支持单个端口，请用空格或英文逗号分隔`);if(seen.has(port))throw new Error(`端口重复: ${port}`);seen.add(port)}return ports}
function openRule(r=null){state.edit=r;let custom=r&&r.lport!==r.dport,stats=r?.statsMode||'total',opts=state.data.targets.map(t=>`<option value="${t.ip}" ${r&&r.ip===t.ip?'selected':''}>${t.alias} / ${t.ip}</option>`).join(''),firewallOption=r?'':`<div class=field><label class=firewall-check><input id=openFirewall type=checkbox checked>同时开放此端口</label></div>`;modal(`<h2>${r?'编辑转发':'新增转发'}</h2><div class=grid><div class=field><label>目标主机</label><select id=ip>${opts}</select></div><div class=field><label>转发别名</label><input id=alias value="${r?.alias||''}"></div></div><div class=field><label>入口端口</label><input id=ports value="${r?.lport||''}" placeholder="例如：80 443,10000"></div><div class=grid><div class=field><label>出口映射</label><select id=mode onchange="document.getElementById('outBox').classList.toggle('hidden',this.value==='same')"><option value=same ${!custom?'selected':''}>与入口端口一致</option><option value=start ${custom?'selected':''}>指定出口起始端口</option></select></div><div class="field ${custom?'':'hidden'}" id=outBox><label>出口起始端口</label><input id=out value="${custom?r.dport:''}" placeholder="多端口将按输入顺序递增"></div></div><div class=field><label>统计口径</label><select id=statsMode><option value=upload ${stats==='upload'?'selected':''}>上传流量</option><option value=download ${stats==='download'?'selected':''}>下载流量</option><option value=total ${stats==='total'?'selected':''}>上传 + 下载总计</option></select></div><div class=field><label>描述</label><textarea id=desc>${r?.desc||''}</textarea></div>${firewallOption}<div class=dialog-actions><button class=ghost onclick="this.closest('.modal').remove()">取消</button><button class=primary onclick="saveRule(this)">保存</button></div>`)}
async function saveRule(btn){await runAction(btn,async()=>{let mode=document.getElementById('mode').value,out=document.getElementById('out').value.trim(),open=document.getElementById('openFirewall'),body={ip:document.getElementById('ip').value,ports:parsePorts(document.getElementById('ports').value),mode,alias:document.getElementById('alias').value,desc:document.getElementById('desc').value,statsMode:document.getElementById('statsMode').value,openFirewall:open?open.checked:true};if(mode==='start')body.outStart=out;if(state.edit){body.oldLport=state.edit.lport;await api('/api/rules/update',{method:'POST',body:JSON.stringify(body),timeout:30000})}else await api('/api/rules/add',{method:'POST',body:JSON.stringify(body),timeout:30000});btn.closest('.modal')?.remove();document.querySelector('.target-rules-layer')?.remove();await load()})}
function delRules(lports){let layer=modal(`<h2>删除转发</h2><p class=dialog-copy>确认删除该端口转发？</p><label class=firewall-check><input id=closeFirewall type=checkbox checked>删除后同时关闭此端口</label><div class=dialog-actions><button class=ghost data-cancel>取消</button> <button class=primary data-confirm>删除</button></div>`);layer.querySelector('[data-cancel]').onclick=()=>layer.remove();layer.querySelector('[data-confirm]').onclick=async e=>{await runAction(e.currentTarget,async()=>{await api('/api/rules/delete',{method:'POST',body:JSON.stringify({lports,closeFirewall:layer.querySelector('#closeFirewall').checked}),timeout:30000});layer.remove();document.querySelector('.target-rules-layer')?.remove();await load()})}}
function openTarget(t=null){modal(`<h2>${t?'编辑主机':'新增主机'}</h2><div class=field><label>别名</label><input id=ta value="${t?.alias||''}"></div><div class=field><label>IP</label><input id=tip value="${t?.ip||''}"></div><div class=dialog-actions><button class=ghost onclick="this.closest('.modal').remove()">取消</button><button class=primary onclick='saveTarget(this,${JSON.stringify(t)})'>保存</button></div>`)}
async function saveTarget(btn,old){await runAction(btn,async()=>{await api('/api/targets/save',{method:'POST',body:JSON.stringify({oldIp:old?.ip,alias:document.getElementById('ta').value,ip:document.getElementById('tip').value})});document.querySelector('.modal').remove();await load()})}
function delTarget(t){confirmDialog('删除主机','确认删除该主机？存在转发规则时将阻止删除。',async()=>{await api('/api/targets/delete',{method:'POST',body:JSON.stringify({ip:t.ip}),timeout:30000});await load()})}
async function savePanelTitle(btn){await runAction(btn,async()=>{await api('/api/settings',{method:'POST',body:JSON.stringify({panelTitle:document.getElementById('panelTitle').value})});await load();toast('顶部标题已保存','success')})}
async function savePollInterval(btn){await runAction(btn,async()=>{let value=Number(document.getElementById('dashboardPollSeconds').value);if(!Number.isInteger(value)||value<2||value>300)throw new Error('首页轮询间隔必须在 2-300 秒之间');await api('/api/settings',{method:'POST',body:JSON.stringify({dashboardPollSeconds:value})});await load();toast(`首页轮询间隔已设为 ${value} 秒`,'success')})}
function openPassword(){modal(`<h2>修改密码</h2><div class=field><label>旧密码</label><input id=oldp type=password></div><div class=field><label>新密码</label><input id=newp type=password></div><div class=dialog-actions><button class=ghost onclick="this.closest('.modal').remove()">取消</button><button class=primary onclick="chgPwd(this)">保存</button></div>`)}
async function chgPwd(btn){await runAction(btn,async()=>{await api('/api/password',{method:'POST',body:JSON.stringify({oldPassword:document.getElementById('oldp').value,newPassword:document.getElementById('newp').value})});document.querySelector('.modal').remove();expireSession();toast('密码已修改，请使用新密码重新登录','success')})}
async function boot(){try{let publicSettings=await api('/api/public-settings');state.publicTitle=publicSettings.panelTitle||'nft-manager';document.title=state.publicTitle}catch(e){}if(authToken()){loading();load()}else login()}
function mergeBandwidthLive(live){let previous=state.data?.bandwidth||{},history=[...(previous.history||[])];if(live.point){history=history.filter(item=>Number(item.bucketTimestamp??item.timestamp)!==Number(live.point.bucketTimestamp));history.push(live.point);history.sort((a,b)=>Number(a.timestamp)-Number(b.timestamp))}state.data.bandwidth={...previous,...live,history}}
async function pollBandwidthLive(){if(!state.data||!authToken()||state.view!=='dash'||document.hidden||state.bandwidthLiveBusy)return;state.bandwidthLiveBusy=true;try{let live=await api('/api/bandwidth/live',{timeout:4000});mergeBandwidthLive(live);let download=document.getElementById('bandwidthLiveDownload'),upload=document.getElementById('bandwidthLiveUpload'),networkInterface=document.getElementById('bandwidthLiveInterface'),chart=document.getElementById('bandwidthLiveChart');if(download)download.textContent=`下载 ${fmtBandwidth(live.downloadMbps)}`;if(upload)upload.textContent=`上传 ${fmtBandwidth(live.uploadMbps)}`;if(networkInterface)networkInterface.textContent=live.available?live.interface:'未检测到出口网卡';if(chart)chart.innerHTML=bandwidthChart()}catch(e){if(e.status===401)expireSession()}finally{state.bandwidthLiveBusy=false}}
function syncBandwidthLive(){let active=!!(state.data&&authToken()&&state.view==='dash'&&!document.hidden);if(!active){if(state.bandwidthLiveTimer)clearInterval(state.bandwidthLiveTimer);state.bandwidthLiveTimer=null;return}if(state.bandwidthLiveTimer)return;pollBandwidthLive();state.bandwidthLiveTimer=setInterval(pollBandwidthLive,1000)}
async function pollDashboard(){if(!state.data||!authToken()||state.view!=='dash'||document.hidden||state.dashboardPollBusy)return;state.dashboardPollBusy=true;try{await load()}finally{state.dashboardPollBusy=false}}
function syncDashboardPoll(){let seconds=Math.min(300,Math.max(2,Number(state.data?.settings?.dashboardPollSeconds||10)));if(state.dashboardPollTimer&&state.dashboardPollSeconds===seconds)return;if(state.dashboardPollTimer)clearInterval(state.dashboardPollTimer);state.dashboardPollSeconds=seconds;state.dashboardPollTimer=setInterval(pollDashboard,seconds*1000)}
boot();
document.addEventListener('visibilitychange',()=>{syncBandwidthLive();if(!document.hidden)pollDashboard()});
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def send_json(self, data, code=200):
        raw = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def body(self):
        n = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(n) or b"{}")

    def authed(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and verify_session(auth.split(" ", 1)[1].strip()):
            return True
        cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        sid = cookie.get("sid")
        return bool(sid and verify_session(sid.value))

    def require(self):
        if not self.authed():
            self.send_json({"error": "未登录"}, 401)
            return False
        return True

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/public-settings":
            self.send_json(read_settings())
            return
        if path == "/api/state":
            if not self.require():
                return
            self.send_json(dashboard())
            return
        if path == "/api/bandwidth/live":
            if not self.require():
                return
            self.send_json(bandwidth_snapshot(persist=False, include_history=False))
            return
        raw = HTML.replace("__WEB_PANEL_VERSION__", WEB_PANEL_VERSION).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        try:
            path = urlparse(self.path).path
            data = self.body()
            if path == "/api/login":
                if verify_password(data.get("username", ""), data.get("password", "")):
                    sid = sign_session(data.get("username", ""), int(time.time()))
                    raw = json.dumps({"ok": True, "token": sid}).encode()
                    self.send_response(200)
                    self.send_header("Set-Cookie", f"sid={sid}; Max-Age={SESSION_MAX_AGE}; HttpOnly; Path=/; SameSite=Lax")
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                else:
                    self.send_json({"error": "账号或密码错误"}, 403)
                return
            if not self.require():
                return
            if path == "/api/password":
                set_password(data.get("oldPassword", ""), data.get("newPassword", ""))
            elif path == "/api/settings":
                save_settings(data)
            elif path == "/api/targets/save":
                targets = read_targets()
                alias, ip, old = clean_label(data.get("alias")), data.get("ip", ""), data.get("oldIp")
                if not alias or not valid_ip(ip):
                    raise ValueError("主机别名或 IP 无效")
                others = [t for t in targets if t["ip"] != old]
                if any(t["ip"] == ip for t in others):
                    raise ValueError("IP 已存在")
                if any(t["alias"] == alias for t in others):
                    raise ValueError("别名已存在")
                write_targets(others + [{"alias": alias, "ip": ip}])
                if old and old != ip:
                    rules = parse_rules()
                    changed = False
                    for r in rules:
                        if r["ip"] == old:
                            r["ip"] = ip
                            changed = True
                    if changed:
                        write_rules(rules)
                        reload_rules()
            elif path == "/api/targets/trace":
                self.send_json({"output": nexttrace_route(data.get("ip", ""))})
                return
            elif path == "/api/targets/latency":
                self.send_json({"results": target_latency_checks()})
                return
            elif path == "/api/targets/delete":
                ip = data.get("ip")
                if any(r["ip"] == ip for r in parse_rules()):
                    raise ValueError("该主机仍有转发规则，请先删除规则")
                write_targets([t for t in read_targets() if t["ip"] != ip])
            elif path == "/api/rules/add":
                add_rules(data)
            elif path == "/api/rules/update":
                update_rule(data)
            elif path == "/api/rules/delete":
                delete_rules(data)
            elif path == "/api/rules/toggle":
                toggle_rule(data)
            elif path == "/api/rules/connectivity":
                self.send_json({"results": rule_connectivity_checks()})
                return
            elif path == "/api/firewall/add":
                add_firewall_port(data.get("port", 0), data.get("protocol", "tcp+udp"), data.get("label", "手动开放"))
            elif path == "/api/firewall/delete":
                remove_firewall_port(data.get("port", 0), data.get("protocol"))
            elif path == "/api/firewall/sync":
                ensure_firewall_configuration(sync_existing=True)
            else:
                self.send_json({"error": "not found"}, 404)
                return
            self.send_json({"ok": True})
        except Exception as e:
            self.send_json({"error": str(e)}, 400)


def traffic_sampler_loop():
    ticks = 0
    while True:
        time.sleep(BANDWIDTH_SAMPLE_INTERVAL)
        try:
            bandwidth_snapshot(persist=True, include_history=False)
        except Exception:
            pass
        ticks += 1
        if ticks % max(1, 30 // BANDWIDTH_SAMPLE_INTERVAL) == 0:
            try:
                nft_counters()
            except Exception:
                pass


if __name__ == "__main__":
    ensure_auth()
    if "--snapshot-traffic" in sys.argv:
        nft_counters()
        raise SystemExit(0)
    migration_ok = migrate_legacy_data()
    if "--firewall-list" in sys.argv:
        print(json.dumps({"ports": read_firewall_ports(), "enabled": os.path.exists(FIREWALL_CONF)}, ensure_ascii=False))
        raise SystemExit(0)
    if "--firewall-add" in sys.argv:
        index = sys.argv.index("--firewall-add")
        port = sys.argv[index + 1] if len(sys.argv) > index + 1 else ""
        protocol = sys.argv[index + 2] if len(sys.argv) > index + 2 else "tcp+udp"
        label = sys.argv[index + 3] if len(sys.argv) > index + 3 else "手动开放"
        add_firewall_port(port, protocol, label)
        raise SystemExit(0)
    if "--firewall-add-forward" in sys.argv:
        index = sys.argv.index("--firewall-add-forward")
        ports = sys.argv[index + 1:]
        if not ports:
            raise ValueError("缺少转发端口")
        add_forward_firewall_ports(ports)
        raise SystemExit(0)
    if "--firewall-delete" in sys.argv:
        index = sys.argv.index("--firewall-delete")
        port = sys.argv[index + 1] if len(sys.argv) > index + 1 else ""
        protocol = sys.argv[index + 2] if len(sys.argv) > index + 2 else None
        remove_firewall_port(port, protocol)
        raise SystemExit(0)
    if "--firewall-remove" in sys.argv:
        index = sys.argv.index("--firewall-remove")
        port = sys.argv[index + 1] if len(sys.argv) > index + 1 else ""
        remove_forward_firewall_ports([port])
        raise SystemExit(0)
    if "--firewall-ssh-status" in sys.argv:
        print(",".join(map(str, detected_ssh_ports())))
        raise SystemExit(0)
    if "--firewall-ssh-port" in sys.argv:
        index = sys.argv.index("--firewall-ssh-port")
        port = sys.argv[index + 1] if len(sys.argv) > index + 1 else ""
        set_firewall_ssh_port(port)
        raise SystemExit(0)
    if "--firewall-ssh-auto" in sys.argv:
        restore_automatic_ssh_port()
        raise SystemExit(0)
    if "--firewall-sync" in sys.argv:
        ensure_firewall_configuration(sync_existing=True)
        raise SystemExit(0)
    if "--firewall-ensure" in sys.argv:
        ensure_firewall_configuration()
        raise SystemExit(0)
    if "--migrate-only" in sys.argv:
        try:
            ensure_firewall_configuration()
        except Exception as e:
            print(f"nft-manager: 防火墙初始化失败：{e}")
            raise SystemExit(1)
        raise SystemExit(0 if migration_ok else 1)
    try:
        ensure_firewall_configuration()
    except Exception as e:
        print(f"nft-manager: 防火墙初始化失败，Web 面板继续启动：{e}")
    try:
        nft_counters()
    except Exception as e:
        print(f"nft-manager: 流量统计初始化失败，Web 面板继续启动：{e}")
    try:
        bandwidth_snapshot(persist=True, include_history=False)
    except Exception as e:
        print(f"nft-manager: 带宽统计初始化失败，Web 面板继续启动：{e}")
    threading.Thread(target=traffic_sampler_loop, daemon=True).start()
    print(f"nft-manager web listening on {HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
