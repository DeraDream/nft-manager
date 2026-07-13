#!/usr/bin/env python3
import base64
import concurrent.futures
import hashlib
import hmac
import http.cookies
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

CONF_DIR = os.environ.get("NFT_MANAGER_CONF_DIR", "/etc/nftables.d")
CONF_FILE = os.path.join(CONF_DIR, "port-forward.conf")
TARGETS_FILE = os.path.join(CONF_DIR, "targets.conf")
AUTH_FILE = os.path.join(CONF_DIR, "web-auth.conf")
STATS_FILE = os.path.join(CONF_DIR, "web-stats.json")
HISTORY_FILE = os.path.join(CONF_DIR, "web-history.json")
TABLE_NAME = "port_forward"
HOST = os.environ.get("NFT_MANAGER_WEB_HOST", "0.0.0.0")
PORT = int(os.environ.get("NFT_MANAGER_WEB_PORT", "5555"))
MAX_BATCH_RULES = int(os.environ.get("NFT_MANAGER_MAX_BATCH", "1000"))
SESSION_MAX_AGE = 86400
WEB_PANEL_VERSION = "3.2"


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


def valid_ip(ip):
    parts = ip.split(".")
    return len(parts) == 4 and all(p.isdigit() and str(int(p)) == p and 0 <= int(p) <= 255 for p in parts)


def valid_port(p):
    return isinstance(p, int) and 1 <= p <= 65535


def clean_label(s):
    return str(s or "").replace("|", " ").replace("\n", " ").replace("\r", " ").strip().lstrip("#").strip()


def ensure_dirs():
    os.makedirs(CONF_DIR, exist_ok=True)


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
        f.write("# WEB_META|3\n\n")
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
            f.write(f"        ip daddr {r['ip']} tcp dport {r['dport']} ct status dnat counter comment \"{upload_marker}\"\n")
            f.write(f"        ip daddr {r['ip']} udp dport {r['dport']} ct status dnat counter comment \"{upload_marker}\"\n")
            f.write(f"        ip saddr {r['ip']} tcp sport {r['dport']} ct status dnat counter comment \"{download_marker}\"\n")
            f.write(f"        ip saddr {r['ip']} udp sport {r['dport']} ct status dnat counter comment \"{download_marker}\"\n")
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

    needs_migration = "WEB_META|3" not in text or 'comment "META_COUNTER_UPLOAD|' not in text
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
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump({"hours": hours}, f)
    return [{"hour": stamp, "bytes": int(hours.get(str(stamp), 0))} for stamp in range(now_hour - 23 * 3600, now_hour + 1, 3600)]


def nft_counters():
    out = run_nft(["list", "table", "ip", TABLE_NAME], timeout=2).stdout
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
                item = counters.setdefault(current, {"upload": {"packets": 0, "bytes": 0}, "download": {"packets": 0, "bytes": 0}})[direction]
                item["packets"] += int(m.group(1))
                item["bytes"] += int(m.group(2))
    previous = {}
    if os.path.exists(STATS_FILE):
        try:
            previous = json.load(open(STATS_FILE, encoding="utf-8"))
        except Exception:
            previous = {}
    now = int(time.time())
    result = {}
    delta_total = 0
    for key, val in counters.items():
        old = previous.get(key, {})
        upload = val["upload"]["bytes"]
        download = val["download"]["bytes"]
        old_upload = int(old.get("upload", {}).get("bytes", upload))
        old_download = int(old.get("download", {}).get("bytes", download))
        delta_upload = upload - old_upload if upload >= old_upload else 0
        delta_download = download - old_download if download >= old_download else 0
        delta_total += delta_upload + delta_download
        result[key] = {**val, "active": (delta_upload + delta_download) > 0, "sampled_at": now}
    with open(STATS_FILE, "w", encoding="utf-8") as f:
        json.dump(counters, f)
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
    write_rules(existing + new_rules)
    reload_rules()
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
    write_rules(rest + new_rules)
    reload_rules()


def delete_rules(payload):
    ports = {int(p) for p in payload.get("lports", [])}
    write_rules([r for r in parse_rules() if r["lport"] not in ports])
    reload_rules()


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
    return {"targets": targets, "rules": enriched, "history": history, "stats": {"totalBytes": total_bytes, "ruleCount": len(rules), "targetCount": len(targets), "activeCount": active, "localIp": local_ip(), "port": PORT}}


HTML = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>nft-manager</title>
<style>
:root{color-scheme:dark;--bg:#050607;--panel:#17181c;--panel2:#1f2026;--line:#343640;--text:#f5f7fb;--muted:#8e96a3;--blue:#0877ff;--green:#1ddb78;--orange:#ff9f1a;--purple:#8e4cff;--danger:#ff5a66}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 -apple-system,BlinkMacSystemFont,Segoe UI,Arial,"Microsoft YaHei",sans-serif}
button,input,select,textarea{font:inherit}button{cursor:pointer;border:0;border-radius:6px;background:#243b63;color:#fff;padding:9px 14px}button:disabled{cursor:not-allowed;opacity:.65}button.primary{background:var(--blue)}button.danger{background:var(--danger)}button.ghost{background:#2b2d35}.login{height:100vh;display:grid;place-items:center}.login form{width:360px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:28px}.login input{width:100%;margin:8px 0 14px;padding:12px;border-radius:6px;border:1px solid var(--line);background:#111318;color:#fff}
.app{display:flex;min-height:100vh}.side{width:238px;background:#020303;border-right:1px solid #2a2d35;padding:28px 16px;position:fixed;inset:0 auto 0 0}.brand{font-weight:800;font-size:18px;margin-bottom:2px}.ver{font-size:12px;color:var(--muted);margin-bottom:34px}.nav button{width:100%;text-align:left;margin:5px 0;background:transparent;color:#d9dde7}.nav button.active{background:#112846;color:#0b84ff}.foot{position:absolute;bottom:18px;color:#737b89;font-size:12px;left:70px}
.main{margin-left:238px;flex:1}.top{height:54px;border-bottom:1px solid #2a2d35;display:flex;align-items:center;justify-content:flex-end;padding:0 26px}.user{font-weight:700}
.content{padding:18px 24px 40px}.cards{display:grid;grid-template-columns:repeat(4,minmax(160px,1fr));gap:14px}.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px}.card h3{font-size:14px;margin:0 0 14px}.big{font-size:25px;font-weight:800}.bar{height:5px;background:linear-gradient(90deg,var(--blue),#b54cff);border-radius:10px;margin-top:14px}.panel{margin-top:20px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}.panel h2{margin:0 0 14px;font-size:22px}.toolbar{display:flex;gap:10px;align-items:center;margin-bottom:14px}.rules-toolbar{justify-content:flex-end}.rule-table-wrap{border:1px solid var(--line);border-radius:8px;overflow:auto}.table{width:100%;border-collapse:collapse}.table th,.table td{border-bottom:1px solid #2a2d35;padding:10px;text-align:left}.table tr:last-child td{border-bottom:0}.muted{color:var(--muted)}.pill{display:inline-flex;gap:6px;background:#11351f;color:#68f0a4;border-radius:5px;padding:4px 8px;font-weight:700}.status{color:var(--muted)}.status.on{color:var(--green);font-weight:700}.metric.upload{color:#46a6ff}.metric.download{color:#20d98a}.metric.total{color:#b779ff}.actions{display:flex;align-items:center;gap:8px}.actions .switch{margin-right:12px}.actions button{padding:6px 10px;margin:0}.hidden{display:none!important}.view-switch{display:flex;border:1px solid var(--line);border-radius:6px;overflow:hidden}.view-switch button{border-radius:0;background:#17181c;padding:7px 11px}.view-switch button.active{background:#1d4d8a}.switch{position:relative;display:inline-flex;width:38px;height:22px;vertical-align:middle;flex:none}.switch input{opacity:0;width:0;height:0}.slider{position:absolute;inset:0;background:#4a252a;border-radius:22px}.slider:before{content:'';position:absolute;width:16px;height:16px;left:3px;top:3px;border-radius:50%;background:#fff;transition:.2s}.switch input:checked+.slider{background:#16855b}.switch input:checked+.slider:before{transform:translateX(16px)}.rule-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px}.rule-card{border:1px solid var(--line);background:#111318;padding:14px;border-radius:8px}.rule-card.disabled{opacity:.6}.rule-card-top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.rule-card h3{font-size:15px;margin:0 0 8px}.rule-card .route{color:#cdd4e0;margin:7px 0}.rule-card .metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;border-top:1px solid #2a2d35;padding-top:10px;margin-top:10px}.rule-card .metrics span{font-size:12px}.rule-card .actions{margin-top:14px}.chart-svg{display:block;width:100%;height:280px}.chart-grid{stroke:#3c414d;stroke-dasharray:3 4}.chart-line{fill:none;stroke:#8e4cff;stroke-width:3}.chart-fill{fill:rgba(142,76,255,.14)}.chart-label{fill:#89919f;font-size:11px}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.58);display:grid;place-items:center;z-index:5}.dialog{width:min(720px,92vw);max-height:88vh;overflow:auto;background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:20px}.dialog.trace-dialog{width:min(980px,95vw)}.dialog-copy{margin:0 0 22px;color:#d7dde8}.dialog-actions{text-align:right}.trace-output{margin:12px 0 18px;max-height:62vh;overflow:auto;padding:14px;border:1px solid var(--line);border-radius:6px;background:#222b2e;color:#e3dac5;white-space:pre-wrap;tab-size:4;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}.trace-output a{color:#68c8d6;text-decoration:underline;text-underline-offset:2px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.field{margin-bottom:12px}.field label{display:block;color:#cbd1dc;margin-bottom:6px}.field input,.field select,.field textarea{width:100%;padding:10px;border-radius:6px;border:1px solid var(--line);background:#101217;color:#fff}.error-box{display:none;margin:0 0 12px;padding:10px 12px;border:1px solid rgba(255,90,102,.55);border-radius:6px;background:rgba(255,90,102,.12);color:#ff9aa3}.error-box.show{display:block}.toast{position:fixed;right:22px;top:18px;z-index:9;max-width:min(460px,calc(100vw - 44px));padding:12px 14px;border:1px solid rgba(255,90,102,.55);border-radius:8px;background:#2a1116;color:#ffd7dc;box-shadow:0 12px 30px rgba(0,0,0,.35)}.tags{min-height:42px;border:1px solid var(--line);background:#101217;border-radius:6px;padding:5px;display:flex;gap:6px;flex-wrap:wrap}.tag{background:#e9eef8;color:#243040;border-radius:4px;padding:4px 8px}.tag button{background:transparent;color:#667085;padding:0 0 0 6px}.tag-input{min-width:120px;flex:1;border:0!important;background:transparent!important;padding:5px!important}.preview{background:#101217;border:1px solid var(--line);border-radius:6px;padding:10px;max-height:160px;overflow:auto;color:#d7dde8}.chart{height:260px;border:1px dashed #3c414d;border-radius:8px;background:linear-gradient(180deg,rgba(128,76,255,.18),transparent)}.probe-pill{display:inline-flex;align-items:center;gap:6px;min-width:96px;padding:4px 9px;border-radius:999px;background:rgba(142,150,163,.14);color:#aeb5c0;white-space:nowrap}.probe-pill i{width:7px;height:7px;border-radius:50%;background:currentColor;box-shadow:0 0 0 0 currentColor;animation:probe-pulse 1.8s infinite}.probe-pill b{font-variant-numeric:tabular-nums}.probe-pill.good{background:rgba(29,219,120,.14);color:#58e69d}.probe-pill.warn{background:rgba(255,205,65,.15);color:#ffd262}.probe-pill.slow{background:rgba(255,159,26,.16);color:#ffae43}.probe-pill.bad{background:rgba(255,90,102,.16);color:#ff8791}.probe-pill.off{background:rgba(142,150,163,.12);color:#9aa2ae}.probe-pill.pending i{animation:none}@keyframes probe-pulse{0%,100%{box-shadow:0 0 0 0 currentColor}50%{box-shadow:0 0 0 4px transparent}}
@media(max-width:900px){.side{position:static;width:100%}.app{display:block}.main{margin:0}.cards{grid-template-columns:1fr}.grid{grid-template-columns:1fr}}
</style></head><body><div id="root"></div><script>
const appRoot=document.getElementById('root');
const authToken=()=>localStorage.getItem('nft_manager_token')||'';
window.addEventListener('error',e=>{if(appRoot&&!appRoot.innerHTML)appRoot.innerHTML=`<div class=login><form><h2>nft-manager</h2><p class=muted>前端加载失败</p><p>${e.message}</p><button type=button onclick="location.reload()" class=primary style="width:100%">刷新</button></form></div>`});
let savedView=localStorage.getItem('nft_manager_view')||'dash';if(!['dash','rules','targets','settings'].includes(savedView))savedView='dash';let state={view:savedView,data:null,edit:null,ruleView:localStorage.getItem('nft_manager_rule_view')||'flat',targetLatency:{},ruleConnectivity:{},autoProbeView:''};
const api=(p,o={})=>{let {timeout=12000,...request}=o,headers={'Content-Type':'application/json',...(request.headers||{})};let token=authToken();if(token)headers.Authorization='Bearer '+token;let ctl=new AbortController();let timer=setTimeout(()=>ctl.abort(),timeout);return fetch(p,{credentials:'same-origin',...request,headers,signal:ctl.signal}).then(async r=>{let j=await r.json().catch(()=>({}));if(!r.ok){let e=new Error(j.error||'请求失败');e.status=r.status;throw e}return j}).catch(e=>{if(e.name==='AbortError')throw new Error('请求超时，请检查 Web 服务或 nftables 状态');throw e}).finally(()=>clearTimeout(timer))};
const fmt=b=>b>1073741824?(b/1073741824).toFixed(2)+' GB':b>1048576?(b/1048576).toFixed(2)+' MB':b>1024?(b/1024).toFixed(1)+' KB':b+' B';
const msg=e=>e?.message||String(e||'操作失败');
function toast(text){document.querySelectorAll('.toast').forEach(x=>x.remove());document.body.insertAdjacentHTML('beforeend',`<div class=toast>${text}</div>`);setTimeout(()=>document.querySelector('.toast')?.remove(),5000)}
function setModalError(text){let box=document.querySelector('.modal .error-box');if(box){box.textContent=text;box.classList.add('show')}else toast(text)}
function clearModalError(){let box=document.querySelector('.modal .error-box');if(box){box.textContent='';box.classList.remove('show')}}
function expireSession(){localStorage.removeItem('nft_manager_token');state.data=null;login()}
async function runAction(btn,fn){let old=btn?.textContent;if(btn){btn.disabled=true;btn.textContent='处理中...'}try{await fn()}catch(e){if(e.status===401)expireSession();else setModalError(msg(e))}finally{if(btn){btn.disabled=false;btn.textContent=old}}}
function loading(){appRoot.innerHTML=`<div class=login><form><h2>nft-manager</h2><p class=muted>正在加载...</p></form></div>`}
function login(){appRoot.innerHTML=`<div class=login><form onsubmit="doLogin(event)"><h2>nft-manager</h2><p class=muted>默认账号 admin / admin</p><input name=u value=admin placeholder=账号><input name=p type=password value=admin placeholder=密码><button class=primary style="width:100%">登录</button></form></div>`}
async function doLogin(e){e.preventDefault();let btn=e.submitter;let old=btn.textContent;btn.disabled=true;btn.textContent='登录中...';try{let res=await api('/api/login',{method:'POST',body:JSON.stringify({username:e.target.u.value,password:e.target.p.value})});if(res.token)localStorage.setItem('nft_manager_token',res.token);loading();load()}catch(err){toast(msg(err))}finally{btn.disabled=false;btn.textContent=old}}
async function load(){try{state.data=await api('/api/state');render();autoProbeCurrentView()}catch(e){if(e.status===401)expireSession();else appRoot.innerHTML=`<div class=login><form><h2>nft-manager</h2><p class=muted>加载失败</p><p>${msg(e)}</p><button type=button onclick="location.reload()" class=primary style="width:100%">刷新</button></form></div>`}}
function nav(v){if(state.view!==v)state.autoProbeView='';state.view=v;localStorage.setItem('nft_manager_view',v);render();autoProbeCurrentView()}
function shell(content){let n=[['dash','仪表板'],['rules','转发管理'],['targets','主机管理'],['settings','系统设置']].map(x=>`<button class="${state.view==x[0]?'active':''}" onclick="nav('${x[0]}')">${x[1]}</button>`).join('');appRoot.innerHTML=`<div class=app><aside class=side><div class=brand>nft-manager</div><div class=ver>v3.2</div><div class=nav>${n}</div><div class=foot>Powered by nft-manager</div></aside><main class=main><div class=top><span class=user>admin ▾</span></div><div class=content>${content}</div></main></div>`}
function hourText(stamp){return String(new Date(stamp*1000).getHours()).padStart(2,'0')+':00'}
function trafficChart(){let h=state.data.history||[],w=960,ht=250,p=34,max=Math.max(1,...h.map(x=>x.bytes)),pts=h.map((x,i)=>`${p+i*(w-p*2)/23},${ht-p-(x.bytes/max)*(ht-p*2)}`),area=`${p},${ht-p} ${pts.join(' ')} ${w-p},${ht-p}`,grid=[0,1,2,3,4].map(i=>{let y=p+i*(ht-p*2)/4;return `<line class=chart-grid x1=${p} y1=${y} x2=${w-p} y2=${y}/><text class=chart-label x=2 y=${y+4}>${fmt(max*(4-i)/4)}</text>`}).join(''),hours=h.map((x,i)=>i%3===0?`<text class=chart-label x=${p+i*(w-p*2)/23-10} y=${ht-6}>${hourText(x.hour)}</text>`:'').join('');return `<svg class=chart-svg viewBox="0 0 ${w} ${ht}" role="img"><g>${grid}</g><polygon class=chart-fill points="${area}"/><polyline class=chart-line points="${pts.join(' ')}"/>${hours}</svg>`}
function render(){let d=state.data;if(state.view==='dash')return shell(`<div class=cards><div class=card><h3>总流量</h3><div class=big>无限制</div><div class=bar></div></div><div class=card><h3>已用流量</h3><div class=big>${fmt(d.stats.totalBytes)}</div><div class=bar></div></div><div class=card><h3>转发配额</h3><div class=big>无限制</div><div class=bar></div></div><div class=card><h3>已用转发</h3><div class=big>${d.stats.ruleCount}</div><div class=bar></div></div></div><div class=panel><h2>24小时流量统计</h2>${trafficChart()}</div><div class=panel><h2>转发配置 <span class=muted>${d.stats.ruleCount}</span></h2>${rulesTable(true)}</div>`);
 if(state.view==='rules')return shell(`<div class="toolbar rules-toolbar"><div class=view-switch><button class="${state.ruleView==='flat'?'active':''}" onclick="setRuleView('flat')">平铺</button><button class="${state.ruleView==='grid'?'active':''}" onclick="setRuleView('grid')">方块</button></div><button onclick="checkRuleConnectivity(this)">连通性检查</button><button class=primary onclick="openRule()">新增转发</button></div>${rulesTable(false)}`);
 if(state.view==='targets')return shell(`<div class=panel><div class=toolbar><h2 style="margin-right:auto">主机管理</h2><button onclick="checkTargetLatency(this)">延迟检测</button><button class=primary onclick="openTarget()">新增主机</button></div>${targetsTable()}</div>`);
 return shell(`<div class=panel><h2>系统设置</h2><p>Web 面板地址：<span class=pill>http://${d.stats.localIp}:${d.stats.port}</span></p><p>默认端口：5555</p><button onclick="openPassword()">修改密码</button> <button class=danger onclick="showInfo('完整卸载','请在 SSH 菜单执行完整卸载')">完整卸载</button></div>`)}
function setRuleView(view){state.ruleView=view;localStorage.setItem('nft_manager_rule_view',view);render()}
function ruleName(r){return r.alias||`${r.targetAlias||r.ip}:${r.lport}`}
function ruleSwitch(r){return `<label class=switch title="${r.enabled?'关闭转发':'开启转发'}"><input type=checkbox ${r.enabled?'checked':''} onchange="toggleRule(${r.lport},this.checked)"><span class=slider></span></label>`}
function ruleActions(r){return `<button onclick='openRule(${JSON.stringify(r)})'>编辑</button><button class=danger onclick="delRules([${r.lport}])">删除</button>`}
function probePill(result,label){if(!result)return `<span class="probe-pill pending"><i></i>${label}<b>未检测</b></span>`;if(result.skipped)return `<span class="probe-pill off"><i></i>${label}<b>已关闭</b></span>`;if(!result.reachable)return `<span class="probe-pill bad"><i></i>${label}<b>不可达</b></span>`;let ms=Number(result.latency||0),level=ms<100?'good':ms<1000?'warn':'slow';return `<span class="probe-pill ${level}"><i></i>${label}<b>${ms.toFixed(ms<10?1:0)} ms</b></span>`}
function rulesTable(limit){let rules=state.data.rules.slice(0,limit?8:9999);if(!limit&&state.ruleView==='grid'){let cards=rules.map(r=>`<article class="rule-card ${r.enabled?'':'disabled'}"><div class=rule-card-top><h3>${ruleName(r)}</h3>${ruleSwitch(r)}</div><div class=muted>${r.targetAlias||'-'} / ${r.ip}</div><div class=route>${r.lport} → ${r.dport}</div><div class=metrics><span class="metric upload">上传<br>${fmt(r.uploadBytes)}</span><span class="metric download">下载<br>${fmt(r.downloadBytes)}</span><span class="metric total">总计<br>${fmt(r.totalBytes)}</span></div><p class="status ${r.active?'on':''}">状态：${r.enabled?(r.active?'活跃':'空闲'):'已关闭'}</p>${probePill(state.ruleConnectivity[r.lport],'连通性')}<div class=actions>${ruleActions(r)}</div></article>`).join('');return `<div class=rule-grid>${cards||'<span class=muted>暂无转发</span>'}</div>`}let rows=rules.map(r=>`<tr><td>${r.targetAlias||'-'}<br><span class=muted>${r.ip}</span></td><td>${ruleName(r)}</td><td>${r.lport}</td><td>${r.dport}</td><td class="metric upload">${fmt(r.uploadBytes)}</td><td class="metric download">${fmt(r.downloadBytes)}</td><td class="metric total">${fmt(r.totalBytes)}</td><td>${r.statsMode==='upload'?'上传':r.statsMode==='download'?'下载':'总计'}</td><td>${probePill(state.ruleConnectivity[r.lport],'连通性')}</td><td class="status ${r.active?'on':''}">${r.enabled?(r.active?'活跃':'空闲'):'关闭'}</td><td class=actions>${ruleSwitch(r)}${ruleActions(r)}</td></tr>`).join('');return `<div class=rule-table-wrap><table class=table><tr><th>目标主机</th><th>别名</th><th>入口</th><th>出口</th><th class="metric upload">上传</th><th class="metric download">下载</th><th class="metric total">总计</th><th>统计口径</th><th>连通性</th><th>状态</th><th>操作</th></tr>${rows||'<tr><td colspan=11 class=muted>暂无转发</td></tr>'}</table></div>`}
async function toggleRule(lport,enabled){try{await api('/api/rules/toggle',{method:'POST',body:JSON.stringify({lport,enabled}),timeout:30000});await load()}catch(e){toast(msg(e));await load()}}
function targetsTable(){let counts={};state.data.rules.forEach(r=>counts[r.ip]=(counts[r.ip]||0)+1);let rows=state.data.targets.map(t=>`<tr><td>${t.alias}</td><td>${t.ip}</td><td>${probePill(state.targetLatency[t.ip],'延迟')}</td><td>${counts[t.ip]||0}</td><td class=actions><button onclick='traceTarget(${JSON.stringify(t)})'>NextTrace 路由</button><button onclick='openTarget(${JSON.stringify(t)})'>编辑</button><button class=danger onclick='delTarget(${JSON.stringify(t)})'>删除</button></td></tr>`).join('');return `<table class=table><tr><th>别名</th><th>IP</th><th>延迟</th><th>规则数</th><th>操作</th></tr>${rows||'<tr><td colspan=5 class=muted>暂无主机</td></tr>'}</table>`}
async function checkTargetLatency(btn){await runAction(btn,async()=>{let result=await api('/api/targets/latency',{method:'POST',body:'{}',timeout:60000});state.targetLatency=result.results||{};render();toast('延迟检测完成')})}
async function checkRuleConnectivity(btn){await runAction(btn,async()=>{let result=await api('/api/rules/connectivity',{method:'POST',body:'{}',timeout:60000});state.ruleConnectivity=result.results||{};render();toast('连通性检查完成')})}
function autoProbeCurrentView(){if(!state.data||state.autoProbeView===state.view)return;if(state.view==='targets'){state.autoProbeView='targets';checkTargetLatency()}else if(state.view==='rules'){state.autoProbeView='rules';checkRuleConnectivity()}}
function ansiToHtml(text){let colors={30:'#111827',31:'#ff7b86',32:'#8bd49c',33:'#e6c27a',34:'#82b1ff',35:'#f38ac2',36:'#70d6e5',37:'#f1eadb',90:'#8a9499',91:'#ff8f9a',92:'#a4e5ae',93:'#f4d68f',94:'#9bc1ff',95:'#f5a5cf',96:'#91e2ed',97:'#ffffff'},fg='',bold=false,out='',last=0,re=/\x1b\[([0-9;]*)m/g,esc=s=>s.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),safe=s=>{let p=0,result='',urls=/https?:\/\/[^\s<>"']+/g,m;while((m=urls.exec(s))){result+=esc(s.slice(p,m.index));let url=esc(m[0]);result+=`<a href="${url}" target="_blank" rel="noopener noreferrer">${url}</a>`;p=urls.lastIndex}return result+esc(s.slice(p))},paint=s=>{if(!s)return;let style=[fg&&`color:${fg}`,bold&&'font-weight:700'].filter(Boolean).join(';'),content=safe(s);out+=style?`<span style="${style}">${content}</span>`:content},match;while((match=re.exec(text))){paint(text.slice(last,match.index));let codes=(match[1]||'0').split(';').map(Number);for(let i=0;i<codes.length;i++){let c=codes[i];if(c===0){fg='';bold=false}else if(c===1)bold=true;else if(c===22)bold=false;else if(c===39)fg='';else if(colors[c])fg=colors[c];else if(c===38&&codes[i+1]===2&&codes.length>=i+4){fg=`rgb(${codes[i+2]},${codes[i+3]},${codes[i+4]})`;i+=4}else if(c===38&&codes[i+1]===5&&codes.length>=i+2){let n=codes[i+2],v=n<16?(colors[[30,31,32,33,34,35,36,37,90,91,92,93,94,95,96,97][n]]||'#f1eadb'):n>=232?`rgb(${8+(n-232)*10},${8+(n-232)*10},${8+(n-232)*10})`:`rgb(${Math.floor((n-16)/36)*51},${Math.floor((n-16)%36/6)*51},${(n-16)%6*51})`;fg=v;i+=2}}last=re.lastIndex}paint(text.slice(last));return out}
function traceTarget(t){let layer=modal(`<h2>NextTrace 路由</h2><p class=dialog-copy data-trace-target></p><pre class=trace-output><code>正在从本机执行 nexttrace，请稍候...</code></pre><div class=dialog-actions><button class=primary data-close>关闭</button></div>`),code=layer.querySelector('code');layer.querySelector('.dialog').classList.add('trace-dialog');layer.querySelector('[data-trace-target]').textContent=`目标主机：${t.alias} (${t.ip})`;layer.querySelector('[data-close]').addEventListener('click',()=>layer.remove());api('/api/targets/trace',{method:'POST',body:JSON.stringify({ip:t.ip}),timeout:125000}).then(r=>{code.innerHTML=ansiToHtml((r.output||'NextTrace 未返回输出。').replace(/\r\n?/g,'\n'))}).catch(e=>{if(e.status===401){layer.remove();expireSession();return}code.textContent=`路由执行失败：${msg(e)}`})}
function modal(html){document.body.insertAdjacentHTML('beforeend',`<div class=modal><div class=dialog><div class=error-box></div>${html}</div></div>`);let layer=document.body.lastElementChild;layer.addEventListener('click',e=>{if(e.target===layer)layer.remove()});return layer}
function showInfo(title,text){let layer=modal(`<h2>${title}</h2><p class=dialog-copy>${text}</p><div class=dialog-actions><button class=primary data-confirm>确定</button></div>`);layer.querySelector('[data-confirm]').addEventListener('click',()=>layer.remove())}
function confirmDialog(title,text,action){let layer=modal(`<h2>${title}</h2><p class=dialog-copy>${text}</p><div class=dialog-actions><button class=ghost data-cancel>取消</button> <button class=primary data-confirm>确定</button></div>`),cancel=layer.querySelector('[data-cancel]'),confirmBtn=layer.querySelector('[data-confirm]');cancel.addEventListener('click',()=>layer.remove());confirmBtn.addEventListener('click',async()=>{let old=confirmBtn.textContent;confirmBtn.disabled=true;confirmBtn.textContent='处理中...';try{await action();layer.remove()}catch(e){if(e.status===401){layer.remove();expireSession()}else toast(msg(e))}finally{confirmBtn.disabled=false;confirmBtn.textContent=old}})}
document.addEventListener('keydown',e=>{let layers=document.querySelectorAll('.modal'),layer=layers[layers.length-1];if(!layer)return;if(e.key==='Escape'){e.preventDefault();layer.remove();return}if(e.key==='Enter'&&!e.shiftKey&&e.target.tagName!=='TEXTAREA'){let button=layer.querySelector('[data-confirm],button.primary');if(button&&!button.disabled){e.preventDefault();button.click()}}})
function parsePorts(value){let ports=value.trim().split(/[ ,]+/).filter(Boolean);if(!ports.length)throw new Error('请至少输入一个入口端口');let seen=new Set;for(let port of ports){if(!/^[0-9]+$/.test(port)||Number(port)<1||Number(port)>65535)throw new Error(`端口无效: ${port}；仅支持单个端口，请用空格或英文逗号分隔`);if(seen.has(port))throw new Error(`端口重复: ${port}`);seen.add(port)}return ports}
function openRule(r=null){state.edit=r;let custom=r&&r.lport!==r.dport,stats=r?.statsMode||'total',opts=state.data.targets.map(t=>`<option value="${t.ip}" ${r&&r.ip===t.ip?'selected':''}>${t.alias} / ${t.ip}</option>`).join('');modal(`<h2>${r?'编辑转发':'新增转发'}</h2><div class=grid><div class=field><label>目标主机</label><select id=ip>${opts}</select></div><div class=field><label>转发别名</label><input id=alias value="${r?.alias||''}"></div></div><div class=field><label>入口端口</label><input id=ports value="${r?.lport||''}" placeholder="例如：80 443,10000"></div><div class=grid><div class=field><label>出口映射</label><select id=mode onchange="document.getElementById('outBox').classList.toggle('hidden',this.value==='same')"><option value=same ${!custom?'selected':''}>与入口端口一致</option><option value=start ${custom?'selected':''}>指定出口起始端口</option></select></div><div class="field ${custom?'':'hidden'}" id=outBox><label>出口起始端口</label><input id=out value="${custom?r.dport:''}" placeholder="多端口将按输入顺序递增"></div></div><div class=field><label>统计口径</label><select id=statsMode><option value=upload ${stats==='upload'?'selected':''}>上传流量</option><option value=download ${stats==='download'?'selected':''}>下载流量</option><option value=total ${stats==='total'?'selected':''}>上传 + 下载总计</option></select></div><div class=field><label>描述</label><textarea id=desc>${r?.desc||''}</textarea></div><div style="text-align:right"><button class=ghost onclick="this.closest('.modal').remove()">取消</button> <button class=primary onclick="saveRule(this)">保存</button></div>`)}
async function saveRule(btn){await runAction(btn,async()=>{let mode=document.getElementById('mode').value,out=document.getElementById('out').value.trim(),body={ip:document.getElementById('ip').value,ports:parsePorts(document.getElementById('ports').value),mode,alias:document.getElementById('alias').value,desc:document.getElementById('desc').value,statsMode:document.getElementById('statsMode').value};if(mode==='start')body.outStart=out;if(state.edit){body.oldLport=state.edit.lport;await api('/api/rules/update',{method:'POST',body:JSON.stringify(body),timeout:30000})}else await api('/api/rules/add',{method:'POST',body:JSON.stringify(body),timeout:30000});document.querySelector('.modal').remove();await load()})}
function delRules(lports){confirmDialog('删除转发','确认删除该端口转发？',async()=>{await api('/api/rules/delete',{method:'POST',body:JSON.stringify({lports}),timeout:30000});await load()})}
function openTarget(t=null){modal(`<h2>${t?'编辑主机':'新增主机'}</h2><div class=field><label>别名</label><input id=ta value="${t?.alias||''}"></div><div class=field><label>IP</label><input id=tip value="${t?.ip||''}"></div><div style="text-align:right"><button class=ghost onclick="this.closest('.modal').remove()">取消</button> <button class=primary onclick='saveTarget(this,${JSON.stringify(t)})'>保存</button></div>`)}
async function saveTarget(btn,old){await runAction(btn,async()=>{await api('/api/targets/save',{method:'POST',body:JSON.stringify({oldIp:old?.ip,alias:document.getElementById('ta').value,ip:document.getElementById('tip').value})});document.querySelector('.modal').remove();await load()})}
function delTarget(t){confirmDialog('删除主机','确认删除该主机？存在转发规则时将阻止删除。',async()=>{await api('/api/targets/delete',{method:'POST',body:JSON.stringify({ip:t.ip}),timeout:30000});await load()})}
function openPassword(){modal(`<h2>修改密码</h2><div class=field><label>旧密码</label><input id=oldp type=password></div><div class=field><label>新密码</label><input id=newp type=password></div><div style="text-align:right"><button class=ghost onclick="this.closest('.modal').remove()">取消</button> <button class=primary onclick="chgPwd(this)">保存</button></div>`)}
async function chgPwd(btn){await runAction(btn,async()=>{await api('/api/password',{method:'POST',body:JSON.stringify({oldPassword:document.getElementById('oldp').value,newPassword:document.getElementById('newp').value})});document.querySelector('.modal').remove();expireSession();toast('密码已修改，请使用新密码重新登录')})}
if(authToken()){loading();load()}else login();
setInterval(()=>{if(state.data&&authToken())load()},10000);
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
        if path == "/api/state":
            if not self.require():
                return
            self.send_json(dashboard())
            return
        raw = HTML.encode()
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
            else:
                self.send_json({"error": "not found"}, 404)
                return
            self.send_json({"ok": True})
        except Exception as e:
            self.send_json({"error": str(e)}, 400)


if __name__ == "__main__":
    ensure_auth()
    migration_ok = migrate_legacy_data()
    if "--migrate-only" in sys.argv:
        raise SystemExit(0 if migration_ok else 1)
    print(f"nft-manager web listening on {HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
