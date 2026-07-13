#!/usr/bin/env python3
import base64
import hashlib
import hmac
import http.cookies
import json
import os
import re
import secrets
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

CONF_DIR = os.environ.get("NFT_MANAGER_CONF_DIR", "/etc/nftables.d")
CONF_FILE = os.path.join(CONF_DIR, "port-forward.conf")
TARGETS_FILE = os.path.join(CONF_DIR, "targets.conf")
AUTH_FILE = os.path.join(CONF_DIR, "web-auth.conf")
STATS_FILE = os.path.join(CONF_DIR, "web-stats.json")
TABLE_NAME = "port_forward"
HOST = os.environ.get("NFT_MANAGER_WEB_HOST", "0.0.0.0")
PORT = int(os.environ.get("NFT_MANAGER_WEB_PORT", "5555"))
MAX_BATCH_RULES = int(os.environ.get("NFT_MANAGER_MAX_BATCH", "1000"))
SESSION_MAX_AGE = 86400


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


def local_ip():
    out = run(["bash", "-lc", "ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \\K[0-9.]+' | head -1"]).stdout.strip()
    if out:
        return out
    out = run(["bash", "-lc", "hostname -I 2>/dev/null | awk '{print $1}'"]).stdout.strip()
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
            parts = (meta.split("|") + ["", "", ""])[:6]
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
                })
                seen_lports.add(lport)
    for line in text:
        m = re.search(r"tcp dport (\d+).*dnat to ([0-9.]+):(\d+)", line)
        if not m:
            continue
        lport = int(m.group(1))
        if lport in seen_lports:
            continue
        rules.append({"lport": lport, "ip": m.group(2), "dport": int(m.group(3)), "alias": "", "desc": ""})
        seen_lports.add(lport)
    return rules


def write_rules(rules):
    ensure_dirs()
    lip = local_ip()
    with open(CONF_FILE, "w", encoding="utf-8") as f:
        f.write("#!/usr/sbin/nft -f\n\n")
        f.write("# WEB_META|1\n\n")
        f.write(f"define LOCAL_IP = {lip}\n\n")
        f.write(f"table ip {TABLE_NAME} {{\n")
        f.write("    chain prerouting {\n        type nat hook prerouting priority -100; policy accept;\n")
        for r in rules:
            alias = clean_label(r.get("alias", ""))
            desc = clean_label(r.get("desc", ""))
            f.write(f"\n        # META_RULE|{r['lport']}|{r['ip']}|{r['dport']}|{alias}||{desc}\n")
            f.write(f"        tcp dport {r['lport']} counter dnat to {r['ip']}:{r['dport']}\n")
            f.write(f"        udp dport {r['lport']} counter dnat to {r['ip']}:{r['dport']}\n")
        f.write("    }\n\n")
        f.write("    chain postrouting {\n        type nat hook postrouting priority 100; policy accept;\n")
        for r in rules:
            f.write(f"\n        ip daddr {r['ip']} tcp dport {r['dport']} ct status dnat snat to $LOCAL_IP\n")
            f.write(f"        ip daddr {r['ip']} udp dport {r['dport']} ct status dnat snat to $LOCAL_IP\n")
        f.write("    }\n}\n")


def reload_rules():
    run(["nft", "flush", "table", "ip", TABLE_NAME])
    run(["nft", "delete", "table", "ip", TABLE_NAME])
    res = run(["nft", "-f", CONF_FILE])
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
        return

    try:
        text = open(CONF_FILE, encoding="utf-8", errors="ignore").read()
    except OSError:
        return

    needs_migration = "WEB_META|1" not in text or "counter dnat to" not in text
    if not needs_migration:
        return

    write_rules(rules)
    try:
        reload_rules()
    except Exception:
        # Keep the migrated file for future operations; the dashboard can still read it.
        pass


def nft_counters():
    out = run(["nft", "list", "table", "ip", TABLE_NAME]).stdout
    counters = {}
    current = None
    for line in out.splitlines():
        if "META_RULE|" in line:
            parts = line.split("META_RULE|", 1)[1].split("|")
            if len(parts) >= 3:
                current = f"{parts[0]}|{parts[1]}|{parts[2]}"
            continue
        if current and " dport " in line and "counter packets" in line and "dnat to" in line:
            m = re.search(r"counter packets (\d+) bytes (\d+)", line)
            if m:
                item = counters.setdefault(current, {"packets": 0, "bytes": 0})
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
    for key, val in counters.items():
        old = previous.get(key, {})
        result[key] = {**val, "active": val["bytes"] > int(old.get("bytes", -1)), "sampled_at": now}
    with open(STATS_FILE, "w", encoding="utf-8") as f:
        json.dump(counters, f)
    return result


def parse_port_tokens(tokens):
    ports = []
    seen = set()
    for token in tokens:
        token = str(token).strip()
        if not token:
            continue
        if "-" in token:
            a, b = token.split("-", 1)
            if not (a.isdigit() and b.isdigit()):
                raise ValueError(f"端口范围无效: {token}")
            start, end = int(a), int(b)
        else:
            if not token.isdigit():
                raise ValueError(f"端口无效: {token}")
            start = end = int(token)
        if not valid_port(start) or not valid_port(end) or start > end:
            raise ValueError(f"端口范围无效: {token}")
        for p in range(start, end + 1):
            if p in seen:
                raise ValueError(f"端口重复或重叠: {p}")
            seen.add(p)
            ports.append(p)
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
    elif mode == "range":
        out_ports = parse_port_tokens(payload.get("outPorts", []))
        if len(out_ports) != len(in_ports):
            raise ValueError("入口端口数量和出口端口数量必须一致")
    else:
        raise ValueError("映射方式无效")
    prefix = clean_label(payload.get("alias", ""))
    desc = clean_label(payload.get("desc", ""))
    batch = len(in_ports) > 1
    rules = []
    for lp, dp in zip(in_ports, out_ports):
        alias = f"{prefix}-{lp}" if prefix and batch else prefix
        rules.append({"lport": lp, "ip": ip, "dport": dp, "alias": alias, "desc": desc})
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
    rest = [r for r in rules if r["lport"] != old_lport]
    new_rules = expand_forward(payload)
    if len(new_rules) != 1:
        raise ValueError("编辑时只能保存为单条规则")
    if any(r["lport"] == new_rules[0]["lport"] for r in rest):
        raise ValueError("入口端口已存在")
    write_rules(rest + new_rules)
    reload_rules()


def delete_rules(payload):
    ports = {int(p) for p in payload.get("lports", [])}
    write_rules([r for r in parse_rules() if r["lport"] not in ports])
    reload_rules()


def dashboard():
    migrate_legacy_data()
    targets = read_targets()
    rules = parse_rules()
    counters = nft_counters()
    enriched = []
    total_bytes = 0
    active = 0
    aliases = {t["ip"]: t["alias"] for t in targets}
    for r in rules:
        key = f"{r['lport']}|{r['ip']}|{r['dport']}"
        c = counters.get(key, {"packets": 0, "bytes": 0, "active": False})
        total_bytes += c["bytes"]
        active += 1 if c.get("active") else 0
        enriched.append({**r, "targetAlias": aliases.get(r["ip"], ""), "packets": c["packets"], "bytes": c["bytes"], "active": c["active"]})
    return {"targets": targets, "rules": enriched, "stats": {"totalBytes": total_bytes, "ruleCount": len(rules), "targetCount": len(targets), "activeCount": active, "localIp": local_ip(), "port": PORT}}


HTML = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>nft-manager</title>
<style>
:root{color-scheme:dark;--bg:#050607;--panel:#17181c;--panel2:#1f2026;--line:#343640;--text:#f5f7fb;--muted:#8e96a3;--blue:#0877ff;--green:#1ddb78;--orange:#ff9f1a;--purple:#8e4cff;--danger:#ff5a66}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 -apple-system,BlinkMacSystemFont,Segoe UI,Arial,"Microsoft YaHei",sans-serif}
button,input,select,textarea{font:inherit}button{cursor:pointer;border:0;border-radius:6px;background:#243b63;color:#fff;padding:9px 14px}button.primary{background:var(--blue)}button.danger{background:var(--danger)}button.ghost{background:#2b2d35}.login{height:100vh;display:grid;place-items:center}.login form{width:360px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:28px}.login input{width:100%;margin:8px 0 14px;padding:12px;border-radius:6px;border:1px solid var(--line);background:#111318;color:#fff}
.app{display:flex;min-height:100vh}.side{width:238px;background:#020303;border-right:1px solid #2a2d35;padding:28px 16px;position:fixed;inset:0 auto 0 0}.brand{font-weight:800;font-size:18px;margin-bottom:2px}.ver{font-size:12px;color:var(--muted);margin-bottom:34px}.nav button{width:100%;text-align:left;margin:5px 0;background:transparent;color:#d9dde7}.nav button.active{background:#112846;color:#0b84ff}.foot{position:absolute;bottom:18px;color:#737b89;font-size:12px;left:70px}
.main{margin-left:238px;flex:1}.top{height:54px;border-bottom:1px solid #2a2d35;display:flex;align-items:center;justify-content:flex-end;padding:0 26px}.user{font-weight:700}
.content{padding:18px 24px 40px}.cards{display:grid;grid-template-columns:repeat(4,minmax(160px,1fr));gap:14px}.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px}.card h3{font-size:14px;margin:0 0 14px}.big{font-size:25px;font-weight:800}.bar{height:5px;background:linear-gradient(90deg,var(--blue),#b54cff);border-radius:10px;margin-top:14px}.panel{margin-top:20px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}.panel h2{margin:0 0 14px;font-size:22px}.toolbar{display:flex;gap:10px;align-items:center;margin-bottom:14px}.table{width:100%;border-collapse:collapse}.table th,.table td{border-bottom:1px solid #2a2d35;padding:10px;text-align:left}.muted{color:var(--muted)}.pill{display:inline-flex;align-items:center;gap:6px;background:#11351f;color:#68f0a4;border-radius:5px;padding:4px 8px;font-weight:700}.status{color:var(--muted)}.status.on{color:var(--green);font-weight:700}.actions button{padding:6px 10px;margin-right:6px}.hidden{display:none!important}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.58);display:grid;place-items:center;z-index:5}.dialog{width:min(720px,92vw);max-height:88vh;overflow:auto;background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:20px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.field{margin-bottom:12px}.field label{display:block;color:#cbd1dc;margin-bottom:6px}.field input,.field select,.field textarea{width:100%;padding:10px;border-radius:6px;border:1px solid var(--line);background:#101217;color:#fff}.tags{min-height:42px;border:1px solid var(--line);background:#101217;border-radius:6px;padding:5px;display:flex;gap:6px;flex-wrap:wrap}.tag{background:#e9eef8;color:#243040;border-radius:4px;padding:4px 8px}.tag button{background:transparent;color:#667085;padding:0 0 0 6px}.tag-input{min-width:120px;flex:1;border:0!important;background:transparent!important;padding:5px!important}.preview{background:#101217;border:1px solid var(--line);border-radius:6px;padding:10px;max-height:160px;overflow:auto;color:#d7dde8}.chart{height:260px;border:1px dashed #3c414d;border-radius:8px;background:linear-gradient(180deg,rgba(128,76,255,.18),transparent)}
@media(max-width:900px){.side{position:static;width:100%}.app{display:block}.main{margin:0}.cards{grid-template-columns:1fr}.grid{grid-template-columns:1fr}}
</style></head><body><div id="root"></div><script>
const appRoot=document.getElementById('root');
const authToken=()=>localStorage.getItem('nft_manager_token')||'';
window.addEventListener('error',e=>{if(appRoot&&!appRoot.innerHTML)appRoot.innerHTML=`<div class=login><form><h2>nft-manager</h2><p class=muted>前端加载失败</p><p>${e.message}</p><button type=button onclick="location.reload()" class=primary style="width:100%">刷新</button></form></div>`});
let state={view:'dash',data:null,ports:[],edit:null};
const api=(p,o={})=>{let headers={'Content-Type':'application/json',...(o.headers||{})};let token=authToken();if(token)headers.Authorization='Bearer '+token;let ctl=new AbortController();let timer=setTimeout(()=>ctl.abort(),12000);return fetch(p,{credentials:'same-origin',...o,headers,signal:ctl.signal}).then(async r=>{let j=await r.json().catch(()=>({}));if(!r.ok){let e=new Error(j.error||'请求失败');e.status=r.status;throw e}return j}).catch(e=>{if(e.name==='AbortError')throw new Error('请求超时，请检查 Web 服务或 nftables 状态');throw e}).finally(()=>clearTimeout(timer))};
const fmt=b=>b>1073741824?(b/1073741824).toFixed(2)+' GB':b>1048576?(b/1048576).toFixed(2)+' MB':b>1024?(b/1024).toFixed(1)+' KB':b+' B';
function loading(){appRoot.innerHTML=`<div class=login><form><h2>nft-manager</h2><p class=muted>正在加载...</p></form></div>`}
function login(){appRoot.innerHTML=`<div class=login><form onsubmit="doLogin(event)"><h2>nft-manager</h2><p class=muted>默认账号 admin / admin</p><input name=u value=admin placeholder=账号><input name=p type=password value=admin placeholder=密码><button class=primary style="width:100%">登录</button></form></div>`}
async function doLogin(e){e.preventDefault();try{let res=await api('/api/login',{method:'POST',body:JSON.stringify({username:e.target.u.value,password:e.target.p.value})});if(res.token)localStorage.setItem('nft_manager_token',res.token);loading();load()}catch(err){alert(err.message)}}
async function load(){try{state.data=await api('/api/state');render()}catch(e){if(e.status===401){localStorage.removeItem('nft_manager_token');login()}else appRoot.innerHTML=`<div class=login><form><h2>nft-manager</h2><p class=muted>加载失败</p><p>${e.message}</p><button type=button onclick="location.reload()" class=primary style="width:100%">刷新</button></form></div>`}}
function nav(v){state.view=v;render()}
function shell(content){let n=[['dash','仪表板'],['rules','转发管理'],['targets','主机管理'],['settings','系统设置']].map(x=>`<button class="${state.view==x[0]?'active':''}" onclick="nav('${x[0]}')">${x[1]}</button>`).join('');appRoot.innerHTML=`<div class=app><aside class=side><div class=brand>nft-manager</div><div class=ver>v1.4</div><div class=nav>${n}</div><div class=foot>Powered by nft-manager</div></aside><main class=main><div class=top><span class=user>admin ▾</span></div><div class=content>${content}</div></main></div>`}
function render(){let d=state.data;if(state.view==='dash')return shell(`<div class=cards><div class=card><h3>总流量</h3><div class=big>${fmt(d.stats.totalBytes)}</div><div class=bar></div></div><div class=card><h3>目标主机</h3><div class=big>${d.stats.targetCount}</div><div class=bar></div></div><div class=card><h3>已用转发</h3><div class=big>${d.stats.ruleCount}</div><div class=bar></div></div><div class=card><h3>活跃转发</h3><div class=big>${d.stats.activeCount}</div><div class=bar></div></div></div><div class=panel><h2>24小时流量统计</h2><div class=chart></div></div><div class=panel><h2>转发配置 <span class=muted>${d.stats.ruleCount}</span></h2>${rulesTable(true)}</div>`);
 if(state.view==='rules')return shell(`<div class=panel><div class=toolbar><h2 style="margin-right:auto">转发管理</h2><button class=primary onclick="openRule()">新增转发</button></div>${rulesTable(false)}</div>`);
 if(state.view==='targets')return shell(`<div class=panel><div class=toolbar><h2 style="margin-right:auto">主机管理</h2><button class=primary onclick="openTarget()">新增主机</button></div>${targetsTable()}</div>`);
 return shell(`<div class=panel><h2>系统设置</h2><p>Web 面板地址：<span class=pill>http://${d.stats.localIp}:${d.stats.port}</span></p><p>默认端口：5555</p><button onclick="openPassword()">修改密码</button> <button class=danger onclick="alert('请在 SSH 菜单执行完整卸载')">完整卸载</button></div>`)}
function rulesTable(limit){let rows=state.data.rules.slice(0,limit?8:9999).map(r=>`<tr><td>${r.targetAlias||'-'}<br><span class=muted>${r.ip}</span></td><td>${r.alias||'-'}</td><td>${r.lport}</td><td>${r.dport}</td><td>${fmt(r.bytes)}</td><td class="status ${r.active?'on':''}">${r.active?'活跃':'空闲'}</td><td class=actions><button onclick='openRule(${JSON.stringify(r)})'>编辑</button><button class=danger onclick="delRules([${r.lport}])">删除</button></td></tr>`).join('');return `<table class=table><tr><th>目标主机</th><th>别名</th><th>入口端口</th><th>出口端口</th><th>流量</th><th>状态</th><th>操作</th></tr>${rows||'<tr><td colspan=7 class=muted>暂无转发</td></tr>'}</table>`}
function targetsTable(){let counts={};state.data.rules.forEach(r=>counts[r.ip]=(counts[r.ip]||0)+1);let rows=state.data.targets.map(t=>`<tr><td>${t.alias}</td><td>${t.ip}</td><td>${counts[t.ip]||0}</td><td class=actions><button onclick='openTarget(${JSON.stringify(t)})'>编辑</button><button class=danger onclick='delTarget(${JSON.stringify(t)})'>删除</button></td></tr>`).join('');return `<table class=table><tr><th>别名</th><th>IP</th><th>规则数</th><th>操作</th></tr>${rows||'<tr><td colspan=4 class=muted>暂无主机</td></tr>'}</table>`}
function modal(html){document.body.insertAdjacentHTML('beforeend',`<div class=modal onclick="if(event.target.className==='modal')this.remove()"><div class=dialog>${html}</div></div>`)}
function addTag(input){let v=input.value.trim();if(!v)return;if(!/^\\d+(-\\d+)?$/.test(v))return alert('请输入端口或端口段，如 100 或 100-200');state.ports.push(v);input.value='';drawTags()}
function drawTags(){let box=document.querySelector('.tags');box.querySelectorAll('.tag').forEach(x=>x.remove());state.ports.forEach((p,i)=>box.insertAdjacentHTML('afterbegin',`<span class=tag>${p}<button onclick="state.ports.splice(${i},1);drawTags()">×</button></span>`))}
function openRule(r=null){state.edit=r;state.ports=r?[String(r.lport)]:[];let opts=state.data.targets.map(t=>`<option value="${t.ip}" ${r&&r.ip===t.ip?'selected':''}>${t.alias} / ${t.ip}</option>`).join('');modal(`<h2>${r?'编辑转发':'新增转发'}</h2><div class=grid><div class=field><label>目标主机</label><select id=ip>${opts}</select></div><div class=field><label>转发别名</label><input id=alias value="${r?.alias||''}"></div></div><div class=field><label>入口端口范围</label><div class=tags><input class=tag-input onkeydown="if(event.key==='Enter'){event.preventDefault();addTag(this)}" onblur="addTag(this)" placeholder="输入 100 或 100-200 后回车"></div></div><div class=grid><div class=field><label>出口映射</label><select id=mode onchange="document.getElementById('outBox').classList.toggle('hidden',this.value==='same')"><option value=same>与入口端口一致</option><option value=start>指定出口起始端口</option><option value=range>指定出口端口范围</option></select></div><div class="field hidden" id=outBox><label>出口端口</label><input id=out placeholder="2000 或 2000-2100"></div></div><div class=field><label>描述</label><textarea id=desc>${r?.desc||''}</textarea></div><div style="text-align:right"><button class=ghost onclick="this.closest('.modal').remove()">取消</button> <button class=primary onclick="saveRule()">保存</button></div>`);drawTags()}
async function saveRule(){let mode=document.getElementById('mode').value,out=document.getElementById('out').value.trim();let body={ip:document.getElementById('ip').value,ports:state.ports,mode,alias:document.getElementById('alias').value,desc:document.getElementById('desc').value};if(mode==='start')body.outStart=out;if(mode==='range')body.outPorts=out?[out]:[];if(state.edit){body.oldLport=state.edit.lport;body.ports=[String(state.edit.lport)];if(mode==='same')body.ports=state.ports;await api('/api/rules/update',{method:'POST',body:JSON.stringify(body)})}else await api('/api/rules/add',{method:'POST',body:JSON.stringify(body)});document.querySelector('.modal').remove();await load()}
async function delRules(lports){if(confirm('确认删除转发？')){await api('/api/rules/delete',{method:'POST',body:JSON.stringify({lports})});await load()}}
function openTarget(t=null){modal(`<h2>${t?'编辑主机':'新增主机'}</h2><div class=field><label>别名</label><input id=ta value="${t?.alias||''}"></div><div class=field><label>IP</label><input id=tip value="${t?.ip||''}"></div><div style="text-align:right"><button class=ghost onclick="this.closest('.modal').remove()">取消</button> <button class=primary onclick='saveTarget(${JSON.stringify(t)})'>保存</button></div>`)}
async function saveTarget(old){await api('/api/targets/save',{method:'POST',body:JSON.stringify({oldIp:old?.ip,alias:document.getElementById('ta').value,ip:document.getElementById('tip').value})});document.querySelector('.modal').remove();await load()}
async function delTarget(t){if(confirm('确认删除主机？有转发规则时会阻止删除。')){await api('/api/targets/delete',{method:'POST',body:JSON.stringify({ip:t.ip})});await load()}}
function openPassword(){modal(`<h2>修改密码</h2><div class=field><label>旧密码</label><input id=oldp type=password></div><div class=field><label>新密码</label><input id=newp type=password></div><div style="text-align:right"><button class=ghost onclick="this.closest('.modal').remove()">取消</button> <button class=primary onclick="chgPwd()">保存</button></div>`)}
async function chgPwd(){await api('/api/password',{method:'POST',body:JSON.stringify({oldPassword:document.getElementById('oldp').value,newPassword:document.getElementById('newp').value})});alert('密码已修改');document.querySelector('.modal').remove()}
loading();load();setInterval(()=>{if(state.data)load()},10000);
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
            else:
                self.send_json({"error": "not found"}, 404)
                return
            self.send_json({"ok": True})
        except Exception as e:
            self.send_json({"error": str(e)}, 400)


if __name__ == "__main__":
    ensure_auth()
    migrate_legacy_data()
    print(f"nft-manager web listening on {HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
