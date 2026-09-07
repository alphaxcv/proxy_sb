#!/usr/bin/env python3
"""
setup_proxy.py - 自适应多协议代理节点解析并启动 sing-box (严格适配 v1.14.0 官方最新 Schema)
"""

import base64
import json
import os
import platform
import subprocess
import sys
import tarfile
import time
import urllib.request
from urllib.parse import urlparse, parse_qs, unquote
import shutil

def log(msg: str) -> None:
    print(msg, flush=True)

def write_github_env(key: str, value: str) -> None:
    gh_env = os.environ.get("GITHUB_ENV")
    if not gh_env: return
    with open(gh_env, "a", encoding="utf-8") as f:
        f.write(f"{key}={value}\n")

def write_github_output(key: str, value: str) -> None:
    gh_output = os.environ.get("GITHUB_OUTPUT")
    if not gh_output: return
    with open(gh_output, "a", encoding="utf-8") as f:
        f.write(f"{key}={value}\n")

def write_result(key: str, value: str) -> None:
    write_github_env(key, value)
    write_github_output(key.lower(), value)

def b64_decode(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    pad = len(s) % 4
    if pad: s += "=" * (4 - pad)
    return base64.b64decode(s)

def get_arch() -> str:
    m = platform.machine().lower()
    mapping = {
        "x86_64": "amd64", "amd64": "amd64",
        "x86": "386", "i686": "386", "i386": "386",
        "aarch64": "arm64", "arm64": "arm64",
        "armv7l": "armv7", "s390x": "s390x",
    }
    if m not in mapping:
        log(f"[ERROR] 不支持的架构: {m}")
        sys.exit(1)
    return mapping[m]

FALLBACK_VERSION = "1.14.0"

def get_latest_singbox_version() -> str:
    log("[INFO] 获取 sing-box 最新版本...")
    try:
        req = urllib.request.Request(
            "https://api.github.com/repos/SagerNet/sing-box/releases",
            headers={"User-Agent": "setup-proxy-script"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            releases = json.loads(resp.read().decode())
        for rel in releases:
            if not rel.get("prerelease", False):
                return rel.get("tag_name", "").lstrip("v")
    except Exception as e:
        log(f"[WARN] 获取版本失败: {e}")
    return FALLBACK_VERSION

def download_singbox(version: str, arch: str) -> None:
    fname = f"sing-box-{version}-linux-{arch}.tar.gz"
    url = f"https://github.com/SagerNet/sing-box/releases/download/v{version}/{fname}"
    log(f"[INFO] 最新稳定版本: v{version}")
    log(f"[INFO] 下载 {url}")
    urllib.request.urlretrieve(url, fname)
    with tarfile.open(fname) as tar:
        tar.extractall(filter="data")
    extracted_dir = f"sing-box-{version}-linux-{arch}"
    shutil.move(os.path.join(extracted_dir, "sing-box"), "./sing-box")
    os.remove(fname)
    shutil.rmtree(extracted_dir, ignore_errors=True)
    os.chmod("./sing-box", 0o755)

def parse_query(qs: str) -> dict:
    parsed = parse_qs(qs, keep_blank_values=True)
    return {k: unquote(v[0]) for k, v in parsed.items()}

def parse_vless(link: str) -> dict:
    u = urlparse(link)
    q = parse_query(u.query)
    insecure = q.get("insecure", "").lower() in ("1", "true") or q.get("allowInsecure", "").lower() in ("1", "true")
    server = u.hostname
    return {
        "type": "vless",
        "server": server,
        "server_port": u.port,
        "uuid": u.username or "",
        "flow": q.get("flow", ""),
        "transport_type": q.get("type", "tcp") or "tcp",
        "path": q.get("path", "/") or "/",
        "host": q.get("host") or server,
        "security": q.get("security", "none"),
        "sni": q.get("sni") or server,
        "fingerprint": q.get("fp", "chrome") or "chrome",
        "reality_pbk": q.get("pbk", ""),
        "reality_sid": q.get("sid", ""),
        "insecure": insecure,
    }

def parse_vmess(link: str) -> dict:
    raw = link[len("vmess://"):]
    try:
        decoded = json.loads(b64_decode(raw).decode("utf-8"))
    except Exception:
        log("[ERROR] VMess 解码失败")
        sys.exit(1)
    server = decoded.get("add", "")
    return {
        "type": "vmess",
        "server": server,
        "server_port": int(decoded.get("port", 443)),
        "uuid": decoded.get("id", ""),
        "alter_id": int(decoded.get("aid", 0) or 0),
        "transport_type": decoded.get("net", "tcp") or "tcp",
        "path": (decoded.get("path", "/") or "/").split("?")[0],
        "host": decoded.get("host") or server,
        "security": decoded.get("tls", ""),
        "sni": decoded.get("sni") or server,
        "fingerprint": decoded.get("fp", "chrome") or "chrome",
        "insecure": False,
    }

PARSERS = {
    "vless": parse_vless,
    "vmess": parse_vmess,
}

def build_outbound(node: dict) -> dict:
    t = node["type"]
    ob = {
        "type": t,
        "tag": "proxy",
        "server": node["server"],
        "server_port": int(node["server_port"]),
        "domain_strategy": "ipv4_only",
    }

    if t == "vless":
        ob["uuid"] = node["uuid"]
        if node.get("flow"): ob["flow"] = node["flow"]
        
        if node.get("transport_type", "tcp") != "tcp":
            ob["transport"] = {
                "type": node["transport_type"],
                "path": node.get("path", "/"),
            }
            if node.get("host"):
                ob["transport"]["headers"] = {"Host": node["host"]}

        tls_enabled = node.get("security") in ("tls", "reality")
        if tls_enabled:
            tls = {
                "enabled": True,
                "server_name": node.get("sni", ""),
                "insecure": node.get("insecure", False),
                "utls": {"enabled": True, "fingerprint": node.get("fingerprint", "chrome")},
            }
            if node.get("security") == "reality":
                tls["reality"] = {
                    "enabled": True,
                    "public_key": node.get("reality_pbk", ""),
                    "short_id": node.get("reality_sid", ""),
                }
            ob["tls"] = tls

    elif t == "vmess":
        ob["uuid"] = node["uuid"]
        ob["security"] = "auto"
        if node.get("transport_type", "tcp") != "tcp":
            ob["transport"] = {
                "type": node.get("transport_type", "tcp"),
                "path": node.get("path", "/"),
            }
            if node.get("host"):
                ob["transport"]["headers"] = {"Host": node["host"]}
        
        tls_enabled = node.get("security") == "tls"
        if tls_enabled:
            ob["tls"] = {
                "enabled": True,
                "server_name": node.get("sni", ""),
                "insecure": node.get("insecure", False),
                "utls": {"enabled": True, "fingerprint": node.get("fingerprint", "chrome")},
            }
            
    return ob

# 严格遵循 sing-box 1.14.0 最新 DNS Schema（使用 type: udp 并提供 address 字段）
def build_config(outbound: dict) -> dict:
    return {
        "log": {"level": "warn"},
        "dns": {
            "servers": [
                {
                    "tag": "google",
                    "type": "udp",
                    "address": "8.8.8.8"
                },
                {
                    "tag": "cloudflare",
                    "type": "udp",
                    "address": "1.1.1.1"
                }
            ],
            "strategy": "ipv4_only"
        },
        "inbounds": [
            {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080},
            {"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": 1081},
        ],
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"}
        ]
    }

def kill_existing_singbox() -> None:
    subprocess.run(["pkill", "-f", "sing-box"], stderr=subprocess.DEVNULL)
    subprocess.run(["fuser", "-k", "1080/tcp", "1081/tcp"], stderr=subprocess.DEVNULL)
    time.sleep(2)

def start_singbox() -> subprocess.Popen:
    log_file = open("sing-box.log", "wb")
    proc = subprocess.Popen(["./sing-box", "run", "-c", "sing-box-config.json"], stdout=log_file, stderr=subprocess.STDOUT)
    time.sleep(5)
    return proc

def test_proxy() -> bool:
    log("[INFO] 测试代理连接...")
    for i in range(1, 4):
        result = subprocess.run(
            ["curl", "-x", "http://127.0.0.1:1081", "-s", "--max-time", "15", "https://api.ipify.org"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            return True
        log(f"[WARN] 尝试 {i}/3...")
        time.sleep(3)
    return False

def main() -> None:
    node_link = os.environ.get("NODE_LINK", "").strip()
    if not node_link:
        log("[INFO] 未配置代理，直连模式")
        write_result("IS_PROXY", "false")
        return

    proto = node_link.split("://", 1)[0].lower()
    parser = PARSERS.get(proto)
    if not parser:
        log(f"[ERROR] 不支持的协议: {proto}")
        sys.exit(1)

    node = parser(node_link)
    outbound = build_outbound(node)
    config = build_config(outbound)

    with open("sing-box-config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

    if not os.path.exists("./sing-box"):
        download_singbox(get_latest_singbox_version(), get_arch())

    kill_existing_singbox()
    start_singbox()

    if test_proxy():
        log("[INFO] ✓ 代理连接成功")
        write_result("IS_PROXY", "true")
        write_result("PROXY_SERVER", "http://127.0.0.1:1081")
        return

    log("[ERROR] ✗ 代理连接失败\n---- sing-box 日志 ----")
    if os.path.exists("sing-box.log"):
        with open("sing-box.log", encoding="utf-8", errors="replace") as f: 
            print(f.read())
    sys.exit(1)

if __name__ == "__main__":
    main()
