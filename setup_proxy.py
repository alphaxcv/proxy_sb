#!/usr/bin/env python3
"""
setup_proxy.py - 自适应多协议代理节点解析并启动 sing-box (严格匹配 v1.14.0 官方 Schema)

支持协议: vless, vmess, trojan, shadowsocks (ss://), hysteria2 (hysteria2:// / hy2://), tuic
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
        # filter="data" 是 Python 3.12 才加入的参数，老版本 Python（如 Ubuntu 22.04
        # 自带的 3.10）传这个参数会直接 TypeError，导致整个脚本崩溃。做兼容判断。
        try:
            tar.extractall(filter="data")
        except TypeError:
            tar.extractall()
    extracted_dir = f"sing-box-{version}-linux-{arch}"
    shutil.move(os.path.join(extracted_dir, "sing-box"), "./sing-box")
    os.remove(fname)
    shutil.rmtree(extracted_dir, ignore_errors=True)
    os.chmod("./sing-box", 0o755)

def parse_query(qs: str) -> dict:
    parsed = parse_qs(qs, keep_blank_values=True)
    return {k: unquote(v[0]) for k, v in parsed.items()}

# 默认 uTLS 指纹。
#
# 之前默认用 "chrome"（对应 utls 的 HelloChrome_Auto，即"最新 Chrome"）。
# 目前 sing-box 1.14.0 打包的 utls 版本里，这个"最新 Chrome"预设已经带上了
# Chrome 现在默认启用的后量子混合密钥交换（X25519MLKEM768）。但同一版本里
# 负责真正握手的底层 TLS 栈还没完全跟上这个新曲线 ID，于是在本地建连阶段
# 就直接报 "tls: CurvePreferences includes unsupported curve"——不需要
# 服务端响应，纯本地校验失败，所以重试多少次都一样，100% 必现。
# 官方 GitHub 上能查到同类报告（chrome_pq 预设的类似问题），firefox/edge
# 等预设不带这个新曲线，握手是正常的。所以把默认指纹换成 "firefox"。
# 如果你的节点链接里显式带了 fp= 参数，这里不受影响，照样用你指定的值。
DEFAULT_FINGERPRINT = "firefox"

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
        # gRPC 的服务名是单独的 query key（Xray 用 serviceName），不是 path。
        # 之前代码把它俩混为一谈，gRPC 节点必然连不上。
        "service_name": q.get("serviceName", "") or q.get("path", "").lstrip("/"),
        "host": q.get("host") or server,
        "security": q.get("security", "none"),
        "sni": q.get("sni") or server,
        "fingerprint": q.get("fp", DEFAULT_FINGERPRINT) or DEFAULT_FINGERPRINT,
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
        "service_name": decoded.get("path", "").lstrip("/"),
        "host": decoded.get("host") or server,
        "security": decoded.get("tls", ""),
        "sni": decoded.get("sni") or server,
        "fingerprint": decoded.get("fp", DEFAULT_FINGERPRINT) or DEFAULT_FINGERPRINT,
        "insecure": False,
    }

def parse_trojan(link: str) -> dict:
    u = urlparse(link)
    q = parse_query(u.query)
    insecure = q.get("allowInsecure", "").lower() in ("1", "true") or q.get("insecure", "").lower() in ("1", "true")
    server = u.hostname
    # trojan 默认就是跑在 TLS 上的（这是它的协议设计前提），只有显式
    # security=none 才当作明文 trojan-go 处理。
    security = q.get("security", "tls") or "tls"
    return {
        "type": "trojan",
        "server": server,
        "server_port": u.port or 443,
        "password": unquote(u.username or ""),
        "transport_type": q.get("type", "tcp") or "tcp",
        "path": q.get("path", "/") or "/",
        "service_name": q.get("serviceName", "") or q.get("path", "").lstrip("/"),
        "host": q.get("host") or server,
        "security": security,
        "sni": q.get("sni") or q.get("peer") or server,
        "fingerprint": q.get("fp", DEFAULT_FINGERPRINT) or DEFAULT_FINGERPRINT,
        "insecure": insecure,
    }

def parse_shadowsocks(link: str) -> dict:
    u = urlparse(link)
    q = parse_query(u.query)
    server = u.hostname
    server_port = u.port
    method = password = None

    if server and u.username and u.password is None:
        # SIP002: ss://BASE64(method:password)@server:port
        try:
            decoded = b64_decode(u.username).decode("utf-8")
            method, password = decoded.split(":", 1)
        except Exception:
            pass
    elif server and u.username and u.password is not None:
        # 极少数客户端会直接明文写 method:password（未 base64）
        method, password = unquote(u.username), unquote(u.password)

    if method is None:
        # 旧式格式: ss://BASE64(method:password@server:port)
        raw = link[len("ss://"):].split("#", 1)[0].split("?", 1)[0]
        try:
            decoded = b64_decode(raw).decode("utf-8")
            creds, hostport = decoded.rsplit("@", 1)
            method, password = creds.split(":", 1)
            server, server_port = hostport.rsplit(":", 1)
        except Exception:
            log("[ERROR] Shadowsocks 链接解析失败")
            sys.exit(1)

    if not (method and password and server and server_port):
        log("[ERROR] Shadowsocks 链接缺少必要字段")
        sys.exit(1)

    return {
        "type": "shadowsocks",
        "server": server,
        "server_port": int(server_port),
        "method": method,
        "password": password,
        "plugin": q.get("plugin", ""),
        "plugin_opts": q.get("plugin-opts", ""),
    }

def parse_hysteria2(link: str) -> dict:
    u = urlparse(link)
    q = parse_query(u.query)
    insecure = q.get("insecure", "").lower() in ("1", "true") or q.get("allowInsecure", "").lower() in ("1", "true")
    server = u.hostname
    return {
        "type": "hysteria2",
        "server": server,
        "server_port": u.port or 443,
        "password": unquote(u.username or ""),
        "sni": q.get("sni") or q.get("peer") or server,
        "insecure": insecure,
        "obfs_type": q.get("obfs", ""),
        "obfs_password": q.get("obfs-password", "") or q.get("obfs_password", ""),
    }

def parse_tuic(link: str) -> dict:
    u = urlparse(link)
    q = parse_query(u.query)
    insecure = q.get("allow_insecure", "").lower() in ("1", "true") or q.get("insecure", "").lower() in ("1", "true")
    server = u.hostname
    alpn_raw = q.get("alpn", "h3")
    alpn_list = [a for a in alpn_raw.split(",") if a] or ["h3"]
    return {
        "type": "tuic",
        "server": server,
        "server_port": u.port or 443,
        "uuid": unquote(u.username or ""),
        "password": unquote(u.password or ""),
        "congestion_control": q.get("congestion_control", "bbr") or "bbr",
        "udp_relay_mode": q.get("udp_relay_mode", "native") or "native",
        "sni": q.get("sni") or server,
        "insecure": insecure,
        "alpn_list": alpn_list,
    }

PARSERS = {
    "vless": parse_vless,
    "vmess": parse_vmess,
    "trojan": parse_trojan,
    "ss": parse_shadowsocks,
    "hysteria2": parse_hysteria2,
    "hy2": parse_hysteria2,
    "tuic": parse_tuic,
}

def build_outbound(node: dict) -> dict:
    t = node["type"]
    ob = {
        "type": t,
        "tag": "proxy",
        "server": node["server"],
        "server_port": int(node["server_port"]),
    }

    transport_type = node.get("transport_type", "tcp")

    def apply_transport():
        if transport_type == "tcp":
            return
        if transport_type == "grpc":
            # gRPC transport 用 service_name 字段，不是 path/headers。
            ob["transport"] = {
                "type": "grpc",
                "service_name": node.get("service_name") or "",
            }
            return
        # ws / httpupgrade 等走 path + Host header 的模式
        ob["transport"] = {
            "type": transport_type,
            "path": node.get("path", "/"),
        }
        if node.get("host"):
            ob["transport"]["headers"] = {"Host": node["host"]}

    if t == "vless":
        ob["uuid"] = node["uuid"]
        if node.get("flow"): ob["flow"] = node["flow"]
        apply_transport()

        tls_enabled = node.get("security") in ("tls", "reality")
        if tls_enabled:
            tls = {
                "enabled": True,
                "server_name": node.get("sni", ""),
                "insecure": node.get("insecure", False),
                "utls": {"enabled": True, "fingerprint": node.get("fingerprint", DEFAULT_FINGERPRINT)},
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
        apply_transport()

        tls_enabled = node.get("security") == "tls"
        if tls_enabled:
            ob["tls"] = {
                "enabled": True,
                "server_name": node.get("sni", ""),
                "insecure": node.get("insecure", False),
                "utls": {"enabled": True, "fingerprint": node.get("fingerprint", DEFAULT_FINGERPRINT)},
            }

    elif t == "trojan":
        ob["password"] = node["password"]
        apply_transport()
        # trojan 只有显式 security=none 才不套 TLS
        if node.get("security", "tls") != "none":
            ob["tls"] = {
                "enabled": True,
                "server_name": node.get("sni", ""),
                "insecure": node.get("insecure", False),
                "utls": {"enabled": True, "fingerprint": node.get("fingerprint", DEFAULT_FINGERPRINT)},
            }

    elif t == "shadowsocks":
        ob["method"] = node["method"]
        ob["password"] = node["password"]
        if node.get("plugin"):
            ob["plugin"] = node["plugin"]
            if node.get("plugin_opts"):
                ob["plugin_opts"] = node["plugin_opts"]

    elif t == "hysteria2":
        ob["password"] = node["password"]
        if node.get("obfs_password"):
            ob["obfs"] = {
                "type": node.get("obfs_type") or "salamander",
                "password": node["obfs_password"],
            }
        # hysteria2 的 tls 是必填字段，没有就直接 schema 校验失败
        ob["tls"] = {
            "enabled": True,
            "server_name": node.get("sni", ""),
            "insecure": node.get("insecure", False),
        }

    elif t == "tuic":
        ob["uuid"] = node["uuid"]
        if node.get("password"):
            ob["password"] = node["password"]
        ob["congestion_control"] = node.get("congestion_control", "bbr")
        ob["udp_relay_mode"] = node.get("udp_relay_mode", "native")
        # tuic 的 tls 同样必填
        ob["tls"] = {
            "enabled": True,
            "server_name": node.get("sni", ""),
            "insecure": node.get("insecure", False),
            "alpn": node.get("alpn_list", ["h3"]),
        }

    return ob

def build_config(outbound: dict) -> dict:
    return {
        "log": {"level": "warn"},
        # sing-box >= 1.14.0: 若 dns.servers 配置了 2 个或以上服务器，
        # 每个用到域名地址的 outbound 就必须显式指定 domain_resolver（或用
        # route.default_domain_resolver 兜底），否则启动阶段直接报错 /
        # 域名解析失败，代理测试必然超时。
        # 原脚本同时配置了 google + cloudflare 两个 DNS，但既没给 outbound
        # 加 domain_resolver，也没设置 route.default_domain_resolver ——
        # 只要节点用的是域名（绝大多数机场/CDN 节点都是），这里就直接炸。
        # 修复方式：只保留一个 DNS server（走系统解析器），这样按官方文档
        # domain_resolver 变为可选，不需要节点数量所限的所有 outbound 一一去加。
        "dns": {
            "servers": [
                {"tag": "local", "type": "local"}
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
        log(f"[ERROR] 不支持的协议: {proto}，目前支持: {', '.join(sorted(set(PARSERS)))}")
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
