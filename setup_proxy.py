#!/usr/bin/env python3
"""
setup_proxy.py - 自适应多协议代理节点解析并启动 sing-box

支持协议: vless, vmess, trojan, hysteria2/hy2, tuic, anytls, socks5/socks

用法:
    export NODE_LINK="vless://uuid@host:port?..."
    python3 setup_proxy.py

行为:
    - 无 NODE_LINK 时直连，写 IS_PROXY=false 到 $GITHUB_ENV
    - 有 NODE_LINK 时解析 -> 生成 sing-box-config.json -> 下载/复用 sing-box 二进制
      -> 启动 -> 测试出网 -> 写 IS_PROXY=true / PROXY_SERVER 到 $GITHUB_ENV
"""

import base64
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
from urllib.parse import urlparse, parse_qs, unquote


# --------------------------------------------------------------------------
# 工具函数
# --------------------------------------------------------------------------

def log(msg: str) -> None:
    print(msg, flush=True)


def write_github_env(key: str, value: str) -> None:
    gh_env = os.environ.get("GITHUB_ENV")
    if not gh_env:
        return
    with open(gh_env, "a", encoding="utf-8") as f:
        f.write(f"{key}={value}\n")


def write_github_output(key: str, value: str) -> None:
    """写入 $GITHUB_OUTPUT，供 composite action 的 outputs 使用"""
    gh_output = os.environ.get("GITHUB_OUTPUT")
    if not gh_output:
        return
    with open(gh_output, "a", encoding="utf-8") as f:
        f.write(f"{key}={value}\n")


def write_result(key: str, value: str) -> None:
    """同时写入 GITHUB_ENV（供后续 shell 步骤用 env 读取）
    和 GITHUB_OUTPUT（供 action outputs / 其它 job 用 steps.<id>.outputs 读取）"""
    write_github_env(key, value)
    write_github_output(key.lower(), value)


def b64_decode(s: str) -> bytes:
    """兼容不带 padding 的 base64/urlsafe base64"""
    s = s.strip()
    s = s.replace("-", "+").replace("_", "/")
    pad = len(s) % 4
    if pad:
        s += "=" * (4 - pad)
    return base64.b64decode(s)


def get_arch() -> str:
    m = platform.machine().lower()
    mapping = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "x86": "386",
        "i686": "386",
        "i386": "386",
        "aarch64": "arm64",
        "arm64": "arm64",
        "armv7l": "armv7",
        "s390x": "s390x",
    }
    if m not in mapping:
        log(f"[ERROR] 不支持的架构: {m}")
        sys.exit(1)
    return mapping[m]


# --------------------------------------------------------------------------
# sing-box 二进制下载
# --------------------------------------------------------------------------

FALLBACK_VERSION = "1.13.14"


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
                tag = rel.get("tag_name", "")
                return tag.lstrip("v")
    except Exception as e:
        log(f"[WARN] 获取版本失败: {e}")
    log(f"[ERROR] 无法获取 sing-box 最新版本, 将下载 {FALLBACK_VERSION}")
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


# --------------------------------------------------------------------------
# 协议解析：每个协议返回一个 dict，供 build_outbound() 统一转换为 sing-box outbound
# --------------------------------------------------------------------------

def parse_query(qs: str) -> dict:
    """parse_qs 但只取第一个值，且做 unquote"""
    parsed = parse_qs(qs, keep_blank_values=True)
    return {k: unquote(v[0]) for k, v in parsed.items()}


def parse_vless(link: str) -> dict:
    u = urlparse(link)
    q = parse_query(u.query)
    insecure = q.get("insecure", "").lower() in ("1", "true") or \
        q.get("allowInsecure", "").lower() in ("1", "true")
    server = u.hostname
    sni = q.get("sni") or server
    host = q.get("host") or server
    return {
        "type": "vless",
        "server": server,
        "server_port": u.port,
        "uuid": u.username or "",
        "flow": q.get("flow", ""),
        "transport_type": q.get("type", "tcp") or "tcp",
        "path": q.get("path", "/") or "/",
        "host": host,
        "security": q.get("security", "none"),
        "sni": sni,
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
        "scy": decoded.get("scy", "auto") or "auto",
        "insecure": False,
    }


def parse_trojan(link: str) -> dict:
    u = urlparse(link)
    q = parse_query(u.query)
    insecure = q.get("insecure", "").lower() in ("1", "true") or \
        q.get("allowInsecure", "").lower() in ("1", "true")
    server = u.hostname
    return {
        "type": "trojan",
        "server": server,
        "server_port": u.port,
        "password": u.username or "",
        "transport_type": q.get("type", "tcp") or "tcp",
        "path": q.get("path", "/") or "/",
        "host": q.get("host") or server,
        "sni": q.get("sni") or server,
        "fingerprint": q.get("fp", "chrome") or "chrome",
        "insecure": insecure,
    }


def parse_hysteria2(link: str) -> dict:
    # hysteria2://[auth@]host:port[/][?params]
    u = urlparse(link.replace("hy2://", "hysteria2://", 1))
    q = parse_query(u.query)
    insecure = q.get("insecure", "").lower() in ("1", "true") or \
        q.get("allowInsecure", "").lower() in ("1", "true")
    server = u.hostname
    return {
        "type": "hysteria2",
        "server": server,
        "server_port": u.port,
        "auth": u.username or "",
        "obfs_password": q.get("obfs", ""),
        "sni": q.get("sni") or server,
        "fingerprint": q.get("fp", "chrome") or "chrome",
        "insecure": insecure,
    }


def parse_tuic(link: str) -> dict:
    u = urlparse(link)
    q = parse_query(u.query)
    insecure = q.get("insecure", "").lower() in ("1", "true") or \
        q.get("allowInsecure", "").lower() in ("1", "true")
    server = u.hostname
    # userinfo 可能是 uuid:password 或用 %3A 编码
    userinfo = ""
    if u.username:
        userinfo = u.username
        if u.password:
            userinfo += ":" + u.password
    userinfo = unquote(userinfo)
    if ":" in userinfo:
        uuid, password = userinfo.split(":", 1)
    else:
        uuid, password = userinfo, ""
    return {
        "type": "tuic",
        "server": server,
        "server_port": u.port,
        "uuid": uuid,
        "password": password,
        "congestion_control": q.get("congestion_control", "bbr") or "bbr",
        "alpn": q.get("alpn", ""),
        "sni": q.get("sni") or server,
        "fingerprint": q.get("fp", "chrome") or "chrome",
        "insecure": insecure,
        "udp_over_stream": True,
        "zero_rtt": False,
    }


def parse_anytls(link: str) -> dict:
    u = urlparse(link)
    q = parse_query(u.query)
    insecure = q.get("insecure", "").lower() in ("1", "true") or \
        q.get("allowInsecure", "").lower() in ("1", "true")
    server = u.hostname
    return {
        "type": "anytls",
        "server": server,
        "server_port": u.port,
        "password": u.username or "",
        "sni": q.get("sni") or server,
        "fingerprint": q.get("fp", "chrome") or "chrome",
        "insecure": insecure,
    }


def parse_socks5(link: str) -> dict:
    u = urlparse(link.replace("socks://", "socks5://", 1))
    username = u.username or ""
    password = u.password or ""
    # 部分分享链接把 user:pass 整体 base64 放在 userinfo 位置（无 @ 前没有冒号时）
    if username and not password and "@" in link.split("://", 1)[1]:
        candidate = link.split("://", 1)[1].split("@", 1)[0]
        try:
            decoded = b64_decode(candidate).decode()
            if ":" in decoded:
                username, password = decoded.split(":", 1)
        except Exception:
            pass
    return {
        "type": "socks",
        "server": u.hostname,
        "server_port": u.port,
        "username": username,
        "password": password,
        "version": "5",
    }


PARSERS = {
    "vless": parse_vless,
    "vmess": parse_vmess,
    "trojan": parse_trojan,
    "hysteria2": parse_hysteria2,
    "hy2": parse_hysteria2,
    "tuic": parse_tuic,
    "anytls": parse_anytls,
    "socks5": parse_socks5,
    "socks": parse_socks5,
}


# --------------------------------------------------------------------------
# outbound 构建
# --------------------------------------------------------------------------

def build_tls(node: dict, extra_utls: bool = True) -> dict:
    tls = {
        "enabled": True,
        "server_name": node.get("sni", ""),
        "insecure": node.get("insecure", False),
    }
    if extra_utls:
        tls["utls"] = {"enabled": True, "fingerprint": node.get("fingerprint", "chrome")}
    return tls


def build_outbound(node: dict) -> dict:
    t = node["type"]
    ob = {
        "type": t,
        "tag": "proxy",
        "server": node["server"],
        "server_port": int(node["server_port"]),
    }

    if t == "vless":
        ob["uuid"] = node["uuid"]
        if node.get("flow"):
            ob["flow"] = node["flow"]
        if node.get("transport_type", "tcp") != "tcp":
            ob["transport"] = {
                "type": node["transport_type"],
                "path": node.get("path", "/"),
                "headers": {"Host": node.get("host", "")},
            }
        tls_enabled = node.get("security") in ("tls", "reality")
        tls = {
            "enabled": tls_enabled,
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
        ob["transport"] = {
            "type": node.get("transport_type", "tcp"),
            "path": node.get("path", "/"),
            "headers": {"Host": node.get("host", "")},
        }
        tls_enabled = node.get("security") == "tls"
        ob["tls"] = {
            "enabled": tls_enabled,
            "server_name": node.get("sni", ""),
            "insecure": node.get("insecure", False),
            "utls": {"enabled": True, "fingerprint": node.get("fingerprint", "chrome")},
        }

    elif t == "trojan":
        ob["password"] = node["password"]
        ob["transport"] = {
            "type": node.get("transport_type", "tcp"),
            "path": node.get("path", "/"),
            "headers": {"Host": node.get("host", "")},
        }
        ob["tls"] = build_tls(node)

    elif t == "hysteria2":
        ob["up_mbps"] = 100
        ob["down_mbps"] = 100
        if node.get("obfs_password"):
            ob["obfs"] = {"type": "salamander", "password": node["obfs_password"]}
        if node.get("auth"):
            ob["password"] = node["auth"]
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
        ob["udp_over_stream"] = node.get("udp_over_stream", True)
        ob["zero_rtt_handshake"] = node.get("zero_rtt", False)
        tls = {
            "enabled": True,
            "server_name": node.get("sni", ""),
            "insecure": node.get("insecure", False),
        }
        if node.get("alpn"):
            tls["alpn"] = [node["alpn"]]
        ob["tls"] = tls

    elif t == "anytls":
        ob["password"] = node["password"]
        ob["tls"] = build_tls(node)

    elif t == "socks":
        if node.get("username"):
            ob["username"] = node["username"]
        if node.get("password"):
            ob["password"] = node["password"]
        ob["version"] = node.get("version", "5")

    else:
        log(f"[ERROR] 不支持的协议: {t}")
        sys.exit(1)

    return ob


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------

def build_config(outbound: dict) -> dict:
    return {
        "log": {"level": "warn"},
        "inbounds": [
            {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 1080},
            {"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": 1081},
        ],
        "outbounds": [outbound],
    }


def kill_existing_singbox() -> None:
    log("[INFO] 清理旧进程...")
    subprocess.run(["pkill", "-f", "sing-box"], stderr=subprocess.DEVNULL)
    subprocess.run(["fuser", "-k", "1080/tcp"], stderr=subprocess.DEVNULL)
    time.sleep(2)


def start_singbox() -> subprocess.Popen:
    log_file = open("sing-box.log", "wb")
    proc = subprocess.Popen(
        ["./sing-box", "run", "-c", "sing-box-config.json"],
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    time.sleep(5)
    return proc


def is_singbox_running() -> bool:
    result = subprocess.run(["pgrep", "-f", "sing-box"], stdout=subprocess.DEVNULL)
    return result.returncode == 0


def test_proxy() -> bool:
    log("[INFO] 测试代理连接...")
    for i in range(1, 4):
        result = subprocess.run(
            ["curl", "-x", "socks5://127.0.0.1:1080", "-s", "--max-time", "15",
             "https://api.ipify.org"],
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

    log(f"[INFO] 协议: {proto}")
    node = parser(node_link)

    if not node.get("server") or not node.get("server_port"):
        log("[ERROR] 无法解析服务器地址或端口")
        sys.exit(1)

    outbound = build_outbound(node)
    config = build_config(outbound)

    with open("sing-box-config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

    # 校验 JSON 合法（其实是我们自己生成的，这里主要是二次确认）
    try:
        with open("sing-box-config.json", encoding="utf-8") as f:
            json.load(f)
    except json.JSONDecodeError:
        log("[ERROR] 生成的 sing-box 配置无效")
        sys.exit(1)

    log("[INFO] ✓ sing-box 配置已生成")

    # 确保有 sing-box 可执行文件
    if not os.path.exists("./sing-box"):
        pinned_version = os.environ.get("SINGBOX_VERSION", "").strip()
        version = pinned_version if pinned_version else get_latest_singbox_version()
        arch = get_arch()
        download_singbox(version, arch)

    kill_existing_singbox()
    start_singbox()

    if not is_singbox_running():
        log("[ERROR] sing-box 进程启动失败，查看日志:")
        if os.path.exists("sing-box.log"):
            with open("sing-box.log", encoding="utf-8", errors="replace") as f:
                print(f.read())
        sys.exit(1)

    if test_proxy():
        log("[INFO] ✓ 代理连接成功")
        write_result("IS_PROXY", "true")
        write_result("PROXY_SERVER", "socks5://127.0.0.1:1080")
        return

    log("[ERROR] ✗ 代理连接失败")
    write_result("IS_PROXY", "false")
    log("---- sing-box 日志 ----")
    if os.path.exists("sing-box.log"):
        with open("sing-box.log", encoding="utf-8", errors="replace") as f:
            print(f.read())
    sys.exit(1)


if __name__ == "__main__":
    main()
