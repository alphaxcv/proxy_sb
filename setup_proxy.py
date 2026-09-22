#!/usr/bin/env python3
"""setup_proxy.py - 解析节点链接并启动 sing-box (SOCKS :1080 / HTTP :1081)

支持协议: vless, vmess, trojan, ss, hysteria2 (hy2), tuic

环境变量:
  NODE_LINK        节点链接；为空则直连
  SINGBOX_VERSION  固定 sing-box 版本，如 1.13.14；为空则取最新稳定版
"""

import base64
import ipaddress
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tarfile
import time
import urllib.request
from urllib.parse import parse_qs, unquote, urlparse

BIN = "./sing-box"
CONFIG = "sing-box-config.json"
LOG_FILE = "sing-box.log"
SOCKS_PORT = 1080
HTTP_PORT = 1081
FALLBACK_VERSION = "1.14.0"

# 默认 uTLS 指纹。"chrome" 在部分 sing-box 版本里会带上后量子曲线，
# 本地握手直接报 "CurvePreferences includes unsupported curve"，所以默认用 firefox。
# 链接里显式写了 fp= 时以链接为准。
DEFAULT_FINGERPRINT = "firefox"

ARCHS = {
    "x86_64": "amd64", "amd64": "amd64",
    "i386": "386", "i686": "386", "x86": "386",
    "aarch64": "arm64", "arm64": "arm64",
    "armv7l": "armv7", "s390x": "s390x",
}


# --------------------------------------------------------------------------- #
# 通用工具
# --------------------------------------------------------------------------- #

def log(msg: str) -> None:
    print(msg, flush=True)


def die(msg: str) -> None:
    log(f"[ERROR] {msg}")
    sys.exit(1)


def append_line(env_var: str, line: str) -> None:
    path = os.environ.get(env_var)
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def write_result(key: str, value: str) -> None:
    append_line("GITHUB_ENV", f"{key}={value}")
    append_line("GITHUB_OUTPUT", f"{key.lower()}={value}")


def b64_decode(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def mask_ip(ip: str) -> str:
    """IP 只保留前两段（1.2.*.* / 2001:db8:*）；域名原样返回"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 4:
        return ".".join(ip.split(".")[:2] + ["*", "*"])
    return ":".join(addr.exploded.split(":")[:2]) + ":*"


# --------------------------------------------------------------------------- #
# sing-box 安装
# --------------------------------------------------------------------------- #

def resolve_version() -> str:
    pinned = os.environ.get("SINGBOX_VERSION", "").strip().lstrip("v")
    if pinned:
        log(f"[INFO] 使用指定版本: v{pinned}")
        return pinned

    log("[INFO] 获取 sing-box 最新稳定版本...")
    try:
        req = urllib.request.Request(
            "https://api.github.com/repos/SagerNet/sing-box/releases",
            headers={"User-Agent": "setup-proxy-script"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            for rel in json.loads(resp.read().decode()):
                if not rel.get("prerelease") and not rel.get("draft"):
                    return rel["tag_name"].lstrip("v")
    except Exception as e:
        log(f"[WARN] 获取版本失败，回退到 {FALLBACK_VERSION}: {e}")
    return FALLBACK_VERSION


def installed_version() -> str | None:
    if not os.path.exists(BIN):
        return None
    try:
        out = subprocess.run([BIN, "version"], capture_output=True, text=True, timeout=10).stdout
        parts = out.split()
        return parts[2] if out.startswith("sing-box version") and len(parts) > 2 else None
    except Exception:
        return None


def ensure_singbox(version: str) -> None:
    if installed_version() == version:
        log(f"[INFO] 本地已有 sing-box v{version}，跳过下载")
        return

    machine = platform.machine().lower()
    arch = ARCHS.get(machine) or die(f"不支持的架构: {machine}")
    name = f"sing-box-{version}-linux-{arch}"
    url = f"https://github.com/SagerNet/sing-box/releases/download/v{version}/{name}.tar.gz"

    log(f"[INFO] 下载 {url}")
    try:
        urllib.request.urlretrieve(url, f"{name}.tar.gz")
    except Exception as e:
        die(f"下载失败（版本号是否存在？）: {e}")

    with tarfile.open(f"{name}.tar.gz") as tar:
        # filter 参数 Python 3.12 才有（3.10/3.11 的新补丁版也有）
        tar.extractall(**({"filter": "data"} if hasattr(tarfile, "data_filter") else {}))
    shutil.move(f"{name}/sing-box", BIN)
    shutil.rmtree(name, ignore_errors=True)
    os.remove(f"{name}.tar.gz")
    os.chmod(BIN, 0o755)


# --------------------------------------------------------------------------- #
# 节点链接 -> sing-box outbound
# --------------------------------------------------------------------------- #

def split_link(link: str):
    u = urlparse(link)
    q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
    return u, q


def is_insecure(q: dict) -> bool:
    return any(q.get(k, "").lower() in ("1", "true") for k in ("insecure", "allowInsecure", "allow_insecure"))


def base_outbound(kind: str, server: str, port: int | None) -> dict:
    return {"type": kind, "tag": "proxy", "server": server, "server_port": int(port or 443)}


def tls_block(server_name: str, insecure: bool = False, fingerprint: str | None = None,
              alpn: list[str] | None = None) -> dict:
    tls = {"enabled": True, "server_name": server_name, "insecure": insecure}
    if fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    if alpn:
        tls["alpn"] = alpn
    return tls


def set_transport(ob: dict, kind: str, path: str, host: str, service_name: str) -> None:
    if kind in ("", "tcp"):
        return
    if kind == "grpc":
        ob["transport"] = {"type": "grpc", "service_name": service_name}
        return
    ob["transport"] = {"type": kind, "path": path or "/"}
    if host:
        ob["transport"]["headers"] = {"Host": host}


def query_transport(ob: dict, q: dict, server: str) -> None:
    path = q.get("path", "/") or "/"
    set_transport(
        ob,
        q.get("type", "tcp"),
        path,
        q.get("host") or server,
        q.get("serviceName") or path.lstrip("/"),  # gRPC 服务名是独立字段
    )


def parse_vless(link: str) -> dict:
    u, q = split_link(link)
    ob = base_outbound("vless", u.hostname, u.port)
    ob["uuid"] = unquote(u.username or "")
    if q.get("flow"):
        ob["flow"] = q["flow"]
    query_transport(ob, q, u.hostname)

    security = q.get("security", "none")
    if security in ("tls", "reality"):
        tls = tls_block(q.get("sni") or u.hostname, is_insecure(q), q.get("fp") or None)
        if security == "reality":
            tls["reality"] = {
                "enabled": True,
                "public_key": q.get("pbk", ""),
                "short_id": q.get("sid", ""),
            }
        ob["tls"] = tls
    return ob


def parse_vmess(link: str) -> dict:
    try:
        d = json.loads(b64_decode(link[len("vmess://"):]))
    except Exception:
        die("VMess 链接解码失败")
    server = d.get("add", "")
    ob = base_outbound("vmess", server, int(d.get("port", 443)))
    ob.update(uuid=d.get("id", ""), security="auto", alter_id=int(d.get("aid", 0) or 0))

    path = d.get("path") or ""
    set_transport(ob, d.get("net") or "tcp", path.split("?")[0] or "/",
                  d.get("host") or server, path.lstrip("/"))
    if d.get("tls") == "tls":
        ob["tls"] = tls_block(d.get("sni") or server, False, d.get("fp") or DEFAULT_FINGERPRINT)
    return ob


def parse_trojan(link: str) -> dict:
    u, q = split_link(link)
    ob = base_outbound("trojan", u.hostname, u.port)
    ob["password"] = unquote(u.username or "")
    query_transport(ob, q, u.hostname)
    # trojan 默认走 TLS，只有显式 security=none 才关闭
    if q.get("security", "tls") != "none":
        ob["tls"] = tls_block(q.get("sni") or q.get("peer") or u.hostname,
                              is_insecure(q), q.get("fp") or DEFAULT_FINGERPRINT)
    return ob


def parse_shadowsocks(link: str) -> dict:
    u, q = split_link(link)
    try:
        if u.hostname and u.username:
            server, port = u.hostname, u.port
            if u.password is None:  # SIP002: ss://BASE64(method:password)@host:port
                method, password = b64_decode(u.username).decode().split(":", 1)
            else:                   # 明文 method:password
                method, password = unquote(u.username), unquote(u.password)
        else:                       # 旧格式: ss://BASE64(method:password@host:port)
            body = link[len("ss://"):].split("#", 1)[0].split("?", 1)[0]
            creds, hostport = b64_decode(body).decode().rsplit("@", 1)
            method, password = creds.split(":", 1)
            server, port = hostport.rsplit(":", 1)
    except Exception:
        die("Shadowsocks 链接解析失败")

    ob = base_outbound("shadowsocks", server, int(port))
    ob.update(method=method, password=password)
    if q.get("plugin"):  # 形如 obfs-local;obfs=http;obfs-host=example.com
        plugin, _, opts = q["plugin"].partition(";")
        ob["plugin"] = plugin
        if opts:
            ob["plugin_opts"] = opts
    return ob


def parse_hysteria2(link: str) -> dict:
    u, q = split_link(link)
    ob = base_outbound("hysteria2", u.hostname, u.port)
    password = unquote(u.username or "")
    if u.password:  # user:pass 认证形式
        password += ":" + unquote(u.password)
    ob["password"] = password

    obfs_password = q.get("obfs-password") or q.get("obfs_password")
    if obfs_password:
        ob["obfs"] = {"type": q.get("obfs") or "salamander", "password": obfs_password}
    ob["tls"] = tls_block(q.get("sni") or q.get("peer") or u.hostname, is_insecure(q))
    return ob


def parse_tuic(link: str) -> dict:
    u, q = split_link(link)
    ob = base_outbound("tuic", u.hostname, u.port)
    ob["uuid"] = unquote(u.username or "")
    if u.password:
        ob["password"] = unquote(u.password)
    ob["congestion_control"] = q.get("congestion_control") or "bbr"
    ob["udp_relay_mode"] = q.get("udp_relay_mode") or "native"
    alpn = [a for a in q.get("alpn", "h3").split(",") if a] or ["h3"]
    ob["tls"] = tls_block(q.get("sni") or u.hostname, is_insecure(q), alpn=alpn)
    return ob


PARSERS = {
    "vless": parse_vless,
    "vmess": parse_vmess,
    "trojan": parse_trojan,
    "ss": parse_shadowsocks,
    "hysteria2": parse_hysteria2,
    "hy2": parse_hysteria2,
    "tuic": parse_tuic,
}


# --------------------------------------------------------------------------- #
# 配置与进程
# --------------------------------------------------------------------------- #

def build_config(outbound: dict) -> dict:
    return {
        "log": {"level": "warn"},
        # 只配一个 DNS server：sing-box >= 1.14 下多个 server 时，
        # 域名节点必须额外指定 domain_resolver，单个则无需。
        "dns": {"servers": [{"tag": "local", "type": "local"}], "strategy": "ipv4_only"},
        "inbounds": [
            {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": SOCKS_PORT},
            {"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": HTTP_PORT},
        ],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {"final": "proxy"},
    }


def port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def start_singbox() -> subprocess.Popen:
    # 先用 check 校验配置，报错信息比运行时日志更直接
    check = subprocess.run([BIN, "check", "-c", CONFIG], capture_output=True, text=True)
    if check.returncode != 0:
        die(f"配置校验失败:\n{check.stdout}{check.stderr}")

    # 用 -x 精确匹配进程名，避免 -f 误杀命令行里带 sing-box 字样的 shell
    subprocess.run(["pkill", "-x", "sing-box"], stderr=subprocess.DEVNULL)
    time.sleep(1)

    with open(LOG_FILE, "wb") as f:
        proc = subprocess.Popen([BIN, "run", "-c", CONFIG], stdout=f, stderr=subprocess.STDOUT,
                                start_new_session=True)

    for _ in range(20):  # 最多等 10 秒
        if proc.poll() is not None:
            die(f"sing-box 启动后退出 (code {proc.returncode})")
        if port_open(HTTP_PORT):
            return proc
        time.sleep(0.5)
    proc.terminate()
    die("sing-box 端口未在 10 秒内就绪")


def test_proxy() -> bool:
    log("[INFO] 测试代理连接...")
    for i in range(1, 4):
        r = subprocess.run(
            ["curl", "-sS", "--max-time", "15", "-x", f"http://127.0.0.1:{HTTP_PORT}",
             "https://api.ipify.org"],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            log(f"[INFO] 出口 IP: {mask_ip(r.stdout.strip())}")
            return True
        # curl 退出码: 28=超时, 35=TLS 握手失败, 56=连接被重置
        log(f"[WARN] 尝试 {i}/3 失败 (curl {r.returncode}): {r.stderr.strip()}")
        time.sleep(3)
    return False


def main() -> None:
    link = os.environ.get("NODE_LINK", "").strip()
    if not link:
        log("[INFO] 未配置代理，直连模式")
        write_result("IS_PROXY", "false")
        return

    proto = link.split("://", 1)[0].lower()
    parser = PARSERS.get(proto) or die(f"不支持的协议: {proto}，支持: {', '.join(sorted(PARSERS))}")
    outbound = parser(link)
    log(f"[INFO] 节点: {outbound['type']} {mask_ip(outbound['server'])}:{outbound['server_port']}")

    with open(CONFIG, "w", encoding="utf-8") as f:
        json.dump(build_config(outbound), f, ensure_ascii=False, indent=2)

    ensure_singbox(resolve_version())
    proc = start_singbox()

    if test_proxy():
        log("[INFO] ✓ 代理连接成功")
        write_result("IS_PROXY", "true")
        write_result("PROXY_SERVER", f"http://127.0.0.1:{HTTP_PORT}")
        return

    proc.terminate()
    log("[ERROR] ✗ 代理连接失败\n---- sing-box 日志 ----")
    with open(LOG_FILE, encoding="utf-8", errors="replace") as f:
        print(f.read())
    sys.exit(1)


if __name__ == "__main__":
    main()
