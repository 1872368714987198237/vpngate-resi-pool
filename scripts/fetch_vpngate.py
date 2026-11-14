#!/usr/bin/env python3
"""
VPN Gate OpenVPN Scraper, Mihomo v1.19.25+ Compatibility Filter & ISP/Residential Classifier.

Zero third-party dependencies (Python 3.10+ standard library only).
Works in GitHub Actions (direct) or locally in Mainland China (via --proxy http://127.0.0.1:7897).
"""

from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import io
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

VPNGATE_URLS = [
    "https://www.vpngate.net/api/iphone/",
    "http://www.vpngate.net/api/iphone/",
]

IP_API_BATCH_URL = (
    "http://ip-api.com/batch"
    "?fields=query,status,message,countryCode,isp,org,as,asname,hosting,proxy"
)

SUPPORTED_CIPHERS = {
    "AES-128-CBC",
    "AES-192-CBC",
    "AES-256-CBC",
    "AES-128-GCM",
    "AES-192-GCM",
    "AES-256-GCM",
    "CHACHA20-POLY1305",
}

AEAD_CIPHERS = {
    "AES-128-GCM",
    "AES-192-GCM",
    "AES-256-GCM",
    "CHACHA20-POLY1305",
}

SUPPORTED_AUTHS = {"SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "MD5"}

DC_KEYWORDS = (
    "amazon",
    "aws",
    "google",
    "microsoft",
    "azure",
    "digitalocean",
    "linode",
    "akamai",
    "vultr",
    "choopa",
    "ovh",
    "hetzner",
    "oracle",
    "alibaba",
    "aliyun",
    "tencent",
    "huawei",
    "contabo",
    "scaleway",
    "leaseweb",
    "m247",
    "cloudflare",
    "datacamp",
    "cdn77",
    "cogent",
    "he.net",
    "hurricane electric",
    "hostinger",
    "ionos",
    "1&1",
    "upcloud",
    "kamatera",
    "racknerd",
    "buyvm",
    "frantech",
    "datacenter",
    "datacentre",
    "hosting",
    "cloud",
    "vps",
    "dedicated",
    "colocation",
    "server",
)

EDU_KEYWORDS = (
    "university",
    "tsukuba",
    "college",
    "academic",
    "education",
    "institute of",
    "research",
    "sinet",
    "nii.ac.jp",
    "edunet",
    "kreonet",
)


def build_opener(proxy: str | None) -> urllib.request.OpenerDirector:
    handlers: list[urllib.request.BaseHandler] = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)
    opener.addheaders = [
        (
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) mihomo-vpngate-pool/1.0",
        )
    ]
    return opener


def fetch_vpngate_csv(opener: urllib.request.OpenerDirector, timeout: int = 30) -> str:
    last_err: Exception | None = None
    for url in VPNGATE_URLS:
        try:
            with opener.open(url, timeout=timeout) as resp:
                raw = resp.read()
            text = raw.decode("utf-8", errors="replace")
            if "*vpn_servers" in text or "OpenVPN_ConfigData_Base64" in text:
                return text
            last_err = RuntimeError(f"Unexpected payload from {url}")
        except Exception as exc:  # noqa: BLE001
            last_err = exc
    raise RuntimeError(f"Failed to fetch VPN Gate CSV: {last_err}")


def extract_xml_block(text: str, tag: str) -> tuple[str | None, str]:
    pattern = re.compile(
        rf"<{re.escape(tag)}>\s*(.*?)\s*</{re.escape(tag)}>",
        re.DOTALL | re.IGNORECASE,
    )
    match = pattern.search(text)
    if not match:
        return None, text
    content = match.group(1).replace("\r\n", "\n").strip()
    cleaned = pattern.sub("", text)
    return content, cleaned


def is_valid_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return ip.version == 4 and ip.is_global
    except ValueError:
        return False


def parse_ovpn_for_mihomo(ovpn_b64: str, csv_ip: str) -> tuple[dict[str, Any] | None, str | None]:
    """
    Parse a base64 .ovpn config and validate compatibility with Mihomo v1.19.25+ `type: openvpn`.
    Returns (proxy_dict, None) if compatible, or (None, reject_reason) if incompatible.
    """
    try:
        raw_text = base64.b64decode(ovpn_b64).decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return None, "invalid_base64"

    text = raw_text.replace("\r\n", "\n").replace("\r", "\n")

    # Reject unsupported tls-crypt-v2
    if re.search(r"<tls-crypt-v2>", text, re.IGNORECASE):
        return None, "unsupported_tls_crypt_v2"

    ca_pem, text = extract_xml_block(text, "ca")
    cert_pem, text = extract_xml_block(text, "cert")
    key_pem, text = extract_xml_block(text, "key")
    tls_auth_pem, text = extract_xml_block(text, "tls-auth")
    tls_crypt_pem, text = extract_xml_block(text, "tls-crypt")
    _, text = extract_xml_block(text, "extra-certs")

    if tls_auth_pem and tls_crypt_pem:
        return None, "mutually_exclusive_tls_auth_and_crypt"

    if not ca_pem or "BEGIN CERTIFICATE" not in ca_pem:
        return None, "missing_inline_ca"

    dev_type: str | None = None
    proto: str | None = None
    remote_host: str | None = None
    remote_port: int = 1194
    cipher: str | None = None
    data_ciphers: list[str] = []
    auth: str | None = None
    comp_lzo: str | None = None
    key_direction: int | None = None
    needs_user_pass = False

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue

        # Strip trailing inline comment outside quotes
        parts = line.split()
        if not parts:
            continue
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd == "dev":
            if not args:
                return None, "empty_dev"
            val = args[0].lower()
            if val.startswith("tap"):
                return None, "unsupported_dev_tap"
            if not val.startswith("tun"):
                return None, f"unsupported_dev_{val}"
            dev_type = "tun"

        elif cmd == "proto":
            if not args:
                continue
            val = args[0].lower()
            if val in ("tcp", "tcp-client", "tcp4", "tcp4-client"):
                proto = "tcp"
            elif val in ("udp", "udp4"):
                proto = "udp"
            else:
                return None, f"unsupported_proto_{val}"

        elif cmd == "remote":
            if remote_host is None and len(args) >= 1:
                remote_host = args[0]
                if len(args) >= 2:
                    try:
                        remote_port = int(args[1])
                    except ValueError:
                        return None, "invalid_remote_port"
                if len(args) >= 3:
                    p3 = args[2].lower()
                    if p3 in ("tcp", "tcp-client", "tcp4"):
                        proto = proto or "tcp"
                    elif p3 in ("udp", "udp4"):
                        proto = proto or "udp"

        elif cmd == "cipher":
            if args:
                c = args[0].upper()
                if c == "AES-CBC":
                    c = "AES-128-CBC"
                cipher = c

        elif cmd == "data-ciphers":
            if args:
                data_ciphers = [x.strip().upper() for x in args[0].split(":") if x.strip()]

        elif cmd == "auth":
            if args:
                auth = args[0].upper()

        elif cmd == "comp-lzo":
            if not args:
                comp_lzo = "adaptive"
            else:
                v = args[0].lower()
                if v in ("yes", "no", "adaptive"):
                    comp_lzo = v
                else:
                    return None, f"unsupported_comp_lzo_{v}"

        elif cmd == "compress":
            if not args:
                comp_lzo = "no"
            else:
                v = args[0].lower()
                if v == "lzo":
                    comp_lzo = "yes"
                else:
                    # lz4 / lz4-v2 / stub / stub-v2 are not compatible with Mihomo comp-lzo
                    return None, f"unsupported_compress_{v}"

        elif cmd == "key-direction":
            if args and args[0] in ("0", "1"):
                key_direction = int(args[0])

        elif cmd == "auth-user-pass":
            needs_user_pass = True

        elif cmd in ("ca", "cert", "key", "tls-auth", "tls-crypt"):
            # External file references are not portable in YAML providers
            return None, f"external_file_{cmd}"

    if dev_type != "tun":
        return None, "missing_dev_tun"

    if proto not in ("tcp", "udp"):
        proto = "udp"

    # Prefer CSV IPv4 directly so dialer-proxy never needs extra DNS resolution
    server = csv_ip if is_valid_ipv4(csv_ip) else (remote_host or "")
    if not server:
        return None, "missing_server"

    if not (1 <= remote_port <= 65535):
        return None, "invalid_port"

    # Cipher resolution & validation
    chosen_cipher: str | None = None
    if cipher:
        if cipher not in SUPPORTED_CIPHERS:
            return None, f"unsupported_cipher_{cipher}"
        chosen_cipher = cipher
    elif data_ciphers:
        for c in data_ciphers:
            norm = "AES-128-CBC" if c == "AES-CBC" else c
            if norm in SUPPORTED_CIPHERS:
                chosen_cipher = norm
                break
        if not chosen_cipher:
            return None, "unsupported_data_ciphers"
    else:
        return None, "missing_cipher"

    # Auth validation (required for non-AEAD ciphers if specified)
    if auth and chosen_cipher not in AEAD_CIPHERS:
        if auth not in SUPPORTED_AUTHS:
            return None, f"unsupported_auth_{auth}"

    # Require cert+key unless username/password is available (we don't have creds for random third-party servers)
    if needs_user_pass:
        return None, "requires_auth_user_pass"
    if not cert_pem or not key_pem:
        return None, "missing_inline_cert_or_key"

    proxy_cfg: dict[str, Any] = {
        "type": "openvpn",
        "server": server,
        "port": remote_port,
        "proto": proto,
        "dev": "tun",
        "cipher": chosen_cipher,
        "udp": True,
        "ca": ca_pem,
        "cert": cert_pem,
        "key": key_pem,
    }

    if auth and chosen_cipher not in AEAD_CIPHERS:
        proxy_cfg["auth"] = auth
    elif auth and auth in SUPPORTED_AUTHS:
        proxy_cfg["auth"] = auth

    if comp_lzo:
        proxy_cfg["comp-lzo"] = comp_lzo

    if tls_auth_pem:
        proxy_cfg["tls-auth"] = tls_auth_pem
        if key_direction is not None:
            proxy_cfg["key-direction"] = key_direction
    elif tls_crypt_pem:
        proxy_cfg["tls-crypt"] = tls_crypt_pem

    return proxy_cfg, None


def query_ip_api_batch(
    ips: list[str],
    opener: urllib.request.OpenerDirector,
    timeout: int = 20,
) -> dict[str, dict[str, Any]]:
    """Query http://ip-api.com/batch in chunks of 100. Fails gracefully if rate-limited."""
    result: dict[str, dict[str, Any]] = {}
    unique_ips = list(dict.fromkeys(ips))
    chunk_size = 100

    for idx in range(0, len(unique_ips), chunk_size):
        chunk = unique_ips[idx : idx + chunk_size]
        payload = json.dumps(chunk).encode("utf-8")
        req = urllib.request.Request(
            IP_API_BATCH_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with opener.open(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and item.get("status") == "success":
                        q = str(item.get("query", "")).strip()
                        if q:
                            result[q] = item
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            print(f"[warn] ip-api batch chunk {idx // chunk_size + 1} failed: {exc}", file=sys.stderr)
        if idx + chunk_size < len(unique_ips):
            time.sleep(1.5)

    return result


def classify_ip_tier(info: dict[str, Any] | None, operator_field: str = "") -> tuple[str, str]:
    """
    Classify an IP into:
      - ISP: non-hosting residential/broadband ISP
      - EDU: university / academic / Tsukuba relay
      - DC:  datacenter / VPS / cloud hosting
      - UNK: lookup unavailable
    Returns (tier, short_isp_label).
    """
    if not info:
        if any(k in operator_field.lower() for k in ("tsukuba", "university")):
            return "EDU", "University"
        return "UNK", "Unknown"

    isp = str(info.get("isp") or "").strip()
    org = str(info.get("org") or "").strip()
    asname = str(info.get("asname") or "").strip()
    hosting = bool(info.get("hosting", False))

    combined = f"{isp} {org} {asname} {operator_field}".lower()

    if any(kw in combined for kw in EDU_KEYWORDS):
        label = isp or org or "EDU"
        return "EDU", label

    if hosting or any(kw in combined for kw in DC_KEYWORDS):
        label = isp or org or "DC"
        return "DC", label

    label = isp or org or "ISP"
    return "ISP", label


def sanitize_label(text: str, max_len: int = 24) -> str:
    cleaned = re.sub(r"[\r\n\t\"'`\\|{}[\]#]", " ", text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len].rstrip()
    return cleaned or "Node"


def yaml_quote(value: str) -> str:
    escaped = value.replace("'", "''")
    return f"'{escaped}'"


def format_pem_block(pem: str, indent: int = 6) -> str:
    pad = " " * indent
    lines = [line.strip() for line in pem.strip().splitlines() if line.strip()]
    return "|\n" + "\n".join(f"{pad}{line}" for line in lines)


def render_proxies_yaml(nodes: list[dict[str, Any]], header_lines: list[str]) -> str:
    out: list[str] = []
    for line in header_lines:
        out.append(f"# {line}")
    out.append("proxies:")

    if not nodes:
        out.append("  []")
        return "\n".join(out) + "\n"

    for node in nodes:
        out.append(f"  - name: {yaml_quote(node['name'])}")
        out.append(f"    type: {node['type']}")
        out.append(f"    server: {node['server']}")
        out.append(f"    port: {node['port']}")
        out.append(f"    proto: {node['proto']}")
        out.append(f"    dev: {node['dev']}")
        out.append(f"    cipher: {node['cipher']}")
        if "auth" in node:
            out.append(f"    auth: {node['auth']}")
        if "comp-lzo" in node:
            out.append(f"    comp-lzo: {yaml_quote(node['comp-lzo'])}")
        out.append(f"    udp: {'true' if node.get('udp', True) else 'false'}")
        out.append(f"    ca: {format_pem_block(node['ca'])}")
        out.append(f"    cert: {format_pem_block(node['cert'])}")
        out.append(f"    key: {format_pem_block(node['key'])}")
        if "tls-auth" in node:
            out.append(f"    tls-auth: {format_pem_block(node['tls-auth'])}")
            if "key-direction" in node:
                out.append(f"    key-direction: {node['key-direction']}")
        elif "tls-crypt" in node:
            out.append(f"    tls-crypt: {format_pem_block(node['tls-crypt'])}")

    return "\n".join(out) + "\n"


def parse_int(val: str, default: int = 0) -> int:
    try:
        return int(float(val.strip()))
    except (ValueError, AttributeError):
        return default


def process_vpngate_csv(
    csv_text: str,
    opener: urllib.request.OpenerDirector,
    skip_ip_api: bool = False,
    tcp_only: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    lines = [ln for ln in csv_text.splitlines() if ln.strip() and not ln.startswith("*")]
    header_idx = -1
    for i, ln in enumerate(lines):
        if ln.startswith("#HostName"):
            header_idx = i
            break
    if header_idx == -1:
        raise RuntimeError("CSV header '#HostName' not found in VPN Gate payload")

    lines[header_idx] = lines[header_idx].lstrip("#")
    reader = csv.DictReader(io.StringIO("\n".join(lines[header_idx:])))

    stats: dict[str, int] = {"total_rows": 0, "compatible": 0}
    reject_counts: dict[str, int] = {}
    candidates: list[dict[str, Any]] = []
    seen_endpoints: set[tuple[str, int, str]] = set()

    for row in reader:
        stats["total_rows"] += 1
        ip = (row.get("IP") or "").strip()
        country = (row.get("CountryShort") or "XX").strip().upper()
        b64_ovpn = (row.get("OpenVPN_ConfigData_Base64") or "").strip()
        if not b64_ovpn or not is_valid_ipv4(ip):
            reject_counts["invalid_row_or_ip"] = reject_counts.get("invalid_row_or_ip", 0) + 1
            continue

        proxy_cfg, err = parse_ovpn_for_mihomo(b64_ovpn, ip)
        if err or proxy_cfg is None:
            key = f"reject_{err}"
            reject_counts[key] = reject_counts.get(key, 0) + 1
            continue

        if tcp_only and proxy_cfg["proto"] != "tcp":
            reject_counts["reject_tcp_only_filter"] = reject_counts.get("reject_tcp_only_filter", 0) + 1
            continue

        endpoint = (proxy_cfg["server"], proxy_cfg["port"], proxy_cfg["proto"])
        if endpoint in seen_endpoints:
            reject_counts["duplicate_endpoint"] = reject_counts.get("duplicate_endpoint", 0) + 1
            continue
        seen_endpoints.add(endpoint)

        stats["compatible"] += 1
        candidates.append(
            {
                "proxy": proxy_cfg,
                "ip": ip,
                "country": country,
                "score": parse_int(row.get("Score", "0")),
                "ping": parse_int(row.get("Ping", "9999"), 9999),
                "speed": parse_int(row.get("Speed", "0")),
                "sessions": parse_int(row.get("NumVpnSessions", "0")),
                "operator": (row.get("Operator") or "").strip(),
            }
        )

    ip_info_map: dict[str, dict[str, Any]] = {}
    if not skip_ip_api and candidates:
        ip_info_map = query_ip_api_batch([c["ip"] for c in candidates], opener=opener)

    tier_rank = {"ISP": 0, "EDU": 1, "UNK": 2, "DC": 3}

    for item in candidates:
        info = ip_info_map.get(item["ip"])
        tier, isp_label = classify_ip_tier(info, item["operator"])
        item["tier"] = tier
        item["isp_label"] = sanitize_label(isp_label, max_len=20)
        stats[f"tier_{tier}"] = stats.get(f"tier_{tier}", 0) + 1

    # Sort priority:
    # 1. Tier: ISP > EDU > UNK > DC
    # 2. Protocol: TCP ahead of UDP (TCP traverses airport dialer-proxy reliably without UDP relay issues)
    # 3. VPN Gate Score (desc) & Speed (desc) & Ping (asc)
    candidates.sort(
        key=lambda x: (
            tier_rank.get(x["tier"], 9),
            0 if x["proxy"]["proto"] == "tcp" else 1,
            -x["score"],
            -x["speed"],
            x["ping"],
        )
    )

    used_names: set[str] = set()
    final_nodes: list[dict[str, Any]] = []
    for item in candidates:
        p = dict(item["proxy"])
        proto_tag = p["proto"].upper()
        base_name = (
            f"[{item['tier']}][{item['country']}][{proto_tag}] "
            f"{item['isp_label']} {p['server']}:{p['port']}"
        )
        name = base_name
        suffix = 2
        while name in used_names:
            name = f"{base_name} #{suffix}"
            suffix += 1
        used_names.add(name)

        p["name"] = name
        p["_meta"] = {
            "tier": item["tier"],
            "country": item["country"],
            "score": item["score"],
            "speed_mbps": round(item["speed"] / 1_000_000, 2),
            "ping": item["ping"],
            "isp": item["isp_label"],
        }
        final_nodes.append(p)

    stats.update(reject_counts)
    return final_nodes, stats


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fetch VPN Gate OpenVPN servers, filter for Mihomo v1.19.25+, and classify ISP/residential IPs."
    )
    parser.add_argument(
        "--out-dir",
        default="dist",
        help="Output directory for generated YAML files (default: dist)",
    )
    parser.add_argument(
        "--isp-limit",
        type=int,
        default=35,
        help="Max nodes in vpngate-isp.yaml (default: 35)",
    )
    parser.add_argument(
        "--all-limit",
        type=int,
        default=80,
        help="Max nodes in vpngate-all.yaml (default: 80)",
    )
    parser.add_argument(
        "--tcp-only",
        action="store_true",
        help="Only include proto: tcp OpenVPN nodes (highest compatibility behind airport dialer-proxy)",
    )
    parser.add_argument(
        "--proxy",
        default=os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or "",
        help="Optional HTTP/HTTPS proxy URL, e.g. http://127.0.0.1:7897",
    )
    parser.add_argument(
        "--skip-ip-api",
        action="store_true",
        help="Skip ip-api.com lookup (useful for offline tests)",
    )
    parser.add_argument(
        "--input-csv",
        default="",
        help="Read CSV from a local file instead of fetching vpngate.net (for testing)",
    )
    args = parser.parse_args()

    opener = build_opener(args.proxy or None)
    if args.input_csv:
        csv_text = Path(args.input_csv).read_text(encoding="utf-8", errors="replace")
    else:
        csv_text = fetch_vpngate_csv(opener)

    nodes, stats = process_vpngate_csv(
        csv_text,
        opener=opener,
        skip_ip_api=args.skip_ip_api,
        tcp_only=args.tcp_only,
    )

    isp_nodes = [n for n in nodes if n["_meta"]["tier"] == "ISP"]
    if len(isp_nodes) < 10:
        # Fallback: supplement with EDU (Tsukuba/university) or UNK if few pure ISP nodes
        extra = [n for n in nodes if n["_meta"]["tier"] in ("EDU", "UNK")]
        isp_nodes = (isp_nodes + extra)[: args.isp_limit]
    else:
        isp_nodes = isp_nodes[: args.isp_limit]

    all_nodes = nodes[: args.all_limit]

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    now_utc = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    isp_yaml = render_proxies_yaml(
        isp_nodes,
        [
            f"Generated at {now_utc}",
            f"Mihomo v1.19.25+ compatible VPN Gate ISP/Residential pool ({len(isp_nodes)} nodes)",
            "Source: https://www.vpngate.net/api/iphone/ + ip-api ASN/hosting filter",
        ],
    )
    all_yaml = render_proxies_yaml(
        all_nodes,
        [
            f"Generated at {now_utc}",
            f"Mihomo v1.19.25+ compatible VPN Gate full pool ({len(all_nodes)} nodes)",
            "Sorted by ISP > EDU > DC, TCP > UDP, Score > Speed",
        ],
    )

    (out_dir / "vpngate-isp.yaml").write_text(isp_yaml, encoding="utf-8")
    (out_dir / "vpngate-all.yaml").write_text(all_yaml, encoding="utf-8")

    summary = {
        "updated_at_utc": now_utc,
        "stats": stats,
        "emitted_isp": len(isp_nodes),
        "emitted_all": len(all_nodes),
        "isp_countries": sorted({n["_meta"]["country"] for n in isp_nodes}),
    }
    (out_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
