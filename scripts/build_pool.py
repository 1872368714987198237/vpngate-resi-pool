#!/usr/bin/env python3
"""
Build the express2api node pool:
  1. merge: 3 airport subscriptions + existing nodes in express2api config.yaml + vpngate-isp.yaml
  2. clean: drop info/junk entries, dedupe by (server, port, type)
  3. health-check every node through a real local mihomo instance (controller delay API)
  4. chain: vpngate openvpn nodes get `dialer-proxy: <best airport node>` (verified alive through the chain)
  5. emit dist/pool-for-2api.yaml  (flat `proxies:` — express2api passes fields through verbatim)
     and optionally rewrite express2api config.yaml `nodes:` (--install)

Zero third-party deps besides PyYAML. Run from repo root:
  python scripts/build_pool.py --subs data/tmp/subs/sub1.yaml data/tmp/subs/sub2.yaml data/tmp/subs/sub3.yaml
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

EXPRESS2API_CONFIG = Path(r"C:/code/express2api/config.yaml")
MIHOMO_EXE = Path(r"C:/code/express2api/tools/mihomo.exe")
DELAY_URL = "https://www.gstatic.com/generate_204"
CONTROLLER = "127.0.0.1:19091"
WORKDIR = Path("data/tmp/pool")

# subscription entries that are not real proxies
JUNK_NAME = re.compile(
    r"(?i)(剩余|流量|到期|重置|过期|官网|网址|域名|群组|频道|通知|公告|更新|订阅|客服|套餐|续费|邀请|返利|"
    r"使用说明|失联|防丢|回国|Traffic|Expire|Reset|Website|Channel|Telegram|Support|Info|倍率)"
)

# regions useless/blocked for the 2api (Gemini) use case
BAD_COUNTRY = re.compile(r"(?i)\[(CN|HK|RU)\]")


def load_proxies(paths: list[Path]) -> list[dict]:
    out: list[dict] = []
    for p in paths:
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
        for pr in doc.get("proxies") or []:
            if isinstance(pr, dict) and pr.get("name") and pr.get("server"):
                out.append(pr)
    return out


def load_config_nodes(cfg_path: Path) -> list[dict]:
    doc = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    nodes = (doc.get("node_pool") or {}).get("nodes") or []
    # express2api nodes may carry a `family` key that mihomo must not see (express2api strips it,
    # but we consume them raw) — strip here so the emitted pool is self-contained.
    return [{k: v for k, v in n.items() if k != "family"} for n in nodes if isinstance(n, dict)]


def clean_merge(groups: dict[str, list[dict]]) -> tuple[list[dict], dict]:
    seen: set[tuple] = set()
    names: set[str] = set()
    stats: dict[str, int] = {}
    merged: list[dict] = []
    for src in ("config", "sub1", "sub2", "sub3"):
        for pr in groups.get(src, []):
            if JUNK_NAME.search(str(pr["name"])):
                stats[f"junk_{src}"] = stats.get(f"junk_{src}", 0) + 1
                continue
            key = (str(pr.get("server")), pr.get("port"), pr.get("type"))
            if key in seen:
                stats["dup"] = stats.get("dup", 0) + 1
                continue
            name = str(pr["name"])
            if name in names:  # mihomo requires unique names; suffix instead of dropping
                i = 2
                while f"{name} #{i}" in names:
                    i += 1
                name = f"{name} #{i}"
                pr = {**pr, "name": name}
            seen.add(key)
            names.add(name)
            merged.append(pr)
            stats[f"kept_{src}"] = stats.get(f"kept_{src}", 0) + 1
    return merged, stats


def write_test_config(path: Path, proxies: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    cfg = {
        "mixed-port": 17891,
        "mode": "direct",
        "log-level": "warning",
        "external-controller": CONTROLLER,
        "proxies": proxies,
    }
    path.write_text(yaml.safe_dump(cfg, allow_unicode=True, width=10**9, sort_keys=False), encoding="utf-8")


def start_mihomo(cfg: Path) -> subprocess.Popen:
    proc = subprocess.Popen(
        [str(MIHOMO_EXE), "-d", str(cfg.parent), "-f", str(cfg)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(50):
        time.sleep(0.2)
        if proc.poll() is not None:
            raise RuntimeError(f"mihomo exited early with code {proc.returncode} (config invalid?)")
        try:
            urllib.request.urlopen(f"http://{CONTROLLER}/version", timeout=1).read()
            return proc
        except Exception:
            continue
    proc.kill()
    raise RuntimeError("mihomo controller did not come up")


def delay_test(proxies: list[dict], rounds: int = 2, timeout_ms: int = 5000, workers: int = 16) -> dict[str, list[int]]:
    """Returns {name: [delays]} via the controller delay endpoint (concurrency handled by mihomo)."""
    results: dict[str, list[int]] = {}
    from concurrent.futures import ThreadPoolExecutor

    def one(pr: dict) -> tuple[str, int | None]:
        q = urllib.parse.quote(str(pr["name"]), safe="")
        try:
            with urllib.request.urlopen(
                f"http://{CONTROLLER}/proxies/{q}/delay?timeout={timeout_ms}&url={DELAY_URL}", timeout=15
            ) as r:
                return str(pr["name"]), json.loads(r.read()).get("delay")
        except Exception:
            return str(pr["name"]), None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for _ in range(rounds):
            for name, d in ex.map(one, proxies):
                if d is not None:
                    results.setdefault(name, []).append(d)
    return results


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Windows GBK console vs emoji node names
    ap = argparse.ArgumentParser()
    ap.add_argument("--subs", nargs="+", required=True, help="airport subscription YAML files")
    ap.add_argument("--config", default=str(EXPRESS2API_CONFIG), help="express2api config.yaml (existing nodes input)")
    ap.add_argument("--vpngate", default="dist/vpngate-isp.yaml", help="vpngate openvpn proxies YAML")
    ap.add_argument("--out", default="dist/pool-for-2api.yaml")
    ap.add_argument("--fronts", type=int, default=3, help="number of top airport nodes used as chain fronts")
    ap.add_argument("--install", action="store_true", help="rewrite express2api config.yaml nodes: with the final pool")
    args = ap.parse_args()

    airport = clean_merge({
        "config": load_config_nodes(Path(args.config)),
        **{f"sub{i+1}": load_proxies([Path(p)]) for i, p in enumerate(args.subs)},
    })
    vpngate_all = load_proxies([Path(args.vpngate)])
    vpngate = [p for p in vpngate_all if not BAD_COUNTRY.search(str(p["name"]))]
    print(f"[merge] airport={len(airport[0])} (+{airport[1]}) vpngate={len(vpngate)}/{len(vpngate_all)} after CN/HK/RU filter")

    # ---- phase 1: health-check airport nodes only (no chains yet) ----
    write_test_config(WORKDIR / "airport.yaml", airport[0])
    proc = start_mihomo(WORKDIR / "airport.yaml")
    try:
        delays = delay_test(airport[0])
    finally:
        proc.kill()
    alive = [p for p in airport[0] if str(p["name"]) in delays]
    print(f"[health] airport alive {len(alive)}/{len(airport[0])}")

    ranked = sorted(alive, key=lambda p: sum(delays[str(p["name"])]) / len(delays[str(p["name"])]))
    fronts = [str(p["name"]) for p in ranked[: args.fronts]]
    if not fronts:
        print("[fatal] no alive airport nodes; aborting", file=sys.stderr)
        return 1

    # ---- phase 2: vpngate nodes chained behind rotating fronts ----
    chained = []
    for i, p in enumerate(vpngate):
        chained.append({**p, "dialer-proxy": fronts[i % len(fronts)]})
    final = alive + chained

    write_test_config(WORKDIR / "full.yaml", final)
    proc = start_mihomo(WORKDIR / "full.yaml")
    try:
        delays2 = delay_test(chained, rounds=2)
    finally:
        proc.kill()
    chain_alive = [p for p in chained if str(p["name"]) in delays2]
    print(f"[health] vpngate chained alive {len(chain_alive)}/{len(chained)} (fronts: {fronts})")

    final = alive + chain_alive

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        yaml.safe_dump({"proxies": final}, allow_unicode=True, width=10**9, sort_keys=False), encoding="utf-8"
    )
    print(f"[out] {out}: {len(final)} nodes ({len(alive)} airport + {len(chain_alive)} vpngate-chain)")

    if args.install:
        install_nodes(Path(args.config), final)
    return 0


def install_nodes(cfg_path: Path, nodes: list[dict]) -> None:
    """Replace the node_pool.nodes block in express2api config.yaml with the new pool (flow style, one per line)."""
    lines = cfg_path.read_text(encoding="utf-8").splitlines(keepends=True)
    start = next(i for i, ln in enumerate(lines) if re.match(r"\s*nodes:\s*(#.*)?$", ln))
    end = start + 1
    while end < len(lines) and not re.match(r"^\S", lines[end]):  # until next top-level key
        end += 1
    block = ["  nodes:\n"] + [
        "    - " + yaml.dump(n, default_flow_style=True, allow_unicode=True, width=10**9, sort_keys=False).strip() + "\n"
        for n in nodes
    ]
    cfg_path.write_text("".join(lines[:start] + block + lines[end:]), encoding="utf-8")
    print(f"[install] rewrote node_pool.nodes in {cfg_path} with {len(nodes)} nodes")


if __name__ == "__main__":
    raise SystemExit(main())
