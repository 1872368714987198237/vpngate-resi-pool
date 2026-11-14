# Mihomo 多订阅聚合 + 家宽链式代理池（无 VPS / 无 Cloudflare）

零成本方案：**GitHub Actions 定时抓取 VPN Gate 家宽节点 → Mihomo (v1.19.25+) `dialer-proxy` 链式落地 → 机场与家宽并存**。最终交付两个 YAML：

| 文件 | 给谁用 | 内容 |
|---|---|---|
| `dist/pool-for-2api.yaml`（本地生成，不入库） | `C:\code\express2api` | 扁平 `proxies:`：3 订阅 + 原 94 节点合并去重、真实健康检查后的存活机场节点，外加带 `dialer-proxy` 链式挂在前置机场节点后面的 VPN Gate 家宽节点（express2api 原样透传节点字段，**无需改任何代码**） |
| `clash-verge-profile.yaml`（本地，不入库） | Clash Verge（独立 Profile 导入） | 3 订阅 `proxy-providers` 聚合 + GitHub Actions 更新的家宽池经 `override.dialer-proxy` 链式挂载；7897 单端口，规则分流 |

## 一次到位（本地重建池）

```bash
# 1. 拉取 3 个订阅（经 7897 代理）
mkdir -p data/tmp/subs
curl -sSL -x http://127.0.0.1:7897 -A "clash-verge/v1.19.0 (mihomo)" -o data/tmp/subs/sub1.yaml "https://api-k1.microrsssub.org/sd/..."
# （sub2/sub3 同理）

# 2. 抓取并清洗 VPN Gate（GitHub Actions 每 4 小时也会自动跑并提交 dist/）
python scripts/fetch_vpngate.py --proxy http://127.0.0.1:7897 --tcp-only --out-dir dist

# 3. 合并 + 健康检查 + 链式注入 + 写回 express2api config.yaml（自动备份原文件）
python scripts/build_pool.py --subs data/tmp/subs/sub1.yaml data/tmp/subs/sub2.yaml data/tmp/subs/sub3.yaml --install
```

`build_pool.py` 用 `express2api/tools/mihomo.exe` 起真实 core，经 controller delay API 两轮实测：
机场节点 159 → ~130 存活；VPN Gate TCP 节点逐个挂 `dialer-proxy: <延迟最低的 3 个前置机场节点轮转>` 再实测，只保留整条链路通的（约 16-18/29）。**重启 express2api 生效。**

## 仓库结构

- `scripts/fetch_vpngate.py` — VPN Gate 抓取 + Mihomo `type: openvpn` 兼容过滤（剔除 `tap`、不兼容 cipher/auth/compress、`auth-user-pass`、`tls-crypt-v2` 等）+ ip-api ASN/hosting 分级（ISP > EDU > DC），TCP 优先
- `scripts/build_pool.py` — 订阅合并去重 + mihomo 实测健康检查 + dialer-proxy 链式注入 + 安装
- `.github/workflows/update-vpngate.yml` — 每 4 小时更新 `dist/vpngate-isp.yaml` / `dist/vpngate-all.yaml`（公开数据，无凭据）
- `clash-verge-profile.example.yaml` — Clash Verge 独立 Profile 模板（真实版被 .gitignore 忽略）
- `proxy_providers/custom_residential.example.yaml` — 后续自购静态住宅 SOCKS5/HTTP 的接入样例
- `tests/` — `fetch_vpngate.py` 的单测：`python -m unittest discover -s tests`

## 注意事项

- `.gitignore` 已忽略 `clash-verge-profile.yaml`、`dist/pool-for-2api.yaml`、`data/` —— 机场 Token / 节点凭据绝不能进公开仓库
- Clash Verge 中请以**独立配置 Profile** 导入，不要用全局 Merge/Script 覆写，避免订阅更新互相覆盖
- 链式 DNS：家宽节点 `server` 一律用 CSV 里的裸 IPv4（脚本已保证），`dialer-proxy` 前置节点域名由 `proxy-server-nameserver` 国内 DoH 解析，无死锁、无泄露
- 机场出口地区会漂移；express2api 运行时的 avoid/换绑机制继续兜底
