# v0.1.3 RB5009 三方数据一致性与关键业务 IP 冲突审计（私有）

**禁止在 GitHub Actions 上执行本流程**。RB5009 的完整 `scaners` 及你指定的关键游戏/代理/管理地址均属于本地隐私数据：仅从内网 Debian/QNAP 或安全 VPN 通过 HTTPS REST 读取，结果写入 `local/`，该目录已被 `.gitignore` 排除。默认没有任何 RouterOS 写操作，也不会更改 RAW 规则。需要 Python >=3.11，纯标准库。你当前 Windows 没有 `py`，建议在 Debian 13 主机运行；以下命令为 Linux 示例。

## 一、先准备现有 GitHub 最新代码和公开 Spamhaus `dist`

```bash
git clone https://github.com/wstxwd007/threat-ip-intelligence.git
cd threat-ip-intelligence
python3 -m unittest discover -s tests -v
```

如果已经 clone，使用 `git pull --ff-only`。确认 `dist/manifest.json`、`dist/ipv4.txt` 为之前的正式发布文件；程序将验证其 SHA-256，且默认拒绝超过 72 小时的旧版本。GitHub 公共仓库克隆到你自己的内网主机，并不意味着连接 RouterOS 的权限自动授予 GitHub。

## 二、RouterOS 只读 HTTPS 准备（非必要时不要开放或修改接口）

先只读查看 `/ip service print where name="www-ssl"`。RouterOS 官方 REST 文档建议使用自定义 `read,api,rest-api` 的最小权限账户，并将账户限制为内网管理主机的源地址。**仅在已规划好 `www-ssl` 证书和访问控制后**，才考虑启用 HTTPS REST；不可为本项目开放公网管理端口，不要使用 `www` 明文 REST。

RouterOS 配置账户时的示意（实际地址/口令需自行替换，不要把口令粘贴到聊天或 GitHub）：

```routeros
/user/group/add name=tipi-audit-read policy=read,api,rest-api
/user/add name=tipi-audit group=tipi-audit-read password="自行生成的高强度密码"
/user/set [find where name=tipi-audit] address=192.168.11.66/32
```

如果已经有专用只读账户和受信任证书，可直接复用。上述网段和用户来源地址只是示例，**仅当私有审计机实际使用该地址时才适用**。证书的主机名/IP 必须与 `--router-url` 一致。参考：<https://manual.mikrotik.com/docs/developer-guides/rest-api/>。

## 三、三方只读在线审计

`--fetch-ros6` 从官方 `.netbsd` 获取**纯地址数据**，不会执行 `.rsc`；服务地址需能从本地审计机访问。`RouterREST` 仅调用 GET 请求，校验当前有启用的 RAW `scaners` 封禁规则。

```bash
export TIPI_ROS_USER='tipi-audit'
read -rsp 'RouterOS 密码: ' TIPI_ROS_PASSWORD; echo
export TIPI_ROS_PASSWORD
export TIPI_ROS_CA='/etc/ssl/certs/routeros-ca.pem'
python3 -m threatip.router_audit \
  --router-url https://192.168.11.1 \
  --fetch-ros6 \
  --watchlist local/watchlist.json \
  --out local/router-audit-latest.json
unset TIPI_ROS_PASSWORD
```

`--watchlist` 可选；若不填写则不检查关键业务 IP。`local/watchlist.json` 示例：

```json
{"addresses":["8.8.8.8", "9.9.9.9"]}
```

**注意：示例 IP 不是你的真实业务 IP**；改为你实际使用的游戏、代理或运维节点的 IPv4。不支持域名自动解析或子网，防止动态 DNS 导致不确定性。建议先检查你的 IP 是否属于上述三个来源，再自行决定是否为业务例外做调整；工具绝不会自动加入白名单。

报告路径在 `local/`，包含命中结果及你指定的业务 IP；不可 `git add -f` 上传。终端仅输出数量与本地报告路径，避免泄露具体 IP。脚本不会保存 RouterOS 密码。

## 四、离线审计（HTTPS REST 不可用时）

可以将 RouterOS REST 返回的 `ip/firewall/address-list` JSON 数组在**你的内网设备**保存为 `local/scaners.json`，只保留 `list=scaners` 条目也可以；同时本地保存 ros6 官方纯地址表为 `local/scaners.netbsd`（不要上传公开仓库）。然后执行：

```bash
python3 -m threatip.router_audit \
  --router-file local/scaners.json \
  --ros6-file local/scaners.netbsd \
  --out local/router-audit-latest.json
```

JSON 必须是真正的 REST 对象数组，而不是 RouterOS 终端的格式化文字输出。**不要用 RouterOS `export` 的 `.rsc` 脚本冒充 REST JSON。**

## 五、结果说明

- `router_unique_entries`: 目前 `scaners` 的去重有效公网 IPv4/CIDR 数，未必等于 RouterOS 的原始 `8,672` 行数（有重复、禁用或非公网时会不同）。
- `ros6_addresses_not_covered_by_router`: 官方源覆盖但路由器未覆盖的独立 IPv4 数量，不等于“未阻断多少次攻击”。
- `spamhaus_addresses_not_covered_by_router`: Spamhaus 源覆盖但路由器未覆盖的地址数量；它可能很大，因为 Spamhaus 是大网段。
- `router_addresses_outside_both_sources`: RB5009 已封禁、但两个当前来源都没有覆盖的地址数量，并不直接代表过期或误封，可能来自其他来源。
- `watchlist_conflicts`: 有多少关键服务 IP 被任一名单覆盖；具体 IP 和来源仅记录在本机 `local/` 报告。

该版本**不自动判断误杀、不自动解封、不自动下发任何条目**。如果 ros6 源数据格式异常或 Spamhaus 校验失败，立即终止并保留上一个本地报告。
