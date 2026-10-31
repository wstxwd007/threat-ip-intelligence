# Threat IP Intelligence（高风险 IP 威胁情报系统）

[![Tests](../../actions/workflows/test.yml/badge.svg)](../../actions/workflows/test.yml)

**版本：v0.1.3 — 情报质量闸门、CIDR 风险与 RB5009 私有只读三方审计**
面向 MikroTik RouterOS 7 的公开威胁 IP 数据构建器与安全更新客户端。项目是独立开发的开源工具，不属于 MikroTik、Spamhaus、abuse.ch 或 ros6 的官方产品。

> 核心承诺：**不修改现有 RAW 规则；不清空 `scaners`；不删除 ros6/手工导入的旧条目；默认只读预演。**

## 已实现

- 纯 Python 3.11+ 标准库，不依赖第三方运行时包。
- GitHub Actions 每天尝试更新 Spamhaus DROP、运行离线单元测试、发布 `dist/ipv4.txt`、`dist/manifest.json` 和 `dist/SHA256SUMS`。
- HTTPS/TLS 验证、数据大小限制、IPv4/CIDR 严格校验、特殊地址拒绝、去重、来源证据元数据、SHA-256 完整性校验。
- RouterOS 7 HTTPS REST 更新：检查已有 RAW 规则、统计预演差异、**先添加后删除**、限制变更数量、仅删除自己标记为 `TIPI/v1` 的条目、更新后再校验、失败尽可能回滚。
- 更新失败不发布空名单；客户端失败默认保留现有列表。
- **v0.1.2-r1：** 独立 `audit-ros6` Actions 每日尝试只读下载 ros6 官方 NetBSD NPF 纯地址文件 `.netbsd`，严格拒绝非地址数据（不下载、不执行 `.rsc`），比较 ros6 与已发布 Spamhaus 的地址覆盖范围，只提交不含 ros6 IP/CIDR 的汇总报告；不修改已有 `dist/ipv4.txt`。

## 数据源与再分发规则

| 来源 | v0.1.2 默认状态 | 原因 |
|---|---|---|
| **Spamhaus DROP IPv4** | 启用 | 官方发布 NDJSON 数据、要求保留来源和版权归属；详见官方 Fair Use 及项目 manifest |
| **abuse.ch Feodo Tracker** | 禁用 | 官方 2026-10-21 Terms 明示 Feodo 数据遵从 CC0 原则；但 2026-10-30 实际下载页可见最近更新为 2026-03-04，现已过期，默认不采用 |
| **ros6 `scaners.netbsd`** | **不加入公开封禁库；单独只读分析** | 未确认数据再分发授权；GitHub Actions 只发布统计及哈希，绝不转载原始数据 |

项目源代码按 MIT 许可发布；**该许可不覆盖第三方情报数据**。Spamhaus 数据来源、声明与作者权益记录在每次的 `manifest.json`；请遵循其最新发布使用政策。启用其他来源前必须核实许可、更新频率及准确度。

## 结构

```text
.github/workflows/        单测 CI、Spamhaus 发布和 ros6 只读审计
config/sources.json       可公开发布的数据源配置
config/ros6-audit.json    ros6 只读审计配置
threatip/feeds.py         采集、格式化与校验
threatip/build.py         安全发布与 SHA-256
threatip/audit.py         CIDR 覆盖统计与匿名化报告
threatip/routeros.py      RouterOS REST 增量客户端
samples/                  合成测试示例（绝非真实黑名单）
scripts/                  更新包装与离线验收脚本
deploy/systemd/           选用的自动更新服务配置
samples/fixture-config.json
README.md, docs/          中文操作与安全说明
dist/                     Spamhaus 已发布正式情报（保留原流程）
reports/                  ros6 只读审计后的汇总报告（不含 IP 明细）
```

## 一分钟测试（不修改路由器）

```bash
sh scripts/acceptance.sh
python3 -m threatip.build --config samples/fixture-config.json --out /tmp/tipi-demo
cat /tmp/tipi-demo/manifest.json
```

演示 feed **仅用于测试程序是否运行，不是真实威胁情报，不得用于封禁**。

## 正式部署

阅读 **[中文部署手册](docs/DEPLOY-ZH.md)**：创建公开 GitHub 仓库、启用自动发布、部署 RouterOS 客户端、预演差异、手动批准首次应用，再安排 systemd 周期更新。

详细安全措施见 [安全模型](docs/SECURITY-ZH.md)。

### v0.1.2-r1 ros6 只读审计

项目升级不需要重新建 GitHub 仓库。`audit-ros6` 工作流每日自动尝试一次，也支持 `gh workflow run audit-ros6.yml --ref main` 手动触发。
生成 `reports/ros6-latest.json` 和 `reports/ros6-latest.md`，仅包含聚合统计与来源哈希。解析失败、源站不可达或 Spamhaus 发布太旧时工作流失败，保留原报告。
**不要把 ros6 `.rsc`、`.netbsd` 原始文件、路由器导出或混合名单提交到公开仓库。** 具体命令、质量指标及故障排查见 [ros6 审计手册](docs/ROS6-AUDIT-ZH.md)。

## v0.1 的边界

- 目前只发布 IPv4；RouterOS `/ip firewall raw` 不能保护 IPv6，IPv6 需独立设计。
- IPv4 名单为精确集合，不把若干 `/32` 推测成整个 `/24`；尚不做历史置信度评分或自动 TTL 学习。
- GH Actions 是非实时发布；源站停更、失效或下载失败时不发布新版本。
- ros6 源文件目前没有可靠、可验证的内置更新时间字段，v0.1.2-r1 只能证明采集时间和内容哈希，不能证明源库本身何时更新。
- ros6 `scaners.netbsd` 已由用户在 GitHub Actions 完成真实下载与聚合审计，生成 `reports/ros6-latest.md`（v0.1.2-r1 提交 `cd91501`）；v0.1.3 新的私有 RouterOS REST 部分仍未在 RB5009 联机验收。
- 公共哈希验证不等于来源签名验证；如果 GitHub 仓库和 manifest 一起被攻击者替换，SHA-256 无法发现。需通过 GitHub 权限管理、分支保护和后续签名版本增强。
- 未经连接验证，不能保证你的 RB5009 已启用 `www-ssl` 或网络可达。本项目**不会自动启用公网管理端口**。
- 目前每次变更使用多个 REST 请求，不具备 RouterOS 原子事务，断网时会尝试补偿回滚但不能保证完全回滚；详见安全手册。

## 来源、规范

- [MikroTik RouterOS REST API](https://manual.mikrotik.com/docs/developer-guides/rest-api/)
- [MikroTik Address Lists](https://manual.mikrotik.com/docs/firewall-and-quality-of-service/firewall/address-lists/)
- [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)
- [abuse.ch Terms of Use](https://abuse.ch/terms-of-use/)
- [ros6 原项目](https://www.ros6.com/?action=show&id=261)

## 责任说明

任何 IP 黑名单都存在误报。工具只能作为纵深防御的一层；不要替代固件补丁、强认证、日志监测与可恢复备份。首次写入前请检查变更数量及关键服务连接状态。

## v0.1.3 新能力

- **公开发布质量闸门：** 候选数据先写入 GitHub Runner 临时目录，与已发布 `dist/ipv4.txt` 比较；计算 CIDR 分布、大网段条目、两版 IP 覆盖新增/移除（包含网段重叠）；异常直接停止，不替换旧数据。发布频率调整为每日一次。详见 [质量闸门文档](docs/QUALITY-V013-ZH.md)。
- **RB5009 私有三方只读审计：** 从本地文件或受控 HTTPS REST GET 读取 `scaners`，与当前 ros6 及 Spamhaus 计算独立覆盖差异，可使用本地关键业务 IP watchlist 检测碰撞。敏感结果只写在 `.gitignore` 排除的 `local/`。详见 [私有审计文档](docs/ROUTER-PRIVATE-AUDIT-ZH.md)。
- **版本验收：** [v0.1.3 验收手册](docs/ACCEPTANCE-V013-ZH.md)。

**注意：** v0.1.3 尚未对真实 RB5009 进行 REST 联机测试，且不会开启任何自动写入；GitHub 的持续集成与新质量闸门也必须在正式仓库完成在线验收。
