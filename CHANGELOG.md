## v0.1.3 — 2026-10-31

- 新增公开 Spamhaus DROP 发布前质量闸门（CIDR 分布、实际 IP 覆盖变化、大网段风险、保留旧数据）。
- GitHub Actions 改成每日一次发布；候选先放 Runner 临时目录，质量审计通过后再更新 dist。
- 新增私有 RouterOS / ros6 / Spamhaus 三方只读覆盖率审计及关键业务 IP 冲突检查。
- 本地报告只能输出至忽略的 local/；不把路由器信息发送到 GitHub。
- ros6 仍仅在公共审计中输出汇总统计；RAW 与 scaners 保持不变。
- 修复审计时两条发布工作流竞争写 main 的调度冲突（共享并发组）。
- 旧功能和新增功能的离线测试；GitHub 在线发布、RouterOS 联机验收待执行。

# 更新记录

## v0.1.2-r1 — 2026-10-31

- 修复首次 GitHub `audit-ros6` 报错 `unsupported RouterOS script directive`。
- 官方网站另有 NetBSD NPF `scaners.netbsd` 数据文件：审计改从此地址读取纯 IP/CIDR，不再尝试解析可执行 RSC；旧 RSC 解析器严格性不变。
- 新增拒绝脚本、HTML、异常行、非公网地址、损坏 UTF-8 的回归测试，避免靠跳过未知命令来掩盖问题。
- `audit-ros6` 仅发布汇总统计和哈希；公开 Spamhaus 发布流程、RB5009 `scaners` 与 RAW 都不修改。
- 本地离线测试 47/47 PASS；`scaners.netbsd` 真实源文件格式及 Github Actions 连接仍待线上验收，失败会保留上次统计。


## v0.1.2 — 2026-10-31

- 新增 `threatip.audit`：下载或从本地只读解析 ros6 `scaners.rsc`，全程不执行 RSC、不接触 RouterOS API。
- 严格允许 `/ip firewall address-list` 的安全 `add list=scaners address=...` 语法；拒绝命令替换、脚本控制、非法属性和非公网 IP。
- 对 ros6 与已发布且 SHA-256 验证通过的 Spamhaus DROP 进行精确条目重合、CIDR 覆盖、真实 IPv4 地址覆盖量和增量分析，不盲目扩大网段。
- 新增每日 `audit-ros6` GitHub Actions，只有聚合统计和来源哈希进入 `reports/`，不提交 ros6 原始名单及合并 IP 库。
- 数据源或发布数据异常时失败并保留上次报告，公开 Spamhaus 构建、`scaners` 与 RAW 规则不变。
- 新增审计安全/数学/发布回归测试与中文操作指南；因未能实时读取 ros6 下载站，线上格式及 9443 连通性仍需用户运行 Actions 验证。

## v0.1.1 — 2026-10-31

- 修复 Github Actions 实际采集 Spamhaus DROP 时 `invalid Spamhaus JSON feed` 错误。
- 兼容官方 NDJSON（一行一个 `cidr` JSON 对象，末尾时间戳/版权元数据）以及原有测试的 JSON 数组和 `data` 列表格式。
- 对损坏行、未知记录、非字符串 CIDR 和缺少有效 CIDR 的数据继续采取失败保护，不发布不完整名单。
- 新增 NDJSON 与失败保护回归测试；不修改 RB5009 的 `scaners` 或 RAW。
- 本地测试仅覆盖合成数据；GitHub Actions 的真实网络抓取仍需用户运行后验收。

# 更新记录

## v0.1.0 — 2026-10-30

- 建立可公开发布的 Python 项目和 GitHub Actions 定时构建。
- Spamhaus DROP IPv4 JSON 采集器、Feodo Tracker 可选接入与过期检查。
- ros6 RouterOS RSC 的只读数据解析兼容，默认禁用，等待再分发许可。
- RAW `scaners` 原配置零修改的 RouterOS 7 REST 增量更新客户端。
- 首次只读预演、安全阈值、完整性校验、异常停止、有限补偿回滚。
- 中文部署与安全文档；本地自动化测试。
