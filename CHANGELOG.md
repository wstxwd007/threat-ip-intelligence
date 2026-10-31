# 更新记录

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
