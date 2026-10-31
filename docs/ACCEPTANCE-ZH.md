# v0.1.2-r1 验收报告与部署前门槛

## 已完成（离线）

- Python `unittest discover`：47 个测试全部通过（v0.1.2-r1）。
- `python -m compileall -q threatip`：通过。
- `sh scripts/acceptance.sh`：通过，合成样例构建后的 SHA-256 与清单相符。
- 新增的 NetBSD 纯地址表解析、原有 RSC 严格拒绝规则与覆盖算法经过合成数据测试。数据损坏或异常语法时保留旧报告。
- v0.1.1 的 `threatip/routeros.py`、`update-feeds.yml`、`test.yml` 未修改，故新版本不会自动操作 RB5009。

## 尚未完成（真实环境）

- 当前构建环境无法联网访问 ros6 `https://pcdn.ros6.com:9443/oss/scaners.netbsd`；未证明实际源文件格式与解析器完全匹配。
- v0.1.2 首次线上审计 `41157283123` 失败：原 `.rsc` 解析器遇到未支持的 RouterOS 指令；v0.1.2-r1 尚未在线验证，因此 GitHub Runner 的端口连通、证书校验及首次报告发布仍需一次真实验收。
- 没有读写 RB5009；这是刻意设计的安全边界。
- 没有取得 ros6 动态数据库公开再分发授权，所以仍不发布合并 IP 明细。

## 建议通过条件

1. GitHub `tests` 工作流显示绿色。
2. GitHub `publish-ip-feeds` 原流程维持稳定（`dist/ipv4.txt`、`manifest.json` 可读、SHA-256 一致）。
3. 手动运行 `audit-ros6` 后成功生成 `reports/ros6-latest.md` / `.json`。
4. 两份报告不包含 ros6 的 IP/CIDR 明细，指标计算逻辑符合说明。
5. RB5009 原有 `scaners` 和 RAW 规则完全不变。

若 ros6 源站 NetBSD 文件格式变更或 :9443 无法连接，工作流应失败，不要绕过安全校验；检查错误后针对性修复。查看日志：`gh run view <运行ID> --log-failed`。
