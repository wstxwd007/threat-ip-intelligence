# v0.1.2 — ros6 只读情报质量审计操作说明

## 目标和明确边界

- 现有 RB5009 `scaners` 条目：上次实际检查为 **8,672 条**，这是**路由器地址列表总数**，不一定等于 ros6 当前源文件条数。
- GitHub `dist/ipv4.txt`：上次验收为 **1,756 条 Spamhaus DROP 地址/CIDR**；v0.1.2 保留这条发布链路不变。
- 每日只读下载 ros6 官方 `scaners.rsc`，检查其 RSC 数据语法并计算与已经发布的 Spamhaus DROP 的交集、覆盖范围和新增覆盖量。
- **不执行 RSC，不导入到 RouterOS，不发布 ros6 或合并后的 IP 明细。** 未确认数据再分发授权之前，这一限制不能取消。

## 架构

```
ros6 scaners.rsc (HTTPS/9443)   GitHub main/dist (已发布 Spamhaus)
         |                                  |
   严格地址列表解析                   清单 SHA-256 验证
         |                                  |
         +----------------+-----------------+
                          |
                整数区间合并和交集统计
                          |
          reports/ros6-latest.json + ros6-latest.md
          仅公开统计/哈希；不公开地址或合并名单
```

GitHub Actions 名称：`audit-ros6`，每天 UTC `02:47` 尝试运行一次，支持 `workflow_dispatch` 手动触发。定时触发可能延迟，不能保证严格准点。

## 从现有 v0.1.1 升级到 v0.1.2（Windows）

1. 在已有 `threat-ip-intelligence` 项目路径解压**覆盖**完整 ZIP，保留 `.git`、`dist/` 和旧源码。
2. PowerShell 进入项目根目录执行：

```powershell
git status --short
git diff --check
py -3 -m unittest discover -s tests -v

git add -A
git commit -m "feat: add ros6 read-only overlap audit v0.1.2"
git push origin main
```

3. `tests` 通过后运行：

```powershell
gh workflow list
gh workflow run audit-ros6.yml --ref main
gh run list --workflow audit-ros6.yml --limit 5
```

4. 如果最新运行失败，使用其 ID 查看日志：

```powershell
gh run view <ID> --log-failed
```

5. 如果成功，访问仓库 `reports/ros6-latest.md` 查看统计；报告会作为 GitHub 提交出现，而**不会更改 `dist/ipv4.txt`**。

## 报告关键指标含义

| 字段 | 含义 |
|---|---|
| `ros6_entry_count` | ros6 解析后，精确去重的 IP/CIDR 条目数量 |
| `inputs.ros6_duplicate_rows` | ros6 原始记录中的完全重复行数（保留公开统计，不保留明细） |
| `spamhaus_entry_count` | 已发布 Spamhaus 的去重条目数量 |
| `exact_same_entries` | 两套数据中写法/网络完全一致的 IP/CIDR 条目数量 |
| `ros6_entries_fully_covered_by_spamhaus` | ros6 的每个条目是否被 Spamhaus 并集完全覆盖 |
| `spamhaus_entries_fully_covered_by_ros6` | 反向覆盖数量 |
| `ros6_ipv4_addresses_covered` | ros6 CIDR 合并去重后实际代表的 IPv4 地址数量 |
| `overlap_ipv4_addresses` | 两套来源共同覆盖的实际 IPv4 地址数量 |
| `combined_unique_ipv4_addresses` | 合并后实际覆盖的 IPv4 地址数量 |
| `additional_ipv4_addresses_from_ros6` | 对比 Spamhaus，ros6 在其之外额外覆盖的地址数量 |
| `additional_ipv4_addresses_from_spamhaus` | 对比 ros6，Spamhaus 在其之外额外覆盖的地址数量 |

**注意：** 这并非风险置信度评分。CIDR 很大时地址覆盖量可能远大于条目数；统计并不证明该段内的每个 IP 都曾攻击过你的设备。

## 故障策略

- `unsupported RouterOS script directive`：ros6 下载格式含本项目未许可的 RSC 命令；暂停审计，先人工审阅**本地**格式，不直接执行脚本。
- `unsafe or unsupported RSC syntax`：包含 `$`、`[]`、命令分隔符或其他被拒绝语法；不应临时放宽限制。
- `source response too large`：下载超过 16 MiB，进入人工审查。
- `ros6 entry count outside safety bounds`：默认要求 1,000～100,000 条，防止空白/截断/异常超量数据被当成正常报告。
- `published Spamhaus SHA-256 mismatch`：现有 `dist` 文件和清单不一致，原审计报告保留。
- `published Spamhaus feed too old/new`：超过 72 小时未成功发布，先检查原 `publish-ip-feeds` 工作流。
- HTTPS 失败、DNS 不通或访问 `:9443` 受阻：保留上次报告。GitHub 公共 Runner 是否能连接该端口需要实际测试，不允许禁用 TLS 校验。

## 离线只读分析（备用）

如果 GitHub Runner 无法连接 ros6，可以在**可信本地计算机**下载 ros6 `.rsc` 后，用 CLI 运行只读审计，不需要 RouterOS 密码：

```bash
python3 -m threatip.audit --config config/ros6-audit.json \
  --dist dist --out /tmp/tipi-ros6-audit --ros6-file /path/to/scaners.rsc
```

该命令只写入 `/tmp/tipi-ros6-audit` 的匿名统计报告，不会改变路由器。**不要上传 `scaners.rsc` 到你的公开 GitHub 仓库。**

本地输出中的 SHA-256 不能证明 ros6 原始内容的来源身份；传输时应验证 HTTPS 证书。由于无法读取 ros6 的可靠源更新时间，仅能确认本次下载时间和 SHA-256。

## 许可与后续

ros6 项目原始说明：https://www.ros6.com/?action=show&id=261

源数据再分发许可没有得到明确的动态数据库授权。后续如要把 ros6 IP 合并进公开 `dist/ipv4.txt`，需要先取得作者明确许可；若只想在 RB5009 本地组合多源封禁，仍需单独设计更新协调，解决 ros6 旧脚本清空 `scaners` 的冲突。
