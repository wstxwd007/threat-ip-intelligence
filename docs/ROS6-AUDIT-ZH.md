# v0.1.2-r1 — ros6 NetBSD 纯地址表质量审计操作说明

## 目标和明确边界

- 现有 RB5009 `scaners` 条目：上次实际检查为 **8,672 条**，这是**路由器地址列表总数**，不一定等于 ros6 当前源文件条数。
- GitHub `dist/ipv4.txt`：上次验收为 **1,756 条 Spamhaus DROP 地址/CIDR**；v0.1.2 保留这条发布链路不变。
- 每日只读下载 ros6 官方 `scaners.netbsd`，检查其纯 IP/CIDR 数据格式并计算与已经发布的 Spamhaus DROP 的交集、覆盖范围和新增覆盖量。
- **不执行 RSC，不导入到 RouterOS，不发布 ros6 或合并后的 IP 明细。** 未确认数据再分发授权之前，这一限制不能取消。

## 架构

```
ros6 scaners.netbsd (HTTPS/9443)   GitHub main/dist (已发布 Spamhaus)
         |                                  |
   严格纯文本 IP/CIDR 解析                   清单 SHA-256 验证
         |                                  |
         +----------------+-----------------+
                          |
                整数区间合并和交集统计
                          |
          reports/ros6-latest.json + ros6-latest.md
          仅公开统计/哈希；不公开地址或合并名单
```

GitHub Actions 名称：`audit-ros6`，每天 UTC `02:47` 尝试运行一次，支持 `workflow_dispatch` 手动触发。定时触发可能延迟，不能保证严格准点。

## 从现有 v0.1.2 升级到 v0.1.2-r1（Windows）

1. 在已有 `threat-ip-intelligence` 项目路径解压**覆盖**完整 ZIP，保留 `.git`、`dist/` 和旧源码。
2. PowerShell 进入项目根目录执行：

```powershell
git status --short
git diff --check
python -m unittest discover -s tests -v  # 本地已安装 Python 时执行；否则以 GitHub tests 工作流为准

git add -A
git commit -m "fix: use ros6 NetBSD plain address feed v0.1.2-r1"
git push origin main
```

3. GitHub `tests` 通过后运行（Windows 如无 `py` 可跳过本地测试）：

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

- `unsupported ros6 NPF data format at line N`：NetBSD 下载文件存在不符合纯 IPv4/CIDR 的数据行，保留旧报告；先确认上游格式，不得盲目跳过数据。
- 脚本控制符、RouterOS 指令、HTML 错误页：NetBSD 纯数据解析器会拒绝，不能通过过滤危险行后继续发布。
- `source response too large`：下载超过 16 MiB，进入人工审查。
- `ros6 entry count outside safety bounds`：默认要求 1,000～100,000 条，防止空白/截断/异常超量数据被当成正常报告。
- `published Spamhaus SHA-256 mismatch`：现有 `dist` 文件和清单不一致，原审计报告保留。
- `published Spamhaus feed too old/new`：超过 72 小时未成功发布，先检查原 `publish-ip-feeds` 工作流。
- HTTPS 失败、DNS 不通或访问 `:9443` 受阻：保留上次报告。GitHub 公共 Runner 是否能连接该端口需要实际测试，不允许禁用 TLS 校验。

## 离线只读分析（备用）

如果 GitHub Runner 无法连接 ros6，可以在**可信本地计算机**下载 ros6 `.netbsd` 后，用 CLI 运行只读审计，不需要 RouterOS 密码：

```bash
python3 -m threatip.audit --config config/ros6-audit.json \
  --dist dist --out /tmp/tipi-ros6-audit --ros6-file /path/to/scaners.netbsd
```

该命令只写入 `/tmp/tipi-ros6-audit` 的匿名统计报告，不会改变路由器。**不要上传 `scaners.netbsd` 或 `scaners.rsc` 到你的公开 GitHub 仓库。**

本地输出中的 SHA-256 不能证明 ros6 原始内容的来源身份；传输时应验证 HTTPS 证书。由于无法读取 ros6 的可靠源更新时间，仅能确认本次下载时间和 SHA-256。

## 许可与后续

ros6 项目原始说明：https://www.ros6.com/?action=show&id=261

源数据再分发许可没有得到明确的动态数据库授权。后续如要把 ros6 IP 合并进公开 `dist/ipv4.txt`，需要先取得作者明确许可；若只想在 RB5009 本地组合多源封禁，仍需单独设计更新协调，解决 ros6 旧脚本清空 `scaners` 的冲突。

## v0.1.2-r1 在线故障修复说明

- v0.1.2 的首次 Github Actions 审计（run `41157283123`）在解析 RouterOS `.rsc` 时遇到不支持的指令，严格失败保护如预期生效。
- ros6 作者的项目网页同时公布了供 NetBSD NPF `table type lpm file` 使用的 `scaners.netbsd`。本版改为只读取该**非脚本格式**，审计阶段仍然只输出计数和哈希。
- 纯文本解析只接受逐行 IP/CIDR 与 `#` 注释。若实际下载包含其他 NPF 语法，将明确失败并保留旧报告；不能推断源文件已经验证通过。
- 文件没有被公开再分发授权前，不上传完整名单；GitHub Actions 只保留审计汇总。
- 改动仅涉及 `audit-ros6`，`publish-ip-feeds` 和 RouterOS 客户端不变。
