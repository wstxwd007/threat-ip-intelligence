# v0.1.3 高风险名单质量闸门与误封影响审计

> 只对公开 Spamhaus DROP 名单运行。**不代表独立测得的误报率，也不证明名单内每个 IP 都为恶意主机。**

## 一、自动发布（默认每日 03:17 UTC）

`update-feeds.yml` 先生成候选文件至 GitHub Runner 的临时目录，再执行 `quality.py` 检查与已发布 `dist/ipv4.txt` 的变化。**只有检查通过才复制候选文件到 `dist/`，并提交 `reports/quality-latest.json`**。失败则保留原发布文件和上一次报告，工作流标红；请审阅来源及配置，不要通过删除闸门来“修复”。

此前工作流每 6 小时采集，现调整为每日一次。Spamhaus 官方文档指出 DROP 更新较慢，通常每天一次足够，过度拉取可能被限制：<https://www.spamhaus.org/faqs/do-not-route-or-peer-drop/>。

## 二、风险指标

- `/16` 或更大 CIDR 的 **条目数**、前缀直方图、**原始地址总量**（不去重），以及全名单的 **独立地址覆盖量**（去重）。
- 两版名单完全相同条目增加/删除量；地址空间新增、移除量（处理 CIDR 重叠；不能用原始条目数相减）。
- 新加入的 `/16` 或更大网段数量。
- 任何一次来源变化都不自动扩大 `/32` 成 `/24`。

`config/quality-policy.json` 默认发布闸门：

| 参数 | 默认值 | 说明 |
|---|---:|---|
| `large_prefix_threshold` | 16 | `/16` 或更大计入“大网段” |
| `max_added_unique_ipv4` | 2,000,000 | 地址新增量绝对阈值 |
| `max_added_ratio` | 0.25 | 新增量占旧版覆盖量比率 |
| `max_removed_ratio` | 0.35 | 移除量占旧版覆盖量比率 |
| `max_new_large_cidrs` | 2 | 新出现的大 CIDR 个数阈值 |

**必须同时超过绝对新增量与新增比例，才触发“大幅新增覆盖”闸门**；超过移除比例或新大 CIDR 数则单独触发。数值是初始保守阈值，需要依据真实一段时间的发布波动调整。异常只要求人工审查，不等于情报源一定错误。

## 三、GitHub 验收

```powershell
gh run list --workflow update-feeds.yml --limit 5
gh workflow run update-feeds.yml --ref main
gh run list --workflow update-feeds.yml --limit 5
git pull --ff-only
Get-Content .\reports\quality-latest.json -Encoding UTF8
```

`reports/quality-latest.json` 在首次**新工作流**成功后生成。不能仅靠“绿色 PASS”证明 RouterOS 已获得最新 IP，因为本工作流**不操作路由器**。

## 四、运行边界

- GitHub 只处理和发布满足来源许可的 Spamhaus 数据，ros6 的原始地址和 RB5009 实际名单不会出现在公开报告。
- 公共 SHA-256 只能用于同发布源内部一致性校验，不等于独立签名。源站或仓库被控制的风险应通过分支保护、最小化 Actions 写权限、独立可信签名等缓解。
- 已有 `dist/ipv4.txt` 必须保留，否则发布闸门安全拒绝运行；不能通过空基线人为绕过。
- 同步公开名单到 RB5009 之前，还需要本地冲突审计和受控增量审批。旧 `scaners` 及 RAW 不变。
