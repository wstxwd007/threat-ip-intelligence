# v0.1.3 开发及发布验收

## A. 本地离线验证

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q threatip
sh scripts/acceptance.sh
```

预期所有 `unittest` 为 OK；包括 v0.1.2-r1 旧功能回归、Spy/假数据异常、公开名单质量闸门、三方覆盖率、私有输出目录及 watchlist 过滤。

## B. GitHub CI

Windows PowerShell 解压完整包覆盖到原目录，确保 `.git` 和 `dist/` 保留：

```powershell
git status --short
git diff --check
git add -A
git diff --cached --check
git commit -m "feat: quality gate and private RouterOS audit v0.1.3"
git push origin main
gh run list --workflow test.yml --limit 5
```

`tests` 通过不代表在线情报已发布，待 CI green 后手动执行公开发布工作流：

```powershell
gh workflow run update-feeds.yml --ref main
gh run list --workflow update-feeds.yml --limit 5
```

如果发布失败，执行 `gh run view <运行ID> --log-failed`。**不要因质量风险闸门失败就取消数据校验。**

## C. 公共报告与历史安全保护

成功工作流应新增/更新 `reports/quality-latest.json`，其中只能含数量、前缀分布、来源哈希、审核标记；不得含私有 RouterOS IP。若质量闸门阻断发布，`dist/` 和上一份报告维持不变。

原 `audit-ros6` 工作流仍独立运行，只公开 ros6 × Spamhaus 聚合统计；不公开 ros6 明细或混合名单。

## D. 路由器本地验收

运行 `docs/ROUTER-PRIVATE-AUDIT-ZH.md` 中只读命令。内网 `local/router-audit-latest.json` 应包含 router、ros6、Spamhaus 的三方覆盖率和指定 watchlist 冲突报告。确认无任何 PUT/POST/PATCH/DELETE 请求、无防火墙规则变化。未通过此项前不允许自动导入 RB5009。
