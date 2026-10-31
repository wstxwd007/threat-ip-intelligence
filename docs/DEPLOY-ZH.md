# Threat IP Intelligence v0.1.2 — 中文部署手册

## 0. 安全承诺与先决条件

- 完全保留 RB5009 原有 `/ip firewall raw` 规则、`scaners` 地址列表名称与现有条目；客户端仅管理注释**完全等于 `TIPI/v1`** 的条目。
- 默认预演，不写 RouterOS；第一次正式更新必须手动加 `--apply --confirm scaners`。
- 建议在 **Debian 13** 等长期在线机器运行 RouterOS 更新客户端；QNAP 如果没有 Python 3.11+，不要替换系统 Python。也可放在使用合适 Python 的容器或管理主机中。
- 需要 RouterOS 7 `www-ssl` HTTPS REST API、可验证 TLS 证书、受限的专用 RouterOS 用户；**绝不把管理 API 开放到公网**。
- 首次采集需要访问 Spamhaus，GitHub Actions 负责公开源构建；终端只需要访问 GitHub 发布的 `manifest.json`/`ipv4.txt`。

## 1. 上传到公开 GitHub

先在 Windows 上解压本项目。安装 Git 和 GitHub CLI (`gh`) 后，在项目根目录运行：

```powershell
gh auth login
git init -b main
git add .
git commit -m "Initial release: threat-ip-intelligence v0.1.0"
gh repo create threat-ip-intelligence --public --source . --remote origin --push
```

`gh` 命令会使用**你自己的 GitHub 身份**创建仓库；不要将路由器密码、API 密钥、证书私钥或内部网络日志提交到 GitHub。

GitHub 仓库 **Settings → Actions → General → Workflow permissions** 确认允许发布工作流的 `GITHUB_TOKEN` 写入仓库内容。如果设置分支保护，须将数据发布权限与审核流程协调，不能为了让自动发布通过而任意取消安全保护。

在仓库 **Actions → publish-ip-feeds → Run workflow** 首次手动运行，成功后检查：

```text
https://raw.githubusercontent.com/<GitHub用户名>/threat-ip-intelligence/main/dist/manifest.json
https://raw.githubusercontent.com/<GitHub用户名>/threat-ip-intelligence/main/dist/ipv4.txt
```

自动更新计划：每 6 小时尝试，GitHub Actions 定时任务不保证准点。首次成功之前 `dist/` 仅有 `.gitkeep`，不能部署。

## 2. 本地构建与测试（可选）

```bash
python3 --version    # >= 3.11
python3 -m unittest discover -s tests -v
python3 -m threatip.build --config config/sources.json --out dist
```

如果官方源异常、TLS 不受信任、格式异常或黑名单为空，程序退出非 0，不会自动删除上一次 GitHub 已发布的内容。

## 3. RB5009 只读检查

以下命令只是查看，不改变网络：

```routeros
/ip firewall raw print detail without-paging
/ip firewall address-list print count-only where list="scaners"
/ip service print detail where name="www-ssl"
/ip service print detail where name="www"
```

你的 RAW 预期规则：`chain=prerouting action=drop src-address-list=scaners`，不应修改、移动或复制。

### 启用 RouterOS HTTPS REST 的注意事项

官方 RouterOS 7 文档规定 REST 由 `www-ssl` 提供；仅允许可信管理机访问这个服务：

- 配置带有正确主机名/IP SAN 的 TLS 服务端证书，管理机信任该 CA；不可使用 `curl -k`、跳过证书验证等方式。
- 创建仅供更新任务使用的专用用户，赋予所需最小策略权限，并使用 RouterOS 用户的来源地址限制。
- `www-ssl` 的 `available-from` 限制为管理主机 IP 或专用管理子网；防火墙 input 同样限制；不将 443/管理端口映射到公网。
- 不启用明文 REST (`www`)；检查 `rest-plain=no` 是否符合你的 ROS 7 版本语法。
- 不知道你现有证书和管理限制前，**不要照抄互联网上的 `/ip service set` 命令直接改线上防火墙**。

官方参考：https://manual.mikrotik.com/docs/developer-guides/rest-api/

## 4. 在 Debian 客户端进行首次预演

从 GitHub 仓库 clone 最新主分支：

```bash
git clone https://github.com/<GitHub用户名>/threat-ip-intelligence.git
cd threat-ip-intelligence

export TIPI_ROS_URL='https://<RB5009的管理地址或主机名>'
export TIPI_ROS_USER='tipi-publisher'
export TIPI_ROS_CA='/etc/threat-ip-intelligence/router-ca.pem'
read -r -s -p 'RouterOS password: ' TIPI_ROS_PASSWORD; echo
export TIPI_ROS_PASSWORD

python3 -m threatip.routeros \
  --manifest-url 'https://raw.githubusercontent.com/<GitHub用户名>/threat-ip-intelligence/main/dist/manifest.json' \
  --router-url "$TIPI_ROS_URL" --ca-file "$TIPI_ROS_CA"
```

**首次输出应为 `DRY-RUN`**。必须阅读 `to_add`、`to_remove_owned_only`、`external_entries_preserved`、`release_count`。对首次更新来说，`to_remove_owned_only` 理应为 0。

若输出 `SAFE STOP`，先排除证书/API/网络或名单安全阈值问题，不应通过关闭校验绕过。

## 5. 人工批准首次更新

从同一目录重新执行，额外添加以下参数：

```bash
  --apply --confirm scaners
```

推荐复制上一步完整命令，在末尾添加两项参数，不要把演示 IP 列表输入真实路由器。首次默认**最多增加 2000 条**。若超过上限，程序拒绝，先评估 RB5009 内存、旧列表和数据规模后，再针对本次批准提高 `--max-adds`。

更新机制：

1. 下载 manifest，校验 schema、文件名、SHA-256、IP 计数、所有 IP 合法性；
2. 读取现有 `scaners` 和 RAW 拦截规则；
3. 计算需要新增的 IP（如果旧列表已存在相同地址，则不重复添加）；
4. 只删除本程序添加、并已不在新版本的过期条目；
5. 更新后再读回校验。如果写入失败，尝试补偿回滚并报警。

**不会清空 `scaners`，也不会删除 ros6 原脚本导入、手动添加或其他工具添加的地址。** 但若你现在的 ros6 scheduler 还在运行，可能随时全量重建整个 `scaners`，把本工具的标记也清掉；正式切换更新主控前，要做好原调度器迁移安排，不能让两套写入器长期冲突。不要在首轮验证时擅自禁用原调度器。

## 6. 自动运行（可选，先验证再启用）

仓库包含 `deploy/systemd/tipi-routeros.service` + `.timer`，默认仍然只读预演。

把仓库部署为 `/opt/threat-ip-intelligence`，创建非特权本机用户 `tipi`，准备只对管理员和服务用户开放的 `/etc/threat-ip-intelligence/credentials.env`：

```ini
TIPI_ROS_URL=https://router.example.lan
TIPI_ROS_USER=tipi-publisher
TIPI_ROS_PASSWORD=在本机填入真实密码_不要提交GitHub
TIPI_ROS_CA=/etc/threat-ip-intelligence/router-ca.pem
TIPI_MANIFEST_URL=https://raw.githubusercontent.com/OWNER/threat-ip-intelligence/main/dist/manifest.json
TIPI_ENABLE_APPLY=no
```

`TIPI_ENABLE_APPLY=no` 先预演几个周期。确认发布、连接与误封情况后，再将其改为 `yes`。把凭据文件设为 `root:tipi`、权限 `0640`，CA 文件向 `tipi` 用户开放只读权限；目录 `/etc/threat-ip-intelligence` 权限建议 `0750`、所属组 `tipi`。**切勿将这个示例文件复制回公开仓库。**

```bash
sudo cp deploy/systemd/tipi-routeros.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tipi-routeros.timer
sudo systemctl start tipi-routeros.service
sudo journalctl -u tipi-routeros.service -n 80 --no-pager
```

这不是让 GitHub Actions 直接登录 RB5009；GitHub 只负责发布公开数据，RouterOS 更新器从自己的 LAN 侧调用受限 REST API，不需要公网开放入站连接。

## 7. 恢复与撤销

- 保留 `scaners` 和 RAW 的情况下，停止本程序的定时任务：`sudo systemctl disable --now tipi-routeros.timer`；这不会自动删除任何地址。
- 若新版本名单有问题，可恢复上一个已知良好 manifest+ipv4 版本，并再次预演差异、人工批准；默认的大量删除保护会阻止异常突降。
- 如果必须从 RB5009 移除本工具自身新增的地址，先使用：

```routeros
/ip firewall address-list print detail where list="scaners" and comment="TIPI/v1"
```

确认后单独清理这些条目。**不许执行 `/ip firewall address-list remove [find list=scaners]`**；那会删除原有 ros6 名单。

## 8. 没有直接执行的内容

本文件不在你的 RB5009 上执行任何操作、不访问你的密码、不改变 RAW、Filter、NAT、PPPoe 或默认路由。所有涉及线上写操作的步骤由你在本机完成并验收。


## 7. v0.1.2 GitHub 仓库覆盖升级（不重新建仓）

将 v0.1.2 源码 ZIP **解压覆盖已有项目文件夹**，但保留原 `.git` 和 `dist/` 目录；不可删除旧目录重来。

在 Windows PowerShell 中：

```powershell
cd "$env:USERPROFILE\Downloads\threat-ip-intelligence"
git status --short
git diff --check
py -3 -m unittest discover -s tests -v
git add -A
git commit -m "feat: ros6 read-only overlap audit v0.1.2"
git push origin main
```

`tests` 通过后触发新的 `audit-ros6`。该工作流与现有 `publish-ip-feeds` **分离**；如审核任务失败，生产数据发布仍按原来方式工作。

```powershell
gh workflow list
gh workflow run audit-ros6.yml --ref main
gh run list --workflow audit-ros6.yml --limit 5
```

成功后浏览 `reports/ros6-latest.md`。若失败，使用 `gh run view <运行ID> --log-failed` 查看失败原因。**不能以 `-k` 跳过 TLS 校验来强行通过验收。**

ros6 私有文件、RB5009 导出及 `.rsc` 不应进入公开仓库，更多见 [ROS6-AUDIT-ZH.md](ROS6-AUDIT-ZH.md)。
