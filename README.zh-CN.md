# agy-bot

[English](./README.md) | [简体中文](./README.zh-CN.md)

基于官方 **Google Antigravity CLI (`agy`)** 原生基座构建的开源配套生态栈——直连本地官方 `agy` 常驻 `stream-json` 会话池（规避第三方反代链路封号风险）：
- **Telegram 群组多 Bot 团队高效协作与 RBAC**：支持 Bot API 9.5+ `sendMessageDraft` 实时流式输出、群聊防 429 自适应退避、`acb-team` 异步委派、可选 Git Worktree（`worktree: true`）并发隔离，以及群聊/成员 RBAC 权限隔离（`AGY_TG_ADMIN_USERS` / `AGY_TG_READONLY_USERS`）。
- **多指纹多出口 Camoufox 浏览器 + Telegram Mini App 人工接管**：支持按命名 Profile 独立配置 OS、视口分辨率、WebGL、WebRTC/GeoIP 与代理出口按需切换（隔离任务环境并应对 Cloudflare 等站点严格风控检查），同时支持对核心账号严格锁定持久化指纹 + 宿主机直出；内置 Mini App 可视化指纹切换抽屉与 Telegram `/browser` 内联控制面板，遇到人机验证或交互确认时可一键人工接管，处理完毕后交还 AI 继续执行。
- **跨会话防遗忘、记忆防投毒、`/dream` 记忆合并与自愈运维**：支持 `/compact` 无损重水合、本地无状态观察者 Shim、三层防记忆投毒守卫（`bridge/memory_guard.py` + Hook Gate + Instinct Daemon 全步审计）、`/dream` 定期本能归并与 `observations.jsonl` gzip 归档、Continuous-Learning v2 习惯演化、`mem-search` 检索、`/undo`/`/redo`、`/schedule`/`/cron`、`/project`、`/usage`/`/cost`、输出前主备模型自动降级（`AGY_TG_FALLBACK_MODELS` / `/model fallback`）、`agy-bot setup`（`--bots ... --systemd-out ...`）/`doctor --fix` 自愈、Docker 容器化部署（[`Dockerfile`](./Dockerfile)、[`docker-compose.example.yml`](./docker-compose.example.yml)、[AI-INSTALL 安装指南](./docs/AI-INSTALL.md)）、`_JobQueue` 原子落盘重启恢复及前置自检 + LKG 自动回滚的零停机热重载。
- **AGY Studio WebUI 控制面（`studio/` + `webui/`）**：基于密码鉴权（`AGY_STUDIO_AUTH_MODE=password`，scrypt + `HttpOnly`/`SameSite` Cookie + CSRF + 脱敏访问日志）的 React + aiohttp 本地 Sidecar，提供基于单写者 IPC（`bridge/studio_ipc.py`）的 Workspace 实时流式对话、Jobs 派工/取消/重试控制面、安全 Schedules 调度管理、全局实时 SSE（`/api/events`）以及同源 Live-Browser 人工接管抽屉，全量 MIT 净室开源。
- **自部署 OpenBao 无痕用密示例 + 全链路脱敏门禁**：提供完全脱敏的 [OpenBao 无痕用密实战指南](./docs/OPENBAO_SECRETOPS_GUIDE.md)，配合工作区与 Git 历史结构化扫描及 Python 3.11–3.14 + Node 22 CI 矩阵闭环保障。

- **开源协议**：[MIT](./LICENSE)
- **代码仓库**：`https://github.com/gaoshanyuhupo/agy-bot`
- **社区交流**：[LINUX.DO](https://linux.do/)
- **安全策略**：[SECURITY.md](./SECURITY.md) · **贡献指南**：[CONTRIBUTING.md](./CONTRIBUTING.md)

![agy-bot 系统架构图](./docs/images/architecture.svg)

---

## 核心架构与组件

### 1. `bridge/` — 多 Bot 实时 Telegram 桥接引擎 v3（`bridge.py`、`cli.py`）
- **原生 `sendMessageDraft` 流式渲染与群聊防 429 回退**：支持 `0ms` 瞬时 *"Thinking…"* 气泡、原生 Telegram 停止按钮、工具/思考状态事件驱动更新、动画流式输出，以及群聊自适应退避与最终消息合并投递。
- **常驻预热 `stream-json` 会话池**：维护 `agy --input-format stream-json --output-format stream-json` 预热子进程池，支持空闲 TTL 回收与即时中断取消。
- **项目与工作区切换（`/project`）**：在已注册的 Antigravity CLI 项目（`~/.gemini/config/projects/*.json`）间一键切换，并按会话域自动恢复对应对话。
- **订阅配额与本地开销账单（`/usage`、`/cost`）**：将云端配额实时查询（`/usage`）与本地 Transcript Token、Prefix Cache 命中率及 API USD 成本统计（`/cost`）清晰分离。
- **自主定时任务调度器（`/schedule` / `/cron`）**：支持标准 5 段式 Cron 表达式与中英文相对倒计时（`in 30m` / `10分钟`），内置最小安全间隔下限（300s）与 Telegram 内联控制面板。
- **内容寻址工作区撤销/重做（`/undo`、`/redo`）**：每轮自动采集工作区前后快照，支持外部修改冲突安全拦截、`force` 强行回滚与一键 Redo 重放。
- **多 Bot 并发与协作总线（`bot_bus.py`、`bot_bus_mcp.py`）**：独立实例 Outbox 隔离、`fcntl.flock` 原子图片认领锁 + 单实例 Poller 文件锁（`FD_CLOEXEC`），支持多 Bot（如 `@bot_one`、`@bot_two`）并发与 `acb-team` stdio MCP 委派；`team_dispatch` 支持可选 `worktree: true` Git Worktree 并发隔离（在 `<repo>/.worktrees/<job_id>` 与 `agy-team/<job_id>` 分支独立运行，通过 `.git/info/exclude` 零污染排除，无改动自动回收，有提交或未提交改动自动保留并可通过 `team_job(action="cleanup_worktree")` 清理）。
- **主备模型自动降级与群聊 RBAC（`model_failover.py`、`access_control.py`）**：在产生任何工具调用或用户可见输出前，遇到 `429`/`5xx` 自动按 `AGY_TG_FALLBACK_MODELS`（或 `/model fallback`）切换备选模型；并支持按 `admin`/`readonly` 区分群成员权限（`AGY_TG_ADMIN_USERS`、`AGY_TG_READONLY_USERS`），为只读成员隔离安全会话池。
- **Telegram `/browser` 内联控制面板**：直接在 Telegram 内查看浏览器实时状态与脱敏出口信息、切换指纹（`browser:switch:*`）或安全启停；强制仅私聊可触发 Mini App `web_app` 按钮，并拦截只读成员写操作。
- **安装引导、环境体检与 Docker 部署（`agy-bot setup` / `agy-bot doctor`、`Dockerfile`）**：基于标准 `pyproject.toml` 提供 `agy-bot` 命令，支持单 Bot 与多 Bot 团队一键初始化（`agy-bot setup --bots ... --systemd-out ...`）、离线/联网 `doctor` 体检及非 root 容器化模板（[`Dockerfile`](./Dockerfile)、[`docker-compose.example.yml`](./docker-compose.example.yml)、[docs/AI-INSTALL.md](./docs/AI-INSTALL.md)）。
- **Fail-Closed GitHub Webhook 接收器（`bridge/github_webhook.py`）**：纯标准库 HMAC-SHA256（`X-Hub-Signature-256`）Webhook 监听服务（`127.0.0.1:18798`），支持 OpenBao/文件/环境变量取密、`Content-Length` 上限与 `X-GitHub-Delivery` 重放去重、提示词注入清洗，并附脱敏模板 [`systemd/examples/agy-github-webhook.service.example`](./systemd/examples/agy-github-webhook.service.example)。
- **`_JobQueue` 原子落盘重启恢复**：将待处理与执行中的排队任务原子持久化至 `QUEUE_FILE`，重启时按 FIFO 顺序自动恢复，内置可配置 TTL 过期清理（`AGY_TG_QUEUE_TTL_SEC`，默认 `3600` 秒）及会话作用域/在途防重（`restore_persisted_queue`）。
- **零停机热重载、前置自检与 LKG 自动回滚**：通过哨兵文件（`AGY_TG_RELOAD_FILE`，如 `/tmp/agy_bridge_reload`）在空闲间隙执行 `os.execv` 重载；重载前强制执行 `py_compile` + `bridge.py --self-check`，配合 Last-Known-Good（`.rollback/lkg`）快照与启动面包屑（`reload_pending.json`）在启动异常时自动回滚并告警，并支持运维快照手动回滚（`sync_live.py rollback`）。
- **三层外部内容防记忆投毒守卫与 `/dream`（`bridge/memory_guard.py`）**：在 Bridge（为不可信/只读会话打污点标记、回收干净预热会话并注入 `AGY_UNTRUSTED_SESSION=1` / `AGY_MEMORY_READONLY=1`）、Hook Gate 与 Instinct Daemon 间共享粘性污点登记与注入规则校验，并支持通过 `/dream` 查看守卫状态或后台触发记忆合并。

### 2. `.agents/skills/live-browser/` — 多指纹多出口实时浏览器与 Telegram 人工接管
- **双模实时视图与面板内指纹切换**：群内单卡片 `editMessageMedia` 实况预览与 `/browser` 控制面板，搭配 Telegram Mini App 低延迟二进制 JPEG WebSocket 流与可视化指纹切换抽屉（基于 Cloudflare Tunnel 暴露 `https://live.your-domain.com`）。
- **多命名 Profile、多指纹与多出口代理切换（`--profile`、`--os`、`--proxy-bao`）**：在 `~/.config/agy-live-browser/profiles.json`（`0600`）管理独立浏览器身份，按需配置 `os`（`windows`/`macos`/`linux`）、`locale`、`window`、`webgl_config`、`block_webrtc`、`geoip`、`--ephemeral` 临时目录及独立 `--proxy` 或 OpenBao 内存动态提取 `--proxy-bao`；状态与 TG 卡片中所有代理凭据均自动脱敏（如 `socks5://***@example.com:1080`）。
- **核心持久化指纹硬锁定（Fail-Closed）**：当宿主机安装有固定 Profile 管理模块时，默认或 `--profile default` 自动锁定持久化指纹（`os="windows"`、`headless="virtual"`）与宿主机直出（`network.proxy.type=0`），任何覆写代理或指纹的企图均直接报错拒绝启动。
- **三态控制权仲裁**：在 AI 观看、一键人工接管（通过 `ai_allowed_event` 暂停 AI，由人类在面板内完成二次确认或 Cloudflare 等人机验证）与交还给 AI 之间无缝切换。
- **移动端/桌面端输入与 X11 剪贴板同步**：自动识别焦点输入框并弹出适配 `visualViewport` 的中文输入面板，支持外部 `xclip` 剪贴板读取与逐字拖拽选字（`document.caretPositionFromPoint`）。
- **CLI 示例**：
  ```bash
  live-browser profile create us-work --os macos --locale en-US --window 1440x900 --block-webrtc --geoip --proxy-bao kv/proxies/us-west
  live-browser start --profile us-work --restart --url "https://example.com"
  ```
- 完整操作与移动端指南见 [docs/TELEGRAM_LIVE_BROWSER_GUIDE.md](./docs/TELEGRAM_LIVE_BROWSER_GUIDE.md)。

### 3. `hooks/` — 无损压缩后重水合与生命周期门控
- **`rehydrate_after_compact.py`（`PreInvocation`）**：自动识别 `transcript_full.jsonl`（含 `/fork` 祖先链路）中的 `/compact` 检查点，精确恢复精简后的用户指令时间线、近期对话与按需 `read_file` 索引。
- **`claude_mem_hook_gate.py` 与 `hooks.json`**：统一生命周期门控（`SessionStart`、`PreInvocation`、`Stop`），通过 `AGY_INTERNAL_OBSERVER=1` 防止观察者递归并跳过斜杠命令与零工具轻交互；同时联动 `memory_guard` 对载荷与 Transcript 尾步做全步污点审计，拦截受污染会话的 `session-init` / `summarize` 记忆写入。

### 4. `mem-hub/` — 本地观察者 LLM Shim 与 Continuous-Learning v2
- **`agy_llm_shim.py`**：兼容 OpenAI/Anthropic 协议的本地 HTTP Shim，由无工具隔离的 `pure-llm` 沙盒驱动（`mem-hub/observer-sandbox/`），支持无状态轮转。
- **`agy_instinct_daemon.py`**：基于置信度提取会话经验（Instinct），通过 `memory_guard` 对采集全步（`USER_INPUT`、`PLANNER_RESPONSE`、工具调用与输出）及 LLM 候选规则进行防投毒校验，维护 `.agents/rules/ecc-active-instincts.md` 并演化受控上限的复用技能；内置 `/dream`（`dream`）定期记忆合并流水线（不安全本能隔离、时间衰减归档、同域相似本能合并、`observations.jsonl` 滚动 gzip 归档压缩及偏移量精确重算）。

### 5. `studio/` 与 `webui/` — AGY Studio Phase A（Workspace 流式对话、控制面与浏览器抽屉）
- **Workspace 流式对话与单写者 IPC（`studio/chat_service.py`、`bridge/studio_ipc.py`）**：提供实时 SSE Token 流式输出、会话历史与模型目录查询、中止控制，以及纯 React 安全 Markdown 渲染（`SafeMarkdown.tsx`，零原始 HTML 注入风险）。
- **Jobs 派工控制面与安全定时调度（`studio/control_plane.py`、`studio/event_hub.py`）**：支持 `acb-team` 任务派发、详情查看、取消与重试；在命令与安全间隔护栏内新增、启停、立即执行或删除定时任务；并通过全局 SSE（`/api/events`）实时推送状态变更。
- **同源 Live-Browser 抽屉（`studio/browser_proxy.py`）**：以同源鉴权代理转发本地 `live-browser` WebSocket 与文件传输，无需直接暴露上游端口。
- **零信任密码鉴权（`studio/auth.py`）**：默认启用 `AGY_STUDIO_AUTH_MODE=password`，凭据存储于仓库外 `0600` 的 `users.json`（可通过 `python3 -m studio.auth set-user` 初始化），强制执行首次改密（`must_change_password`）、同源与 CSRF 校验、实时 RBAC 降权驱逐及脱敏访问日志；脱敏服务模板见 [`systemd/examples/agy-studio.service.example`](./systemd/examples/agy-studio.service.example)。

### 6. `scripts/`、`tests/` 与 `docs/OPENBAO_SECRETOPS_GUIDE.md` — 无痕用密示例、脱敏门禁与成本核算
- **自部署 OpenBao 无痕用密示例指南**：完全脱敏的实战范式（`0600` 本地凭据初始化、CLI 短暂环境变量注入、Python 内存动态提取与 `live-browser --proxy-bao` 零落盘代理），详见 [docs/OPENBAO_SECRETOPS_GUIDE.md](./docs/OPENBAO_SECRETOPS_GUIDE.md)。
- **`scripts/security_audit.py`**：零泄漏结构化扫描器，覆盖明文密钥/Token、半掩码前缀、含凭证 URL、非白名单外链与裸域名、长数字/Hex/UUID ID、个人邮箱与未登记 `@handle`、硬编码 `/home/<user>` 或 `User=` 路径、非文档 IP、高危运行态文件及 Git 全量提交历史（`--check-history`），支持外部黑名单文件（`--blocklist-file` / `~/.config/agy-audit-blocklist.txt`）。
- **`tests/`**：全离线 `unittest` 回归套件，覆盖脱敏门禁（`test_desensitization.py`）、P0 稳定性加固（`test_bridge_p0.py`）、核心引擎与撤销/相册/429（`test_bridge_core.py`）、群聊 RBAC（`test_access_control.py`）、模型主备降级（`test_model_failover.py`）、定时调度（`test_scheduler.py`）、CLI 体检向导（`test_cli_doctor.py`）、Mini App 与 `/browser` 面板（`test_browser_panel.py`）、多指纹/固定指纹隔离（`test_live_browser_profiles.py`）、GitHub Webhook 安全（`test_github_webhook.py`）、每周对标雷达（`test_benchmark_digest.py`）、三层防记忆投毒与 `/dream` 合并（`test_memory_guard_and_dream.py`）、`_JobQueue` 持久化恢复与 LKG 热重载回滚（`test_queue_persistence_and_rollback.py`）与多 Bot 总线及 Worktree 隔离（`test_bot_bus.py`、`test_bot_bus_worktree.py`、`test_group_chat_bus.py`）。
- **`scripts/benchmark_digest.py`**：纯标准库每周对标雷达工具，通过 `--repos-file` 追踪可配置上游仓库的正式 Release、近期合并 PR 与默认分支 Commit，支持 `0600` 状态去重、无变更输出 `[SILENT]` 及外部文本防注入清洗。
- **`scripts/calc_cycle_cost.py`**：独立命令行工具，解析 `~/.gemini/antigravity-cli/brain/*/logs/transcript.jsonl`，输出 Token 消耗、缓存命中率与估算 USD 节省。

---

## 目录结构

```text
agy-bot/
├── .agents/                  # 通用技能（live-browser、continuous-learning-v2、altare、mem-search）与工作流
├── .github/                  # CI 工作流、Issue 表单模板与 PR 脱敏自检清单
├── bridge/                   # Telegram Bridge v3（bridge.py、studio_ipc.py、memory_guard.py、github_webhook.py、access_control.py、model_failover.py、scheduler.py、bot_bus*.py、cli.py、.env.example）
├── config/                   # 脱敏后的 MCP 配置模板（mcp_config.example.json）
├── docs/                     # AI-INSTALL 安装指南、系统架构图、Live Browser 指南与 OpenBao 无痕用密指南
├── hooks/                    # hooks.json、无损 rehydrate_after_compact.py 与生命周期门控
├── legacy/sdk-bridge/        # 早期 SDK bridge v1 历史参考
├── mem-hub/                  # agy_llm_shim.py、agy_instinct_daemon.py 与隔离 observer-sandbox/
├── scripts/                  # security_audit.py 脱敏审计器、verify_gate.py、benchmark_digest.py 对标雷达与 calc_cycle_cost.py 账单工具
├── studio/                   # AGY Studio aiohttp Sidecar（server.py、auth.py、chat_service.py、control_plane.py、event_hub.py、data_sources.py、browser_proxy.py、requirements.txt）
├── systemd/examples/         # 通用 systemd 单元模板（含 agy-studio.service.example、agy-github-webhook.service.example 与 YOUR_USER 占位符）
├── tests/                    # 脱敏审计、Studio/WebUI、RBAC、降级、桥接核心、调度器、CLI 向导、浏览器面板与协作总线单测
├── webui/                    # AGY Studio React + Vite + Tailwind 前端源码（通过 `npm ci && npm run build` 构建 `webui/dist`）
├── workspace/                # 通用工作区 Agent 规范（AGENTS.md）
├── Dockerfile                # 基于 pyproject.toml 的非 root 容器镜像构建模板
├── docker-compose.example.yml # 脱敏版 Coordinator + Worker Docker Compose 编排模板
├── .dockerignore             # Docker 构建上下文排除清单
├── pyproject.toml            # PEP 621 包定义、`agy-bot` CLI 入口与 Ruff 门禁配置
├── README.md / README.zh-CN.md
├── SECURITY.md / CONTRIBUTING.md
└── LICENSE
```

---

## 快速上手

> 如需单/多 Bot 一键初始化（`agy-bot setup --bots ... --systemd-out ...`）或 Docker / Compose 容器化部署（[`Dockerfile`](./Dockerfile)、[`docker-compose.example.yml`](./docker-compose.example.yml)）的完整零猜测指引，请参阅 **[docs/AI-INSTALL.md](./docs/AI-INSTALL.md)**。

### 1. 克隆仓库、安装 CLI 并初始化运行目录

```bash
git clone https://github.com/gaoshanyuhupo/agy-bot.git
cd agy-bot

python3 -m venv "$HOME/agy-tg-bridge/venv"
"$HOME/agy-tg-bridge/venv/bin/pip" install -e .

# 一键初始化运行时目录与 .env（自动设置 chmod 0600；若未传 --force 绝不覆盖已有 .env）：
"$HOME/agy-tg-bridge/venv/bin/agy-bot" setup --target-dir "$HOME/agy-tg-bridge"
```

也可手工将 `bridge/*.py` 复制到 Git 工作区外目录并配置 `chmod 600` 的 `.env`：

```bash
mkdir -p "$HOME/agy-tg-bridge"
cp bridge/bridge.py bridge/scheduler.py bridge/bot_bus.py bridge/bot_bus_mcp.py "$HOME/agy-tg-bridge/"
cp bridge/.env.example "$HOME/agy-tg-bridge/.env"
chmod 600 "$HOME/agy-tg-bridge/.env"
# 编辑 $HOME/agy-tg-bridge/.env，填入 Telegram BotFather Token 与允许的 Chat ID
```

将 [config/mcp_config.example.json](./config/mcp_config.example.json) 复制到 `~/.gemini/antigravity-cli/mcp_config.json`，并将 `YOUR_USER` 与占位 Token 替换为本地实际值。

### 2. 运行环境体检与启动

```bash
# 默认离线只读体检（追加 --fix 可自动收紧 .env 至 0600 并创建缺失目录；追加 --online 可联机校验 Telegram getMe 连通性）：
"$HOME/agy-tg-bridge/venv/bin/agy-bot" doctor --env-file "$HOME/agy-tg-bridge/.env"

# 前台试运行验证（生产环境建议使用第 3 步的 systemd 管理）：
# AGY_TG_ENV_FILE="$HOME/agy-tg-bridge/.env" "$HOME/agy-tg-bridge/venv/bin/python" "$HOME/agy-tg-bridge/bridge.py"
```

若启用 `.agents/skills/live-browser/`，请将 Tunnel Token 存放在仓库外的 `chmod 600` 文件中：

```bash
mkdir -p "$HOME/.config/agy-live-browser"
chmod 700 "$HOME/.config/agy-live-browser"
cat <<'EOF' > "$HOME/.config/agy-live-browser/tunnel.env"
CLOUDFLARE_TUNNEL_TOKEN=REPLACE_WITH_YOUR_TUNNEL_TOKEN
EOF
chmod 600 "$HOME/.config/agy-live-browser/tunnel.env"
```

### 3. AGY Studio WebUI（可选）

```bash
# 安装 Studio 后端依赖并构建 React WebUI 静态产物
python3 -m pip install -r studio/requirements.txt
(cd webui && npm ci && npm run build)

# 在 ~/.config/agy-studio/users.json（0600）初始化密码模式管理员账号
python3 -m studio.auth set-user --username admin --bot main --user-id 123456789 --role admin

# 启动本地环回 Sidecar（127.0.0.1:18796）
python3 -m studio.server
```

### 4. Systemd 托管部署（可选）

通用服务模板位于 [`systemd/examples/`](./systemd/examples)（含 [`agy-studio.service.example`](./systemd/examples/agy-studio.service.example)），桥接服务均已配置 `KillMode=mixed`（支持平滑退出与后台子进程隔离）。部署前请将模板中的 `YOUR_USER` 与 `/path/to/agy-bot` 替换为实际路径后安装到 `/etc/systemd/system/` 或 `~/.config/systemd/user/`。

### 5. 运行脱敏门禁、Lint 与单元测试

```bash
# 对工作区与全部 Git 历史执行严格公开级脱敏审计
python3 scripts/security_audit.py --mode public-release --check-history

# 代码 Lint 检查（可通过 pip install -e ".[dev]" 安装 ruff）
ruff check .

# 运行全量脱敏、Bridge 与 Studio 单元测试
python3 -m pip install -r bridge/requirements.txt -r studio/requirements.txt
python3 -m unittest discover -s tests -v
```

---

## 致谢与设计参考

`agy-bot` 的架构设计与工程实践借鉴并致敬了以下优秀开源项目：

### 记忆管理与持续学习（Memory Management & Continuous Learning）
- [`thedotmack/claude-mem`](https://github.com/thedotmack/claude-mem)：跨会话持久化记忆与三步 `mem-search`（`search → timeline → get_observations`）检索架构；`hooks/claude_mem_hook_gate.py`、`hooks/hooks.json` 与 `mem-hub/agy_llm_shim.py` 面向其生命周期与观察者流水线实现了 `agy` 无递归适配。
- [`affaan-m/ECC`](https://github.com/affaan-m/ECC)（Everything Claude Code，及其引用的 *Homunculus* 架构思想）：`.agents/skills/continuous-learning-v2/`（`origin: ECC`）与 `mem-hub/agy_instinct_daemon.py` 借鉴了其原子级本能观察、置信度评分、项目作用域隔离与技能演化流程。
- [`NousResearch/hermes-agent`](https://github.com/NousResearch/hermes-agent) 与 [`HKUDS/nanobot`](https://github.com/HKUDS/nanobot)：借鉴了 Prefix Cache 友好的冻结规则集边界纪律（避免动态注入破坏提示词前缀缓存）、按需触发与后台记忆整合思路，以及多 Agent 协作工作区隔离设计。

### Telegram 桥接、人机协同与工程运维（Telegram Bridge, HITL & Ops）
- [`banteg/takopi`](https://github.com/banteg/takopi)：单实例 `flock` 防 `409` 冲突、`pyproject.toml` + `setup`/`doctor` CLI 向导、Mock Telegram 离线单测模式及 Python 3.11–3.14 + `ruff` CI 矩阵设计。
- [`overwirehq/claude-code-telegram`](https://github.com/overwirehq/claude-code-telegram)：`sendMessageDraft` 流式边界对照、`SECURITY.md` 与社区安全治理规范思路。
- [`grinev/opencode-telegram-bot`](https://github.com/grinev/opencode-telegram-bot)：Telegram HTML 分片重封代码块健壮性与人机工具审批 UI 规划参考。
- [`openclaw/openclaw`](https://github.com/openclaw/openclaw)：视频/贴纸/媒体组多模态路由及长轮询退避自愈纪律。
- [`chenhg5/cc-connect`](https://github.com/chenhg5/cc-connect)：轻量快速入门文档组织、多渠道桥接思路与按需任务调度参考。
- [`emreturkmencom/antigravity-telegram-suite`](https://github.com/emreturkmencom/antigravity-telegram-suite) 与 [`pavel-molyanov/telegram-ai-agent`](https://github.com/pavel-molyanov/telegram-ai-agent)：同领域 Antigravity / AI CLI Telegram 桥接先驱项目对照启发。

---

## 社区与友情链接

- **[LINUX.DO](https://linux.do/)** —— 友情社区入口，欢迎前往交流技术实践、工程经验与开源工具心得。

