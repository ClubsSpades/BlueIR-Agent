# BlueIR-Agent

BlueIR-Agent 是一个面向蓝队攻防演练与应急响应场景的智能辅助分析 Agent。

当前版本定位为比赛 MVP：通过 DeepSeek API、结构化安全 Skill、多角色 Agent 分工、只读分析工具和轻量 Web UI，实现告警分诊、IOC 提取、时间线整理、Webshell 日志分析、Windows 登录爆破分析、Linux 应急证据分析、PCAP/EVTX 安全预分析、MITRE ATT&CK 映射和 Markdown 应急报告生成。

> 当前默认模型：`deepseek-v4-pro`

## 项目定位

BlueIR-Agent 不是自动攻击工具，也不是全自动处置平台。它的目标是辅助蓝队分析员完成可审计、可复核、可展示的应急分析流程：

- 输入告警、日志或事件文本
- 自动提取 IOC
- 判断可能的事件类型
- 调用对应分析 Skill
- 生成风险发现、证据和处置建议
- 输出 Markdown 应急响应报告

系统采用 Human-in-the-loop 思路：默认只做只读分析，高风险动作只作为人工确认建议输出。

## 当前能力

- IOC 提取：IPv4、域名、URL、Hash、邮箱
- 结构化 IOC：来源、置信度、首次出现时间
- 攻击时间线提取
- Webshell / Web 入侵日志分析
- Windows 登录爆破分析
- Linux 应急响应证据分析
- PCAP/PCAPNG/EVTX/二进制证据安全预分析
- 用户问题 / Investigation Question
- 分析模式：快速分诊、深度分析、报告生成、只提取 IOC、针对问题分析
- 多角色 Agent 分工：Triage、Evidence、IOC、Timeline、MITRE、Planner、Report、Reviewer
- Web UI 动态流程图：展示 Case、IOC、Skill、Role Agents、Summary、Report 进度
- 初步 MITRE ATT&CK 映射
- DeepSeek 事件摘要与风险判断
- 本地启发式 fallback，无 API Key 也能跑通基础流程
- Markdown 报告生成
- 标准库轻量 Web UI，支持事件类型选择、文件上传和中英文切换
- 角色配置与后续多模型 Provider 扩展接口

## 安全边界

- 默认只读分析
- 不自动删除文件
- 不自动封禁 IP
- 不自动隔离主机
- 不执行任意 shell 命令
- 不生成攻击利用链
- 不主动扫描公网目标
- 所有处置建议需要人工确认

## 快速开始

进入项目目录：

```bash
cd /Users/spadesclubs/Agent/blueir-agent
```

配置 DeepSeek API Key：

```bash
export DEEPSEEK_API_KEY="your_api_key_here"
```

命令行分析文本：

```bash
python3 -B -m blueir_agent.cli --text "2026-05-19 EventID=4625 Account=admin SourceNetworkAddress=203.0.113.8"
```

命令行分析样例日志：

```bash
python3 -B -m blueir_agent.cli --file examples/webshell_access.log
```

启动 Web UI：

```bash
python3 -B -m blueir_agent.web
```

浏览器打开：

```txt
http://127.0.0.1:8765
```

Web UI 支持中文和 English 切换，并支持上传 `.txt`、`.log`、`.csv`、`.json`、`.xml`、`.pcap`、`.pcapng`、`.evtx`。

必填规则：

- `Case ID` 可选，不填会自动生成。
- `Incident Type` 必选，默认 `Auto detect`。
- `Analysis Mode` 必选，默认 `快速分诊 / Quick triage`。
- `Investigation Question` 可选，用于针对你的问题做聚焦分析。
- `告警 / 日志文本` 和 `文件上传` 至少提供一个。
- 如果同时上传文件并填写文本框，系统优先分析上传文件。

如果没有配置 `DEEPSEEK_API_KEY`，系统会自动进入本地启发式模式，仍然可以测试 IOC 提取、事件识别、Finding 生成和报告输出。

## 配置项

通过环境变量配置：

```txt
DEEPSEEK_API_KEY      DeepSeek API Key，模型调用需要
BLUEIR_MODEL          模型名称，默认 deepseek-v4-pro
BLUEIR_BASE_URL       API 地址，默认 https://api.deepseek.com
BLUEIR_TIMEOUT        请求超时时间，默认 60 秒
BLUEIR_ROLES_CONFIG   可选角色配置文件，例如 configs/roles.example.json
BLUEIR_WEB_PORT       Web UI 端口，默认 8765
```

示例配置见 [.env.example](.env.example)。

## 测试样例

推荐直接使用 [attachments](attachments/) 目录里的仿真附件测试 v0.5 Web UI：

| 文件 | 建议事件类型 | 预期效果 |
|---|---|---|
| `attachments/webshell_access.log` | Webshell / Web intrusion | Webshell、IOC、时间线、`T1505.003` |
| `attachments/windows_bruteforce.csv` | Windows logon | 4625 失败后 4624 成功、账号、LogonType、`T1110` |
| `attachments/linux_ir.txt` | Linux IR | SSH 登录、反弹 shell、计划任务、恶意 URL |
| `attachments/mixed_alert.txt` | Auto detect | 综合 IOC、Finding、时间线 |
| `attachments/benign_web.log` | Auto detect | 普通 PHP 页面不应直接报 Webshell 高危 |
| `attachments/sample_http.pcap` | Auto detect / Generic alert | PCAP 元数据、包数量、IPv4 flow |
| `attachments/sample_security.evtx` | Auto detect / Generic alert | EVTX 识别、哈希、字符串和导出建议 |

使用方式：

1. 启动 Web UI。
2. 选择语言：中文或 English。
3. 选择事件类型，或保持 `Auto detect`。
4. 选择分析模式，或保持 `快速分诊 / Quick triage`。
5. 可选填写分析问题，例如“是否存在爆破成功？请指出证据。”
6. 上传 `attachments/` 目录中的样例文件。
7. 点击分析，查看右侧 Markdown 报告。

Webshell 分析：

```bash
python3 -B -m blueir_agent.cli --file examples/webshell_access.log
```

预期效果：

- 事件类型：`webshell_or_web_intrusion`
- IOC：提取访问源 IP
- MITRE：`T1505.003`
- Finding：发现疑似 Webshell 或命令执行行为

Windows 登录爆破分析：

```bash
python3 -B -m blueir_agent.cli --file examples/windows_logon.txt
```

预期效果：

- 事件类型：`windows_logon_triage`
- IOC：提取源 IP
- MITRE：`T1110`
- Finding：识别多次失败登录后成功登录的高风险模式

Linux 应急证据分析：

```bash
python3 -B -m blueir_agent.cli --file examples/linux_ir.txt --incident-type linux
```

预期效果：

- 事件类型：`linux_ir_triage`
- IOC：提取登录源 IP、反连 IP、恶意 URL
- Timeline：提取登录失败、登录成功、反弹 shell、计划任务
- Finding：识别可疑 Linux 主机活动

运行 smoke test：

```bash
python3 -B tests/smoke_test.py
```

## 项目结构

```txt
blueir_agent/
  agent/              主控编排、状态、护栏、模型路由
  providers/          LLM Provider 抽象与 DeepSeek 实现
  skills/             蓝队分析 Skill
  tools/              只读本地分析工具
  web/                标准库 Web UI
configs/              角色与多模型路由配置样例
docs/                 工作流图和设计说明
attachments/          Web UI 上传测试附件
examples/             测试样例日志
reports/              本地生成报告，默认不上传 Git
tests/                轻量测试
```

## 架构思路

当前版本是单主控 Agent + 多 Skill：

```txt
User Input
  ↓
BlueIR Orchestrator
  ↓
IOC Extractor
  ↓
Skill Selection + Role Runner
  ├── Webshell Triage Skill
  ├── Windows Logon Skill
  ├── Linux IR Skill
  ├── File Evidence Skill
  ├── Triage / Evidence / IOC / MITRE / Planner / Reviewer Agents
  └── Report Writer Skill
  ↓
Model Router
  ↓
DeepSeek Provider
  ↓
Markdown Report
```

虽然当前只接入 DeepSeek，但代码已经预留 Provider 和 Router：

```txt
Model Router
  ├── DeepSeek
  ├── Qwen
  ├── Kimi
  ├── Zhipu
  ├── OpenAI-compatible Provider
  └── Local Ollama
```

后续可以按任务类型、成本、隐私级别、上下文长度和工具调用能力进行多模型路由。

v4 工作流图见 [docs/workflow_v4.md](docs/workflow_v4.md)。

Web UI 现在采用异步任务方式执行分析：提交后会显示动态流程图，不需要盯着空白页面等待。

SSH 远程应急响应功能的安全设计见 [docs/ssh_ir_design.md](docs/ssh_ir_design.md)。该能力后续会先实现只读采集，不默认自动修复。

## 角色与多模型铺垫

当前真实接入仍然只有 DeepSeek，但系统已经有角色配置层和角色运行器。默认角色包括：

```txt
triage     事件分诊
ioc        IOC 提取
evidence   证据结构化
timeline   时间线整理
mitre      ATT&CK 映射
planner    处置建议
report     报告生成
reviewer   质量复核
```

角色配置样例见 [configs/roles.example.json](configs/roles.example.json)。

使用方式：

```bash
export BLUEIR_ROLES_CONFIG=configs/roles.example.json
python3 -B -m blueir_agent.cli --file examples/linux_ir.txt --incident-type linux
```

后续接入 Qwen、Kimi、Zhipu、OpenAI-compatible Provider 或 Ollama 时，可以让不同角色使用不同模型，而不用重写业务 Skill。

## 版本状态

```txt
v0.5 MVP
```

已完成：

- DeepSeek API 接入
- Web UI
- CLI
- 结构化 IOC 提取
- 攻击时间线
- Webshell 日志分析
- Windows 登录爆破分析
- Linux 应急证据分析
- PCAP/EVTX 文件预分析
- 中英文 Web UI
- UI 必填项、事件类型和上传优先级提示
- 用户问题和分析模式
- 多角色 Agent 分工输出
- 证据缺口复核
- 动态分析流程图
- 报告中英双语标题和输入说明
- Markdown 报告生成
- 角色配置与多模型路由铺垫
- GitHub 安全忽略规则

后续计划：

- Zeek / Suricata 深度流量分析 Skill
- EVTX 原生解析或 EvtxECmd CSV 工作流
- SSH 远程只读应急采集
- Volatility 输出分析 Skill
- RAG 知识库
- 多模型 Provider 实现与 fallback
- 报告导出 HTML / PDF

## 免责声明

本项目仅用于蓝队防御、安全学习、应急响应演示和比赛作品开发。请勿将其用于未授权攻击、入侵、扫描或破坏性操作。
