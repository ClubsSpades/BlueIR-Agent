# BlueIR-Agent

BlueIR-Agent 是一个面向蓝队攻防演练与应急响应场景的智能辅助分析 Agent。

当前版本定位为比赛 MVP：通过 DeepSeek API、结构化安全 Skill、只读分析工具和轻量 Web UI，实现告警分诊、IOC 提取、Webshell 日志分析、Windows 登录爆破分析、MITRE ATT&CK 映射和 Markdown 应急报告生成。

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
- Webshell / Web 入侵日志分析
- Windows 登录爆破分析
- 初步 MITRE ATT&CK 映射
- DeepSeek 事件摘要与风险判断
- 本地启发式 fallback，无 API Key 也能跑通基础流程
- Markdown 报告生成
- 标准库轻量 Web UI
- 后续多模型 Provider 扩展接口

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

如果没有配置 `DEEPSEEK_API_KEY`，系统会自动进入本地启发式模式，仍然可以测试 IOC 提取、事件识别、Finding 生成和报告输出。

## 配置项

通过环境变量配置：

```txt
DEEPSEEK_API_KEY      DeepSeek API Key，模型调用需要
BLUEIR_MODEL          模型名称，默认 deepseek-v4-pro
BLUEIR_BASE_URL       API 地址，默认 https://api.deepseek.com
BLUEIR_TIMEOUT        请求超时时间，默认 60 秒
```

示例配置见 [.env.example](.env.example)。

## 测试样例

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
Skill Selection
  ├── Webshell Triage Skill
  ├── Windows Logon Skill
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

## 版本状态

```txt
v0.1 MVP
```

已完成：

- DeepSeek API 接入
- Web UI
- CLI
- IOC 提取
- Webshell 日志分析
- Windows 登录爆破分析
- Markdown 报告生成
- GitHub 安全忽略规则

后续计划：

- 文件上传
- 事件时间线
- Linux 应急响应 Skill
- PCAP / Zeek / Suricata 分析 Skill
- Volatility 输出分析 Skill
- RAG 知识库
- 多模型路由与 fallback
- 报告导出 HTML / PDF

## 免责声明

本项目仅用于蓝队防御、安全学习、应急响应演示和比赛作品开发。请勿将其用于未授权攻击、入侵、扫描或破坏性操作。
