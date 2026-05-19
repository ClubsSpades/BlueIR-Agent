# SSH 远程应急响应功能设计

## 可行性

可以增加“只提供 IP、SSH 连接信息，让 Agent 远程采集证据并生成报告”的能力，但必须采用安全分级：

1. **默认只读采集**
   - 读取系统信息、登录日志、进程、端口、计划任务、用户、SSH key、服务状态
   - 不修改系统
   - 不删除文件
   - 不停止进程

2. **人工确认处置**
   - 封禁 IP
   - 停止进程
   - 禁用账号
   - 修改防火墙
   - 移动或隔离可疑文件

3. **默认禁止**
   - 清空日志
   - 删除证据
   - 执行未知脚本
   - 对公网主动扫描
   - 执行攻击利用代码

## 建议工作流

```txt
用户提供 IP / SSH 端口 / 用户名 / 密钥或密码
  ↓
连接预检查
  ↓
只读命令计划展示
  ↓
用户确认
  ↓
远程只读采集
  ↓
Linux IR Skill 分析
  ↓
多角色 Agent 复核
  ↓
输出报告和人工处置建议
```

## VPN 问题

如果目标服务器在特殊网段，Agent 可以运行在已经接入 VPN 的机器上。更安全的做法是：

- 由用户或运维人员先建立 VPN
- Agent 只检测目标 IP 是否可达
- Agent 不自动配置 VPN、不保存 VPN 密码

后续可以增加 VPN profile 配置，但必须避免把 VPN 凭据写入仓库或报告。

## 后续实现建议

新增模块：

```txt
blueir_agent/remote/
  ssh_client.py        SSH 连接适配
  linux_collector.py   只读采集命令
  command_policy.py    命令白名单和风险分级
```

新增 UI：

```txt
Remote IR
├── Host
├── Port
├── Username
├── Auth method
├── Read-only collection profile
└── Human approval checkbox
```

第一版远程 IR 不做自动修复，只做采集、分析和报告。
