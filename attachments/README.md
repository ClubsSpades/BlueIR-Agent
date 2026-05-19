# BlueIR-Agent v0.2 测试附件

这些文件用于测试 Web UI 的文件上传能力，均为仿真数据。

## 建议测试顺序

1. `webshell_access.log`
   - Web UI 事件类型选择：`Webshell / Web intrusion`
   - 预期：生成 Webshell 报告、IOC、时间线、MITRE `T1505.003`

2. `windows_bruteforce.csv`
   - Web UI 事件类型选择：`Windows logon`
   - 预期：识别 4625 多次失败后 4624 成功登录、账号、LogonType、MITRE `T1110`

3. `linux_ir.txt`
   - Web UI 事件类型选择：`Linux IR`
   - 预期：识别 SSH 登录、反弹 shell、计划任务、恶意 URL、MITRE `T1059 / T1053`

4. `mixed_alert.txt`
   - Web UI 事件类型选择：`Auto detect`
   - 预期：自动触发多个 Skill，生成综合 IOC、Finding 和时间线

5. `benign_web.log`
   - Web UI 事件类型选择：`Auto detect`
   - 预期：不会因为普通 `.php` 页面直接报 Webshell 高危
