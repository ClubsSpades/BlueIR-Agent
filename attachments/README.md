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

6. `sample_http.pcap`
   - Web UI 事件类型选择：`Auto detect` 或 `Generic alert`
   - 预期：识别 PCAP、计算 SHA256、提取包数量和 IPv4 flow

7. `sample_security.evtx`
   - Web UI 事件类型选择：`Auto detect` 或 `Generic alert`
   - 预期：识别 EVTX、计算 SHA256、提取可见字符串，并提示导出 CSV/XML 后深度分析

## v3 文件类型说明

- 文本类：`.txt`、`.log`、`.csv`、`.json`、`.xml`
- 流量类：`.pcap`、`.pcapng`
- Windows 事件：`.evtx`

当前 v3 对 PCAP/EVTX 是安全预分析：

- PCAP：支持 classic pcap 的文件头、包数量、部分 Ethernet IPv4 TCP/UDP flow 提取
- PCAPNG：识别格式和字符串，完整解析建议后续接入 tshark/Zeek
- EVTX：识别格式和字符串，完整事件解析建议先导出 CSV/XML 再上传

## v4 提示词测试

上传附件后，可以在 Web UI 的“分析问题 / Investigation Question”里输入：

- `这个文件里最可疑的 IOC 是什么？`
- `是否存在爆破成功？请指出证据。`
- `这份流量里有没有可疑外联？`
- `攻击入口可能是什么？`
- `请按应急响应报告格式总结，并列出证据不足。`

分析模式建议：

- 快速分诊：日常测试和演示
- 深度分析：让多个角色给出更全面判断
- 报告生成：更偏最终报告
- 只提取 IOC：只关心指标时使用
- 针对我的问题：配合上面的分析问题使用
