# BlueIR-Agent v4 工作流

```mermaid
flowchart TD
    A["用户输入 / User Input"] --> B{"输入类型"}
    B -->|"上传文件"| C["File Preprocessor<br/>类型识别、Hash、字符串、PCAP/EVTX 预分析"]
    B -->|"粘贴文本"| D["Text Normalizer<br/>文本标准化"]
    C --> E["Case Builder<br/>构建 Case / Evidence"]
    D --> E

    E --> F["User Question Parser<br/>解析用户问题和分析模式"]
    F --> G["Triage Agent<br/>事件分诊"]
    G --> H["Evidence Agent<br/>证据结构化"]
    H --> I["IOC Agent<br/>IOC 提取"]
    H --> J["Timeline Agent<br/>时间线整理"]
    I --> K["MITRE Agent<br/>ATT&CK 映射"]
    J --> K
    K --> L["Planner Agent<br/>处置建议"]
    L --> M["Report Agent<br/>报告生成"]
    M --> N["Reviewer Agent<br/>复核证据不足和幻觉风险"]
    N --> O["Final Report<br/>Markdown / UI 展示"]

    P["Model Router<br/>角色到模型路由"] --> G
    P --> H
    P --> I
    P --> J
    P --> K
    P --> L
    P --> M
    P --> N

    Q["roles.example.json<br/>当前全部 deepseek-v4-pro<br/>后续可替换 OpenAI / Claude / Qwen / Ollama"] --> P
```

## v4 角色

- `triage`：事件分诊
- `evidence`：证据结构化
- `ioc`：IOC 提取与归纳
- `timeline`：时间线整理和复核
- `mitre`：ATT&CK 映射
- `planner`：处置建议
- `report`：报告组织
- `reviewer`：证据缺口和幻觉风险复核

当前所有角色默认使用 `deepseek/deepseek-v4-pro`。后续接入其他模型时，优先修改 `configs/roles.example.json` 或新增 provider adapter。
