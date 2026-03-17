# Llama Shield 困难记录

## 2026-03-16 LlamaFirewall API 假设错误

### 问题描述
- 之前编写的代码基于假设的 LlamaFirewall API
- 实际安装 `pip install llamafirewall` 后发现 API 完全不同

### 实际 API vs 假设
| 项目 | 实际 API | 假设（错误） |
|------|----------|-------------|
| 包版本 | 1.0.3 | 2026.1.0 ❌ |
| ScannerType | PROMPT_GUARD, CODE_SHIELD, AGENT_ALIGNMENT | LLAMA_GUARD, ALIGNMENT_CHECK ❌ |
| Decision | ScanDecision.BLOCK/ALLOW | Decision.DENY ❌ |
| 初始化 | LlamaFirewall(scanners={Role: [...]}) | LlamaFirewall(mode=..., threshold=...) ❌ |
| 扫描方法 | scan(input=Message, trace=Trace) | scan(messages=..., scanner_type=...) ❌ |

### 尝试方案
1. 尝试查找 llamafirewall 官方文档
2. 通过 GitHub API 获取实际源码
3. 分析源码中的实际 API
4. 访问官方文档页面 https://meta-llama.github.io/PurpleLlama/LlamaFirewall/
5. 从 GitHub examples/ 获取官方示例代码验证

### 最终方案
- 完全重写 app/firewall.py 使用实际 API
- 更新 requirements.txt 版本号
- 验证 API 兼容性

### 状态
✅ 已解决

---

## 2026-03-16 补充规则 - API 复查

### 复查结果

**自检答案**: Yes（代码基于官方文档和示例，无假设 API）

#### 复查详情：

1. **import 语句**: ✅ 从官方 PyPI 和源码确认
   ```python
   from llamafirewall import LlamaFirewall, UserMessage, Role, ScannerType, ScanDecision
   ```

2. **初始化**: ✅ 与官方示例一致
   ```python
   lf = LlamaFirewall(scanners={
       Role.USER: [ScannerType.PROMPT_GUARD],
       Role.SYSTEM: [ScannerType.PROMPT_GUARD],
   })
   ```

3. **scan 方法**: ✅ 与官方示例一致
   ```python
   result = lf.scan(UserMessage(content="..."))
   ```

4. **Scanner 类型**: ✅ 从官方源码确认
   - PROMPT_GUARD
   - CODE_SHIELD
   - AGENT_ALIGNMENT
   - PII_DETECTION
   - HIDDEN_ASCII
   - REGEX

5. **官方文档链接**:
   - PyPI: https://pypi.org/project/llamafirewall/
   - GitHub: https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall
   - 文档: https://meta-llama.github.io/PurpleLlama/LlamaFirewall/
   - 论文: https://arxiv.org/pdf/2505.03574.pdf

### 当前处理
- 代码已基于官方文档和示例修正
- 待用户本地验证

---

## 2026-03-16 模型信息汇总

### 官方模型列表（从源码确认）

| Scanner | 模型名称 | 来源 | 是否必需 |
|---------|----------|------|----------|
| **Prompt Guard** | `meta-llama/Llama-Prompt-Guard-2-86M` | HuggingFace | ✅ 必需 |
| **Code Shield** | `codeshield` (Python 包) | PyPI | ✅ 必需 |
| **Alignment Check** | `meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8` | Together.ai API | ❌ 实验性 |
| **PII Detection** | - | - | ❌ 可选 |
| **Hidden ASCII** | - | 本地检测 | ❌ 可选 |
| **Regex** | - | 自定义规则 | ❌ 可选 |

### 依赖包
```
llamafirewall==1.0.3
codeshield>=1.0.1
huggingface-hub>=0.30.2
numpy>=2.1.1
openai>=1.76.0
pydantic>=2.11.3
torch>=2.4.1
transformers>=4.51.3
typer>=0.15.2
```

### 状态
✅ 已记录

---

## 2026-03-16 文档更新完成

已更新以下文档反映最新官方信息：
1. README.md - 添加 LlamaFirewall 组件详情、模型信息、官方链接
2. architecture.md - 添加 Scanner 详细说明、模块依赖
3. logs.md - 记录更新过程
4. module_logs.md - 更新版本和 API 状态

### 状态
✅ 完成
