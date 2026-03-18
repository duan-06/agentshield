# Llama Shield 困难记录

## 2026-03-18 Express → FastAPI 迁移：MySQL 异步驱动

### 问题
原 Express 后端用 MySQL，Llama Shield 原设计用 PostgreSQL，迁移时需统一数据库。

### 方案对比
| 方案 | 结论 |
|------|------|
| 继续用 PostgreSQL | 需额外安装，增加运维成本 ❌ |
| `aiomysql` + SQLAlchemy 2.x | 直接复用已有 MySQL ✅ |

### 解决
- 新建 `app/db.py`（异步 MySQL 连接，替代原 `database.py`）
- 新建 `app/db_models.py`（User / RiskCategory / TestCase / TestResult / AuditLog）
- 连接 URL：`mysql+aiomysql://user:pass@host:port/db?charset=utf8mb4`
- 安装：`pip install aiomysql PyMySQL`

### 状态
✅ 已解决

---

## 2026-03-18 main.py 中文编码导致 StrReplace 失败

### 问题
`app/main.py` 含大量中文注释，Cursor StrReplace 工具因编码匹配问题持续报 `old_string not found`。

### 尝试
1. 直接 StrReplace → 失败
2. PowerShell `Get-Content | cat -A` → 中文乱码无法定位
3. `python -c` 内联脚本 → 三引号与 PowerShell 引号冲突，SyntaxError

### 解决
将修改逻辑写为独立 Python 脚本（`fix_main.py`、`fix_audit_logger.py`），通过 `python fix_xxx.py` 执行，完全绕过 Shell 引号问题。

### 状态
✅ 已解决

---

## 2026-03-18 routes/__init__.py 空字节

### 问题
PowerShell `echo "" > __init__.py` 写入了 BOM/null 字节，导致 Python 报 `SyntaxError: source code string cannot contain null bytes`。

### 解决
```python
python -c "open(r'app/routes/__init__.py', 'w', encoding='utf-8').write('')"
```

### 状态
✅ 已解决

---

## 2026-03-18 auth.py 变量定义顺序错误

### 问题
`get_current_user()` 函数被插入到 `JWT_SECRET` 变量定义之前，导致运行时 `NameError: name 'JWT_SECRET' is not defined`。

### 解决
重写 `auth.py`，确保顺序：
1. JWT 常量定义（`JWT_SECRET`、`JWT_ALGORITHM`）
2. 密码工具函数（`hash_password`、`verify_password`）
3. `get_current_user()` 依赖函数
4. `router` 及路由处理函数

### 状态
✅ 已解决

---

## 2026-03-18 main.py 中残留 audit_logger 引用

### 问题
迁移过程中删除了全局 `audit_logger` 变量，但 `health_check`、`chat` 端点内仍有多处引用，导致服务启动后所有请求返回 `500 NameError`。

### 解决
使用 `fix_audit_logger.py` 脚本扫描并删除所有 `audit_logger.*` 调用块，`health_check` 改为用 `firewall_manager` 判断数据库状态。

### 状态
✅ 已解决

---

## 2026-03-16 LlamaFirewall API 假设错误

### 问题
最初代码基于假设的 API，`pip install llamafirewall` 后发现实际 API 完全不同。

### 对比
| 项目 | 实际 API | 假设（错误）|
|------|----------|-----------|
| 包版本 | 1.0.3 | 2026.1.0 ❌ |
| ScannerType | PROMPT_GUARD, CODE_SHIELD | LLAMA_GUARD ❌ |
| Decision | ScanDecision.BLOCK/ALLOW | Decision.DENY ❌ |
| 初始化 | `LlamaFirewall(scanners={Role:[...]})` | `LlamaFirewall(mode=..., threshold=...)` ❌ |
| 扫描方法 | `scan(input=Message, trace=Trace)` | `scan(messages=..., scanner_type=...)` ❌ |

### 解决
完全重写 `app/firewall.py`，基于官方 PyPI 和 GitHub 示例验证 API。

### 状态
✅ 已解决

---

## 官方模型信息

| Scanner | 模型 | 必需 |
|---------|------|------|
| Prompt Guard | `meta-llama/Llama-Prompt-Guard-2-86M` | ✅ |
| CodeShield | `codeshield` 包（内置）| ✅ |
| Alignment Check | `Llama-4-Maverick`（Together.ai）| ❌ 实验性 |
