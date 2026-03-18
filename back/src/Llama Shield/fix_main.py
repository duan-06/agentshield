# -*- coding: utf-8 -*-
"""
修复 main.py：
1. 替换 lifespan 中的数据库初始化逻辑（改用 MySQL）
2. 在 app 创建后注册新路由
3. 删除旧的 audit_logger 全局变量引用
"""
import re

path = r'app/main.py'

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

print(f"File loaded, {len(content)} chars")

# ========== 修改 1：删除全局 audit_logger 变量声明 ==========
content = content.replace(
    'audit_logger: Optional[AuditLogger] = None\n',
    ''
)
print("Fix 1 done: removed audit_logger global")

# ========== 修改 2：替换 lifespan 内容 ==========
# 用正则匹配 lifespan 函数体内的初始化块
old_init = (
    '    global firewall_manager, audit_logger, metrics\n'
    '\n'
    '    startup_time = time.time()\n'
    '\n'
    '    # 初始化数据库\n'
    '    logger.info("Initializing database...")\n'
    '    await init_db()\n'
    '    audit_logger = AuditLogger()\n'
)
new_init = (
    '    global firewall_manager, metrics\n'
    '\n'
    '    startup_time = time.time()\n'
    '\n'
    '    # 初始化 MySQL 数据库\n'
    '    logger.info("Initializing MySQL database...")\n'
    '    from app.db import init_db as mysql_init_db, close_db\n'
    '    await mysql_init_db()\n'
)
if old_init in content:
    content = content.replace(old_init, new_init)
    print("Fix 2 done: replaced lifespan init block")
else:
    print("WARNING Fix 2: block not found, dumping nearby context...")
    idx = content.find('audit_logger = AuditLogger()')
    if idx >= 0:
        print(repr(content[max(0, idx-300):idx+100]))
    else:
        print("'audit_logger = AuditLogger()' not found either")

# ========== 修改 3：替换 shutdown 部分（删除 AuditLogger cleanup） ==========
old_shutdown = (
    '    if firewall_manager:\n'
    '        await firewall_manager.cleanup()\n'
    '    logger.info("Application shutdown complete")'
)
new_shutdown = (
    '    if firewall_manager:\n'
    '        await firewall_manager.cleanup()\n'
    '    await close_db()\n'
    '    logger.info("Application shutdown complete")'
)
if old_shutdown in content:
    content = content.replace(old_shutdown, new_shutdown)
    print("Fix 3 done: added close_db() to shutdown")
else:
    print("WARNING Fix 3: shutdown block not found")

# ========== 修改 4：在 CORS 中间件后注册新路由 ==========
old_cors_end = (
    '    allow_headers=["*"],\n'
    ')\n'
    '\n'
    '\n'
    '# ==================== 中间件 ===================='
)
new_cors_end = (
    '    allow_headers=["*"],\n'
    ')\n'
    '\n'
    '# ==================== 注册业务路由 ====================\n'
    'from app.routes import auth as auth_router\n'
    'from app.routes import tests as tests_router\n'
    'from app.routes import stats as stats_router\n'
    'app.include_router(auth_router.router)\n'
    'app.include_router(tests_router.router)\n'
    'app.include_router(stats_router.router)\n'
    '\n'
    '\n'
    '# ==================== 中间件 ===================='
)
if old_cors_end in content:
    content = content.replace(old_cors_end, new_cors_end)
    print("Fix 4 done: registered new routers")
else:
    print("WARNING Fix 4: CORS end block not found, trying alternate...")
    # 尝试只有一个空行的版本
    alt = (
        '    allow_headers=["*"],\n'
        ')\n'
        '\n'
        '# ==================== 中间件 ===================='
    )
    alt_new = (
        '    allow_headers=["*"],\n'
        ')\n'
        '\n'
        '# ==================== 注册业务路由 ====================\n'
        'from app.routes import auth as auth_router\n'
        'from app.routes import tests as tests_router\n'
        'from app.routes import stats as stats_router\n'
        'app.include_router(auth_router.router)\n'
        'app.include_router(tests_router.router)\n'
        'app.include_router(stats_router.router)\n'
        '\n'
        '\n'
        '# ==================== 中间件 ===================='
    )
    if alt in content:
        content = content.replace(alt, alt_new)
        print("Fix 4 done (alternate): registered new routers")
    else:
        print("WARNING Fix 4: both patterns not found")

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)

print("\nAll fixes applied and saved.")
