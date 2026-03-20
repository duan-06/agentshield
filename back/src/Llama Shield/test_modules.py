"""
Llama Shield 模块检测脚本
检测各模块是否能正常工作
"""

import sys
import os

# 添加 app 目录到路径
sys.path.insert(0, os.path.dirname(__file__))

def test_module(name, test_func):
    """测试单个模块"""
    print(f"\n{'='*60}")
    print(f"测试模块: {name}")
    print('='*60)
    try:
        result = test_func()
        print(f"✅ {name} - 正常")
        return True, result
    except Exception as e:
        print(f"❌ {name} - 失败: {e}")
        return False, str(e)

def test_imports():
    """测试基础导入"""
    results = {}

    # 1. Pydantic 模型
    try:
        from app.models import ChatRequest, ChatResponse, HealthResponse
        results["Pydantic模型"] = "✅ 正常"
    except Exception as e:
        results["Pydantic模型"] = f"❌ 失败: {e}"

    # 2. 监控模块
    try:
        from app.monitoring import MetricsCollector, get_metrics
        m = get_metrics()
        results["监控模块"] = "✅ 正常"
    except Exception as e:
        results["监控模块"] = f"❌ 失败: {e}"

    # 3. 环境变量
    try:
        from dotenv import load_dotenv
        load_dotenv()
        results["环境变量加载"] = "✅ 正常"
    except Exception as e:
        results["环境变量加载"] = f"❌ 失败: {e}"

    return results

def test_firewall_import():
    """测试防火墙模块导入"""
    try:
        from app.firewall import LlamaFirewallManager
        return "LlamaFirewallManager 导入成功"
    except Exception as e:
        return f"导入失败: {e}"

def test_database_import():
    """测试数据库模块导入"""
    try:
        from app.db import get_mysql_url
        url = get_mysql_url()
        return f"MySQL URL: {url[:30]}..."
    except Exception as e:
        return f"失败: {e}"

def test_llamafirewall_package():
    """测试 LlamaFirewall 包"""
    try:
        import llamafirewall
        return f"llamafirewall 版本: {llamafirewall.__version__ if hasattr(llamafirewall, '__version__') else '未知'}"
    except ImportError as e:
        return f"未安装: {e}"
    except Exception as e:
        return f"失败: {e}"

def test_structlog():
    """测试 structlog"""
    try:
        import structlog
        structlog.configure([
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer()
        ])
        logger = structlog.get_logger("test")
        logger.info("structlog 测试")
        return "structlog 正常"
    except Exception as e:
        return f"失败: {e}"

def test_prometheus():
    """测试 Prometheus 客户端"""
    try:
        from prometheus_client import Counter, Histogram, Gauge
        c = Counter('test_counter', 'Test counter')
        c.inc()
        return "Prometheus 客户端正常"
    except Exception as e:
        return f"失败: {e}"

def test_fastapi():
    """测试 FastAPI"""
    try:
        from fastapi import FastAPI
        app = FastAPI()
        return "FastAPI 正常"
    except Exception as e:
        return f"失败: {e}"

def test_sqlalchemy():
    """测试 SQLAlchemy"""
    try:
        from sqlalchemy.ext.asyncio import create_async_engine
        return "SQLAlchemy 异步引擎可用"
    except Exception as e:
        return f"失败: {e}"

def test_aiomysql():
    """测试 aiomysql"""
    try:
        import aiomysql
        return f"aiomysql 版本: {aiomysql.__version__}"
    except Exception as e:
        return f"失败: {e}"

def test_redis():
    """测试 Redis"""
    try:
        import redis
        return f"redis 库可用"
    except Exception as e:
        return f"失败: {e}"

def test_transformers():
    """测试 transformers"""
    try:
        import transformers
        return f"transformers 版本: {transformers.__version__}"
    except Exception as e:
        return f"失败: {e}"

def test_torch():
    """测试 PyTorch"""
    try:
        import torch
        cuda = torch.cuda.is_available()
        return f"PyTorch 版本: {torch.__version__}, CUDA: {cuda}"
    except Exception as e:
        return f"失败: {e}"

def test_node_js():
    """测试 Node.js (用于 StackOne Defender)"""
    try:
        import subprocess
        result = subprocess.run(['node', '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return f"Node.js {result.stdout.strip()}"
        return "Node.js 不可用"
    except FileNotFoundError:
        return "Node.js 未安装"
    except Exception as e:
        return f"检查失败: {e}"

def test_models_directory():
    """检查模型目录"""
    path = "D:/计算机设计大赛/models"
    if os.path.exists(path):
        items = os.listdir(path)
        return f"模型目录存在，共 {len(items)} 个项目: {', '.join(items[:5])}..."
    return "模型目录不存在"

def test_env_configuration():
    """检查环境配置"""
    from dotenv import load_dotenv
    load_dotenv()

    configs = {
        "MYSQL_HOST": os.getenv("MYSQL_HOST", "未设置"),
        "MYSQL_PORT": os.getenv("MYSQL_PORT", "未设置"),
        "MYSQL_DB": os.getenv("MYSQL_DB", "未设置"),
        "HF_HOME": os.getenv("HF_HOME", "未设置"),
        "LLAMAFIREWALL_MODE": os.getenv("LLAMAFIREWALL_MODE", "未设置"),
        "USE_MINIMAX_API": os.getenv("USE_MINIMAX_API", "未设置"),
        "USE_VLLM": os.getenv("USE_VLLM", "未设置"),
    }

    lines = []
    for key, value in configs.items():
        if value == "未设置":
            lines.append(f"  {key}: {value} ⚠️")
        else:
            lines.append(f"  {key}: {value}")

    return "\n".join(lines)

def main():
    print("=" * 60)
    print("Llama Shield 模块检测")
    print("=" * 60)

    all_passed = True

    # 基础导入测试
    passed, result = test_module("基础导入 (Pydantic, Monitoring, Env)", test_imports)
    if passed:
        for k, v in result.items():
            print(f"  {k}: {v}")
    else:
        print(f"  失败: {result}")

    # 详细模块测试
    modules = [
        ("structlog 日志", test_structlog),
        ("Prometheus 监控", test_prometheus),
        ("FastAPI 框架", test_fastapi),
        ("SQLAlchemy ORM", test_sqlalchemy),
        ("aiomysql 驱动", test_aiomysql),
        ("Redis 客户端", test_redis),
        ("Transformers", test_transformers),
        ("PyTorch", test_torch),
        ("Node.js (StackOne)", test_node_js),
    ]

    for name, test_func in modules:
        passed, result = test_module(name, test_func)
        print(f"  {result}")
        if not passed:
            all_passed = False

    # LlamaFirewall 特殊测试
    passed, result = test_module("LlamaFirewall 核心", test_llamafirewall_package)
    print(f"  {result}")
    if not passed:
        all_passed = False

    passed, result = test_module("LlamaFirewall 管理器", test_firewall_import)
    print(f"  {result}")
    if not passed:
        all_passed = False

    passed, result = test_module("数据库模块", test_database_import)
    print(f"  {result}")
    if not passed:
        all_passed = False

    # 环境配置检查
    passed, result = test_module("环境配置", test_env_configuration)
    print(result)
    if not passed:
        all_passed = False

    # 模型目录检查
    passed, result = test_module("模型目录", test_models_directory)
    print(f"  {result}")
    if not passed:
        all_passed = False

    # 总结
    print("\n" + "=" * 60)
    print("检测总结")
    print("=" * 60)
    if all_passed:
        print("✅ 所有核心模块检测通过")
    else:
        print("⚠️ 部分模块检测失败，请检查上述错误")

    print("\n注意事项:")
    print("1. 如果 LlamaFirewall 导入失败，可能需要安装: pip install llamafirewall")
    print("2. 如果 Node.js 未安装，StackOne Defender 将不可用")
    print("3. 数据库连接需要确保 MySQL 服务运行中")
    print("4. 模型文件需要下载到指定目录")

if __name__ == "__main__":
    main()
