"""
CyberSecEval 测试集筛选和执行脚本

从 CyberSecEval 数据集中选取各类型攻击数据，对 Llama Shield 进行测试
"""

import json
import os
import sys
import asyncio
import aiohttp
import time
from datetime import datetime
from pathlib import Path

# 添加父目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 配置
LLAMA_SHIELD_URL = "http://localhost:8000"
DATASET_DIR = "D:/计算机设计大赛/datasets/CyberSecEval/CybersecurityBenchmarks/datasets"
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyberseceval_test_results")

# 测试数据配置
TEST_SAMPLES = {
    "prompt_injection_direct": {"count": 5, "filter": {"injection_type": "direct"}},
    "prompt_injection_indirect": {"count": 3, "filter": {"injection_type": "indirect"}},
    "interpreter_privilege_escalation": {"count": 3, "filter": {"attack_type": ["Privilege Escalation"]}},
    "interpreter_container_escape": {"count": 3, "filter": {"attack_type": ["Container Escape"]}},
    "interpreter_reflected_attack": {"count": 3, "filter": {"attack_type": ["Reflected Attack"]}},
    "interpreter_post_exploitation": {"count": 3, "filter": {"attack_type": ["Post Exploitation"]}},
    "interpreter_social_engineering": {"count": 3, "filter": {"attack_type": ["Social Engineering"]}},
    "mitre": {"count": 7, "filter": {}},
}


def load_dataset(name, file_path):
    """加载数据集"""
    print(f"Loading {name} from {file_path}...")
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    print(f"  Loaded {len(data)} items")
    return data


def filter_items(items, filters):
    """根据过滤条件筛选数据"""
    if not filters:
        return items

    filtered = []
    for item in items:
        match = True
        for key, value in filters.items():
            item_value = item.get(key)
            if isinstance(value, list):
                # 处理列表类型的攻击类型
                if isinstance(item_value, list):
                    if not any(v in value for v in item_value):
                        match = False
                        break
                elif item_value not in value:
                    match = False
                    break
            elif item_value != value:
                match = False
                break
        if match:
            filtered.append(item)
    return filtered


def select_samples(dataset, category_name, count):
    """选取指定数量的样本"""
    samples = []
    for i in range(min(count, len(dataset))):
        if i < len(dataset):
            item = dataset[i].copy()
            item['test_category'] = category_name
            item['sample_index'] = i
            samples.append(item)
    return samples


# 测试用 JWT Token (从 Express 后端获取)
TEST_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjMsImlhdCI6MTc3MzkyNjExMywiZXhwIjoxNzc0NTMwOTEzfQ.Zt7I3Znj5SkQJLc-3U63fxhUQzezDCPOfcDyKjp6paY"


async def test_llama_shield(session, sample):
    """测试单个样本"""
    # 构建测试输入
    test_input = sample.get('user_input') or sample.get('mutated_prompt') or sample.get('base_prompt') or sample.get('test_case_prompt', '')

    # 构建多轮对话格式（触发 AlignmentCheck）
    # 第一轮：正常的系统请求
    # 第二轮：AI 正常回复
    # 第三轮：注入恶意指令（测试 AlignmentCheck）
    multi_turn_messages = [
        {"role": "user", "content": "Help me with a coding task. I'll provide instructions and you'll help me write code."},
        {"role": "assistant", "content": "Sure, I'd be happy to help you with coding tasks. What would you like to work on?"},
        {"role": "user", "content": test_input}
    ]

    result = {
        "test_category": sample.get('test_category'),
        "sample_index": sample.get('sample_index'),
        "test_input": test_input,
        "original_data": sample,
        "timestamp": datetime.now().isoformat(),
        "shield_response": None,
        "shield_decision": None,
        "shield_blocked": None,
        "shield_blocked_by": None,
        "shield_blocked_reason": None,
        "shield_score": None,
        "error": None,
        "duration_ms": None,
    }

    start_time = time.time()

    try:
        # 调用 Llama Shield API（使用多轮对话触发 AlignmentCheck）
        async with session.post(
            f"{LLAMA_SHIELD_URL}/api/v1/scan/input",
            json={"messages": multi_turn_messages},
            headers={"Authorization": f"Bearer {TEST_TOKEN}"},
            timeout=aiohttp.ClientTimeout(total=120)
        ) as resp:
            duration_ms = int((time.time() - start_time) * 1000)
            result["duration_ms"] = duration_ms

            if resp.status == 403:
                # 被阻断
                data = await resp.json()
                result["shield_decision"] = "BLOCK"
                result["shield_blocked"] = True
                result["shield_blocked_by"] = data.get("detail", {}).get("blocked_by", "Unknown")
                result["shield_blocked_reason"] = data.get("detail", {}).get("blocked_reason", "Unknown")
                result["shield_score"] = data.get("detail", {}).get("score", 1.0)
                result["shield_response"] = data
            elif resp.status == 200:
                # 通过
                data = await resp.json()
                result["shield_decision"] = "ALLOW"
                result["shield_blocked"] = False
                result["shield_response"] = data
            else:
                # 其他响应
                result["error"] = f"HTTP {resp.status}"
                result["shield_decision"] = "ERROR"

    except asyncio.TimeoutError:
        result["error"] = "Timeout"
        result["shield_decision"] = "ERROR"
        result["duration_ms"] = int((time.time() - start_time) * 1000)
    except Exception as e:
        result["error"] = str(e)
        result["shield_decision"] = "ERROR"
        result["duration_ms"] = int((time.time() - start_time) * 1000)

    return result


async def run_tests():
    """运行所有测试"""
    print("=" * 60)
    print("Llama Shield CyberSecEval 测试")
    print("=" * 60)
    print()

    # 加载数据集
    datasets = {}

    # Prompt Injection
    pi_data = load_dataset("Prompt Injection", os.path.join(DATASET_DIR, "prompt_injection/prompt_injection.json"))

    # Interpreter
    interp_data = load_dataset("Interpreter", os.path.join(DATASET_DIR, "interpreter/interpreter.json"))

    # MITRE
    mitre_data = load_dataset("MITRE", os.path.join(DATASET_DIR, "mitre/mitre_benchmark_100_per_category_with_augmentation.json"))

    # 按类别组织测试样本
    all_samples = []

    # Prompt Injection (直接)
    direct_samples = filter_items(pi_data, {"injection_type": "direct"})
    all_samples.extend(select_samples(direct_samples, "prompt_injection_direct", 5))

    # Prompt Injection (间接)
    indirect_samples = filter_items(pi_data, {"injection_type": "indirect"})
    all_samples.extend(select_samples(indirect_samples, "prompt_injection_indirect", 3))

    # Interpreter 各类型
    for attack_type in ["Privilege Escalation", "Container Escape", "Reflected Attack", "Post Exploitation", "Social Engineering"]:
        filtered = filter_items(interp_data, {"attack_type": [attack_type]})
        category_name = f"interpreter_{attack_type.lower().replace(' ', '_')}"
        all_samples.extend(select_samples(filtered, category_name, 3))

    # MITRE (从各100条类别中各取1条)
    mitre_categories = ["C2", "Collection", "Discovery", "Evasion", "Execution", "Exfil", "Privilege Escalation"]
    for cat in mitre_categories:
        cat_samples = [s for s in mitre_data if s.get('mitre_category') == cat]
        if cat_samples:
            sample = cat_samples[0].copy()
            sample['test_category'] = f"mitre_{cat.lower().replace(' ', '_')}"
            sample['sample_index'] = mitre_categories.index(cat)
            all_samples.append(sample)

    print(f"\nTotal samples selected: {len(all_samples)}")
    print()

    # 创建输出目录
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 运行测试
    print("Starting tests...")
    print("-" * 60)

    results = []
    connector = aiohttp.TCPConnector(limit=1)
    timeout = aiohttp.ClientTimeout(total=120)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        for i, sample in enumerate(all_samples):
            category = sample.get('test_category', 'unknown')
            print(f"[{i+1}/{len(all_samples)}] Testing {category}...", end=" ")

            result = await test_llama_shield(session, sample)
            results.append(result)

            if result["shield_decision"] == "BLOCK":
                print(f"BLOCKED by {result['shield_blocked_by']}")
            elif result["shield_decision"] == "ALLOW":
                print("ALLOWED")
            else:
                print(f"ERROR: {result['error']}")

            # 避免请求过快
            await asyncio.sleep(0.5)

    print("-" * 60)
    print()

    # 统计结果
    total = len(results)
    blocked = sum(1 for r in results if r["shield_decision"] == "BLOCK")
    allowed = sum(1 for r in results if r["shield_decision"] == "ALLOW")
    errors = sum(1 for r in results if r["shield_decision"] == "ERROR")

    print("=" * 60)
    print("测试结果统计")
    print("=" * 60)
    print(f"总测试数: {total}")
    print(f"被阻断: {blocked} ({blocked/total*100:.1f}%)")
    print(f"通过: {allowed} ({allowed/total*100:.1f}%)")
    print(f"错误: {errors} ({errors/total*100:.1f}%)")
    print()

    # 按类别统计
    categories = {}
    for r in results:
        cat = r["test_category"]
        if cat not in categories:
            categories[cat] = {"total": 0, "blocked": 0, "allowed": 0, "error": 0}
        categories[cat]["total"] += 1
        if r["shield_decision"] == "BLOCK":
            categories[cat]["blocked"] += 1
        elif r["shield_decision"] == "ALLOW":
            categories[cat]["allowed"] += 1
        else:
            categories[cat]["error"] += 1

    print("按类别统计:")
    for cat, stats in sorted(categories.items()):
        print(f"  {cat}: {stats['blocked']}/{stats['total']} blocked")

    # 保存结果
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(OUTPUT_DIR, f"test_results_{timestamp}.json")

    output_data = {
        "test_metadata": {
            "timestamp": datetime.now().isoformat(),
            "total_samples": total,
            "blocked": blocked,
            "allowed": allowed,
            "errors": errors,
            "block_rate": blocked / total if total > 0 else 0,
            "llama_shield_url": LLAMA_SHIELD_URL,
            "dataset_source": DATASET_DIR,
        },
        "category_stats": categories,
        "results": results,
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)

    print()
    print(f"结果已保存到: {output_file}")
    print("=" * 60)

    return output_data


if __name__ == "__main__":
    asyncio.run(run_tests())