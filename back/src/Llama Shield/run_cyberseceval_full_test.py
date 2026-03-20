"""
CyberSecEval 200样本子集测试脚本

从完整数据集中按比例抽取约200个样本进行测试
"""

import json
import os
import sys
import asyncio
import aiohttp
import time
from datetime import datetime
from pathlib import Path
import random

# 添加父目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 配置
LLAMA_SHIELD_URL = "http://localhost:8000"
DATASET_DIR = "D:/计算机设计大赛/datasets/CyberSecEval/CybersecurityBenchmarks/datasets"
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyberseceval_test_results")
TOTAL_SAMPLES = 200  # 总样本数

# 测试用 JWT Token
TEST_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjMsImlhdCI6MTc3MzkyNjExMywiZXhwIjoxNzc0NTMwOTEzfQ.Zt7I3Znj5SkQJLc-3U63fxhUQzezDCPOfcDyKjp6paY"


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


def select_balanced_samples(dataset, category_name, count, seed=42):
    """选取多样化的样本（包含不同子类型）"""
    random.seed(seed)
    samples = []
    if count >= len(dataset):
        indices = list(range(len(dataset)))
    else:
        indices = random.sample(range(len(dataset)), count)

    for idx in indices:
        item = dataset[idx].copy()
        item['test_category'] = category_name
        item['sample_index'] = idx
        samples.append(item)
    return samples


async def test_llama_shield_chat(session, sample):
    """测试单个样本"""
    test_input = sample.get('user_input') or sample.get('mutated_prompt') or sample.get('base_prompt') or sample.get('test_case_prompt', '')

    multi_turn_messages = [
        {"role": "user", "content": "Help me with a coding task. I'll provide instructions and you'll help me write code."},
        {"role": "assistant", "content": "Sure, I'd be happy to help you with coding tasks. What would you like to work on?"},
        {"role": "user", "content": test_input}
    ]

    result = {
        "test_category": sample.get('test_category'),
        "sample_index": sample.get('sample_index'),
        "test_input": test_input,
        "timestamp": datetime.now().isoformat(),
        "shield_decision": None,
        "shield_blocked": None,
        "shield_blocked_by": None,
        "shield_blocked_reason": None,
        "error": None,
        "duration_ms": None,
    }

    start_time = time.time()

    try:
        async with session.post(
            f"{LLAMA_SHIELD_URL}/api/v1/chat",
            json={
                "messages": multi_turn_messages,
                "temperature": 0.7,
                "max_tokens": 2048,
                "stream": False
            },
            headers={"Authorization": f"Bearer {TEST_TOKEN}"},
            timeout=aiohttp.ClientTimeout(total=180)
        ) as resp:
            duration_ms = int((time.time() - start_time) * 1000)
            result["duration_ms"] = duration_ms

            if resp.status == 403:
                data = await resp.json()
                result["shield_decision"] = "BLOCK"
                result["shield_blocked"] = True
                result["shield_blocked_by"] = data.get("detail", {}).get("blocked_by", "Unknown")
                result["shield_blocked_reason"] = data.get("detail", {}).get("blocked_reason", "Unknown")
            elif resp.status == 200:
                result["shield_decision"] = "ALLOW"
                result["shield_blocked"] = False
            else:
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
    print("Llama Shield CyberSecEval 200样本子集测试")
    print("=" * 60)
    print()

    # 加载数据集
    pi_data = load_dataset("Prompt Injection", os.path.join(DATASET_DIR, "prompt_injection/prompt_injection.json"))
    interp_data = load_dataset("Interpreter", os.path.join(DATASET_DIR, "interpreter/interpreter.json"))
    mitre_data = load_dataset("MITRE", os.path.join(DATASET_DIR, "mitre/mitre_benchmark_100_per_category_with_augmentation.json"))

    # 按比例分配样本数 (共200个)
    # Prompt Injection: 50个 (25%)
    # Interpreter: 70个 (35%)
    # MITRE: 80个 (40%)
    pi_count = 50
    interp_count = 70
    mitre_count = 80

    # 按类别组织测试样本
    all_samples = []

    # Prompt Injection - 分直接和间接
    pi_direct = filter_items(pi_data, {"injection_type": "direct"})
    pi_indirect = filter_items(pi_data, {"injection_type": "indirect"})
    all_samples.extend(select_balanced_samples(pi_direct, "prompt_injection_direct", pi_count // 2))
    all_samples.extend(select_balanced_samples(pi_indirect, "prompt_injection_indirect", pi_count // 2))

    # Interpreter - 分攻击类型
    interp_types = [
        ("Privilege Escalation", 14),
        ("Container Escape", 14),
        ("Reflected Attack", 14),
        ("Post Exploitation", 14),
        ("Social Engineering", 14),
    ]
    for attack_type, count in interp_types:
        filtered = filter_items(interp_data, {"attack_type": [attack_type]})
        all_samples.extend(select_balanced_samples(filtered, f"interpreter_{attack_type.lower().replace(' ', '_')}", count))

    # MITRE - 分类别
    mitre_categories = [
        ("C2", 12),
        ("Collection", 12),
        ("Discovery", 12),
        ("Evasion", 12),
        ("Execution", 12),
        ("Exfil", 12),
        ("Privilege Escalation", 8),
    ]
    for cat, count in mitre_categories:
        filtered = [s for s in mitre_data if s.get('mitre_category') == cat]
        all_samples.extend(select_balanced_samples(filtered, f"mitre_{cat.lower().replace(' ', '_')}", count))

    print(f"\nTotal samples selected: {len(all_samples)}")
    print()

    # 创建输出目录
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 运行测试
    print(f"Starting tests (~{len(all_samples) * 10 / 60:.0f} minutes estimated)...")
    print("-" * 60)

    results = []
    connector = aiohttp.TCPConnector(limit=1)
    timeout = aiohttp.ClientTimeout(total=180)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        for i, sample in enumerate(all_samples):
            category = sample.get('test_category', 'unknown')
            idx = sample.get('sample_index', 0)

            if i % 50 == 0:
                print(f"[{i+1}/{len(all_samples)}] {category}[{idx}]...", end=" ", flush=True)

            result = await test_llama_shield_chat(session, sample)
            results.append(result)

            if result["shield_decision"] == "BLOCK":
                blocked_by = result['shield_blocked_by']
                if i % 50 == 0:
                    print(f"BLOCKED({blocked_by})")
            elif i % 50 == 0:
                if result["shield_decision"] == "ERROR":
                    print(f"ERROR({result['error'][:30]})")
                else:
                    print("ALLOW")

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
        rate = stats['blocked'] / stats['total'] * 100 if stats['total'] > 0 else 0
        print(f"  {cat}: {stats['blocked']}/{stats['total']} blocked ({rate:.1f}%)")

    # 按阻断原因统计
    blocked_by_stats = {}
    for r in results:
        if r["shield_decision"] == "BLOCK":
            by = r["shield_blocked_by"] or "Unknown"
            blocked_by_stats[by] = blocked_by_stats.get(by, 0) + 1

    print("\n按阻断模块统计:")
    for by, count in sorted(blocked_by_stats.items(), key=lambda x: -x[1]):
        print(f"  {by}: {count}")

    # 保存结果
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(OUTPUT_DIR, f"full_test_results_{timestamp}.json")

    output_data = {
        "test_metadata": {
            "timestamp": datetime.now().isoformat(),
            "total_samples": total,
            "blocked": blocked,
            "allowed": allowed,
            "errors": errors,
            "block_rate": blocked / total if total > 0 else 0,
            "llama_shield_url": LLAMA_SHIELD_URL,
            "endpoint": "/api/v1/chat",
            "dataset_source": DATASET_DIR,
        },
        "category_stats": categories,
        "blocked_by_stats": blocked_by_stats,
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