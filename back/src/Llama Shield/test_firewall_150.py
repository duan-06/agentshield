"""
CyberSecEval 150样本测试脚本 - 直接测试防火墙
测试新添加的编码预处理器效果
"""

import json
import os
import sys
import asyncio
import time
from datetime import datetime
from pathlib import Path
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

from app.firewall import LlamaFirewallManager

# 配置
DATASET_DIR = "D:/计算机设计大赛/datasets/CyberSecEval/CybersecurityBenchmarks/datasets"
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyberseceval_test_results")
TOTAL_SAMPLES = 150


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
                    if not any(v in value for v in value):
                        match = False
                        break
                elif item_value not in value:
                    match = False
                    break
        if match:
            filtered.append(item)
    return filtered


def select_samples(dataset, category_name, count, seed=42):
    """选取样本"""
    random.seed(seed)
    if count >= len(dataset):
        indices = list(range(len(dataset)))
    else:
        indices = random.sample(range(len(dataset)), count)
    samples = []
    for idx in indices:
        item = dataset[idx].copy()
        item['test_category'] = category_name
        item['sample_index'] = idx
        samples.append(item)
    return samples


async def test_single_sample(manager, sample):
    """测试单个样本"""
    test_input = sample.get('user_input') or sample.get('mutated_prompt') or sample.get('base_prompt') or sample.get('test_case_prompt', '')

    messages = [
        {"role": "user", "content": "Help me with a coding task."},
        {"role": "assistant", "content": "Sure, what would you like to work on?"},
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
        scan_result = await manager.scan_input(messages, request_id=f"test-{sample.get('test_category')}-{sample.get('sample_index')}")
        duration_ms = int((time.time() - start_time) * 1000)
        result["duration_ms"] = duration_ms

        result["shield_decision"] = "BLOCK" if scan_result.is_blocked else "ALLOW"
        result["shield_blocked"] = scan_result.is_blocked
        result["shield_blocked_by"] = scan_result.blocked_by
        result["shield_blocked_reason"] = scan_result.blocked_reason

    except Exception as e:
        result["error"] = str(e)
        result["shield_decision"] = "ERROR"
        result["duration_ms"] = int((time.time() - start_time) * 1000)

    return result


async def run_tests():
    """运行所有测试"""
    print("=" * 60)
    print("Llama Shield Firewall Test - 150 samples")
    print("=" * 60)
    print()

    # 加载数据集
    pi_data = load_dataset("Prompt Injection",
        os.path.join(DATASET_DIR, "prompt_injection/prompt_injection.json"))
    interp_data = load_dataset("Interpreter",
        os.path.join(DATASET_DIR, "interpreter/interpreter.json"))
    mitre_data = load_dataset("MITRE",
        os.path.join(DATASET_DIR, "mitre/mitre_benchmark_100_per_category_with_augmentation.json"))

    # 分配样本数 (共150个)
    pi_count = 40
    interp_count = 50
    mitre_count = 60

    all_samples = []

    # Prompt Injection - 分直接和间接
    pi_direct = filter_items(pi_data, {"injection_type": "direct"})
    pi_indirect = filter_items(pi_data, {"injection_type": "indirect"})
    all_samples.extend(select_samples(pi_direct, "prompt_injection_direct", pi_count // 2))
    all_samples.extend(select_samples(pi_indirect, "prompt_injection_indirect", pi_count // 2))

    # Interpreter - 分攻击类型
    interp_types = [
        ("Privilege Escalation", 10),
        ("Container Escape", 10),
        ("Reflected Attack", 10),
        ("Post Exploitation", 10),
        ("Social Engineering", 10),
    ]
    for attack_type, count in interp_types:
        filtered = filter_items(interp_data, {"attack_type": [attack_type]})
        all_samples.extend(select_samples(filtered, f"interpreter_{attack_type.lower().replace(' ', '_')}", count))

    # MITRE - 分类别
    mitre_categories = [
        ("C2", 9),
        ("Collection", 9),
        ("Discovery", 9),
        ("Evasion", 9),
        ("Execution", 9),
        ("Exfil", 9),
        ("Privilege Escalation", 6),
    ]
    for cat, count in mitre_categories:
        filtered = [s for s in mitre_data if s.get('mitre_category') == cat]
        all_samples.extend(select_samples(filtered, f"mitre_{cat.lower()}", count))

    print(f"\nTotal samples: {len(all_samples)}")
    print()

    # 初始化防火墙
    print("Initializing firewall...")
    manager = LlamaFirewallManager()
    await manager.initialize()
    print("Firewall ready.\n")

    # 运行测试
    results = []
    batch_size = 10

    for i in range(0, len(all_samples), batch_size):
        batch = all_samples[i:i+batch_size]
        print(f"Running batch {i//batch_size + 1}/{(len(all_samples) + batch_size - 1)//batch_size}...")

        batch_results = await asyncio.gather(*[test_single_sample(manager, s) for s in batch])
        results.extend(batch_results)

    # 统计结果
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)

    # 总体统计
    total = len(results)
    blocked = sum(1 for r in results if r['shield_blocked'])
    allowed = sum(1 for r in results if r['shield_decision'] == 'ALLOW')
    errors = sum(1 for r in results if r['shield_decision'] == 'ERROR')

    print(f"\nTotal: {total}")
    print(f"Blocked: {blocked}")
    print(f"Allowed: {allowed}")
    print(f"Errors: {errors}")
    print(f"Block rate: {blocked/total*100:.1f}%")

    # 按类别统计
    print("\n--- Category Stats ---")
    categories = {}
    for r in results:
        cat = r['test_category']
        if cat not in categories:
            categories[cat] = {'total': 0, 'blocked': 0, 'allowed': 0, 'errors': 0}
        categories[cat]['total'] += 1
        if r['shield_blocked']:
            categories[cat]['blocked'] += 1
        elif r['shield_decision'] == 'ALLOW':
            categories[cat]['allowed'] += 1
        else:
            categories[cat]['errors'] += 1

    for cat, stats in sorted(categories.items()):
        rate = stats['blocked'] / stats['total'] * 100 if stats['total'] > 0 else 0
        print(f"  {cat}: {stats['blocked']}/{stats['total']} ({rate:.0f}%)")

    # 拦截来源统计
    print("\n--- Blocked By Stats ---")
    blocked_by = {}
    for r in results:
        if r['shield_blocked'] and r['shield_blocked_by']:
            by = r['shield_blocked_by']
            blocked_by[by] = blocked_by.get(by, 0) + 1

    for by, count in sorted(blocked_by.items(), key=lambda x: -x[1]):
        print(f"  {by}: {count}")

    # 保存结果
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(OUTPUT_DIR, f"firewall_test_{timestamp}.json")

    output_data = {
        "test_metadata": {
            "timestamp": datetime.now().isoformat(),
            "total_samples": total,
            "blocked": blocked,
            "allowed": allowed,
            "errors": errors,
            "block_rate": blocked / total if total > 0 else 0,
            "encoding_preprocessor_enabled": True,
        },
        "category_stats": categories,
        "blocked_by_stats": blocked_by,
        "results": results
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)

    print(f"\nResults saved to: {output_file}")

    return output_data


if __name__ == '__main__':
    asyncio.run(run_tests())
