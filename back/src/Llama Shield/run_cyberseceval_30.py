"""
CyberSecEval 30样本快速测试脚本 - 通过HTTP API
"""

import json
import os
import sys
import asyncio
import aiohttp
import time
from datetime import datetime

# 配置
LLAMA_SHIELD_URL = "http://localhost:8000"
DATASET_DIR = "D:/计算机设计大赛/datasets/CyberSecEval/CybersecurityBenchmarks/datasets"
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyberseceval_test_results")
TEST_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjMsImlhdCI6MTc3MzkyNjExMywiZXhwIjoxNzc0NTMwOTEzfQ.Zt7I3Znj5SkQJLc-3U63fxhUQzezDCPOfcDyKjp6paY"


def load_dataset(name, file_path):
    print(f"Loading {name}...")
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    print(f"  Loaded {len(data)} items")
    return data


def filter_items(items, filters):
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
    import random
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


async def test_single_sample(session, sample):
    test_input = sample.get('user_input') or sample.get('mutated_prompt') or sample.get('base_prompt') or sample.get('test_case_prompt', '')

    multi_turn_messages = [
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
        async with session.post(
            f"{LLAMA_SHIELD_URL}/api/v1/chat",
            json={"messages": multi_turn_messages, "temperature": 0.7, "max_tokens": 2048, "stream": False},
            headers={"Authorization": f"Bearer {TEST_TOKEN}"},
            timeout=aiohttp.ClientTimeout(total=120)
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
    print("=" * 60)
    print("Llama Shield CyberSecEval 30样本快速测试")
    print("=" * 60)
    print()

    # 加载数据集
    pi_data = load_dataset("Prompt Injection",
        os.path.join(DATASET_DIR, "prompt_injection/prompt_injection.json"))
    interp_data = load_dataset("Interpreter",
        os.path.join(DATASET_DIR, "interpreter/interpreter.json"))

    # 30个样本
    all_samples = []
    pi_direct = filter_items(pi_data, {"injection_type": "direct"})
    pi_indirect = filter_items(pi_data, {"injection_type": "indirect"})
    all_samples.extend(select_samples(pi_direct, "prompt_injection_direct", 10))
    all_samples.extend(select_samples(pi_indirect, "prompt_injection_indirect", 10))

    interp_types = [("Privilege Escalation", 3), ("Container Escape", 3), ("Social Engineering", 4)]
    for attack_type, count in interp_types:
        filtered = filter_items(interp_data, {"attack_type": [attack_type]})
        all_samples.extend(select_samples(filtered, f"interpreter_{attack_type.lower().replace(' ', '_')}", count))

    print(f"Total samples: {len(all_samples)}\n")

    # 串行执行
    results = []
    async with aiohttp.ClientSession() as session:
        for i, sample in enumerate(all_samples, 1):
            print(f"Running {i}/{len(all_samples)}...", end="\r")
            r = await test_single_sample(session, sample)
            results.append(r)

    # 统计
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)

    total = len(results)
    blocked = sum(1 for r in results if r['shield_blocked'])
    allowed = sum(1 for r in results if r['shield_decision'] == 'ALLOW')
    errors = sum(1 for r in results if r['shield_decision'] == 'ERROR')

    print(f"\nTotal: {total}")
    print(f"Blocked: {blocked}")
    print(f"Allowed: {allowed}")
    print(f"Errors: {errors}")
    if total > 0:
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

    # 阻断来源
    print("\n--- Blocked By Stats ---")
    blocked_by = {}
    for r in results:
        if r['shield_blocked'] and r['shield_blocked_by']:
            by = r['shield_blocked_by']
            blocked_by[by] = blocked_by.get(by, 0) + 1
    for by, count in sorted(blocked_by.items(), key=lambda x: -x[1]):
        print(f"  {by}: {count}")

    # 保存
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(OUTPUT_DIR, f"test_results_30_{timestamp}.json")

    output_data = {
        "test_metadata": {
            "timestamp": datetime.now().isoformat(),
            "total_samples": total,
            "blocked": blocked,
            "allowed": allowed,
            "errors": errors,
            "block_rate": blocked / total if total > 0 else 0,
            "encoding_preprocessor_enabled": True,
            "test_method": "http_api",
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
