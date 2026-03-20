"""
快速测试20个样本 - 验证服务稳定性
"""

import json
import os
import asyncio
import aiohttp
import time
from datetime import datetime

LLAMA_SHIELD_URL = "http://localhost:8000"
DATASET_DIR = "D:/计算机设计大赛/datasets/CyberSecEval/CybersecurityBenchmarks/datasets"
TEST_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjMsImlhdCI6MTc3MzkyNjExMywiZXhwIjoxNzc0NTMwOTEzfQ.Zt7I3Znj5SkQJLc-3U63fxhUQzezDCPOfcDyKjp6paY"


def load_dataset(name, file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data[:10]  # 只取10个


async def test_single_sample(session, sample, i):
    test_input = sample.get('user_input') or sample.get('mutated_prompt') or sample.get('test_case_prompt', '')

    multi_turn_messages = [
        {"role": "user", "content": "Help me with a coding task."},
        {"role": "assistant", "content": "Sure, what would you like to work on?"},
        {"role": "user", "content": test_input}
    ]

    result = {
        "index": i,
        "category": sample.get('test_category', 'unknown'),
        "test_input": test_input[:50],
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
            timeout=aiohttp.ClientTimeout(total=60)
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

    except Exception as e:
        result["error"] = str(e)
        result["shield_decision"] = "ERROR"
        result["duration_ms"] = int((time.time() - start_time) * 1000)

    return result


async def run_tests():
    print("=" * 60)
    print("20样本快速测试")
    print("=" * 60)

    # 加载数据集
    pi_data = load_dataset("PI", os.path.join(DATASET_DIR, "prompt_injection/prompt_injection.json"))
    interp_data = load_dataset("Interp", os.path.join(DATASET_DIR, "interpreter/interpreter.json"))

    all_samples = []
    for i, item in enumerate(pi_data):
        item['test_category'] = f"pi_{i}"
        all_samples.append(item)
    for i, item in enumerate(interp_data):
        item['test_category'] = f"interp_{i}"
        all_samples.append(item)

    print(f"Total samples: {len(all_samples)}\n")

    results = []
    async with aiohttp.ClientSession() as session:
        for i, sample in enumerate(all_samples):
            print(f"Testing {i+1}/{len(all_samples)}: {sample['test_category']}...", end=" ")
            r = await test_single_sample(session, sample, i)
            results.append(r)
            status = "BLOCKED" if r['shield_blocked'] else ("ERROR" if r['error'] else "ALLOWED")
            by = f"({r['shield_blocked_by']})" if r['shield_blocked'] else ""
            print(f"{status} {by}")

    # 统计
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)

    total = len(results)
    blocked = sum(1 for r in results if r['shield_blocked'])
    allowed = sum(1 for r in results if r['shield_decision'] == 'ALLOW')
    errors = sum(1 for r in results if r['shield_decision'] == 'ERROR')

    print(f"\nTotal: {total}")
    print(f"Blocked: {blocked} ({blocked/total*100:.1f}%)")
    print(f"Allowed: {allowed} ({allowed/total*100:.1f}%)")
    print(f"Errors: {errors} ({errors/total*100:.1f}%)")

    # 错误详情
    if errors > 0:
        print("\n--- Error Details ---")
        for r in results:
            if r['error']:
                print(f"  {r['category']}: {r['error']}")

    # Blocked by 统计
    blocked_by = {}
    for r in results:
        if r['shield_blocked'] and r['shield_blocked_by']:
            by = r['shield_blocked_by']
            blocked_by[by] = blocked_by.get(by, 0) + 1

    if blocked_by:
        print("\n--- Blocked By ---")
        for by, count in sorted(blocked_by.items(), key=lambda x: -x[1]):
            print(f"  {by}: {count}")

    return results


if __name__ == '__main__':
    asyncio.run(run_tests())
