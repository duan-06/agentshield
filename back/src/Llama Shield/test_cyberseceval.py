#!/usr/bin/env python3
"""
CyberSecEval Prompt Injection 测试脚本
使用 LlamaShield 服务测试 prompt injection 数据集
"""

import json
import asyncio
import aiohttp
import argparse
from typing import List, Dict, Any
from datetime import datetime


class CyberSecEvalTester:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url.rstrip("/")
        self.results: List[Dict[str, Any]] = []

    async def scan_input(
        self,
        session: aiohttp.ClientSession,
        messages: List[Dict[str, str]],
        token: str = None
    ) -> Dict[str, Any]:
        """调用 LlamaShield 输入扫描 API"""
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            async with session.post(
                f"{self.base_url}/api/v1/scan/input",
                json={"messages": messages},
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=60)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "is_blocked": False,
                        "decision": data.get("decision", "ALLOW"),
                        "score": data.get("score", 0.0)
                    }
                elif resp.status == 403:
                    data = await resp.json()
                    detail = data.get("detail", {})
                    return {
                        "is_blocked": True,
                        "decision": "BLOCK",
                        "blocked_by": detail.get("blocked_by", "Unknown"),
                        "blocked_reason": detail.get("blocked_reason", ""),
                        "score": detail.get("score", 1.0)
                    }
                else:
                    return {
                        "is_blocked": False,
                        "error": f"HTTP {resp.status}"
                    }
        except Exception as e:
            return {
                "is_blocked": False,
                "error": str(e)
            }

    async def test_single_case(
        self,
        session: aiohttp.ClientSession,
        test_case: Dict[str, Any],
        token: str = None
    ) -> Dict[str, Any]:
        """测试单个用例"""
        try:
            prompt_id = test_case.get("prompt_id", 0)
            test_case_prompt = test_case.get("test_case_prompt", "")
            user_input = test_case.get("user_input", "")
            injection_variant = test_case.get("injection_variant", "")
            injection_type = test_case.get("injection_type", "")
            risk_category = test_case.get("risk_category", "")
            judge_question = test_case.get("judge_question", "")

            # 构建消息列表（模拟真实对话）
            messages = [
                {"role": "system", "content": test_case_prompt},
                {"role": "user", "content": user_input}
            ]

            # 调用扫描 API
            scan_result = await self.scan_input(session, messages, token)

            # 判断是否应该被阻断（security-violating 和 logic-violating 应该被阻断）
            expected_blocked = risk_category in ["security-violating", "logic-violating"]
            actually_blocked = scan_result.get("is_blocked", False)

            result = {
                "prompt_id": prompt_id,
                "injection_variant": injection_variant,
                "injection_type": injection_type,
                "risk_category": risk_category,
                "judge_question": judge_question,
                "user_input": user_input,
                "expected_blocked": expected_blocked,
                "actually_blocked": actually_blocked,
                "detected": expected_blocked == actually_blocked,
                "scan_result": scan_result
            }

            return result
        except Exception as e:
            return {
                "prompt_id": test_case.get("prompt_id", 0),
                "error": str(e),
                "detected": False
            }

    async def run_tests(
        self,
        dataset_path: str,
        token: str = None,
        max_tests: int = None
    ):
        """运行所有测试"""
        print(f"加载数据集: {dataset_path}")

        with open(dataset_path, "r", encoding="utf-8") as f:
            dataset = json.load(f)

        if max_tests:
            dataset = dataset[:max_tests]

        total = len(dataset)
        print(f"共 {total} 个测试用例\n")

        # 使用信号量限制并发数，避免网络错误
        connector = aiohttp.TCPConnector(limit=5)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for i, case in enumerate(dataset):
                task = self.test_single_case(session, case, token)
                tasks.append(task)

                # 每次等待一小批完成
                if len(tasks) >= 5:
                    results_batch = await asyncio.gather(*tasks, return_exceptions=True)
                    for r in results_batch:
                        if isinstance(r, Exception):
                            print(f"  错误: {r}")
                        else:
                            self.results.append(r)
                    tasks = []

                if (i + 1) % 10 == 0 or (i + 1) == total:
                    print(f"进度: {i + 1}/{total}")

            # 处理剩余任务
            if tasks:
                results_batch = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results_batch:
                    if isinstance(r, Exception):
                        print(f"  错误: {r}")
                    else:
                        self.results.append(r)

        return self.results

    def print_summary(self):
        """打印测试结果摘要"""
        if not self.results:
            print("没有测试结果")
            return

        total = len(self.results)
        detected = sum(1 for r in self.results if r["detected"])
        true_positives = sum(
            1 for r in self.results
            if r["expected_blocked"] and r["actually_blocked"]
        )
        false_positives = sum(
            1 for r in self.results
            if not r["expected_blocked"] and r["actually_blocked"]
        )
        true_negatives = sum(
            1 for r in self.results
            if not r["expected_blocked"] and not r["actually_blocked"]
        )
        false_negatives = sum(
            1 for r in self.results
            if r["expected_blocked"] and not r["actually_blocked"]
        )

        # 计算指标
        detection_rate = detected / total * 100 if total > 0 else 0
        precision = true_positives / (true_positives + false_positives) * 100 if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) * 100 if (true_positives + false_negatives) > 0 else 0

        print("\n" + "=" * 60)
        print("CyberSecEval Prompt Injection 测试结果摘要")
        print("=" * 60)
        print(f"总测试用例:    {total}")
        print(f"正确检测:      {detected} ({detection_rate:.1f}%)")
        print(f"漏检 (FN):     {false_negatives}")
        print(f"误报 (FP):     {false_positives}")
        print("-" * 60)
        print(f"精确率 (Precision):  {precision:.1f}%")
        print(f"召回率 (Recall):     {recall:.1f}%")
        print("=" * 60)

        # 按注入类型分组统计
        by_variant = {}
        for r in self.results:
            variant = r.get("injection_variant", "unknown")
            if variant not in by_variant:
                by_variant[variant] = {"total": 0, "detected": 0}
            by_variant[variant]["total"] += 1
            if r["detected"]:
                by_variant[variant]["detected"] += 1

        print("\n按注入变体分类:")
        print("-" * 40)
        for variant, stats in sorted(by_variant.items()):
            rate = stats["detected"] / stats["total"] * 100 if stats["total"] > 0 else 0
            print(f"  {variant}: {stats['detected']}/{stats['total']} ({rate:.1f}%)")

        # 漏检案例分析
        print("\n漏检案例 (应该阻断但未阻断):")
        print("-" * 40)
        missed = [r for r in self.results if not r["detected"] and r["expected_blocked"]]
        for r in missed[:5]:
            print(f"  [ID {r['prompt_id']}] {r['injection_variant']}: {r['user_input'][:60]}...")
        if len(missed) > 5:
            print(f"  ... 还有 {len(missed) - 5} 个漏检案例")

        return {
            "total": total,
            "detected": detected,
            "detection_rate": detection_rate,
            "precision": precision,
            "recall": recall,
            "by_variant": by_variant
        }

    def save_results(self, output_path: str):
        """保存详细结果到文件"""
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.results, f, ensure_ascii=False, indent=2)
        print(f"\n详细结果已保存到: {output_path}")


async def main():
    parser = argparse.ArgumentParser(description="CyberSecEval Prompt Injection 测试")
    parser.add_argument(
        "--dataset",
        default="D:/计算机设计大赛/datasets/CyberSecEval/CybersecurityBenchmarks/datasets/prompt_injection/prompt_injection.json",
        help="数据集路径"
    )
    parser.add_argument(
        "--url",
        default="http://localhost:8000",
        help="LlamaShield 服务地址"
    )
    parser.add_argument(
        "--token",
        default=None,
        help="认证 token"
    )
    parser.add_argument(
        "--max",
        type=int,
        default=None,
        help="最大测试数量"
    )
    parser.add_argument(
        "--output",
        default=None,
        help="结果输出文件路径"
    )

    args = parser.parse_args()

    tester = CyberSecEvalTester(base_url=args.url)
    await tester.run_tests(args.dataset, token=args.token, max_tests=args.max)
    summary = tester.print_summary()

    if args.output:
        tester.save_results(args.output)

    return summary


if __name__ == "__main__":
    asyncio.run(main())
