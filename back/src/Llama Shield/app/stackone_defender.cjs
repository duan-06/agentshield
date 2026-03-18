#!/usr/bin/env node

/**
 * StackOne Defender 封装脚本
 *
 * 用于检测工具输出中的间接 prompt injection
 *
 * 使用方法:
 *   node stackone_defender.js <tool_output> [tool_name]
 *
 * 输出:
 *   JSON 格式: { "allowed": true/false, "riskLevel": "low/medium/high/critical", "score": 0.0-1.0, "detections": [] }
 */

const { createPromptDefense } = require('@stackone/defender');

// 创建 defense 实例
const defense = createPromptDefense({
  blockHighRisk: true,
  useDefaultToolRules: true,
});

async function main() {
  // 获取命令行参数
  const args = process.argv.slice(2);
  const toolOutput = args[0] || '';
  const toolName = args[1] || 'default';

  if (!toolOutput) {
    console.log(JSON.stringify({
      allowed: true,
      riskLevel: 'none',
      score: 0.0,
      detections: [],
      error: 'No input provided'
    }));
    process.exit(0);
  }

  try {
    // 预热模型（首次调用需要）
    if (!defense.isTier2Ready()) {
      await defense.warmupTier2();
    }

    // 调用 StackOne Defender 检测（异步）
    const result = await defense.defendToolResult(toolOutput, toolName);

    // 返回结果
    console.log(JSON.stringify({
      allowed: result.allowed,
      riskLevel: result.riskLevel || 'none',
      score: result.tier2Score || 0.0,
      detections: result.detections || [],
      sanitized: result.sanitized || toolOutput
    }));
  } catch (error) {
    console.log(JSON.stringify({
      allowed: true,  // 出错时默认放行
      riskLevel: 'none',
      score: 0.0,
      detections: [],
      error: error.message
    }));
  }
}

main();
