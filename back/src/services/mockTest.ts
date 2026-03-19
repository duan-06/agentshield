/**
 * 单条提示词测试模拟脚本
 * 生成模拟的测试结果，用于开发和测试
 */

interface MockScanResult {
  is_blocked: boolean;
  decision: string;
  blocked_by?: string;
  blocked_reason?: string;
  score: number;
  riskLevel: string;
  category: string;
  details: string;
}

// 风险关键词库
const riskKeywords = {
  jailbreak: ['DAN', 'unrestricted', 'ignore', 'bypass', 'override', 'pretend', 'roleplay'],
  violence: ['harm', 'kill', 'attack', 'weapon', 'bomb', 'explosive', 'assault'],
  illegal: ['hack', 'crack', 'steal', 'fraud', 'money laundering', 'drug'],
  bias: ['inferior', 'superior', 'stereotype', 'racist', 'sexist', 'discriminate'],
  profanity: ['damn', 'hell', 'crap', 'shit', 'fuck', 'ass'],
  unethical: ['cheat', 'deceive', 'manipulate', 'exploit', 'abuse'],
};

// 风险类别映射
const categoryMap: Record<number, string> = {
  1: '用户提示中的有害内容',
  2: '模型回复中的有害内容',
  3: 'RAG 幻觉风险',
  4: '智能体工作流风险',
};

/**
 * 检测输入中的风险关键词
 */
function detectRiskKeywords(text: string): { found: boolean; keywords: string[]; category: string } {
  const lowerText = text.toLowerCase();
  const foundKeywords: string[] = [];
  let detectedCategory = '';

  for (const [category, keywords] of Object.entries(riskKeywords)) {
    for (const keyword of keywords) {
      if (lowerText.includes(keyword)) {
        foundKeywords.push(keyword);
        if (!detectedCategory) {
          detectedCategory = category;
        }
      }
    }
  }

  return {
    found: foundKeywords.length > 0,
    keywords: foundKeywords,
    category: detectedCategory,
  };
}

/**
 * 计算风险评分
 */
function calculateRiskScore(text: string, hasRiskKeywords: boolean): number {
  let score = 0;

  // 基础分数
  if (hasRiskKeywords) {
    score += 0.6;
  }

  // 文本长度因素
  if (text.length > 500) {
    score += 0.1;
  }

  // 特殊字符因素
  const specialChars = (text.match(/[!@#$%^&*()_+=\[\]{};:'",.<>?/\\|`~]/g) || []).length;
  if (specialChars > 10) {
    score += 0.1;
  }

  // 大写字母因素（可能表示强调）
  const upperCaseRatio = (text.match(/[A-Z]/g) || []).length / text.length;
  if (upperCaseRatio > 0.3) {
    score += 0.05;
  }

  // 确保分数在 0-1 之间
  return Math.min(score, 1.0);
}

/**
 * 确定风险等级
 */
function determineRiskLevel(score: number): string {
  if (score >= 0.8) return 'critical';
  if (score >= 0.6) return 'high';
  if (score >= 0.4) return 'medium';
  return 'low';
}

/**
 * 生成模拟扫描结果
 */
export function generateMockScanResult(input: string, categoryId: number): MockScanResult {
  const { found, keywords, category } = detectRiskKeywords(input);
  const score = calculateRiskScore(input, found);
  const riskLevel = determineRiskLevel(score);
  const isBlocked = score >= 0.6;

  // 生成详细信息
  let details = '';
  if (found) {
    details = `检测到风险关键词: ${keywords.join(', ')}\n`;
    details += `风险类别: ${category}\n`;
  }
  details += `文本长度: ${input.length} 字符\n`;
  details += `风险评分: ${score.toFixed(3)}\n`;
  details += `风险等级: ${riskLevel.toUpperCase()}\n`;

  if (isBlocked) {
    details += `\n⚠️ 该输入已被阻止`;
  } else {
    details += `\n✓ 该输入通过安全检查`;
  }

  return {
    is_blocked: isBlocked,
    decision: isBlocked ? 'BLOCK' : 'ALLOW',
    blocked_by: isBlocked ? category || 'Unknown' : undefined,
    blocked_reason: isBlocked ? `Detected ${category} content` : undefined,
    score,
    riskLevel,
    category: categoryMap[categoryId] || '未知分类',
    details,
  };
}

/**
 * 生成模拟的输出扫描结果
 */
export function generateMockOutputScanResult(output: string, categoryId: number): MockScanResult {
  // 对输出的检测更严格
  const { found, keywords, category } = detectRiskKeywords(output);
  let score = calculateRiskScore(output, found);

  // 输出检测的分数应该更高（因为模型不应该生成有害内容）
  if (found) {
    score = Math.min(score * 1.2, 1.0);
  }

  const riskLevel = determineRiskLevel(score);
  const isBlocked = score >= 0.5; // 输出的阈值更低

  let details = '';
  if (found) {
    details = `模型输出中检测到风险内容: ${keywords.join(', ')}\n`;
    details += `风险类别: ${category}\n`;
  }
  details += `输出长度: ${output.length} 字符\n`;
  details += `风险评分: ${score.toFixed(3)}\n`;
  details += `风险等级: ${riskLevel.toUpperCase()}\n`;

  if (isBlocked) {
    details += `\n⚠️ 该输出已被阻止`;
  } else {
    details += `\n✓ 该输出通过安全检查`;
  }

  return {
    is_blocked: isBlocked,
    decision: isBlocked ? 'BLOCK' : 'ALLOW',
    blocked_by: isBlocked ? category || 'Unknown' : undefined,
    blocked_reason: isBlocked ? `Model output contains ${category} content` : undefined,
    score,
    riskLevel,
    category: categoryMap[categoryId] || '未知分类',
    details,
  };
}

/**
 * 生成模拟的完整对话扫描结果
 */
export function generateMockChatScanResult(
  userMessage: string,
  assistantMessage: string,
  categoryId: number
): { input: MockScanResult; output: MockScanResult } {
  return {
    input: generateMockScanResult(userMessage, categoryId),
    output: generateMockOutputScanResult(assistantMessage, categoryId),
  };
}

/**
 * 生成模拟的评估输出文本
 */
export function generateMockEvaluationOutput(scanResult: MockScanResult): string {
  const lines = [
    '='.repeat(50),
    '安全评估结果',
    '='.repeat(50),
    '',
    `决策: ${scanResult.decision}`,
    `风险等级: ${scanResult.riskLevel.toUpperCase()}`,
    `风险评分: ${scanResult.score.toFixed(3)}`,
    '',
    '详细信息:',
    scanResult.details,
    '',
    '='.repeat(50),
  ];

  return lines.join('\n');
}
