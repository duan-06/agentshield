import { Router, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { authMiddleware, AuthRequest } from '../middleware/auth';
import { testEvaluateSchema } from '../validators/schemas';
import { llamaShieldService } from '../services/llamaShield';
import { generateMockScanResult, generateMockEvaluationOutput } from '../services/mockTest';
import { testModeConfig, logTestMode } from '../config/testMode';

const router = Router();
const prisma = new PrismaClient();

type ExpectedDecision = 'block' | 'allow';

interface PromptDatasetItem {
  prompt: string;
  expectedDecision?: ExpectedDecision;
}

function normalizeExpectedDecision(value: unknown): ExpectedDecision | undefined {
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'block' || normalized === 'allow') return normalized;
  return undefined;
}

function toRiskLevel(score: number, isBlocked: boolean): 'low' | 'medium' | 'high' | 'critical' {
  // 统一风险分层区间：
  // [0, 0.2) -> low, [0.2, 0.6) -> medium, [0.6, 0.8) -> high, [0.8, 1.0] -> critical
  if (score >= 0.8) return 'critical';
  if (score >= 0.6) return 'high';
  if (score >= 0.2) return 'medium';
  return 'low';
}

function buildRiskScoreDistribution(scores: number[]): number[] {
  const bins = Array.from({ length: 10 }, () => 0);
  for (const score of scores) {
    const normalized = Math.max(0, Math.min(0.999999, score));
    const idx = Math.floor(normalized * 10);
    bins[idx] += 1;
  }
  return bins;
}

async function evaluatePromptRealMode(prompt: string, token?: string) {
  const messages = [{ role: 'user', content: prompt }];

  if (token) {
    llamaShieldService.setToken(token);
  }

  const scanResult = await llamaShieldService.scanInputOnly(messages);
  const riskLevel = toRiskLevel(scanResult.score, scanResult.is_blocked);

  return {
    isBlocked: scanResult.is_blocked,
    score: scanResult.score,
    riskLevel,
    blockedBy: scanResult.blocked_by || (scanResult.is_blocked ? 'Unknown' : 'Pass'),
    blockedReason: scanResult.blocked_reason || '',
  };
}

type PromptEvalResult = {
  isBlocked: boolean;
  decision: string;
  score: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  blockedBy: string;
  blockedReason: string;
};

function getDatasetEvalConcurrency(total: number): number {
  const raw = parseInt(process.env.DATASET_EVAL_CONCURRENCY || '2', 10);
  const normalized = Number.isFinite(raw) && raw > 0 ? raw : 2;
  return Math.max(1, Math.min(8, Math.min(normalized, total)));
}

function getDatasetEvalChunkSize(total: number): number {
  const raw = parseInt(process.env.DATASET_EVAL_CHUNK_SIZE || '40', 10);
  const normalized = Number.isFinite(raw) && raw > 0 ? raw : 40;
  return Math.max(20, Math.min(300, Math.min(normalized, total)));
}

// Get test mode info
router.get('/mode', (req: Request, res: Response) => {
  res.json({
    success: true,
    data: {
      useMockMode: testModeConfig.useMockMode,
      mockDelay: testModeConfig.mockDelay,
      verbose: testModeConfig.verbose,
      modeInfo: testModeConfig.useMockMode ? '模拟模式' : '真实模式',
    },
  });
});

// Get all risk categories
router.get('/categories', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    const categories = await prisma.riskCategory.findMany({
      include: {
        testCases: true,
      },
    });

    res.json({
      success: true,
      data: categories,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Failed to fetch categories' });
  }
});

// Evaluate a test - 支持模拟模式和真实模式
router.post('/evaluate', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    const { error, value } = testEvaluateSchema.validate(req.body);

    if (error) {
      return res.status(400).json({ success: false, message: error.details[0].message });
    }

    const { input } = value;
    // 将子分类 id (100~401) 映射到父分类 id (1~4)
    const categoryId = value.categoryId <= 4 ? value.categoryId : Math.floor(value.categoryId / 100);

    let mockResult;
    let output;

    if (testModeConfig.useMockMode) {
      // 模拟模式
      logTestMode('使用模拟模式进行评估', { categoryId, inputLength: input.length });

      // 模拟延迟
      if (testModeConfig.mockDelay > 0) {
        await new Promise(resolve => setTimeout(resolve, testModeConfig.mockDelay));
      }

      mockResult = generateMockScanResult(input, categoryId);
      output = generateMockEvaluationOutput(mockResult);
    } else {
      // 真实模式 - 调用 Llama Shield
      logTestMode('使用真实模式进行评估', { categoryId, inputLength: input.length });

      const messages = [{ role: 'user', content: input }];

      // 设置 Llama Shield 的认证 Token
      const authHeader = req.headers.authorization;
      if (authHeader) {
        const token = authHeader.replace('Bearer ', '');
        llamaShieldService.setToken(token);
      }

      // 调用 Llama Shield 进行输入扫描
      const scanResult = await llamaShieldService.scanInput(messages);

      mockResult = {
        is_blocked: scanResult.is_blocked,
        decision: scanResult.decision,
        blocked_by: scanResult.blocked_by,
        blocked_reason: scanResult.blocked_reason,
        score: scanResult.score,
        riskLevel: scanResult.is_blocked ? (scanResult.score > 0.8 ? 'critical' : 'high') : 'low',
        category: '',
        details: '',
      };

      output = scanResult.is_blocked
        ? `[BLOCKED by ${scanResult.blocked_by}] ${scanResult.blocked_reason}`
        : 'Content passed security check.';
    }

    // 保存测试结果到数据库
    const testResult = await prisma.testResult.create({
      data: {
        userId: req.userId!,
        categoryId,
        input,
        output,
        riskLevel: mockResult.riskLevel,
        riskScore: mockResult.score,
        testType: 'single',
      },
      include: {
        category: true,
      },
    });

    res.json({
      success: true,
      message: mockResult.is_blocked ? 'Input blocked by security policy' : 'Test evaluated successfully',
      data: {
        ...testResult,
        scanResult: {
          is_blocked: mockResult.is_blocked,
          blocked_by: mockResult.blocked_by,
          blocked_reason: mockResult.blocked_reason,
          score: mockResult.score,
        },
      },
    });
  } catch (error: any) {
    console.error('Evaluation failed:', error);
    res.status(500).json({ success: false, message: 'Evaluation failed: ' + error.message });
  }
});

// Get user's test history
router.get('/history', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    const testResults = await prisma.testResult.findMany({
      where: { userId: req.userId },
      include: {
        category: true,
        testCase: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    const datasetResults = await prisma.datasetTestResult.findMany({
      where: { userId: req.userId },
      include: {
        category: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    // 合并并按时间排序
    const allResults = [
      ...testResults.map(r => ({ ...r, type: 'single' })),
      ...datasetResults.map(r => ({ ...r, type: 'dataset' })),
    ].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    res.json({
      success: true,
      data: allResults,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Failed to fetch history' });
  }
});

// Save dataset test result
router.post('/dataset-test', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    const { categoryId, fileName, fileSize, stats, prompts, promptItems } = req.body;

    if (!categoryId || !fileName) {
      return res.status(400).json({ success: false, message: 'Missing required fields: categoryId/fileName' });
    }

    // 兼容旧前端：若直接传入 stats，则仅落库
    if (stats) {
      const datasetResult = await prisma.datasetTestResult.create({
        data: {
          userId: req.userId!,
          categoryId,
          fileName,
          fileSize: fileSize || 0,
          total: stats.total,
          blocked: stats.blocked,
          passed: stats.passed,
          blockRate: parseFloat(String(stats.blockRate).replace('%', '')),
          avgRiskScore: parseFloat(String(stats.avgRiskScore)),
          riskDistribution: JSON.stringify(stats.riskDistribution),
          categoryDistribution: JSON.stringify(stats.categoryDistribution),
          riskScoreDistribution: JSON.stringify(stats.riskScoreDistribution),
          details: stats.details,
        },
        include: {
          category: true,
        },
      });

      return res.json({
        success: true,
        message: 'Dataset test result saved (legacy mode)',
        data: datasetResult,
      });
    }

    // 新模式：后端真实检测
    const normalizedItems: PromptDatasetItem[] = [];

    if (Array.isArray(promptItems) && promptItems.length > 0) {
      for (const item of promptItems) {
        if (!item || typeof item !== 'object') continue;
        const prompt = typeof (item as any).prompt === 'string' ? (item as any).prompt.trim() : '';
        if (!prompt) continue;
        normalizedItems.push({
          prompt,
          expectedDecision: normalizeExpectedDecision((item as any).expectedDecision),
        });
      }
    } else if (Array.isArray(prompts) && prompts.length > 0) {
      for (const p of prompts) {
        const prompt = typeof p === 'string' ? p.trim() : '';
        if (!prompt) continue;
        normalizedItems.push({ prompt });
      }
    }

    if (normalizedItems.length === 0) {
      return res.status(400).json({ success: false, message: 'No valid prompts found in dataset' });
    }

    const authHeader = req.headers.authorization;
    const token = authHeader ? authHeader.replace('Bearer ', '') : undefined;

    let blocked = 0;
    let errorCount = 0;
    const total = normalizedItems.length;
    const riskDistribution: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };
    const categoryDistribution: Record<string, number> = {};
    const scores: number[] = [];
    const sampleLines: string[] = [];

    let labeledTotal = 0;
    let truePositive = 0;
    let trueNegative = 0;
    let falsePositive = 0;
    let falseNegative = 0;

    const evalResults: PromptEvalResult[] = new Array(total);

    if (testModeConfig.useMockMode) {
      for (let i = 0; i < total; i += 1) {
        const prompt = normalizedItems[i].prompt;
        const mock = generateMockScanResult(prompt, categoryId);
        evalResults[i] = {
          isBlocked: mock.is_blocked,
          decision: mock.is_blocked ? 'BLOCK' : 'ALLOW',
          score: mock.score,
          riskLevel: (mock.riskLevel as 'low' | 'medium' | 'high' | 'critical'),
          blockedBy: mock.blocked_by || (mock.is_blocked ? 'Unknown' : 'Pass'),
          blockedReason: mock.blocked_reason || '',
        };
      }
    } else {
      if (token) {
        llamaShieldService.setToken(token);
      }

      const chunkSize = getDatasetEvalChunkSize(total);
      const chunkConcurrency = getDatasetEvalConcurrency(Math.ceil(total / chunkSize));
      let nextChunkStart = 0;

      const chunkWorker = async () => {
        while (true) {
          const start = nextChunkStart;
          nextChunkStart += chunkSize;
          if (start >= total) return;

          const end = Math.min(start + chunkSize, total);
          const chunkMessages = normalizedItems
            .slice(start, end)
            .map(item => [{ role: 'user', content: item.prompt }]);

          const chunkResults = await llamaShieldService.scanInputBatchOnly(chunkMessages);

          for (let offset = 0; offset < chunkResults.length; offset += 1) {
            const i = start + offset;
            const scanResult = chunkResults[offset];
            const riskLevel = toRiskLevel(scanResult.score, scanResult.is_blocked);
            evalResults[i] = {
              isBlocked: scanResult.is_blocked,
              decision: scanResult.decision,
              score: scanResult.score,
              riskLevel,
              blockedBy: scanResult.blocked_by || (scanResult.is_blocked ? 'Unknown' : 'Pass'),
              blockedReason: scanResult.blocked_reason || '',
            };
          }
        }
      };

      await Promise.all(Array.from({ length: chunkConcurrency }, () => chunkWorker()));
    }

    for (let i = 0; i < normalizedItems.length; i += 1) {
      const item = normalizedItems[i];
      const result = evalResults[i];

      if (result.decision === 'ERROR') {
        errorCount += 1;
      }

      if (result.isBlocked) blocked += 1;
      riskDistribution[result.riskLevel] += 1;
      scores.push(result.score);

      const cat = result.blockedBy || 'Pass';
      categoryDistribution[cat] = (categoryDistribution[cat] || 0) + 1;

      if (item.expectedDecision) {
        labeledTotal += 1;
        if (item.expectedDecision === 'block' && result.isBlocked) truePositive += 1;
        if (item.expectedDecision === 'allow' && !result.isBlocked) trueNegative += 1;
        if (item.expectedDecision === 'allow' && result.isBlocked) falsePositive += 1;
        if (item.expectedDecision === 'block' && !result.isBlocked) falseNegative += 1;
      }

      if (i < 20) {
        const expectedText = item.expectedDecision ? item.expectedDecision.toUpperCase() : 'N/A';
        sampleLines.push(
          `${i + 1}. [${result.decision}] score=${result.score.toFixed(3)} level=${result.riskLevel} by=${cat} expected=${expectedText}`
        );
      }
    }

    const passed = total - blocked;
    const avgRiskScore = scores.length > 0
      ? scores.reduce((sum, v) => sum + v, 0) / scores.length
      : 0;
    const blockRate = total > 0 ? (blocked / total) * 100 : 0;
    const riskScoreDistribution = buildRiskScoreDistribution(scores);

    const metrics = labeledTotal > 0
      ? {
          labeledTotal,
          truePositive,
          trueNegative,
          falsePositive,
          falseNegative,
          accuracy: ((truePositive + trueNegative) / labeledTotal) * 100,
          falseNegativeRate: (truePositive + falseNegative) > 0
            ? (falseNegative / (truePositive + falseNegative)) * 100
            : 0,
          falsePositiveRate: (falsePositive + trueNegative) > 0
            ? (falsePositive / (falsePositive + trueNegative)) * 100
            : 0,
          precision: (truePositive + falsePositive) > 0
            ? (truePositive / (truePositive + falsePositive)) * 100
            : 0,
          recall: (truePositive + falseNegative) > 0
            ? (truePositive / (truePositive + falseNegative)) * 100
            : 0,
        }
      : null;

    const details = [
      '📊 数据集真实检测报告',
      '----------------------------------------',
      `文件名称：${fileName}`,
      `测试时间：${new Date().toLocaleString()}`,
      `模式：${testModeConfig.useMockMode ? '模拟模式' : '真实模式'}`,
      '',
      `总样本数：${total}`,
      `扫描异常：${errorCount}`,
      `拦截样本：${blocked}`,
      `通过样本：${passed}`,
      `拦截率：${blockRate.toFixed(1)}%`,
      `平均风险分：${avgRiskScore.toFixed(3)}`,
      ...(metrics
        ? [
            '',
            '📐 指标（基于 expected_decision）',
            `标注样本：${metrics.labeledTotal}`,
            `准确率：${metrics.accuracy.toFixed(2)}%`,
            `漏报率（该拦截却放行）：${metrics.falseNegativeRate.toFixed(2)}%`,
            `误报率（该放行却拦截）：${metrics.falsePositiveRate.toFixed(2)}%`,
            `TP/TN/FP/FN：${metrics.truePositive}/${metrics.trueNegative}/${metrics.falsePositive}/${metrics.falseNegative}`,
          ]
        : []),
      '',
      '样本结果（前20条）：',
      ...sampleLines,
    ].join('\n');

    const datasetResult = await prisma.datasetTestResult.create({
      data: {
        userId: req.userId!,
        categoryId,
        fileName,
        fileSize: fileSize || 0,
        total,
        blocked,
        passed,
        blockRate,
        avgRiskScore,
        riskDistribution: JSON.stringify(riskDistribution),
        categoryDistribution: JSON.stringify(categoryDistribution),
        riskScoreDistribution: JSON.stringify(riskScoreDistribution),
        details,
      },
      include: {
        category: true,
      },
    });

    res.json({
      success: true,
      message: 'Dataset evaluated successfully',
      data: {
        ...datasetResult,
        computedStats: {
          total,
          blocked,
          passed,
          errorCount,
          blockRate,
          avgRiskScore,
          riskDistribution,
          categoryDistribution,
          riskScoreDistribution,
          metrics,
          details,
        },
      },
    });
  } catch (error: any) {
    console.error('Save dataset test failed:', error);
    res.status(500).json({ success: false, message: 'Failed to save dataset test: ' + error.message });
  }
});

// Get single test result detail
router.get('/result/:id', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    const { id } = req.params;
    const testResult = await prisma.testResult.findUnique({
      where: { id: parseInt(id) },
      include: {
        category: true,
        testCase: true,
      },
    });

    if (!testResult || testResult.userId !== req.userId) {
      return res.status(404).json({ success: false, message: 'Test result not found' });
    }

    res.json({
      success: true,
      data: testResult,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Failed to fetch test result' });
  }
});

// Get dataset test result detail
router.get('/dataset-result/:id', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    const { id } = req.params;
    const datasetResult = await prisma.datasetTestResult.findUnique({
      where: { id: parseInt(id) },
      include: {
        category: true,
      },
    });

    if (!datasetResult || datasetResult.userId !== req.userId) {
      return res.status(404).json({ success: false, message: 'Dataset result not found' });
    }

    // 解析 JSON 字段
    const result = {
      ...datasetResult,
      riskDistribution: JSON.parse(datasetResult.riskDistribution),
      categoryDistribution: JSON.parse(datasetResult.categoryDistribution),
      riskScoreDistribution: JSON.parse(datasetResult.riskScoreDistribution),
    };

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Failed to fetch dataset result' });
  }
});

// Get test statistics
router.get('/stats', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    const stats = await prisma.testResult.groupBy({
      by: ['riskLevel'],
      where: { userId: req.userId },
      _count: true,
    });

    res.json({
      success: true,
      data: stats,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Failed to fetch statistics' });
  }
});

export default router;
