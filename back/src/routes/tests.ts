import { Router, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { authMiddleware, AuthRequest } from '../middleware/auth';
import { testEvaluateSchema } from '../validators/schemas';
import { llamaShieldService } from '../services/llamaShield';
import { generateMockScanResult, generateMockEvaluationOutput } from '../services/mockTest';
import { testModeConfig, logTestMode } from '../config/testMode';

const router = Router();
const prisma = new PrismaClient();

// Get test mode info
router.get('/mode', (req: Response, res: Response) => {
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
    const { categoryId, fileName, fileSize, stats } = req.body;

    if (!categoryId || !fileName || !stats) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    const datasetResult = await prisma.datasetTestResult.create({
      data: {
        userId: req.userId!,
        categoryId,
        fileName,
        fileSize: fileSize || 0,
        total: stats.total,
        blocked: stats.blocked,
        passed: stats.passed,
        blockRate: parseFloat(stats.blockRate),
        avgRiskScore: parseFloat(stats.avgRiskScore),
        riskDistribution: JSON.stringify(stats.riskDistribution),
        categoryDistribution: JSON.stringify(stats.categoryDistribution),
        riskScoreDistribution: JSON.stringify(stats.riskScoreDistribution),
        details: stats.details,
      },
      include: {
        category: true,
      },
    });

    res.json({
      success: true,
      message: 'Dataset test result saved',
      data: datasetResult,
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
