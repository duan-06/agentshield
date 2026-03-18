import { Router, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { authMiddleware, AuthRequest } from '../middleware/auth';
import { testEvaluateSchema } from '../validators/schemas';
import { llamaShieldService } from '../services/llamaShield';

const router = Router();
const prisma = new PrismaClient();

// Get all risk categories
router.get('/categories', async (req: AuthRequest, res: Response) => {
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

// Evaluate a test - 调用 Llama Shield 进行 AI 安全检测
router.post('/evaluate', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    const { error, value } = testEvaluateSchema.validate(req.body);

    if (error) {
      return res.status(400).json({ success: false, message: error.details[0].message });
    }

    const { categoryId, input } = value;

    // 构建消息格式
    const messages = [{ role: 'user', content: input }];

    // 设置 Llama Shield 的认证 Token
    const authHeader = req.headers.authorization;
    if (authHeader) {
      const token = authHeader.replace('Bearer ', '');
      llamaShieldService.setToken(token);
    }

    // 调用 Llama Shield 进行输入扫描
    const scanResult = await llamaShieldService.scanInput(messages);

    // 确定风险等级
    let riskLevel = 'low';
    if (scanResult.is_blocked) {
      riskLevel = scanResult.score > 0.8 ? 'critical' : 'high';
    } else if (scanResult.score > 0.5) {
      riskLevel = 'medium';
    }

    // 生成模拟输出（实际应由 Llama Shield 返回）
    const output = scanResult.is_blocked
      ? `[BLOCKED by ${scanResult.blocked_by}] ${scanResult.blocked_reason}`
      : 'Content passed security check.';

    const testResult = await prisma.testResult.create({
      data: {
        userId: req.userId!,
        categoryId,
        input,
        output,
        riskLevel,
        riskScore: scanResult.score,
      },
    });

    res.json({
      success: true,
      message: scanResult.is_blocked ? 'Input blocked by security policy' : 'Test evaluated successfully',
      data: {
        ...testResult,
        scanResult: {
          is_blocked: scanResult.is_blocked,
          blocked_by: scanResult.blocked_by,
          blocked_reason: scanResult.blocked_reason,
          score: scanResult.score,
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

    res.json({
      success: true,
      data: testResults,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Failed to fetch history' });
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
