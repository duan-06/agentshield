import { Router, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { authMiddleware, AuthRequest } from '../middleware/auth';
import { testEvaluateSchema } from '../validators/schemas';

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

// Evaluate a test (placeholder for actual evaluation logic)
router.post('/evaluate', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    const { error, value } = testEvaluateSchema.validate(req.body);
    
    if (error) {
      return res.status(400).json({ success: false, message: error.details[0].message });
    }

    // TODO: Implement actual evaluation logic here
    // This would call your AI safety evaluation service
    const riskLevel = 'low'; // Placeholder
    const riskScore = 0.2; // Placeholder

    const testResult = await prisma.testResult.create({
      data: {
        userId: req.userId!,
        categoryId: value.categoryId,
        input: value.input,
        output: 'Evaluation result placeholder', // Replace with actual output
        riskLevel,
        riskScore,
      },
    });

    res.json({
      success: true,
      message: 'Test evaluated successfully',
      data: testResult,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Evaluation failed' });
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
