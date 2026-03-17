import { Router, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { authMiddleware, AuthRequest } from '../middleware/auth';

const router = Router();
const prisma = new PrismaClient();

// Get chart data for user
router.get('/charts', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    // Risk level distribution
    const riskDistribution = await prisma.testResult.groupBy({
      by: ['riskLevel'],
      where: { userId: req.userId },
      _count: true,
    });

    // Tests by category
    const testsByCategory = await prisma.testResult.groupBy({
      by: ['categoryId'],
      where: { userId: req.userId },
      _count: true,
    });

    // Get category names
    const categories = await prisma.riskCategory.findMany();
    const categoryMap = new Map(categories.map(c => [c.id, c.name]));

    const chartData = {
      riskDistribution: riskDistribution.map(item => ({
        name: item.riskLevel,
        value: item._count,
      })),
      testsByCategory: testsByCategory.map(item => ({
        name: categoryMap.get(item.categoryId) || 'Unknown',
        value: item._count,
      })),
    };

    res.json({
      success: true,
      data: chartData,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Failed to fetch chart data' });
  }
});

// Get overall statistics
router.get('/overview', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    const totalTests = await prisma.testResult.count({
      where: { userId: req.userId },
    });

    const criticalTests = await prisma.testResult.count({
      where: {
        userId: req.userId,
        riskLevel: 'critical',
      },
    });

    const avgRiskScore = await prisma.testResult.aggregate({
      where: { userId: req.userId },
      _avg: { riskScore: true },
    });

    res.json({
      success: true,
      data: {
        totalTests,
        criticalTests,
        avgRiskScore: avgRiskScore._avg.riskScore || 0,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Failed to fetch overview' });
  }
});

export default router;
