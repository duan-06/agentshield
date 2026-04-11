import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';

export interface AuthRequest extends Request {
  userId?: number;
}

export const authMiddleware = (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret') as { userId: number };
    req.userId = decoded.userId;
    next();
  } catch (error: any) {
    if (error?.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, message: 'Token expired' });
    }
    if (error?.name === 'JsonWebTokenError') {
      return res.status(401).json({ success: false, message: 'Invalid token' });
    }
    return res.status(401).json({ success: false, message: 'Authentication failed' });
  }
};

export const generateToken = (userId: number): string => {
  return jwt.sign({ userId }, process.env.JWT_SECRET || 'secret', {
    expiresIn: '7d',
  });
};
