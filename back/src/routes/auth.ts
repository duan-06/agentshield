import { Router, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import { registerSchema, loginSchema } from '../validators/schemas';
import { generateToken } from '../middleware/auth';

const router = Router();
const prisma = new PrismaClient();

// Register
router.post('/register', async (req: Request, res: Response) => {
  try {
    const { error, value } = registerSchema.validate(req.body);
    
    if (error) {
      return res.status(400).json({ success: false, message: error.details[0].message });
    }

    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [
          { username: value.username },
          { email: value.email },
        ],
      },
    });

    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Username or email already exists' });
    }

    const hashedPassword = await bcrypt.hash(value.password, 10);

    const user = await prisma.user.create({
      data: {
        username: value.username,
        email: value.email,
        password: hashedPassword,
      },
    });

    const token = generateToken(user.id);

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        userId: user.id,
        username: user.username,
        email: user.email,
        token,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Registration failed' });
  }
});

// Login
router.post('/login', async (req: Request, res: Response) => {
  try {
    const { error, value } = loginSchema.validate(req.body);
    
    if (error) {
      return res.status(400).json({ success: false, message: error.details[0].message });
    }

    const user = await prisma.user.findUnique({
      where: { username: value.username },
    });

    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const passwordMatch = await bcrypt.compare(value.password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const token = generateToken(user.id);

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        userId: user.id,
        username: user.username,
        email: user.email,
        token,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Login failed' });
  }
});

export default router;
