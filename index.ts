import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import { PrismaClient } from '@prisma/client';
import session from 'express-session';
import cors from 'cors';

const prisma = new PrismaClient();
const app = express();
const PORT = 3000;

app.use(express.json());
app.use(cors());
app.use(
    session({
        secret: 'your-secret-key',
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false }, // Set to true if using HTTPS
    })
);

// Middleware to verify JWT
const verifyJWT = (req: any, res: any, next: any) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ message: 'Access denied' });

    jwt.verify(token, 'your-jwt-secret', (err: any, user: any) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Register a new user
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const user = await prisma.user.create({
            data: {
                username,
                password: hashedPassword,
                email,
            },
        });
        res.status(201).json({ message: 'User registered', user });
    } catch (error) {
        res.status(400).json({ message: 'Registration failed', error });
    }
});

// JWT Login
app.post('/auth/jwt/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await prisma.user.findUnique({ where: { username } });

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id }, 'your-jwt-secret', { expiresIn: '1h' });
    res.json({ token });
});

// Session Login
app.post('/auth/session/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await prisma.user.findUnique({ where: { username } });

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    req.session.user = user;
    res.json({ message: 'Logged in', user });
});

// 2FA Setup
app.post('/auth/2fa/setup', verifyJWT, async (req, res) => {
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const secret = speakeasy.generateSecret({ length: 20 });
    await prisma.user.update({
        where: { id: user.id },
        data: { twoFactorSecret: secret.base32 },
    });

    qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
        if (err) return res.status(500).json({ message: 'Error generating QR code' });
        res.json({ secret: secret.base32, qrCode: data_url });
    });
});

// 2FA Verification
app.post('/auth/2fa/verify', verifyJWT, async (req, res) => {
    const { token } = req.body;
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    if (!user || !user.twoFactorSecret) return res.status(404).json({ message: '2FA not setup' });

    const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token,
    });

    if (!verified) return res.status(401).json({ message: 'Invalid 2FA token' });
    res.json({ message: '2FA verified' });
});

// Protected route example
app.get('/protected', verifyJWT, (req, res) => {
    res.json({ message: 'You have access to this protected route', user: req.user });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});