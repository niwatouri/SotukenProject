import express from 'express';
import pool from './db.js';
import bcrypt from 'bcrypt';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import { JWT_SECRET, JWT_EXPIRES_IN } from './config.js';

const app = express();
app.use(cors());
app.use(express.json());

const issueToken = (user) =>
  jwt.sign(
    { userId: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );

const getTokenFromRequest = (req) => {
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }
  return null;
};

// ── 新規登録 API ─────────────────────────────
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'メールアドレスとパスワードは必須です' });
  }
  const hasUppercase = /[A-Z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  if (password.length < 8 || !hasUppercase || !hasNumber) {
    return res.status(400).json({ error: 'パスワードは8文字以上で、大文字と数字を含めてください' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email',
      [email, hash]
    );
    const user = result.rows[0];
    const token = issueToken(user);
    return res.status(201).json({
      message: '登録成功',
      token,
      user: { userId: user.id, email: user.email },
    });
  } catch (err) {
    // UNIQUE 制約違反だったら適切に処理
    if (err.code === '23505') {
      return res.status(409).json({ error: 'このメールアドレスは既に登録されています' });
    }
    console.error(err);
    return res.status(500).json({ error: '登録失敗' });
  }
});

// ── ログイン API ─────────────────────────────
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'メールアドレスとパスワードは必須です' });
  }

  try {
    // ① ユーザー取得
    const result = await pool.query('SELECT id, email, password FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'ユーザーが存在しません' });
    }

    const user = result.rows[0];

    // ② パスワード照合
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'パスワードが間違っています' });
    }

    const token = issueToken(user);
    return res.status(200).json({
      message: 'ログイン成功',
      token,
      user: { userId: user.id, email: user.email },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'ログイン失敗' });
  }
});

// ── ログイン状態確認 API ─────────────────────
app.get('/me', (req, res) => {
  const token = getTokenFromRequest(req);
  if (!token) {
    return res.status(401).json({ error: '認証が必要です' });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    return res.status(200).json({
      user: { userId: payload.userId, email: payload.email },
    });
  } catch (err) {
    return res.status(401).json({ error: 'トークンが無効です' });
  }
});

app.listen(3000, () => {
  console.log('Backend server listening on port 3000');
});
