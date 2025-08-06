import express from 'express';
import pool from './db.js';
import bcrypt from 'bcrypt';
import cors from 'cors';

const app = express();
app.use(cors());
app.use(express.json());

// ── 新規登録 API ─────────────────────────────
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'メールアドレスとパスワードは必須です' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2)',
      [email, hash]
    );
    return res.status(201).json({ message: '登録成功' });
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
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'ユーザーが存在しません' });
    }

    const user = result.rows[0];

    // ② パスワード照合
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'パスワードが間違っています' });
    }

    // 成功
    return res.status(200).json({ message: 'ログイン成功' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'ログイン失敗' });
  }
});

app.listen(3000, () => {
  console.log('Backend server listening on port 3000');
});
