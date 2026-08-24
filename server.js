import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import pkg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dns from 'dns';

const { Pool } = pkg;

dotenv.config();
dns.setDefaultResultOrder('ipv4first');
const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  host: 'aws-0-eu-west-1.pooler.supabase.com',
  port: 5432,
  user: 'postgres',
  password: 'Insecuresecur!1',
  database: 'postgres',
  ssl: {
    rejectUnauthorized: false,
    servername: 'db.foblvcrhovmfltpoimfu.supabase.co'
  }
});

// ========== Initialize Tables ==========
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      full_name TEXT,
      checking_balance REAL DEFAULT 0,
      savings_balance REAL DEFAULT 0,
      credit_card_balance REAL DEFAULT 0,
      credit_limit REAL DEFAULT 5000,
      checking_account_number TEXT DEFAULT '4832',
      savings_account_number TEXT DEFAULT '9182',
      credit_account_number TEXT DEFAULT '2345',
      is_active INTEGER DEFAULT 1,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      last_login_at TIMESTAMPTZ,
      last_login_ip TEXT
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS login_attempts (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      attempt_time TIMESTAMPTZ DEFAULT NOW(),
      ip_address TEXT,
      success INTEGER,
      failure_reason TEXT
    )
  `);

  const admin = await pool.query(`SELECT * FROM users WHERE username = 'admin'`);
  if (admin.rows.length === 0) {
    const hash = bcrypt.hashSync('admin123', 10);
    await pool.query(
      `INSERT INTO users (username, password_hash, full_name, checking_balance, savings_balance, credit_limit)
       VALUES ('admin', $1, 'Administrator', 5000, 2000, 10000)`,
      [hash]
    );
    console.log('✅ Admin user created');
  }

  console.log('✅ Database ready');
}

await initDB();

// ========== Login ==========
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  try {
    const result = await pool.query('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [username]);
    const user = result.rows[0];

    if (!user) {
      await pool.query('INSERT INTO login_attempts (username, ip_address, success, failure_reason) VALUES ($1, $2, 0, $3)', [username, ip, 'user_not_found']);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!user.is_active) {
      await pool.query('INSERT INTO login_attempts (username, ip_address, success, failure_reason) VALUES ($1, $2, 0, $3)', [username, ip, 'account_disabled']);
      return res.status(401).json({ error: 'Account disabled' });
    }

    const valid = bcrypt.compareSync(password, user.password_hash);
    if (!valid) {
      await pool.query('INSERT INTO login_attempts (username, ip_address, success, failure_reason) VALUES ($1, $2, 0, $3)', [username, ip, 'wrong_password']);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    await pool.query('INSERT INTO login_attempts (username, ip_address, success) VALUES ($1, $2, 1)', [username, ip]);
    await pool.query('UPDATE users SET last_login_at = NOW(), last_login_ip = $1 WHERE id = $2', [ip, user.id]);

    const token = jwt.sign({ userId: user.id, username: user.username }, process.env.JWT_SECRET || 'secretkey', { expiresIn: '24h' });

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        full_name: user.full_name,
        checking_balance: user.checking_balance,
        savings_balance: user.savings_balance,
        credit_card_balance: user.credit_card_balance,
        credit_limit: user.credit_limit,
        checking_account_number: user.checking_account_number,
        savings_account_number: user.savings_account_number,
        credit_account_number: user.credit_account_number
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== Get Current User ==========
app.get('/api/user/me', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secretkey');
    const result = await pool.query(`SELECT id, username, full_name, checking_balance, savings_balance, credit_card_balance, credit_limit, is_active, last_login_at, checking_account_number, savings_account_number, credit_account_number FROM users WHERE id = $1`, [decoded.userId]);
    res.json(result.rows[0]);
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ========== Internal Transfer ==========
app.post('/api/transfer/internal', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const { fromAccount, toAccount, amount } = req.body;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secretkey');
    const user = (await pool.query('SELECT checking_balance, savings_balance FROM users WHERE id = $1', [decoded.userId])).rows[0];

    const fromBalance = fromAccount === 'checking' ? user.checking_balance : user.savings_balance;
    if (fromBalance < amount) return res.status(400).json({ error: 'Insufficient funds' });

    if (fromAccount === 'checking') {
      await pool.query('UPDATE users SET checking_balance = checking_balance - $1 WHERE id = $2', [amount, decoded.userId]);
    } else {
      await pool.query('UPDATE users SET savings_balance = savings_balance - $1 WHERE id = $2', [amount, decoded.userId]);
    }

    if (toAccount === 'checking') {
      await pool.query('UPDATE users SET checking_balance = checking_balance + $1 WHERE id = $2', [amount, decoded.userId]);
    } else {
      await pool.query('UPDATE users SET savings_balance = savings_balance + $1 WHERE id = $2', [amount, decoded.userId]);
    }

    const updated = (await pool.query('SELECT checking_balance, savings_balance FROM users WHERE id = $1', [decoded.userId])).rows[0];
    res.json({ success: true, checking_balance: updated.checking_balance, savings_balance: updated.savings_balance });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ========== Admin: Add User ==========
app.post('/api/admin/users', async (req, res) => {
  const { username, password, full_name, checking_balance, savings_balance, credit_card_balance, credit_limit, checking_account_number, savings_account_number, credit_account_number } = req.body;

  try {
    const hash = bcrypt.hashSync(password, 10);
    await pool.query(
      `INSERT INTO users (username, password_hash, full_name, checking_balance, savings_balance, credit_card_balance, credit_limit, checking_account_number, savings_account_number, credit_account_number)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [username, hash, full_name, checking_balance || 0, savings_balance || 0, credit_card_balance || 0, credit_limit || 5000, checking_account_number || '4832', savings_account_number || '9182', credit_account_number || '2345']
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== Admin: Get All Users ==========
app.get('/api/admin/users', async (req, res) => {
  const result = await pool.query('SELECT id, username, full_name, checking_balance, savings_balance, credit_card_balance, credit_limit, is_active, checking_account_number, savings_account_number, credit_account_number FROM users');
  res.json(result.rows);
});

// ========== Admin: Update User ==========
app.put('/api/admin/users/:id', async (req, res) => {
  const { checking_balance, savings_balance, credit_card_balance, credit_limit, is_active, checking_account_number, savings_account_number, credit_account_number } = req.body;

  if (checking_balance !== undefined) await pool.query('UPDATE users SET checking_balance = $1 WHERE id = $2', [checking_balance, req.params.id]);
  if (savings_balance !== undefined) await pool.query('UPDATE users SET savings_balance = $1 WHERE id = $2', [savings_balance, req.params.id]);
  if (credit_card_balance !== undefined) await pool.query('UPDATE users SET credit_card_balance = $1 WHERE id = $2', [credit_card_balance, req.params.id]);
  if (credit_limit !== undefined) await pool.query('UPDATE users SET credit_limit = $1 WHERE id = $2', [credit_limit, req.params.id]);
  if (is_active !== undefined) await pool.query('UPDATE users SET is_active = $1 WHERE id = $2', [is_active, req.params.id]);
  if (checking_account_number !== undefined) await pool.query('UPDATE users SET checking_account_number = $1 WHERE id = $2', [checking_account_number, req.params.id]);
  if (savings_account_number !== undefined) await pool.query('UPDATE users SET savings_account_number = $1 WHERE id = $2', [savings_account_number, req.params.id]);
  if (credit_account_number !== undefined) await pool.query('UPDATE users SET credit_account_number = $1 WHERE id = $2', [credit_account_number, req.params.id]);

  res.json({ success: true });
});

// ========== Admin: Delete User ==========
app.delete('/api/admin/users/:id', async (req, res) => {
  await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

// ========== Admin: Get Login Logs ==========
app.get('/api/admin/login-logs', async (req, res) => {
  const result = await pool.query('SELECT * FROM login_attempts ORDER BY attempt_time DESC LIMIT 100');
  res.json(result.rows);
});

// ========== Health Check ==========
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Server running on port ${PORT}`));