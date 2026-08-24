import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

// ========== MongoDB Connection ==========
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://bfakorewa_db_user:g84FZYsheQSGl7d0@cluster0.io4awow.mongodb.net/citibank?retryWrites=true&w=majority';

mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => {
    console.error('❌ MongoDB connection failed:', err);
    process.exit(1);
  });

// ========== Schemas ==========
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true },
  password_hash: { type: String, required: true },
  full_name: String,
  checking_balance: { type: Number, default: 0 },
  savings_balance: { type: Number, default: 0 },
  credit_card_balance: { type: Number, default: 0 },
  credit_limit: { type: Number, default: 5000 },
  checking_account_number: { type: String, default: '4832' },
  savings_account_number: { type: String, default: '9182' },
  credit_account_number: { type: String, default: '2345' },
  is_active: { type: Number, default: 1 },
  created_at: { type: Date, default: Date.now },
  last_login_at: Date,
  last_login_ip: String
});

const LoginAttemptSchema = new mongoose.Schema({
  username: String,
  attempt_time: { type: Date, default: Date.now },
  ip_address: String,
  success: Number,
  failure_reason: String
});

const User = mongoose.model('User', UserSchema);
const LoginAttempt = mongoose.model('LoginAttempt', LoginAttemptSchema);

// ========== Create Default Admin ==========
async function ensureAdmin() {
  try {
    const existing = await User.findOne({ username: 'admin' });
    if (!existing) {
      const hash = bcrypt.hashSync('admin123', 10);
      await User.create({
        username: 'admin',
        password_hash: hash,
        full_name: 'Administrator',
        checking_balance: 5000,
        savings_balance: 2000,
        credit_limit: 10000,
        is_active: 1
      });
      console.log('✅ Admin user created');
    }
  } catch (err) {
    console.error('❌ Error creating admin:', err);
  }
}

// ========== Login ==========
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  try {
    const user = await User.findOne({ username: username.toLowerCase() });

    if (!user) {
      await LoginAttempt.create({ username, ip_address: ip, success: 0, failure_reason: 'user_not_found' });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!user.is_active) {
      await LoginAttempt.create({ username, ip_address: ip, success: 0, failure_reason: 'account_disabled' });
      return res.status(401).json({ error: 'Account disabled' });
    }

    const valid = bcrypt.compareSync(password, user.password_hash);
    if (!valid) {
      await LoginAttempt.create({ username, ip_address: ip, success: 0, failure_reason: 'wrong_password' });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    await LoginAttempt.create({ username, ip_address: ip, success: 1 });
    user.last_login_at = new Date();
    user.last_login_ip = ip;
    await user.save();

    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET || 'secretkey',
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user._id,
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
    const user = await User.findById(decoded.userId)
      .select('username full_name checking_balance savings_balance credit_card_balance credit_limit is_active last_login_at checking_account_number savings_account_number credit_account_number');
    res.json(user);
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
    const user = await User.findById(decoded.userId);

    const fromBalance = fromAccount === 'checking' ? user.checking_balance : user.savings_balance;
    if (fromBalance < amount) return res.status(400).json({ error: 'Insufficient funds' });

    if (fromAccount === 'checking') {
      user.checking_balance -= amount;
    } else {
      user.savings_balance -= amount;
    }

    if (toAccount === 'checking') {
      user.checking_balance += amount;
    } else {
      user.savings_balance += amount;
    }

    await user.save();

    res.json({
      success: true,
      checking_balance: user.checking_balance,
      savings_balance: user.savings_balance
    });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ========== Admin: Add User ==========
app.post('/api/admin/users', async (req, res) => {
  const { username, password, full_name, checking_balance, savings_balance, credit_card_balance, credit_limit, checking_account_number, savings_account_number, credit_account_number } = req.body;

  try {
    const hash = bcrypt.hashSync(password, 10);
    const user = await User.create({
      username,
      password_hash: hash,
      full_name,
      checking_balance: checking_balance || 0,
      savings_balance: savings_balance || 0,
      credit_card_balance: credit_card_balance || 0,
      credit_limit: credit_limit || 5000,
      checking_account_number: checking_account_number || '4832',
      savings_account_number: savings_account_number || '9182',
      credit_account_number: credit_account_number || '2345',
      is_active: 1
    });
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== Admin: Get All Users ==========
app.get('/api/admin/users', async (req, res) => {
  const users = await User.find()
    .select('username full_name checking_balance savings_balance credit_card_balance credit_limit is_active checking_account_number savings_account_number credit_account_number');
  res.json(users);
});

// ========== Admin: Update User ==========
app.put('/api/admin/users/:id', async (req, res) => {
  const updates = {};
  const fields = ['checking_balance', 'savings_balance', 'credit_card_balance', 'credit_limit', 'is_active', 'checking_account_number', 'savings_account_number', 'credit_account_number'];

  fields.forEach(field => {
    if (req.body[field] !== undefined) {
      updates[field] = req.body[field];
    }
  });

  try {
    await User.findByIdAndUpdate(req.params.id, updates);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== Admin: Delete User ==========
app.delete('/api/admin/users/:id', async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== Admin: Get Login Logs ==========
app.get('/api/admin/login-logs', async (req, res) => {
  const logs = await LoginAttempt.find().sort({ attempt_time: -1 }).limit(100);
  res.json(logs);
});

// ========== Health Check ==========
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ========== Start Server ==========
async function startServer() {
  await ensureAdmin();
  const PORT = process.env.PORT || 10000;
  app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Server running on port ${PORT}`));
}

startServer();