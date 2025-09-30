const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// 安全中间件
app.use(helmet({
  contentSecurityPolicy: false
}));

// 限流中间件
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15分钟
  max: 100 // 限制每个IP 15分钟内最多100个请求
});
app.use(limiter);

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// JWT密钥
const JWT_SECRET = 'customer_service_secret_key_2024';

// 初始化数据库
const db = new sqlite3.Database('./database.db');

// 创建表
db.serialize(() => {
  // 用户表
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME
  )`);

  // 对话记录表
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    message TEXT NOT NULL,
    sender_type TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);

  // 创建默认管理员账户
  const adminPassword = bcrypt.hashSync('admin123', 10);
  db.run(`INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)`, 
    ['admin', adminPassword, 'admin']);
});

// 验证JWT中间件
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: '访问令牌缺失' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: '令牌无效' });
    }
    req.user = user;
    next();
  });
};

// 登录API
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: '用户名和密码不能为空' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).json({ error: '数据库错误' });
    }

    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    // 更新最后登录时间
    db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });
  });
});

// 注册API
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: '用户名和密码不能为空' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: '密码长度至少6位' });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);

  db.run('INSERT INTO users (username, password) VALUES (?, ?)', 
    [username, hashedPassword], 
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(400).json({ error: '用户名已存在' });
        }
        return res.status(500).json({ error: '注册失败' });
      }

      const token = jwt.sign(
        { id: this.lastID, username, role: 'user' },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      res.json({
        token,
        user: {
          id: this.lastID,
          username,
          role: 'user'
        }
      });
    }
  );
});

// 获取用户信息
app.get('/api/user', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// 获取对话历史
app.get('/api/messages', authenticateToken, (req, res) => {
  const query = req.user.role === 'admin' 
    ? 'SELECT * FROM messages ORDER BY created_at DESC LIMIT 100'
    : 'SELECT * FROM messages WHERE user_id = ? ORDER BY created_at DESC LIMIT 50';
  
  const params = req.user.role === 'admin' ? [] : [req.user.id];

  db.all(query, params, (err, messages) => {
    if (err) {
      return res.status(500).json({ error: '获取消息失败' });
    }
    res.json(messages.reverse());
  });
});

// 管理员API - 获取用户列表
app.get('/api/admin/users', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: '权限不足' });
  }

  db.all(`SELECT id, username, role, created_at, last_login FROM users ORDER BY created_at DESC`, 
    (err, users) => {
      if (err) {
        return res.status(500).json({ error: '获取用户列表失败' });
      }
      res.json(users);
    }
  );
});

// 管理员API - 获取统计数据
app.get('/api/admin/stats', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: '权限不足' });
  }

  const stats = {};
  
  // 获取用户总数
  db.get('SELECT COUNT(*) as total FROM users WHERE role = "user"', (err, result) => {
    if (err) return res.status(500).json({ error: '统计失败' });
    stats.totalUsers = result.total;

    // 获取消息总数
    db.get('SELECT COUNT(*) as total FROM messages', (err, result) => {
      if (err) return res.status(500).json({ error: '统计失败' });
      stats.totalMessages = result.total;

      // 获取今日活跃用户
      db.get(`SELECT COUNT(DISTINCT user_id) as active FROM messages 
              WHERE date(created_at) = date('now')`, (err, result) => {
        if (err) return res.status(500).json({ error: '统计失败' });
        stats.activeToday = result.active;

        res.json(stats);
      });
    });
  });
});

// Socket.IO 实时通信
io.on('connection', (socket) => {
  console.log('用户连接:', socket.id);

  // 用户加入房间
  socket.on('join', (userData) => {
    socket.userData = userData;
    socket.join('chat_room');
    console.log(`${userData.username} 加入聊天室`);
  });

  // 处理消息
  socket.on('message', (data) => {
    const { message, token } = data;

    // 验证token
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        socket.emit('error', '认证失败');
        return;
      }

      // 保存消息到数据库
      db.run('INSERT INTO messages (user_id, username, message, sender_type) VALUES (?, ?, ?, ?)',
        [user.id, user.username, message, user.role === 'admin' ? 'admin' : 'user'],
        function(err) {
          if (err) {
            console.error('保存消息失败:', err);
            return;
          }

          const messageData = {
            id: this.lastID,
            user_id: user.id,
            username: user.username,
            message: message,
            sender_type: user.role === 'admin' ? 'admin' : 'user',
            created_at: new Date().toISOString()
          };

          // 广播消息给所有用户
          io.to('chat_room').emit('message', messageData);
        }
      );
    });
  });

  socket.on('disconnect', () => {
    console.log('用户断开连接:', socket.id);
  });
});

// 启动服务器
const PORT = process.env.PORT || 3000;

if (process.env.NODE_ENV !== 'production') {
  server.listen(PORT, () => {
    console.log(`服务器运行在端口 ${PORT}`);
    console.log(`访问地址: http://localhost:${PORT}`);
  });
}

// 导出app用于Vercel
module.exports = app;