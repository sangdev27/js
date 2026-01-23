// server.js - IMPROVED VERSION - ĐẢM BẢO HOẠT ĐỘNG ỔN ĐỊNH
const express = require('express');
const multer = require('multer');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const properLockfile = require('proper-lockfile');
const sanitizeHtml = require('sanitize-html');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-change-in-production';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'your-refresh-secret-key-change-in-production';

// ============ BẢO MẬT ============
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "blob:", "*"],
      mediaSrc: ["'self'", "blob:", "*"]
    }
  },
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3001'],
  credentials: true,
  maxAge: 86400
}));

app.use(compression());
app.use(express.json({ limit: '50mb' }));

// Rate limiting theo từng loại endpoint
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: 'Too many requests' }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many authentication attempts' }
});

const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { error: 'Too many upload attempts' }
});

app.use('/', generalLimiter);
app.use('/auth/login', authLimiter);
app.use('/auth/register', authLimiter);
app.use('/upload', uploadLimiter);

// ============ CẤU HÌNH THƯ MỤC ============
const uploadsDir = path.join(__dirname, 'uploads');
const productsDir = path.join(uploadsDir, 'products');
const musicDir = path.join(uploadsDir, 'music');
const filesDir = path.join(uploadsDir, 'files');
const backupDir = path.join(__dirname, 'backups');

const usersFile = path.join(__dirname, 'data', 'users.json');
const productsFile = path.join(__dirname, 'data', 'products.json');
const categoriesFile = path.join(__dirname, 'data', 'categories.json');
const transactionsFile = path.join(__dirname, 'data', 'transactions.json');
const activityLogFile = path.join(__dirname, 'data', 'activity_log.json');
const revokedTokensFile = path.join(__dirname, 'data', 'revoked_tokens.json');

const MAX_IMAGE_SIZE = 10 * 1024 * 1024; // 10MB
const MAX_MUSIC_SIZE = 50 * 1024 * 1024; // 50MB
const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB
const MAX_UPLOAD_FILES = 5; // Tối đa 5 file cùng lúc

const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
const ALLOWED_MUSIC_TYPES = ['audio/mpeg', 'audio/mp3', 'audio/wav', 'audio/ogg'];
const ALLOWED_FILE_TYPES = ['application/zip', 'application/x-rar-compressed', 'application/pdf', 'application/x-zip-compressed'];

// ============ HELPER FUNCTIONS ============
const readJSONWithLock = async (filePath) => {
  const release = await properLockfile.lock(filePath, { retries: 10 });
  try {
    const data = await fs.readFile(filePath, 'utf-8');
    return JSON.parse(data);
  } catch (error) {
    if (error.code === 'ENOENT') {
      return [];
    }
    throw error;
  } finally {
    await release();
  }
};

const writeJSONWithLock = async (filePath, data) => {
  const release = await properLockfile.lock(filePath, { retries: 10 });
  try {
    await fs.writeFile(filePath, JSON.stringify(data, null, 2));
  } finally {
    await release();
  }
};

const sanitizeInput = (input) => {
  if (typeof input === 'string') {
    return sanitizeHtml(input.trim(), {
      allowedTags: [], // Không cho phép tag HTML
      allowedAttributes: {}
    });
  }
  return input;
};

const checkDiskSpace = async (dir) => {
  try {
    const stats = fsSync.statfsSync(dir);
    const freeGB = (stats.bavail * stats.bsize) / (1024 * 1024 * 1024);
    return freeGB;
  } catch (error) {
    console.error('Disk space check failed:', error);
    return 100; // Giả định đủ dung lượng nếu không kiểm tra được
  }
};

const backupData = async () => {
  try {
    await fs.mkdir(backupDir, { recursive: true });
    
    const files = [
      { src: usersFile, name: 'users' },
      { src: productsFile, name: 'products' },
      { src: categoriesFile, name: 'categories' },
      { src: transactionsFile, name: 'transactions' }
    ];
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    
    for (const file of files) {
      if (fsSync.existsSync(file.src)) {
        const backupPath = path.join(backupDir, `${file.name}-${timestamp}.json`);
        await fs.copyFile(file.src, backupPath);
      }
    }
    
    // Giữ tối đa 10 bản backup mỗi loại
    const backups = await fs.readdir(backupDir);
    const groups = {};
    
    backups.forEach(backup => {
      const match = backup.match(/^([a-z]+)-/);
      if (match) {
        const type = match[1];
        if (!groups[type]) groups[type] = [];
        groups[type].push(backup);
      }
    });
    
    for (const [type, fileList] of Object.entries(groups)) {
      if (fileList.length > 10) {
        fileList.sort();
        const toDelete = fileList.slice(0, fileList.length - 10);
        for (const file of toDelete) {
          await fs.unlink(path.join(backupDir, file));
        }
      }
    }
    
    console.log('✅ Backup created');
  } catch (error) {
    console.error('Backup failed:', error);
  }
};

const logActivity = async (uid, action, details = {}) => {
  try {
    const logs = await readJSONWithLock(activityLogFile);
    logs.push({
      id: `log-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      uid,
      action,
      details: sanitizeInput(details),
      timestamp: new Date().toISOString(),
      ip: details.ip || 'unknown'
    });
    
    if (logs.length > 10000) {
      logs.splice(0, logs.length - 10000);
    }
    
    await writeJSONWithLock(activityLogFile, logs);
  } catch (error) {
    console.error('Failed to log activity:', error);
  }
};

const safeDeleteFile = async (filePath) => {
  try {
    await fs.access(filePath);
    await fs.unlink(filePath);
    return true;
  } catch {
    return false;
  }
};

const isTokenRevoked = async (token) => {
  try {
    const revokedTokens = await readJSONWithLock(revokedTokensFile);
    return revokedTokens.some(t => t.token === token);
  } catch {
    return false;
  }
};

const revokeToken = async (token) => {
  try {
    const revokedTokens = await readJSONWithLock(revokedTokensFile);
    revokedTokens.push({
      token,
      revokedAt: new Date().toISOString()
    });
    
    // Dọn dẹp tokens cũ hơn 30 ngày
    const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const filtered = revokedTokens.filter(t => new Date(t.revokedAt) > cutoff);
    
    await writeJSONWithLock(revokedTokensFile, filtered);
  } catch (error) {
    console.error('Failed to revoke token:', error);
  }
};

// ============ KHỞI TẠO ============
(async () => {
  try {
    await fs.mkdir(path.join(__dirname, 'data'), { recursive: true });
    await fs.mkdir(backupDir, { recursive: true });
    await fs.mkdir(productsDir, { recursive: true });
    await fs.mkdir(musicDir, { recursive: true });
    await fs.mkdir(filesDir, { recursive: true });

    const files = [
      { path: usersFile, data: [] },
      { path: productsFile, data: [] },
      { path: categoriesFile, data: [] },
      { path: transactionsFile, data: [] },
      { path: activityLogFile, data: [] },
      { path: revokedTokensFile, data: [] }
    ];

    for (const file of files) {
      if (!fsSync.existsSync(file.path)) {
        await writeJSONWithLock(file.path, file.data);
      }
    }

    // Tạo admin mặc định với password ngẫu nhiên
    const users = await readJSONWithLock(usersFile);
    if (users.length === 0) {
      const randomPassword = Math.random().toString(36).slice(-12) + Math.random().toString(36).slice(-12);
      const hashedPassword = await bcrypt.hash(randomPassword, 10);
      
      console.log('\n========================================');
      console.log('🚨 ADMIN ACCOUNT CREATED 🚨');
      console.log('Username: admin');
      console.log(`Password: ${randomPassword}`);
      console.log('⚠️  Please change password immediately!');
      console.log('========================================\n');
      
      users.push({
        uid: 'admin-' + Date.now(),
        username: 'admin',
        password: hashedPassword,
        email: 'admin@example.com',
        role: 'admin',
        balance: 0,
        totalRevenue: 0,
        mustChangePassword: true,
        createdAt: new Date().toISOString(),
        lastLogin: null
      });
      await writeJSONWithLock(usersFile, users);
    }

    // Tạo backup tự động mỗi 6 giờ
    setInterval(backupData, 6 * 60 * 60 * 1000);
    
    // Backup lần đầu
    await backupData();
    
  } catch (err) {
    console.error('Init error:', err);
    process.exit(1);
  }
})();

// ============ MULTER CONFIGS ============
const createMulterConfig = (destination, allowedTypes, maxSize, maxCount = 1) => {
  const storage = multer.diskStorage({
    destination: async (req, file, cb) => {
      // Kiểm tra dung lượng ổ đĩa
      const freeSpace = await checkDiskSpace(destination);
      if (freeSpace < 1) { // Ít hơn 1GB trống
        return cb(new Error('Disk space is low. Please free up space.'), null);
      }
      cb(null, destination);
    },
    filename: (req, file, cb) => {
      const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
      const ext = path.extname(file.originalname);
      const safeName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
      cb(null, `${safeName}-${uniqueSuffix}${ext}`);
    }
  });

  const fileFilter = (req, file, cb) => {
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`Invalid file type. Allowed: ${allowedTypes.join(', ')}`), false);
    }
  };

  return multer({
    storage,
    fileFilter,
    limits: { 
      fileSize: maxSize,
      files: maxCount 
    }
  });
};

const uploadImage = createMulterConfig(productsDir, ALLOWED_IMAGE_TYPES, MAX_IMAGE_SIZE, MAX_UPLOAD_FILES);
const uploadMusic = createMulterConfig(musicDir, ALLOWED_MUSIC_TYPES, MAX_MUSIC_SIZE, MAX_UPLOAD_FILES);
const uploadFile = createMulterConfig(filesDir, ALLOWED_FILE_TYPES, MAX_FILE_SIZE, MAX_UPLOAD_FILES);

// ============ MIDDLEWARE ============
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    // Kiểm tra token bị thu hồi
    if (await isTokenRevoked(token)) {
      return res.status(403).json({ error: 'Token has been revoked' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) return res.status(403).json({ error: 'Invalid token' });
      req.user = user;
      next();
    });
  } catch (error) {
    res.status(500).json({ error: 'Authentication failed' });
  }
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

const checkOwnership = (resource, resourceKey = 'uid') => {
  return (req, res, next) => {
    if (req.user.role === 'admin') return next();
    if (req.user[resourceKey] === req.params[resourceKey]) return next();
    res.status(403).json({ error: 'Access denied' });
  };
};

// ============ STATIC FILES ============
app.use('/uploads', express.static(uploadsDir, {
  maxAge: '1d',
  etag: true,
  setHeaders: (res, path) => {
    // Thêm header bảo mật cho file tĩnh
    res.set('X-Content-Type-Options', 'nosniff');
  }
}));

// Middleware để kiểm tra file download
app.use('/uploads/files/:filename', async (req, res, next) => {
  if (req.method === 'GET') {
    try {
      const filename = req.params.filename;
      const products = await readJSONWithLock(productsFile);
      const product = products.find(p => 
        p.downloadFile && p.downloadFile.includes(filename)
      );
      
      if (product) {
        // Kiểm tra xem user đã mua sản phẩm chưa
        const authHeader = req.headers['authorization'];
        if (authHeader) {
          const token = authHeader.split(' ')[1];
          if (token) {
            try {
              const user = jwt.verify(token, JWT_SECRET);
              const transactions = await readJSONWithLock(transactionsFile);
              const hasPurchased = transactions.some(t => 
                t.uid === user.uid && t.productId === product.id && t.status === 'completed'
              );
              
              if (!hasPurchased && user.role !== 'admin') {
                return res.status(403).json({ error: 'You need to purchase this product first' });
              }
            } catch (error) {
              // Token không hợp lệ, yêu cầu đăng nhập
            }
          }
        } else {
          // Không có token, redirect đến trang đăng nhập
          return res.status(401).json({ error: 'Authentication required' });
        }
      }
    } catch (error) {
      console.error('Download check error:', error);
    }
  }
  next();
});

// ============ AUTH ROUTES ============
app.post('/auth/register', async (req, res) => {
  try {
    let { username, password, email } = req.body;

    username = sanitizeInput(username);
    email = sanitizeInput(email);

    if (!username || !password || !email) {
      return res.status(400).json({ error: 'All fields required' });
    }

    if (username.length < 3 || username.length > 30) {
      return res.status(400).json({ error: 'Username must be 3-30 characters' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    const users = await readJSONWithLock(usersFile);

    if (users.find(u => u.username === username)) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    if (users.find(u => u.email === email)) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = {
      uid: `user-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      username,
      password: hashedPassword,
      email,
      role: 'user',
      balance: 0,
      createdAt: new Date().toISOString(),
      lastLogin: null,
      mustChangePassword: false
    };

    users.push(newUser);
    await writeJSONWithLock(usersFile, users);
    await logActivity(newUser.uid, 'register', { ip: req.ip });

    res.json({
      success: true,
      message: 'User registered successfully',
      uid: newUser.uid
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const users = await readJSONWithLock(usersFile);
    const user = users.find(u => u.username === username);

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Yêu cầu đổi mật khẩu nếu cần
    if (user.mustChangePassword) {
      return res.status(200).json({
        success: true,
        requiresPasswordChange: true,
        message: 'Please change your password'
      });
    }

    user.lastLogin = new Date().toISOString();
    await writeJSONWithLock(usersFile, users);

    const accessToken = jwt.sign(
      { 
        uid: user.uid, 
        username: user.username, 
        role: user.role 
      },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { uid: user.uid },
      REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    await logActivity(user.uid, 'login', { ip: req.ip });

    res.json({
      success: true,
      accessToken,
      refreshToken,
      user: {
        uid: user.uid,
        username: user.username,
        email: user.email,
        role: user.role,
        balance: user.balance,
        lastLogin: user.lastLogin
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Both passwords are required' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters' });
    }

    const users = await readJSONWithLock(usersFile);
    const userIndex = users.findIndex(u => u.uid === req.user.uid);

    if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found' });
    }

    const validPassword = await bcrypt.compare(currentPassword, users[userIndex].password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Không cho phép đặt lại mật khẩu giống mật khẩu cũ
    const samePassword = await bcrypt.compare(newPassword, users[userIndex].password);
    if (samePassword) {
      return res.status(400).json({ error: 'New password must be different from current password' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);
    users[userIndex].password = hashedPassword;
    users[userIndex].mustChangePassword = false;
    users[userIndex].updatedAt = new Date().toISOString();

    await writeJSONWithLock(usersFile, users);
    await logActivity(req.user.uid, 'change_password', { ip: req.ip });

    res.json({
      success: true,
      message: 'Password changed successfully'
    });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

app.post('/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token required' });
    }

    // Kiểm tra token bị thu hồi
    if (await isTokenRevoked(refreshToken)) {
      return res.status(403).json({ error: 'Refresh token has been revoked' });
    }

    jwt.verify(refreshToken, REFRESH_SECRET, async (err, user) => {
      if (err) return res.status(403).json({ error: 'Invalid refresh token' });

      const users = await readJSONWithLock(usersFile);
      const userData = users.find(u => u.uid === user.uid);

      if (!userData) {
        return res.status(404).json({ error: 'User not found' });
      }

      const newAccessToken = jwt.sign(
        { 
          uid: userData.uid, 
          username: userData.username, 
          role: userData.role 
        },
        JWT_SECRET,
        { expiresIn: '15m' }
      );

      res.json({
        success: true,
        accessToken: newAccessToken
      });
    });
  } catch (error) {
    res.status(500).json({ error: 'Token refresh failed' });
  }
});

app.post('/auth/logout', authenticateToken, async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader.split(' ')[1];
    
    await revokeToken(token);
    await logActivity(req.user.uid, 'logout', { ip: req.ip });
    
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Logout failed' });
  }
});

// ============ PRODUCT ROUTES ============
app.post('/admin/products', authenticateToken, isAdmin, uploadImage.single('image'), async (req, res) => {
  try {
    let { name, description, price, categoryId, downloadLink, demoLink, isPinned } = req.body;

    // Sanitize input
    name = sanitizeInput(name);
    description = sanitizeInput(description);
    downloadLink = sanitizeInput(downloadLink);
    demoLink = sanitizeInput(demoLink);

    if (!name || !price) {
      return res.status(400).json({ error: 'Name and price required' });
    }

    const parsedPrice = parseFloat(price);
    if (isNaN(parsedPrice) || parsedPrice < 0) {
      return res.status(400).json({ error: 'Invalid price' });
    }

    const products = await readJSONWithLock(productsFile);
    const product = {
      id: `prod-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      name: name.trim(),
      description: description || '',
      price: parsedPrice,
      categoryId: categoryId || null,
      image: req.file ? `/uploads/products/${req.file.filename}` : null,
      downloadLink: downloadLink || null,
      demoLink: demoLink || null,
      isPinned: isPinned === 'true',
      createdBy: req.user.uid,
      createdAt: new Date().toISOString(),
      sales: 0
    };

    products.push(product);
    await writeJSONWithLock(productsFile, products);
    await logActivity(req.user.uid, 'create_product', { productId: product.id });

    res.json({ success: true, product });
  } catch (error) {
    console.error('Create product error:', error);
    
    // Xóa file nếu có lỗi
    if (req.file) {
      await safeDeleteFile(path.join(productsDir, req.file.filename));
    }
    
    res.status(500).json({ error: 'Failed to create product' });
  }
});

// ============ MUA SẢN PHẨM - VỚI TRANSACTION ATOMIC ============
app.post('/products/:productId/purchase', authenticateToken, async (req, res) => {
  let backupUsers = null;
  let backupProducts = null;
  let backupTransactions = null;
  
  try {
    const { productId } = req.params;
    
    // Đọc tất cả dữ liệu cần thiết
    const [products, users, transactions] = await Promise.all([
      readJSONWithLock(productsFile),
      readJSONWithLock(usersFile),
      readJSONWithLock(transactionsFile)
    ]);

    // Tạo backup để rollback nếu cần
    backupUsers = JSON.parse(JSON.stringify(users));
    backupProducts = JSON.parse(JSON.stringify(products));
    backupTransactions = JSON.parse(JSON.stringify(transactions));

    const product = products.find(p => p.id === productId);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    const userIndex = users.findIndex(u => u.uid === req.user.uid);
    if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = users[userIndex];

    if (user.balance < product.price) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Kiểm tra xem user đã mua sản phẩm này chưa
    const alreadyPurchased = transactions.some(t => 
      t.uid === user.uid && t.productId === productId && t.status === 'completed'
    );
    
    if (alreadyPurchased) {
      return res.status(400).json({ error: 'You have already purchased this product' });
    }

    // Bắt đầu "transaction" - thực hiện tất cả thay đổi
    users[userIndex].balance -= product.price;

    // Cộng tiền admin
    const adminIndex = users.findIndex(u => u.role === 'admin');
    if (adminIndex !== -1) {
      users[adminIndex].totalRevenue = (users[adminIndex].totalRevenue || 0) + product.price;
    }

    // Tăng số lượt bán
    const productIndex = products.findIndex(p => p.id === productId);
    if (productIndex !== -1) {
      products[productIndex].sales = (products[productIndex].sales || 0) + 1;
    }

    // Tạo giao dịch
    const transaction = {
      id: `txn-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      uid: user.uid,
      type: 'purchase',
      productId: product.id,
      productName: product.name,
      amount: product.price,
      status: 'completed',
      createdAt: new Date().toISOString()
    };

    transactions.push(transaction);

    // Lưu tất cả dữ liệu
    await Promise.all([
      writeJSONWithLock(usersFile, users),
      writeJSONWithLock(productsFile, products),
      writeJSONWithLock(transactionsFile, transactions)
    ]);

    await logActivity(user.uid, 'purchase_product', { 
      productId, 
      amount: product.price,
      productName: product.name
    });

    res.json({
      success: true,
      message: 'Purchase successful',
      downloadLink: product.downloadLink,
      downloadFile: product.downloadFile,
      newBalance: users[userIndex].balance,
      transactionId: transaction.id
    });
    
  } catch (error) {
    console.error('Purchase error:', error);
    
    // Rollback nếu có lỗi
    try {
      if (backupUsers && backupProducts && backupTransactions) {
        await Promise.all([
          writeJSONWithLock(usersFile, backupUsers),
          writeJSONWithLock(productsFile, backupProducts),
          writeJSONWithLock(transactionsFile, backupTransactions)
        ]);
        console.log('Purchase rolled back successfully');
      }
    } catch (rollbackError) {
      console.error('Rollback failed:', rollbackError);
      // Log chi tiết để xử lý thủ công sau
      await logActivity('system', 'purchase_rollback_failed', {
        error: rollbackError.message,
        userId: req.user?.uid,
        productId: req.params.productId
      });
    }
    
    res.status(500).json({ 
      error: 'Purchase failed. Please try again or contact support.' 
    });
  }
});

// ============ HEALTH CHECK ============
app.get('/health', async (req, res) => {
  try {
    const diskSpace = await checkDiskSpace(__dirname);
    const files = [
      usersFile,
      productsFile,
      categoriesFile,
      transactionsFile,
      activityLogFile
    ];
    
    const fileStatus = {};
    for (const file of files) {
      try {
        const stats = await fs.stat(file);
        fileStatus[path.basename(file)] = {
          exists: true,
          size: stats.size,
          modified: stats.mtime
        };
      } catch {
        fileStatus[path.basename(file)] = { exists: false };
      }
    }
    
    res.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      diskSpace: `${diskSpace.toFixed(2)} GB free`,
      files: fileStatus,
      uptime: process.uptime()
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error',
      error: error.message 
    });
  }
});

// ============ ERROR HANDLING ============
app.use((err, req, res, next) => {
  console.error('Error:', err);

  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large' });
    }
    if (err.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({ error: 'Too many files uploaded' });
    }
    return res.status(400).json({ error: err.message });
  }

  res.status(500).json({ error: 'Internal server error' });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ============ START SERVER ============
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`📁 Uploads: ${uploadsDir}`);
  console.log(`🎵 Music: ${musicDir}`);
  console.log(`📦 Files: ${filesDir}`);
  console.log(`💾 Backups: ${backupDir}`);
  console.log(`🔒 Using file locks for data consistency`);
});

// Graceful shutdown
const gracefulShutdown = async () => {
  console.log('Shutting down gracefully...');
  
  try {
    // Tạo backup trước khi shutdown
    await backupData();
    
    server.close(() => {
      console.log('HTTP server closed');
      process.exit(0);
    });
    
    // Force shutdown sau 10s
    setTimeout(() => {
      console.error('Could not close connections in time, forcefully shutting down');
      process.exit(1);
    }, 10000);
  } catch (error) {
    console.error('Error during shutdown:', error);
    process.exit(1);
  }
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);
