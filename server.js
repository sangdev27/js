// server.js
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

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-change-in-production';

// ============ BẢO MẬT ============
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  maxAge: 86400
}));

app.use(compression());
app.use(express.json({ limit: '50mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: 'Too many requests' }
});
app.use(limiter);

// ============ CẤU HÌNH THƯ MỤC ============
const uploadsDir = path.join(__dirname, 'uploads');
const productsDir = path.join(uploadsDir, 'products');
const musicDir = path.join(uploadsDir, 'music');
const filesDir = path.join(uploadsDir, 'files');

const usersFile = path.join(__dirname, 'data', 'users.json');
const productsFile = path.join(__dirname, 'data', 'products.json');
const categoriesFile = path.join(__dirname, 'data', 'categories.json');
const transactionsFile = path.join(__dirname, 'data', 'transactions.json');
const activityLogFile = path.join(__dirname, 'data', 'activity_log.json');

const MAX_IMAGE_SIZE = 10 * 1024 * 1024; // 10MB
const MAX_MUSIC_SIZE = 50 * 1024 * 1024; // 50MB
const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB

const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
const ALLOWED_MUSIC_TYPES = ['audio/mpeg', 'audio/mp3', 'audio/wav', 'audio/ogg'];
const ALLOWED_FILE_TYPES = ['application/zip', 'application/x-rar-compressed', 'application/pdf', 'application/x-zip-compressed'];

// ============ KHỞI TẠO ============
(async () => {
  try {
    await fs.mkdir(path.join(__dirname, 'data'), { recursive: true });
    await fs.mkdir(productsDir, { recursive: true });
    await fs.mkdir(musicDir, { recursive: true });
    await fs.mkdir(filesDir, { recursive: true });

    const files = [
      { path: usersFile, data: [] },
      { path: productsFile, data: [] },
      { path: categoriesFile, data: [] },
      { path: transactionsFile, data: [] },
      { path: activityLogFile, data: [] }
    ];

    for (const file of files) {
      if (!fsSync.existsSync(file.path)) {
        await fs.writeFile(file.path, JSON.stringify(file.data, null, 2));
      }
    }

    // Tạo admin mặc định nếu chưa có
    const users = await readJSON(usersFile);
    if (users.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      users.push({
        uid: 'admin-' + Date.now(),
        username: 'admin',
        password: hashedPassword,
        email: 'admin@example.com',
        role: 'admin',
        balance: 0,
        totalRevenue: 0,
        createdAt: new Date().toISOString(),
        lastLogin: null
      });
      await writeJSON(usersFile, users);
      console.log('✅ Admin account created: admin / admin123');
    }
  } catch (err) {
    console.error('Init error:', err);
    process.exit(1);
  }
})();

// ============ HELPER FUNCTIONS ============
const readJSON = async (filePath) => {
  try {
    const data = await fs.readFile(filePath, 'utf-8');
    return JSON.parse(data);
  } catch {
    return [];
  }
};

const writeJSON = async (filePath, data) => {
  await fs.writeFile(filePath, JSON.stringify(data, null, 2));
};

const logActivity = async (uid, action, details = {}) => {
  const logs = await readJSON(activityLogFile);
  logs.push({
    id: `log-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    uid,
    action,
    details,
    timestamp: new Date().toISOString(),
    ip: details.ip || 'unknown'
  });
  
  // Giữ tối đa 10000 logs
  if (logs.length > 10000) logs.shift();
  await writeJSON(activityLogFile, logs);
};

// ============ MULTER CONFIGS ============
const createMulterConfig = (destination, allowedTypes, maxSize) => {
  const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, destination),
    filename: (req, file, cb) => {
      const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
      const ext = path.extname(file.originalname);
      cb(null, `${file.fieldname}-${uniqueSuffix}${ext}`);
    }
  });

  const fileFilter = (req, file, cb) => {
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`Invalid file type. Allowed: ${allowedTypes.join(', ')}`), false);
    }
  };

  return multer({ storage, fileFilter, limits: { fileSize: maxSize } });
};

const uploadImage = createMulterConfig(productsDir, ALLOWED_IMAGE_TYPES, MAX_IMAGE_SIZE);
const uploadMusic = createMulterConfig(musicDir, ALLOWED_MUSIC_TYPES, MAX_MUSIC_SIZE);
const uploadFile = createMulterConfig(filesDir, ALLOWED_FILE_TYPES, MAX_FILE_SIZE);

// ============ MIDDLEWARE ============
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// ============ STATIC FILES ============
app.use('/uploads', express.static(uploadsDir, {
  maxAge: '1d',
  etag: true
}));

// ============ AUTH ROUTES ============

// Đăng ký
app.post('/auth/register', async (req, res) => {
  try {
    const { username, password, email } = req.body;

    if (!username || !password || !email) {
      return res.status(400).json({ error: 'All fields required' });
    }

    const users = await readJSON(usersFile);
    
    if (users.find(u => u.username === username)) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      uid: `user-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      username,
      password: hashedPassword,
      email,
      role: 'user',
      balance: 0,
      createdAt: new Date().toISOString(),
      lastLogin: null
    };

    users.push(newUser);
    await writeJSON(usersFile, users);

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

// Đăng nhập
app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const users = await readJSON(usersFile);
    const user = users.find(u => u.username === username);

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Cập nhật lastLogin
    user.lastLogin = new Date().toISOString();
    await writeJSON(usersFile, users);

    const token = jwt.sign(
      { uid: user.uid, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    await logActivity(user.uid, 'login', { ip: req.ip });

    res.json({
      success: true,
      token,
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

// ============ USER ROUTES ============

// Lấy thông tin user
app.get('/user/profile', authenticateToken, async (req, res) => {
  try {
    const users = await readJSON(usersFile);
    const user = users.find(u => u.uid === req.user.uid);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      success: true,
      user: {
        uid: user.uid,
        username: user.username,
        email: user.email,
        role: user.role,
        balance: user.balance,
        totalRevenue: user.totalRevenue || 0,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Yêu cầu nạp tiền
app.post('/user/deposit-request', authenticateToken, async (req, res) => {
  try {
    const { amount, method } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }

    const transactions = await readJSON(transactionsFile);
    const transaction = {
      id: `txn-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      uid: req.user.uid,
      type: 'deposit',
      amount,
      method: method || 'bank_transfer',
      status: 'pending',
      createdAt: new Date().toISOString(),
      processedAt: null
    };

    transactions.push(transaction);
    await writeJSON(transactionsFile, transactions);

    await logActivity(req.user.uid, 'deposit_request', { amount, method });

    res.json({
      success: true,
      message: 'Deposit request created',
      transaction
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create deposit request' });
  }
});

// Admin duyệt nạp tiền
app.post('/admin/approve-deposit/:txnId', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { txnId } = req.params;
    const transactions = await readJSON(transactionsFile);
    const users = await readJSON(usersFile);

    const transaction = transactions.find(t => t.id === txnId);
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    if (transaction.status !== 'pending') {
      return res.status(400).json({ error: 'Transaction already processed' });
    }

    const user = users.find(u => u.uid === transaction.uid);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Cập nhật số dư
    user.balance += transaction.amount;
    transaction.status = 'completed';
    transaction.processedAt = new Date().toISOString();

    await writeJSON(transactionsFile, transactions);
    await writeJSON(usersFile, users);

    await logActivity(req.user.uid, 'approve_deposit', { txnId, amount: transaction.amount });

    res.json({
      success: true,
      message: 'Deposit approved',
      newBalance: user.balance
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to approve deposit' });
  }
});

// ============ CATEGORY ROUTES ============

// Thêm danh mục (Admin)
app.post('/admin/categories', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { name, description } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'Category name required' });
    }

    const categories = await readJSON(categoriesFile);
    
    const category = {
      id: `cat-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      name,
      description: description || '',
      createdAt: new Date().toISOString()
    };

    categories.push(category);
    await writeJSON(categoriesFile, categories);

    await logActivity(req.user.uid, 'create_category', { categoryId: category.id });

    res.json({ success: true, category });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create category' });
  }
});

// Lấy danh sách danh mục
app.get('/categories', async (req, res) => {
  try {
    const categories = await readJSON(categoriesFile);
    res.json({ success: true, data: categories });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch categories' });
  }
});

// Sửa danh mục (Admin)
app.put('/admin/categories/:categoryId', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { categoryId } = req.params;
    const { name, description } = req.body;

    const categories = await readJSON(categoriesFile);
    const categoryIndex = categories.findIndex(c => c.id === categoryId);

    if (categoryIndex === -1) {
      return res.status(404).json({ error: 'Category not found' });
    }

    categories[categoryIndex] = {
      ...categories[categoryIndex],
      name: name || categories[categoryIndex].name,
      description: description !== undefined ? description : categories[categoryIndex].description,
      updatedAt: new Date().toISOString()
    };

    await writeJSON(categoriesFile, categories);
    await logActivity(req.user.uid, 'update_category', { categoryId });

    res.json({ success: true, category: categories[categoryIndex] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update category' });
  }
});

// Xóa danh mục (Admin)
app.delete('/admin/categories/:categoryId', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { categoryId } = req.params;
    const categories = await readJSON(categoriesFile);
    
    const categoryIndex = categories.findIndex(c => c.id === categoryId);
    if (categoryIndex === -1) {
      return res.status(404).json({ error: 'Category not found' });
    }

    // Kiểm tra xem có sản phẩm nào dùng category này không
    const products = await readJSON(productsFile);
    const hasProducts = products.some(p => p.categoryId === categoryId);

    if (hasProducts) {
      return res.status(400).json({ 
        error: 'Cannot delete category with existing products. Remove products first.' 
      });
    }

    categories.splice(categoryIndex, 1);
    await writeJSON(categoriesFile, categories);
    await logActivity(req.user.uid, 'delete_category', { categoryId });

    res.json({ success: true, message: 'Category deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete category' });
  }
});

// ============ PRODUCT ROUTES ============

// Tạo sản phẩm (Admin)
app.post('/admin/products', authenticateToken, isAdmin, uploadImage.single('image'), async (req, res) => {
  try {
    const { name, description, price, categoryId, downloadLink, demoLink, isPinned } = req.body;

    if (!name || !price) {
      return res.status(400).json({ error: 'Name and price required' });
    }

    const products = await readJSON(productsFile);
    
    const product = {
      id: `prod-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      name,
      description: description || '',
      price: parseFloat(price),
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
    await writeJSON(productsFile, products);

    await logActivity(req.user.uid, 'create_product', { productId: product.id });

    res.json({ success: true, product });
  } catch (error) {
    console.error('Create product error:', error);
    res.status(500).json({ error: 'Failed to create product' });
  }
});

// Upload file sản phẩm
app.post('/admin/products/:productId/upload-file', authenticateToken, isAdmin, uploadFile.single('file'), async (req, res) => {
  try {
    const { productId } = req.params;
    const products = await readJSON(productsFile);
    
    const product = products.find(p => p.id === productId);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    product.downloadFile = `/uploads/files/${req.file.filename}`;
    await writeJSON(productsFile, products);

    res.json({
      success: true,
      downloadFile: product.downloadFile
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to upload file' });
  }
});

// Lấy danh sách sản phẩm
app.get('/products', async (req, res) => {
  try {
    const { category, search, pinned } = req.query;
    let products = await readJSON(productsFile);

    if (category) {
      products = products.filter(p => p.categoryId === category);
    }

    if (search) {
      const searchLower = search.toLowerCase();
      products = products.filter(p => 
        p.name.toLowerCase().includes(searchLower) ||
        p.description.toLowerCase().includes(searchLower)
      );
    }

    if (pinned === 'true') {
      products = products.filter(p => p.isPinned);
    }

    // Sắp xếp: pinned lên đầu, sau đó theo ngày tạo
    products.sort((a, b) => {
      if (a.isPinned && !b.isPinned) return -1;
      if (!a.isPinned && b.isPinned) return 1;
      return new Date(b.createdAt) - new Date(a.createdAt);
    });

    res.json({ success: true, data: products });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// Sửa sản phẩm (Admin)
app.put('/admin/products/:productId', authenticateToken, isAdmin, uploadImage.single('image'), async (req, res) => {
  try {
    const { productId } = req.params;
    const { name, description, price, categoryId, downloadLink, demoLink, isPinned } = req.body;

    const products = await readJSON(productsFile);
    const productIndex = products.findIndex(p => p.id === productId);

    if (productIndex === -1) {
      return res.status(404).json({ error: 'Product not found' });
    }

    const product = products[productIndex];

    // Xóa ảnh cũ nếu upload ảnh mới
    if (req.file && product.image) {
      try {
        const oldImagePath = path.join(__dirname, product.image);
        await fs.unlink(oldImagePath);
      } catch (err) {
        console.log('Old image not found or already deleted');
      }
    }

    // Cập nhật thông tin
    products[productIndex] = {
      ...product,
      name: name || product.name,
      description: description !== undefined ? description : product.description,
      price: price ? parseFloat(price) : product.price,
      categoryId: categoryId !== undefined ? categoryId : product.categoryId,
      image: req.file ? `/uploads/products/${req.file.filename}` : product.image,
      downloadLink: downloadLink !== undefined ? downloadLink : product.downloadLink,
      demoLink: demoLink !== undefined ? demoLink : product.demoLink,
      isPinned: isPinned !== undefined ? isPinned === 'true' : product.isPinned,
      updatedAt: new Date().toISOString()
    };

    await writeJSON(productsFile, products);
    await logActivity(req.user.uid, 'update_product', { productId });

    res.json({ success: true, product: products[productIndex] });
  } catch (error) {
    console.error('Update product error:', error);
    res.status(500).json({ error: 'Failed to update product' });
  }
});

// Xóa sản phẩm (Admin)
app.delete('/admin/products/:productId', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { productId } = req.params;
    const products = await readJSON(productsFile);
    
    const productIndex = products.findIndex(p => p.id === productId);
    if (productIndex === -1) {
      return res.status(404).json({ error: 'Product not found' });
    }

    const product = products[productIndex];

    // Xóa ảnh
    if (product.image) {
      try {
        const imagePath = path.join(__dirname, product.image);
        await fs.unlink(imagePath);
      } catch (err) {
        console.log('Image file not found');
      }
    }

    // Xóa file tải
    if (product.downloadFile) {
      try {
        const filePath = path.join(__dirname, product.downloadFile);
        await fs.unlink(filePath);
      } catch (err) {
        console.log('Download file not found');
      }
    }

    products.splice(productIndex, 1);
    await writeJSON(productsFile, products);
    await logActivity(req.user.uid, 'delete_product', { productId });

    res.json({ success: true, message: 'Product deleted' });
  } catch (error) {
    console.error('Delete product error:', error);
    res.status(500).json({ error: 'Failed to delete product' });
  }
});

// Mua sản phẩm
app.post('/products/:productId/purchase', authenticateToken, async (req, res) => {
  try {
    const { productId } = req.params;
    const products = await readJSON(productsFile);
    const users = await readJSON(usersFile);
    const transactions = await readJSON(transactionsFile);

    const product = products.find(p => p.id === productId);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    const user = users.find(u => u.uid === req.user.uid);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.balance < product.price) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Trừ tiền user
    user.balance -= product.price;

    // Cộng tiền admin
    const admin = users.find(u => u.role === 'admin');
    if (admin) {
      admin.totalRevenue = (admin.totalRevenue || 0) + product.price;
    }

    // Tăng số lượt bán
    product.sales = (product.sales || 0) + 1;

    // Tạo giao dịch
    const transaction = {
      id: `txn-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      uid: user.uid,
      type: 'purchase',
      productId: product.id,
      amount: product.price,
      status: 'completed',
      createdAt: new Date().toISOString()
    };

    transactions.push(transaction);

    await writeJSON(users, users);
    await writeJSON(productsFile, products);
    await writeJSON(transactionsFile, transactions);

    await logActivity(user.uid, 'purchase_product', { productId, amount: product.price });

    res.json({
      success: true,
      message: 'Purchase successful',
      downloadLink: product.downloadLink,
      downloadFile: product.downloadFile,
      newBalance: user.balance
    });
  } catch (error) {
    console.error('Purchase error:', error);
    res.status(500).json({ error: 'Purchase failed' });
  }
});

// ============ MUSIC ROUTES ============

// Upload nhạc
app.post('/music/upload', authenticateToken, uploadMusic.single('music'), async (req, res) => {
  try {
    const { title, artist } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: 'No music file uploaded' });
    }

    const musicUrl = `/uploads/music/${req.file.filename}`;

    await logActivity(req.user.uid, 'upload_music', { title, filename: req.file.filename });

    res.json({
      success: true,
      music: {
        url: musicUrl,
        title: title || 'Untitled',
        artist: artist || 'Unknown',
        filename: req.file.filename,
        size: req.file.size
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to upload music' });
  }
});

// Lấy danh sách nhạc
app.get('/music', async (req, res) => {
  try {
    const files = await fs.readdir(musicDir);
    const musicFiles = files.filter(file => {
      const ext = path.extname(file).toLowerCase();
      return ['.mp3', '.wav', '.ogg'].includes(ext);
    });

    const musicList = musicFiles.map(file => ({
      url: `/uploads/music/${file}`,
      filename: file
    }));

    res.json({ success: true, data: musicList });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch music' });
  }
});

// Xóa nhạc
app.delete('/music/:filename', authenticateToken, async (req, res) => {
  try {
    const filename = path.basename(req.params.filename); // Chặn path traversal
    const filePath = path.join(musicDir, filename);

    // Kiểm tra file có tồn tại
    try {
      await fs.access(filePath);
    } catch {
      return res.status(404).json({ error: 'Music file not found' });
    }

    await fs.unlink(filePath);
    await logActivity(req.user.uid, 'delete_music', { filename });

    res.json({ success: true, message: 'Music deleted' });
  } catch (error) {
    console.error('Delete music error:', error);
    res.status(500).json({ error: 'Failed to delete music' });
  }
});

// ============ ADMIN ROUTES ============

// Thống kê admin
app.get('/admin/stats', authenticateToken, isAdmin, async (req, res) => {
  try {
    const users = await readJSON(usersFile);
    const products = await readJSON(productsFile);
    const transactions = await readJSON(transactionsFile);

    const admin = users.find(u => u.role === 'admin');
    const totalUsers = users.filter(u => u.role === 'user').length;
    const totalProducts = products.length;
    const totalRevenue = admin?.totalRevenue || 0;
    
    const completedTransactions = transactions.filter(t => t.type === 'purchase' && t.status === 'completed');
    const totalSales = completedTransactions.length;

    res.json({
      success: true,
      stats: {
        totalUsers,
        totalProducts,
        totalRevenue,
        totalSales,
        adminBalance: admin?.balance || 0
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// Lịch sử hoạt động
app.get('/admin/activity-log', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { uid, limit = 100 } = req.query;
    let logs = await readJSON(activityLogFile);

    if (uid) {
      logs = logs.filter(log => log.uid === uid);
    }

    logs = logs.slice(-parseInt(limit)).reverse();

    res.json({ success: true, data: logs });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch activity log' });
  }
});

// Danh sách user
app.get('/admin/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const users = await readJSON(usersFile);
    const usersList = users.map(u => ({
      uid: u.uid,
      username: u.username,
      email: u.email,
      role: u.role,
      balance: u.balance,
      createdAt: u.createdAt,
      lastLogin: u.lastLogin
    }));

    res.json({ success: true, data: usersList });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Sửa thông tin user (Admin)
app.put('/admin/users/:uid', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { uid } = req.params;
    const { username, email, balance, role } = req.body;

    const users = await readJSON(usersFile);
    const userIndex = users.findIndex(u => u.uid === uid);

    if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Không cho phép sửa admin chính
    if (users[userIndex].role === 'admin' && users[userIndex].uid !== req.user.uid) {
      return res.status(403).json({ error: 'Cannot modify other admin accounts' });
    }

    users[userIndex] = {
      ...users[userIndex],
      username: username || users[userIndex].username,
      email: email || users[userIndex].email,
      balance: balance !== undefined ? parseFloat(balance) : users[userIndex].balance,
      role: role || users[userIndex].role,
      updatedAt: new Date().toISOString()
    };

    await writeJSON(usersFile, users);
    await logActivity(req.user.uid, 'update_user', { targetUid: uid });

    res.json({ success: true, user: users[userIndex] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// Xóa user (Admin)
app.delete('/admin/users/:uid', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { uid } = req.params;
    const users = await readJSON(usersFile);
    
    const userIndex = users.findIndex(u => u.uid === uid);
    if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Không cho phép xóa admin hoặc chính mình
    if (users[userIndex].role === 'admin') {
      return res.status(403).json({ error: 'Cannot delete admin accounts' });
    }

    if (users[userIndex].uid === req.user.uid) {
      return res.status(403).json({ error: 'Cannot delete yourself' });
    }

    users.splice(userIndex, 1);
    await writeJSON(usersFile, users);
    await logActivity(req.user.uid, 'delete_user', { targetUid: uid });

    res.json({ success: true, message: 'User deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Xóa giao dịch (Admin)
app.delete('/admin/transactions/:txnId', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { txnId } = req.params;
    const transactions = await readJSON(transactionsFile);
    
    const txnIndex = transactions.findIndex(t => t.id === txnId);
    if (txnIndex === -1) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    transactions.splice(txnIndex, 1);
    await writeJSON(transactionsFile, transactions);
    await logActivity(req.user.uid, 'delete_transaction', { txnId });

    res.json({ success: true, message: 'Transaction deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete transaction' });
  }
});

// Xóa log hoạt động (Admin)
app.delete('/admin/activity-log/:logId', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { logId } = req.params;
    const logs = await readJSON(activityLogFile);
    
    const logIndex = logs.findIndex(l => l.id === logId);
    if (logIndex === -1) {
      return res.status(404).json({ error: 'Log not found' });
    }

    logs.splice(logIndex, 1);
    await writeJSON(activityLogFile, logs);

    res.json({ success: true, message: 'Log deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete log' });
  }
});

// Xóa tất cả logs (Admin)
app.delete('/admin/activity-log', authenticateToken, isAdmin, async (req, res) => {
  try {
    await writeJSON(activityLogFile, []);
    res.json({ success: true, message: 'All logs cleared' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to clear logs' });
  }
});

// ============ HEALTH CHECK ============
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============ ERROR HANDLING ============
app.use((err, req, res, next) => {
  console.error('Error:', err);
  
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large' });
    }
    return res.status(400).json({ error: err.message });
  }
  
  res.status(500).json({ error: 'Internal server error' });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ============ START SERVER ============
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`📁 Uploads: ${uploadsDir}`);
  console.log(`🎵 Music: ${musicDir}`);
  console.log(`📦 Files: ${filesDir}`);
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});
