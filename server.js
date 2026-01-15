// server.js
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const cors = require('cors'); // Để hỗ trợ CORS nếu cần gọi từ frontend khác

const app = express();
const PORT = process.env.PORT || 3000;

// Sử dụng JSON parser
app.use(express.json());

// Cho phép CORS (nếu bạn gọi API từ domain khác)
app.use(cors());

// Tạo thư mục lưu trữ nếu chưa tồn tại
const uploadsDir = path.join(__dirname, 'uploads');
const messagesFile = path.join(__dirname, 'messages.json');

if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

if (!fs.existsSync(messagesFile)) {
  fs.writeFileSync(messagesFile, JSON.stringify([]));
}

// Cấu hình Multer để lưu hình ảnh
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage });

// Phục vụ file tĩnh cho hình ảnh (để có thể truy cập qua URL)
app.use('/uploads', express.static(uploadsDir));

// Endpoint để upload hình ảnh
app.post('/upload-image', upload.single('image'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No image uploaded' });
  }
  const imageUrl = `/uploads/${req.file.filename}`;
  res.json({ message: 'Image uploaded successfully', url: imageUrl });
});

// Endpoint để lưu tin nhắn
app.post('/send-message', (req, res) => {
  const { message } = req.body;
  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  // Đọc file messages.json
  let messages = JSON.parse(fs.readFileSync(messagesFile, 'utf-8'));
  messages.push({ text: message, timestamp: new Date().toISOString() });
  fs.writeFileSync(messagesFile, JSON.stringify(messages));

  res.json({ message: 'Message saved successfully' });
});

// Endpoint để lấy danh sách tin nhắn
app.get('/messages', (req, res) => {
  const messages = JSON.parse(fs.readFileSync(messagesFile, 'utf-8'));
  res.json(messages);
});

// Endpoint để lấy danh sách hình ảnh (tùy chọn)
app.get('/images', (req, res) => {
  fs.readdir(uploadsDir, (err, files) => {
    if (err) {
      return res.status(500).json({ error: 'Error reading images' });
    }
    const imageUrls = files.map(file => `/uploads/${file}`);
    res.json(imageUrls);
  });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
