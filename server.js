const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
    credentials: true
  }
});

app.use(cors());
app.use(express.json({ limit: '10mb' }));

const rooms = new Map();
const waitingQueue = [];

function generateFriendlyCode() {
  const adjectives = ['HAPPY', 'SMILE', 'SUNNY', 'BRIGHT', 'SWEET', 'COOL', 'STAR', 'MAGIC', 'DREAM', 'LUCKY'];
  const numbers = Math.floor(100 + Math.random() * 900);
  const adj = adjectives[Math.floor(Math.random() * adjectives.length)];
  return `${adj}${numbers}`;
}

function isRoomCodeUnique(code) {
  return !rooms.has(code);
}

function generateUniqueRoomCode() {
  let code;
  let attempts = 0;
  do {
    code = generateFriendlyCode();
    attempts++;
  } while (!isRoomCodeUnique(code) && attempts < 10);
  
  if (attempts >= 10) {
    code = Math.random().toString(36).substring(2, 8).toUpperCase();
  }
  return code;
}

io.on('connection', (socket) => {
  console.log('✅ Client connected:', socket.id);

  socket.on('find-match', () => {
    console.log('🔍 User looking for match:', socket.id);
    
    if (waitingQueue.length > 0) {
      const partner = waitingQueue.shift();
      const roomCode = generateUniqueRoomCode();
      
      const roles = Math.random() > 0.5 
        ? { host: partner.socketId, remote: socket.id }
        : { host: socket.id, remote: partner.socketId };
      
      rooms.set(roomCode, {
        host: roles.host,
        remote: roles.remote,
        createdAt: Date.now()
      });
      
      partner.socket.join(roomCode);
      socket.join(roomCode);
      
      partner.socket.emit('match-found', { 
        roomCode, 
        role: roles.host === partner.socketId ? 'host' : 'remote'
      });
      
      socket.emit('match-found', { 
        roomCode, 
        role: roles.host === socket.id ? 'host' : 'remote'
      });
      
      console.log(`✅ Match created: ${roomCode}`);
    } else {
      waitingQueue.push({
        socketId: socket.id,
        socket: socket,
        timestamp: Date.now()
      });
      
      socket.emit('waiting-for-match');
      console.log('⏳ Added to waiting queue:', socket.id);
    }
  });

  socket.on('cancel-match', () => {
    const index = waitingQueue.findIndex(u => u.socketId === socket.id);
    if (index !== -1) {
      waitingQueue.splice(index, 1);
      console.log('❌ Removed from waiting queue:', socket.id);
    }
  });

  socket.on('create-room', (roomCode) => {
    if (!roomCode) {
      roomCode = generateUniqueRoomCode();
    }
    
    if (!isRoomCodeUnique(roomCode)) {
      socket.emit('error', 'Mã phòng đã tồn tại, vui lòng thử lại');
      return;
    }
    
    rooms.set(roomCode, {
      host: socket.id,
      remote: null,
      createdAt: Date.now()
    });
    
    socket.join(roomCode);
    socket.emit('room-created', { roomCode });
    console.log(`🏠 Room created: ${roomCode} by ${socket.id.substring(0,5)}`);
  });

  socket.on('join-room', (roomCode) => {
    console.log(`👤 User trying to join: ${roomCode}`);
    
    const room = rooms.get(roomCode);
    
    if (!room) {
      console.log('❌ Room not found:', roomCode);
      socket.emit('error', 'Phòng không tồn tại. Vui lòng kiểm tra lại mã.');
      return;
    }
    
    if (room.remote) {
      console.log('❌ Room full:', roomCode);
      socket.emit('error', 'Phòng đã đầy (chỉ cho phép 2 người)');
      return;
    }

    room.remote = socket.id;
    socket.join(roomCode);
    
    io.to(room.host).emit('remote-connected', { userId: socket.id });
    socket.emit('joined-room', { roomCode });
    
    console.log(`✅ Remote joined: ${roomCode}`);
  });

  socket.on('trigger-capture', (roomCode) => {
    console.log(`📸 Capture triggered for room: ${roomCode}`);
    
    const room = rooms.get(roomCode);
    if (room && room.host) {
      io.to(room.host).emit('capture-photo');
      console.log(`✅ Capture signal sent to host`);
    }
  });

  socket.on('photo-captured', ({ roomCode, photo }) => {
    console.log(`🖼️ Photo captured for room: ${roomCode}`);
    
    const room = rooms.get(roomCode);
    if (room) {
      io.to(roomCode).emit('photo-ready', { photo });
      console.log(`✅ Photo broadcasted to room`);
    }
  });

  socket.on('retake-requested', ({ roomCode }) => {
    console.log(`🔄 Retake requested for room: ${roomCode}`);
    io.to(roomCode).emit('retake-photo');
  });

  socket.on('disconnect', () => {
    console.log('❌ Client disconnected:', socket.id);
    
    const queueIndex = waitingQueue.findIndex(u => u.socketId === socket.id);
    if (queueIndex !== -1) {
      waitingQueue.splice(queueIndex, 1);
    }
    
    rooms.forEach((room, code) => {
      if (room.host === socket.id || room.remote === socket.id) {
        const partnerId = room.host === socket.id ? room.remote : room.host;
        
        if (partnerId) {
          io.to(partnerId).emit('partner-disconnected');
        }
        
        io.to(code).emit('room-closed');
        rooms.delete(code);
        console.log(`🗑️ Room closed: ${code}`);
      }
    });
  });
});

setInterval(() => {
  const now = Date.now();
  
  rooms.forEach((room, code) => {
    if (now - room.createdAt > 30 * 60 * 1000) {
      io.to(code).emit('room-timeout');
      rooms.delete(code);
      console.log('⏱️ Room timeout:', code);
    }
  });
  
  for (let i = waitingQueue.length - 1; i >= 0; i--) {
    if (now - waitingQueue[i].timestamp > 5 * 60 * 1000) {
      const user = waitingQueue[i];
      user.socket.emit('match-timeout');
      waitingQueue.splice(i, 1);
      console.log('⏱️ Match timeout for:', user.socketId);
    }
  }
}, 2 * 60 * 1000);

app.get('/stats', (req, res) => {
  res.json({
    activeRooms: rooms.size,
    waitingUsers: waitingQueue.length,
    timestamp: new Date().toISOString()
  });
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok',
    rooms: rooms.size,
    waiting: waitingQueue.length,
    timestamp: new Date().toISOString()
  });
});

app.get('/debug/rooms', (req, res) => {
  const roomList = Array.from(rooms.entries()).map(([code, room]) => ({
    code,
    host: room.host,
    remote: room.remote,
    createdAt: new Date(room.createdAt).toISOString()
  }));
  
  res.json({
    total: rooms.size,
    rooms: roomList
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Stats: http://localhost:${PORT}/stats`);
});