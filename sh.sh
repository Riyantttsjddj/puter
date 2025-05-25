#!/bin/bash
set -e

APP_DIR=/opt/chat-backend
SERVICE_NAME=chat-backend
USER=$(whoami)

echo "Update dan install curl, git, build-essential..."
sudo apt update
sudo apt install -y curl git build-essential

echo "Install Node.js 18.x dari NodeSource..."
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

echo "Buat direktori aplikasi di $APP_DIR"
sudo mkdir -p $APP_DIR
sudo chown $USER:$USER $APP_DIR

echo "Pindah ke direktori aplikasi..."
cd $APP_DIR

echo "Inisialisasi project npm dan install dependencies..."
if [ ! -f package.json ]; then
  npm init -y
fi
npm install express cors bcrypt jsonwebtoken body-parser dotenv

echo "Buat file index.js backend..."
cat > index.js <<'EOF'
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'rahasia123';
const JWT_EXPIRES_IN = '2h';

const CHAT_DIR = path.join(__dirname, 'chats');
if (!fs.existsSync(CHAT_DIR)) fs.mkdirSync(CHAT_DIR);

const USERS_FILE = path.join(__dirname, 'users.json');

let users = {};
try {
  if (fs.existsSync(USERS_FILE)) {
    users = JSON.parse(fs.readFileSync(USERS_FILE));
  }
} catch (err) {
  console.error('Gagal membaca users.json:', err);
  users = {};
}

function saveUsers() {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  } catch (err) {
    console.error('Gagal menyimpan users.json:', err);
  }
}

app.use(cors());
app.use(bodyParser.json());

function formatResponse(text) {
  if (!text || typeof text !== 'string') return '';

  if (text.startsWith('```') && text.endsWith('```')) return text;

  if (/function|const|let|var|=>|class|import|export|console\.log/.test(text)) {
    return `\`\`\`js\n${text}\n\`\`\``;
  }

  return text;
}

function saveChat(username, message, response) {
  const file = path.join(CHAT_DIR, `${username}.json`);
  let data = [];
  try {
    if (fs.existsSync(file)) {
      data = JSON.parse(fs.readFileSync(file));
    }
  } catch (err) {
    console.error('Gagal baca chat file:', err);
  }
  data.push({
    message,
    response,
    time: new Date()
  });
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error('Gagal simpan chat file:', err);
  }
}

function getChat(username) {
  const file = path.join(CHAT_DIR, `${username}.json`);
  try {
    if (fs.existsSync(file)) {
      return JSON.parse(fs.readFileSync(file));
    }
  } catch (err) {
    console.error('Gagal baca chat file:', err);
  }
  return [];
}

function clearChat(username) {
  const file = path.join(CHAT_DIR, `${username}.json`);
  try {
    if (fs.existsSync(file)) fs.unlinkSync(file);
  } catch (err) {
    console.error('Gagal hapus chat file:', err);
  }
}

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, message: 'Username dan password wajib diisi' });
  if (users[username]) return res.status(409).json({ success: false, message: 'Username sudah terdaftar' });

  try {
    users[username] = await bcrypt.hash(password, 10);
    saveUsers();
    res.json({ success: true, message: 'Registrasi berhasil' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error saat registrasi' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, message: 'Username dan password wajib diisi' });

  const userPass = users[username];
  if (!userPass) return res.status(401).json({ success: false, message: 'Username tidak ditemukan' });

  try {
    const isValid = await bcrypt.compare(password, userPass);
    if (!isValid) return res.status(401).json({ success: false, message: 'Password salah' });

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    res.json({ success: true, token, username, message: 'Login berhasil' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error saat login' });
  }
});

function auth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ success: false, message: 'Unauthorized, token tidak ditemukan' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Unauthorized, token kosong' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ success: false, message: 'Invalid token' });
  }
}

app.get('/chat', auth, (req, res) => {
  const chatData = getChat(req.user.username);
  res.json({ success: true, chat: chatData });
});

app.post('/chat', auth, (req, res) => {
  const { message } = req.body;
  let { response } = req.body;

  response = formatResponse(response);

  saveChat(req.user.username, message, response);
  res.json({ success: true, message: 'Chat tersimpan' });
});

app.post('/clear-chat', auth, (req, res) => {
  clearChat(req.user.username);
  res.json({ success: true, message: 'Chat berhasil dihapus' });
});

app.listen(PORT, '0.0.0.0', () => console.log(`Backend jalan di http://0.0.0.0:${PORT}`));
EOF

echo "Buat file .env untuk konfigurasi PORT & JWT_SECRET"
cat > .env <<EOF
PORT=8080
JWT_SECRET=rahasia123
EOF

echo "Buka port 8080 di ufw (jika ufw aktif)..."
sudo ufw allow 8080/tcp || true
sudo ufw reload || true

echo "Buat service systemd untuk menjalankan backend"
sudo tee /etc/systemd/system/$SERVICE_NAME.service > /dev/null <<EOF
[Unit]
Description=Chat Backend Service
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$APP_DIR
ExecStart=$(which node) $APP_DIR/index.js
Restart=on-failure
RestartSec=5s
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

echo "Reload systemd daemon dan enable service..."
sudo systemctl daemon-reload
sudo systemctl enable $SERVICE_NAME
sudo systemctl start $SERVICE_NAME

echo "Setup selesai! Backend berjalan di http://0.0.0.0:8080"
echo "Cek status service dengan: sudo systemctl status $SERVICE_NAME"
