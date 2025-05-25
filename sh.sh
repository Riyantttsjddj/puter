#!/bin/bash
set -e

APP_DIR=/opt/chatgpt-clone
SERVICE_NAME=chatgpt-clone
FRONTEND_DIR=/var/www/chatgpt-frontend
PORT=8080

echo "Update sistem..."
apt update && apt upgrade -y

echo "Install dependencies dasar..."
apt install -y curl git build-essential nginx mongodb

echo "Enable dan start mongodb..."
systemctl enable mongodb
systemctl start mongodb

# Install Node.js jika belum ada
if ! command -v node >/dev/null 2>&1; then
  echo "Install Node.js LTS..."
  curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
  apt install -y nodejs
fi

echo "Buat folder aplikasi backend di $APP_DIR"
mkdir -p $APP_DIR
cd $APP_DIR

echo "Buat package.json"
cat > package.json << EOF
{
  "name": "chatgpt-clone",
  "version": "1.0.0",
  "main": "server.js",
  "license": "MIT",
  "dependencies": {
    "bcrypt": "^5.1.0",
    "body-parser": "^1.20.2",
    "cors": "^2.8.5",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.0",
    "mongoose": "^7.2.2"
  }
}
EOF

echo "Buat server.js dengan port $PORT"
cat > server.js << EOF
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
const PORT = $PORT;
const JWT_SECRET = 'ini_rahasia_123'; // ganti dengan secret key yang aman

app.use(cors());
app.use(bodyParser.json());

mongoose.connect('mongodb://127.0.0.1:27017/chatgpt_clone', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String,
});

const chatSchema = new mongoose.Schema({
    userId: mongoose.Schema.Types.ObjectId,
    message: String,
    response: String,
    createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
const Chat = mongoose.model('Chat', chatSchema);

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    try {
        const user = new User({ username, password: hashed });
        await user.save();
        res.json({ success: true });
    } catch (err) {
        res.json({ success: false, message: 'Username sudah dipakai' });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.json({ success: false, message: 'Password salah' });

    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET);
    res.json({ success: true, token, username: user.username });
});

function auth(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });
    try {
        const decoded = jwt.verify(token.split(' ')[1], JWT_SECRET);
        req.user = decoded;
        next();
    } catch {
        res.status(401).json({ message: 'Token tidak valid' });
    }
}

app.get('/chat', auth, async (req, res) => {
    const chats = await Chat.find({ userId: req.user.id }).sort({ createdAt: 1 });
    res.json(chats);
});

app.post('/chat', auth, async (req, res) => {
    const { message, response } = req.body;
    const chat = new Chat({
        userId: req.user.id,
        message,
        response,
    });
    await chat.save();
    res.json({ success: true });
});

app.listen(PORT, () => console.log(\`Server jalan di http://localhost:\${PORT}\`));
EOF

echo "Install dependencies backend..."
npm install

echo "Setup systemd service $SERVICE_NAME"
cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=ChatGPT Clone Node.js Server
After=network.target mongodb.service

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
ExecStart=/usr/bin/node $APP_DIR/server.js
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

echo "Setup frontend di $FRONTEND_DIR"
mkdir -p $FRONTEND_DIR

cat > $FRONTEND_DIR/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>ChatGPT Clone</title>
    <style>
        #chat-box {
            border: 1px solid #ccc; padding: 10px; height: 300px; overflow-y: auto; white-space: pre-wrap;
        }
    </style>
</head>
<body>
    <div id="auth">
        <h3>Login / Register</h3>
        <input id="username" placeholder="Username"><br/>
        <input id="password" type="password" placeholder="Password"><br/>
        <button onclick="login()">Login</button>
        <button onclick="register()">Register</button>
        <p id="msg" style="color:red"></p>
    </div>

    <div id="chat" style="display:none;">
        <h3>Chat dengan GPT</h3>
        <div id="chat-box"></div><br/>
        <textarea id="input" rows="3" cols="50" placeholder="Tulis pesan..."></textarea><br/>
        <button onclick="sendChat()">Kirim</button>
        <button onclick="logout()">Logout</button>
    </div>

    <script src="https://js.puter.com/v2/"></script>
    <script>
        let token = '';
        let username = '';

        function showMessage(msg, isError = false) {
            const p = document.getElementById('msg');
            p.style.color = isError ? 'red' : 'green';
            p.textContent = msg;
        }

        function register() {
            const user = document.getElementById('username').value.trim();
            const pass = document.getElementById('password').value.trim();
            if (!user || !pass) return showMessage('Username dan password harus diisi', true);

            fetch('/register', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username: user, password: pass})
            }).then(res => res.json())
            .then(data => {
                if(data.success){
                    showMessage('Registrasi berhasil, silakan login');
                } else {
                    showMessage(data.message || 'Registrasi gagal', true);
                }
            });
        }

        function login() {
            const user = document.getElementById('username').value.trim();
            const pass = document.getElementById('password').value.trim();
            if (!user || !pass) return showMessage('Username dan password harus diisi', true);

            fetch('/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username: user, password: pass})
            }).then(res => res.json())
            .then(data => {
                if (data.success) {
                    token = data.token;
                    username = data.username;
                    showMessage('');
                    document.getElementById('auth').style.display = 'none';
                    document.getElementById('chat').style.display = 'block';
                    loadChat();
                } else {
                    showMessage(data.message || 'Login gagal', true);
                }
            });
        }

        function logout() {
            token = '';
            username = '';
            document.getElementById('chat').style.display = 'none';
            document.getElementById('auth').style.display = 'block';
            document.getElementById('chat-box').innerHTML = '';
            document.getElementById('input').value = '';
            showMessage('');
        }

        function loadChat() {
            fetch('/chat', {
                headers: { 'Authorization': 'Bearer ' + token }
            })
            .then(res => res.json())
            .then(chats => {
                const chatBox = document.getElementById('chat-box');
                chatBox.innerHTML = '';
                chats.forEach(c => {
                    chatBox.innerHTML += `<b>Anda:</b> ${c.message}\n<b>GPT:</b> ${c.response}\n\n`;
                });
                chatBox.scrollTop = chatBox.scrollHeight;
            });
        }

        function sendChat() {
            const input = document.getElementById('input');
            const msg = input.value.trim();
            if (!msg) return;
            input.value = '';
            appendMessage('Anda', msg);

            // Panggil API puter.ai chat
            puter.ai.chat(msg).then(response => {
                appendMessage('GPT', response);
                // Simpan chat ke backend
                fetch('/chat', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + token
                    },
                    body: JSON.stringify({ message: msg, response })
                });
            });
        }

        function appendMessage(sender, text) {
            const chatBox = document.getElementById('chat-box');
            chatBox.innerHTML += `<b>${sender}:</b> ${text}\n\n`;
            chatBox.scrollTop = chatBox.scrollHeight;
        }
    </script>
</body>
</html>
EOF

echo "Konfigurasi Nginx untuk proxy ke localhost:$PORT"
cat > /etc/nginx/sites-available/chatgpt << EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root $FRONTEND_DIR;
    index index.html;

    location / {
        try_files \$uri /index.html;
    }

    location /register {
        proxy_pass http://localhost:$PORT/register;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }

    location /login {
        proxy_pass http://localhost:$PORT/login;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }

    location /chat {
        proxy_pass http://localhost:$PORT/chat;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

ln -sf /etc/nginx/sites-available/chatgpt /etc/nginx/sites-enabled/
nginx -t
systemctl reload nginx

echo "Setup selesai. Akses aplikasi di http://<IP_VPS>"
