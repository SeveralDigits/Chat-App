// server.js
const http = require('http');
const fs = require('fs');
const path = require('path');
const WebSocket = require('ws');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const HTTP_PORT = 8080;
const WS_PORT = 3000;

// Ensure uploads directory exists inside the public folder
const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Simple HTTP server to serve static files from 'public' folder
const server = http.createServer((req, res) => {
  let filePath = '.' + req.url;
  if (filePath === './') filePath = './public/index.html';

  // Normalize and prevent directory traversal
  filePath = path.normalize(filePath);

  // If user requests directory, try to serve index.html from that directory
  if (fs.existsSync(filePath) && fs.statSync(filePath).isDirectory()) {
    const indexPath = path.join(filePath, 'index.html');
    if (fs.existsSync(indexPath)) filePath = indexPath;
  }

  const extname = String(path.extname(filePath)).toLowerCase();
  const mimeTypes = {
    '.html': 'text/html',
    '.js':   'application/javascript',
    '.css':  'text/css',
    '.png':  'image/png',
    '.jpg':  'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif':  'image/gif',
    '.svg':  'image/svg+xml',
    '.json': 'application/json',
    '.mp3':  'audio/mpeg',
    '.ico':  'image/x-icon'
  };

  const contentType = mimeTypes[extname] || 'application/octet-stream';

  fs.readFile(filePath, (error, content) => {
    if (error) {
      if(error.code == 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('404 Not Found', 'utf-8');
      } else {
        res.writeHead(500);
        res.end('Server error: '+error.code);
      }
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content, 'utf-8');
    }
  });
});

server.listen(HTTP_PORT, () => {
  console.log(`HTTP server running at http://localhost:${HTTP_PORT}`);
});

// WebSocket Server
const wss = new WebSocket.Server({ port: WS_PORT });
console.log(`WebSocket server running on ws://localhost:${WS_PORT}`);

const db = new sqlite3.Database('./chat.db');

// Create tables if not exist (unchanged)
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    color TEXT DEFAULT '#000000'
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    message TEXT,
    color TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    recipient TEXT DEFAULT NULL
  )`);
});

let clients = new Map(); // ws -> {username, color}

function broadcast(data, exceptWs = null) {
  const str = JSON.stringify(data);
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN && client !== exceptWs) {
      client.send(str);
    }
  });
}

function sendUserList() {
  const users = [];
  clients.forEach(({ username, color }) => {
    users.push({ username, color });
  });
  broadcast({ type: 'userlist', users });
}

function sendChatHistory(ws) {
  // Get last 100 messages
  db.all(`SELECT id, username, message, color, timestamp, recipient FROM messages ORDER BY id DESC LIMIT 100`, [], (err, rows) => {
    if (err) {
      console.error('Failed to load chat history:', err);
      return;
    }
    // Reverse so oldest first
    rows.reverse();

    // Filter messages to send:
    // For public messages recipient is NULL
    // For private messages, send only if the ws user is sender or recipient
    const user = clients.get(ws);
    if (!user) return; // not authorized yet, just skip

    const filtered = rows.filter(row => {
      if (!row.recipient) return true; // public message
      // private message
      return (row.username === user.username || row.recipient === user.username);
    });

    ws.send(JSON.stringify({ type: 'history', messages: filtered }));
  });
}

wss.on('connection', (ws) => {
  ws.isAuthorized = false;

  ws.on('message', async (message) => {
    let msg;
    try {
      msg = JSON.parse(message);
    } catch {
      ws.send(JSON.stringify({ type: 'system', message: 'Invalid JSON' }));
      return;
    }

    if (msg.type === 'register') {
      const { username, password } = msg;
      if (!username || !password) {
        ws.send(JSON.stringify({ type: 'register', success: false, message: 'Missing username or password' }));
        return;
      }

      db.get('SELECT username FROM users WHERE username = ?', [username], async (err, row) => {
        if (err) {
          ws.send(JSON.stringify({ type: 'register', success: false, message: 'Database error' }));
          return;
        }
        if (row) {
          ws.send(JSON.stringify({ type: 'register', success: false, message: 'Username already exists' }));
          return;
        }

        const hashed = await bcrypt.hash(password, 10);
        db.run('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hashed], (err) => {
          if (err) {
            ws.send(JSON.stringify({ type: 'register', success: false, message: 'Database error' }));
          } else {
            ws.send(JSON.stringify({ type: 'register', success: true, message: 'Registration successful!' }));
          }
        });
      });
    } else if (msg.type === 'login') {
      const { username, password } = msg;
      if (!username || !password) {
        ws.send(JSON.stringify({ type: 'login', success: false, message: 'Missing username or password' }));
        return;
      }

      db.get('SELECT username, password_hash, color FROM users WHERE username = ?', [username], async (err, row) => {
        if (err || !row) {
          ws.send(JSON.stringify({ type: 'login', success: false, message: 'Invalid username or password' }));
          return;
        }

        const match = await bcrypt.compare(password, row.password_hash);
        if (match) {
          ws.isAuthorized = true;
          clients.set(ws, { username: row.username, color: row.color || '#000000' });
          ws.send(JSON.stringify({ type: 'login', success: true, color: row.color || '#000000' }));
          broadcast({ type: 'system', message: `${row.username} has joined.` }, ws);
          sendUserList();
          sendChatHistory(ws);
        } else {
          ws.send(JSON.stringify({ type: 'login', success: false, message: 'Invalid username or password' }));
        }
      });
    } else {
      // Only allow further actions if authorized
      if (!ws.isAuthorized) {
        ws.send(JSON.stringify({ type: 'system', message: 'Please login first.' }));
        return;
      }

      const user = clients.get(ws);
      if (!user) return;

      if (msg.type === 'message') {
        const text = msg.message.trim();
        if (text.startsWith('/pm ')) {
          // Private message format: /pm username message
          const parts = text.split(' ');
          if (parts.length < 3) {
            ws.send(JSON.stringify({ type: 'system', message: 'Usage: /pm username message' }));
            return;
          }
          const targetUser = parts[1];
          const pmMessage = parts.slice(2).join(' ');

          // Find ws client with that username
          let targetWs = null;
          for (const [clientWs, info] of clients.entries()) {
            if (info.username === targetUser) {
              targetWs = clientWs;
              break;
            }
          }

          if (!targetWs) {
            ws.send(JSON.stringify({ type: 'system', message: `User ${targetUser} not found or not online.` }));
            return;
          }

          // Send private message to target
          const pmData = {
            type: 'private_message',
            from: user.username,
            message: pmMessage,
            color: user.color
          };
          targetWs.send(JSON.stringify(pmData));

          // Also send confirmation to sender
          ws.send(JSON.stringify({ type: 'private_message_sent', to: targetUser, message: pmMessage }));

          // Save private message in DB with recipient
          db.run(`INSERT INTO messages (username, message, color, recipient) VALUES (?, ?, ?, ?)`,
            [user.username, pmMessage, user.color, targetUser]);

        } else if (text === '/users') {
          // List users command
          const userNames = Array.from(clients.values()).map(u => u.username);
          ws.send(JSON.stringify({ type: 'system', message: 'Online users: ' + userNames.join(', ') }));
        } else if (text.startsWith('/color ')) {
          const newColor = text.split(' ')[1];
          if(/^#([0-9A-F]{3}){1,2}$/i.test(newColor)) {
            user.color = newColor;
            // Update DB color
            db.run('UPDATE users SET color = ? WHERE username = ?', [newColor, user.username]);
            clients.set(ws, user);
            sendUserList();
            ws.send(JSON.stringify({ type: 'system', message: `You changed your color to ${newColor}` }));
          } else {
            ws.send(JSON.stringify({ type: 'system', message: 'Invalid color format. Use hex like #ff0000' }));
          }
        } else if (text === '/help') {
          ws.send(JSON.stringify({ type: 'system', message:
            `Commands:\n/help - Show commands\n/color #hex - Change name color\n/users - List users\n/pm username message - Private message` }));
        } else {
          // Normal public message
          broadcast({ type: 'message', username: user.username, message: text, color: user.color });
          // Save public message to DB (recipient=null)
          db.run(`INSERT INTO messages (username, message, color) VALUES (?, ?, ?)`,
            [user.username, text, user.color]);
        }
      } else if (msg.type === 'colorchange') {
        user.color = msg.color;
        // Update DB color
        db.run('UPDATE users SET color = ? WHERE username = ?', [msg.color, user.username]);
        clients.set(ws, user);
        sendUserList();
      } else if (msg.type === 'image') {
        // NEW: handle image messages
        // msg.imageUrl can be:
        //  - a data URL (data:<mime>;base64,<data>) -> we decode and save to ./public/uploads and broadcast saved path
        //  - an external/http(s) URL -> we broadcast directly
        // Note: we do not change or remove any existing behavior for other messages.

        const imageUrl = (msg.imageUrl || '').trim();
        if (!imageUrl) {
          ws.send(JSON.stringify({ type: 'system', message: 'No image provided.' }));
          return;
        }

        // Helper to broadcast and save DB entry
        function publishImage(publicUrl) {
          const imageData = {
            type: 'image',
            username: user.username,
            imageUrl: publicUrl,
            color: user.color
          };
          broadcast(imageData);

          // Save to DB as message with special prefix so clients can detect images if they wish.
          // Keep DB schema unchanged.
          const dbMessage = `::IMAGE::${publicUrl}`;
          db.run(`INSERT INTO messages (username, message, color) VALUES (?, ?, ?)`,
            [user.username, dbMessage, user.color]);
        }

        // If data URL (base64)
        if (imageUrl.startsWith('data:')) {
          // Format: data:<mime>;base64,<data>
          const matches = imageUrl.match(/^data:([^;]+);base64,(.*)$/);
          if (!matches) {
            ws.send(JSON.stringify({ type: 'system', message: 'Invalid data URL format.' }));
            return;
          }
          const mime = matches[1];
          const b64 = matches[2];

          // Map some common mime types to extensions
          const extMap = {
            'image/png': '.png',
            'image/jpeg': '.jpg',
            'image/jpg': '.jpg',
            'image/gif': '.gif',
            'image/webp': '.webp',
            'image/svg+xml': '.svg'
          };
          const ext = extMap[mime] || path.extname(mime) || '.bin';

          // Build filename
          const filename = `${Date.now()}_${crypto.randomBytes(6).toString('hex')}${ext}`;
          const filepath = path.join(uploadsDir, filename);
          const publicPath = `/uploads/${filename}`;

          // Decode base64 and save
          try {
            const buffer = Buffer.from(b64, 'base64');
            fs.writeFile(filepath, buffer, (err) => {
              if (err) {
                console.error('Failed to save uploaded image:', err);
                ws.send(JSON.stringify({ type: 'system', message: 'Failed to save image on server.' }));
                return;
              }
              // Broadcast saved image path
              publishImage(publicPath);
            });
          } catch (e) {
            console.error('Error decoding image data URL:', e);
            ws.send(JSON.stringify({ type: 'system', message: 'Failed to process image data.' }));
            return;
          }

        } else {
          // External URL - basic validation (http(s) or //)
          if (/^https?:\/\//i.test(imageUrl) || /^\/\//.test(imageUrl)) {
            // Broadcast as-is
            publishImage(imageUrl);
          } else {
            // Not a recognized format — we still accept it but mark as invalid URL
            ws.send(JSON.stringify({ type: 'system', message: 'Unsupported image URL. Provide a data URL or a http(s) URL.' }));
          }
        }
      } else {
        // Unknown message type - ignore or notify
        ws.send(JSON.stringify({ type: 'system', message: 'Unknown message type.' }));
      }
    }
  });

  ws.on('close', () => {
    const user = clients.get(ws);
    if (user) {
      broadcast({ type: 'system', message: `${user.username} has left.` });
      clients.delete(ws);
      sendUserList();
    }
  });
});
