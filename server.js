const WebSocket = require('ws');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const wss = new WebSocket.Server({ port: 3000 });

const db = new sqlite3.Database('./chat.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    color TEXT DEFAULT '#000000'
  )`);
});

let clients = new Map(); // ws -> {username, color}

function broadcast(data) {
  const str = JSON.stringify(data);
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
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
          broadcast({ type: 'system', message: `${row.username} has joined.` });
          sendUserList();
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

      if (msg.type === 'message') {
        const user = clients.get(ws);
        if (!user) return;
        broadcast({ type: 'message', username: user.username, message: msg.message, color: user.color });
      } else if (msg.type === 'colorchange') {
        const user = clients.get(ws);
        if (!user) return;
        user.color = msg.color;
        // Update DB color
        db.run('UPDATE users SET color = ? WHERE username = ?', [msg.color, user.username]);
        clients.set(ws, user);
        sendUserList();
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

console.log('Server running on ws://localhost:3000');
