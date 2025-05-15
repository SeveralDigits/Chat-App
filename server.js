const express = require('express');
const http = require('http');
const fs = require('fs');
const WebSocket = require('ws');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const chatLogPath = path.join(__dirname, 'chatlogs.txt');
let clients = [];

function broadcast(msg, exclude = null) {
  const data = JSON.stringify(msg);
  clients.forEach(c => {
    if (c.ws !== exclude && c.ws.readyState === WebSocket.OPEN) {
      c.ws.send(data);
    }
  });
}

function updateUserList() {
  const list = clients.map(c => ({ username: c.username, color: c.color }));
  broadcast({ type: 'userlist', users: list });
}

function saveMessage(line) {
  fs.appendFile(chatLogPath, line + '\n', () => {});
}

function loadChatLog() {
  if (fs.existsSync(chatLogPath)) {
    return fs.readFileSync(chatLogPath, 'utf-8').trim().split('\n');
  }
  return [];
}

wss.on('connection', ws => {
  let currentUser = { ws, username: 'Unknown', color: '#000000' };
  clients.push(currentUser);

  // Send chat log to user
  const history = loadChatLog();
  history.forEach(line => ws.send(JSON.stringify({ type: 'system', message: line })));

  ws.on('message', data => {
    try {
      const msg = JSON.parse(data);
      if (msg.type === 'login') {
        currentUser.username = msg.username;
        currentUser.color = msg.color || '#000000';
        broadcast({ type: 'system', message: `${msg.username} joined.` });
        updateUserList();
      } else if (msg.type === 'colorchange') {
        currentUser.color = msg.color;
        updateUserList();
      } else if (msg.type === 'message') {
        const line = `${currentUser.username}: ${msg.message}`;
        broadcast({ type: 'message', username: currentUser.username, message: msg.message, color: currentUser.color });
        saveMessage(line);
      } else if (msg.type === 'pm') {
        const toUser = clients.find(u => u.username === msg.to);
        if (toUser) {
          const pmText = `[PM from ${currentUser.username}]: ${msg.message}`;
          toUser.ws.send(JSON.stringify({ type: 'message', username: currentUser.username, message: `[PM] ${msg.message}`, color: currentUser.color }));
          ws.send(JSON.stringify({ type: 'message', username: currentUser.username, message: `[PM to ${msg.to}] ${msg.message}`, color: currentUser.color }));
        } else {
          ws.send(JSON.stringify({ type: 'system', message: `User ${msg.to} not found.` }));
        }
      } else if (msg.type === 'clear') {
        fs.writeFileSync(chatLogPath, '');
        broadcast({ type: 'system', message: 'Chat log was cleared.' });
      }
    } catch (err) {
      console.error('Invalid message:', data);
    }
  });

  ws.on('close', () => {
    clients = clients.filter(c => c.ws !== ws);
    broadcast({ type: 'system', message: `${currentUser.username} left.` });
    updateUserList();
  });
});

app.use(express.static('public'));

server.listen(3000, () => {
  console.log('Server running at http://localhost:3000');
});
