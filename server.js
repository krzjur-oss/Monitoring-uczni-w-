#!/usr/bin/env node
/**
 * Monitor Klasy — Bezpieczny Serwer WebSocket
 * Zabezpieczenia:
 *  1. Hasło nauczyciela (env: TEACHER_PASSWORD)
 *  2. Kod sesji — uczniowie dołączają tylko z aktywnym kodem
 *  3. WSS szyfrowanie (zapewniane przez Railway/Render automatycznie)
 *  4. Sesje jednorazowe — kod wygasa po zakończeniu lekcji
 *  5. Rate limiting — blokada po 5 błędnych próbach
 */

const WebSocket = require('ws');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = parseInt(process.env.PORT) || 8765;
const TEACHER_PASSWORD = process.env.TEACHER_PASSWORD || 'zmien-to-haslo';
const MAX_FAILED = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

const teachers = new Map();     // token -> { ws, ip }
const students = new Map();     // id -> { ws, name, student, locked, sessionCode }
const sessions = new Map();     // code -> { createdAt, active }
const failedAttempts = new Map(); // ip -> { count, lockedUntil }

const httpServer = http.createServer((req, res) => {
  const routes = { '/': 'teacher.html', '/teacher': 'teacher.html', '/student': 'student.html' };
  const file = routes[req.url];
  if (file) {
    const fp = path.join(__dirname, file);
    if (fs.existsSync(fp)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(fs.readFileSync(fp));
    }
  }
  res.writeHead(404); res.end('Not found');
});

function log(msg, lvl = 'INFO') {
  const icons = { INFO: '📘', WARN: '⚠️', AUTH: '🔐', ERR: '❌' };
  console.log(`[${new Date().toLocaleTimeString('pl-PL')}] ${icons[lvl] || ''} ${msg}`);
}
function token() { return crypto.randomBytes(32).toString('hex'); }
function sessionCode() {
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let s = '';
  for (let i = 0; i < 7; i++) { if (i === 3) s += '-'; s += c[crypto.randomInt(c.length)]; }
  return s;
}
function isLocked(ip) {
  const d = failedAttempts.get(ip);
  if (!d) return false;
  if (d.lockedUntil && Date.now() < d.lockedUntil) return true;
  failedAttempts.delete(ip); return false;
}
function failAttempt(ip) {
  const d = failedAttempts.get(ip) || { count: 0 };
  d.count++;
  if (d.count >= MAX_FAILED) { d.lockedUntil = Date.now() + LOCKOUT_MS; log(`Blokada IP ${ip} na 15 min`, 'WARN'); }
  failedAttempts.set(ip, d);
}
function sendTo(ws, obj) { if (ws?.readyState === 1) ws.send(JSON.stringify(obj)); }
function broadcast(obj) { const d = JSON.stringify(obj); teachers.forEach(t => { if (t.ws?.readyState === 1) t.ws.send(d); }); }
function deviceList() { return [...students.values()].map(s => ({ id: s.id, name: s.name, student: s.student, locked: s.locked })); }
function activeSessions() { return [...sessions.entries()].filter(([, s]) => s.active).map(([code, s]) => ({ code, createdAt: s.createdAt })); }

const wss = new WebSocket.Server({ server: httpServer });

wss.on('connection', (ws, req) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  let role = null, authToken = null, studentId = null;

  const authTimeout = setTimeout(() => { if (!role) ws.close(1008, 'Auth timeout'); }, 10000);

  ws.on('message', raw => {
    let msg; try { msg = JSON.parse(raw); } catch { return; }

    // ── LOGOWANIE NAUCZYCIELA ────────────────────────────────────────────────
    if (msg.type === 'teacher_login') {
      if (isLocked(ip)) return sendTo(ws, { type: 'auth_error', reason: 'Zbyt wiele błędnych prób. Zaczekaj 15 minut.' });
      if (msg.password !== TEACHER_PASSWORD) {
        failAttempt(ip);
        log(`Błędne hasło z ${ip}`, 'AUTH');
        return sendTo(ws, { type: 'auth_error', reason: 'Nieprawidłowe hasło.' });
      }
      failedAttempts.delete(ip);
      authToken = token(); role = 'teacher';
      clearTimeout(authTimeout);
      teachers.set(authToken, { ws, ip });
      log(`Nauczyciel zalogowany z ${ip}`, 'AUTH');
      return sendTo(ws, { type: 'teacher_ok', token: authToken, devices: deviceList(), sessions: activeSessions() });
    }

    // ── RECONNECT NAUCZYCIELA ────────────────────────────────────────────────
    if (msg.type === 'teacher_hello') {
      if (!msg.token || !teachers.has(msg.token)) return sendTo(ws, { type: 'auth_required' });
      authToken = msg.token; role = 'teacher';
      clearTimeout(authTimeout);
      teachers.set(authToken, { ws, ip });
      return sendTo(ws, { type: 'teacher_ok', token: authToken, devices: deviceList(), sessions: activeSessions() });
    }

    // ── DOŁĄCZANIE UCZNIA ────────────────────────────────────────────────────
    if (msg.type === 'student_hello') {
      const sess = sessions.get(msg.sessionCode);
      if (!sess?.active) {
        log(`Zły kod sesji "${msg.sessionCode}" z ${ip}`, 'AUTH');
        return sendTo(ws, { type: 'auth_error', reason: 'Nieprawidłowy kod sesji. Zapytaj nauczyciela o aktualny kod.' });
      }
      role = 'student'; studentId = 'dev_' + crypto.randomBytes(6).toString('hex');
      clearTimeout(authTimeout);
      students.set(studentId, { id: studentId, ws, name: msg.name || 'Urządzenie', student: msg.student || 'Nieznany', locked: false, sessionCode: msg.sessionCode });
      log(`Uczeń: ${msg.student} (${msg.name}) sesja:${msg.sessionCode}`, 'AUTH');
      sendTo(ws, { type: 'student_ok', id: studentId });
      broadcast({ type: 'device_joined', id: studentId, name: msg.name, student: msg.student });
      return;
    }

    // ── POLECENIA NAUCZYCIELA (wymagają roli) ────────────────────────────────
    if (role === 'teacher') {
      if (msg.type === 'create_session') {
        const code = sessionCode();
        sessions.set(code, { createdAt: Date.now(), active: true });
        log(`Nowa sesja: ${code}`, 'INFO');
        return sendTo(ws, { type: 'session_created', code, createdAt: Date.now() });
      }
      if (msg.type === 'end_session') {
        const sess = sessions.get(msg.code);
        if (sess) {
          sess.active = false;
          students.forEach(s => {
            if (s.sessionCode === msg.code) {
              sendTo(s.ws, { type: 'session_ended', reason: 'Nauczyciel zakończył lekcję.' });
              setTimeout(() => s.ws.close(1000), 3000);
            }
          });
          log(`Sesja zakończona: ${msg.code}`, 'INFO');
          broadcast({ type: 'session_ended', code: msg.code });
        }
        return;
      }
      if (msg.type === 'lock') {
        const s = students.get(msg.id);
        if (s) {
          s.locked = msg.locked;
          sendTo(s.ws, { type: 'lock', locked: msg.locked, reason: msg.reason || '' });
          broadcast({ type: 'lock_ack', id: msg.id, locked: msg.locked });
          log(`${msg.locked ? 'Zablokowano' : 'Odblokowano'}: ${s.student}`, 'INFO');
        }
        return;
      }
      if (msg.type === 'get_screen') {
        const s = students.get(msg.id);
        if (s) sendTo(s.ws, { type: 'get_screen' });
        return;
      }
      if (msg.type === 'message') {
        if (msg.id) { const s = students.get(msg.id); if (s) sendTo(s.ws, { type: 'message', text: msg.text }); }
        else students.forEach(s => sendTo(s.ws, { type: 'message', text: msg.text }));
        log(`Wiadomość: "${msg.text}"`, 'INFO');
        return;
      }
    }

    // ── DANE OD UCZNIA ───────────────────────────────────────────────────────
    if (role === 'student' && msg.type === 'screen_data') {
      broadcast({ type: 'screen_data', id: studentId, data: msg.data });
    }
  });

  ws.on('close', () => {
    clearTimeout(authTimeout);
    if (role === 'teacher' && authToken) { teachers.delete(authToken); log(`Nauczyciel rozłączony (${ip})`, 'INFO'); }
    if (role === 'student' && studentId) {
      const s = students.get(studentId);
      if (s) { log(`Uczeń rozłączył się: ${s.student}`, 'INFO'); broadcast({ type: 'device_left', id: studentId }); students.delete(studentId); }
    }
  });
  ws.on('error', e => log('WS error: ' + e.message, 'ERR'));
});

httpServer.listen(PORT, '0.0.0.0', () => {
  console.log('\n╔═══════════════════════════════════════════════════════════╗');
  console.log('║      Monitor Klasy — Serwer BEZPIECZNY uruchomiony       ║');
  console.log('╠═══════════════════════════════════════════════════════════╣');
  console.log(`║  Panel nauczyciela : http://localhost:${PORT}/teacher         ║`);
  console.log(`║  Strona ucznia     : http://localhost:${PORT}/student         ║`);
  console.log(`║  Hasło (domyślne)  : ${TEACHER_PASSWORD.substring(0,33).padEnd(33)}  ║`);
  console.log('╠═══════════════════════════════════════════════════════════╣');
  console.log('║  ⚠️  Ustaw env TEACHER_PASSWORD przed wdrożeniem!         ║');
  console.log('╚═══════════════════════════════════════════════════════════╝\n');
});
