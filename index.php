<?php
/**
 * PHP Chatroom — single-file version
 * -----------------------------------------
 * Drop this file on your PHP-enabled server (PHP 8+ recommended).
 * Fill in the MySQL credentials below. On first load it will create the
 * necessary tables automatically (utf8mb4 for full emoji support).
 *
 * Features
 * - Clean, modern UI (responsive)
 * - Emoji picker (basic set, easily extendable)
 * - Stores user name + email and chat messages in MySQL
 * - Uses UTF-8/utf8mb4 everywhere so emojis just work
 * - Simple CSRF protection for message posts
 * - Efficient fetching with incremental updates (since_id)
 * - Minimal dependencies (no external libs/CDNs)
 */

// ---------- CONFIGURE YOUR DATABASE HERE ----------
$DB_HOST = 'localhost';
$DB_NAME = 'your_database_name';
$DB_USER = 'your_username';
$DB_PASS = 'your_password';
$DB_PORT = 3306; // change if needed
// --------------------------------------------------

// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: no-referrer-when-downgrade');

// Start session for CSRF + lightweight rate limiting
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

// Lazy PDO connection
function db(): PDO {
    static $pdo = null;
    global $DB_HOST, $DB_NAME, $DB_USER, $DB_PASS, $DB_PORT;
    if ($pdo === null) {
        $dsn = "mysql:host={$DB_HOST};port={$DB_PORT};dbname={$DB_NAME};charset=utf8mb4";
        $pdo = new PDO($dsn, $DB_USER, $DB_PASS, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
        ]);
    }
    return $pdo;
}

function ensureSchema(): void {
    $pdo = db();
    // Users
    $pdo->exec(<<<SQL
        CREATE TABLE IF NOT EXISTS users (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(50) NOT NULL,
            email VARCHAR(255) NOT NULL UNIQUE,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX (email)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
    SQL);

    // Messages
    $pdo->exec(<<<SQL
        CREATE TABLE IF NOT EXISTS messages (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            user_id INT UNSIGNED NOT NULL,
            content TEXT NOT NULL,
            ip VARCHAR(45) NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX (created_at),
            INDEX (user_id),
            CONSTRAINT fk_messages_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
    SQL);
}

function jsonResponse($data, int $status = 200): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function validateEmail(string $email): bool {
    return (bool) filter_var($email, FILTER_VALIDATE_EMAIL);
}

function getClientIp(): string {
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

// Create CSRF token if missing
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

// Rate limit: at most 1 message / 1.0 seconds per session
function allowedToPost(): bool {
    $now = microtime(true);
    $last = $_SESSION['last_post_ts'] ?? 0.0;
    if (($now - $last) < 1.0) { return false; }
    $_SESSION['last_post_ts'] = $now;
    return true;
}

// Routing for API actions
$action = $_GET['action'] ?? null;
if ($action) {
    try {
        ensureSchema();
        switch ($action) {
            case 'init':
                jsonResponse(['ok' => true]);
                break;

            case 'send':
                if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
                    jsonResponse(['error' => 'POST required'], 405);
                }
                $payload = $_POST;
                if (($payload['csrf'] ?? '') !== ($_SESSION['csrf'] ?? '')) {
                    jsonResponse(['error' => 'Invalid CSRF token'], 403);
                }
                if (!allowedToPost()) {
                    jsonResponse(['error' => 'You are sending messages too quickly. Please slow down.'], 429);
                }
                $name = trim((string)($payload['name'] ?? ''));
                $email = trim((string)($payload['email'] ?? ''));
                $content = trim((string)($payload['content'] ?? ''));

                if ($name === '' || mb_strlen($name) > 50) {
                    jsonResponse(['error' => 'Name is required (max 50 chars).'], 422);
                }
                if (!validateEmail($email) || mb_strlen($email) > 255) {
                    jsonResponse(['error' => 'A valid email is required.'], 422);
                }
                if ($content === '' || mb_strlen($content) > 1000) {
                    jsonResponse(['error' => 'Message is required (max 1000 chars).'], 422);
                }

                $pdo = db();
                $pdo->beginTransaction();
                try {
                    // Upsert user by email
                    $stmt = $pdo->prepare('SELECT id, name FROM users WHERE email = ? LIMIT 1');
                    $stmt->execute([$email]);
                    $user = $stmt->fetch();
                    if ($user) {
                        // Optionally update name if changed
                        if ($user['name'] !== $name) {
                            $upd = $pdo->prepare('UPDATE users SET name = ? WHERE id = ?');
                            $upd->execute([$name, $user['id']]);
                        }
                        $userId = (int)$user['id'];
                    } else {
                        $ins = $pdo->prepare('INSERT INTO users (name, email) VALUES (?, ?)');
                        $ins->execute([$name, $email]);
                        $userId = (int)$pdo->lastInsertId();
                    }

                    $insMsg = $pdo->prepare('INSERT INTO messages (user_id, content, ip) VALUES (?, ?, ?)');
                    $insMsg->execute([$userId, $content, getClientIp()]);
                    $msgId = (int)$pdo->lastInsertId();
                    $pdo->commit();
                } catch (Throwable $e) {
                    $pdo->rollBack();
                    throw $e;
                }

                jsonResponse(['ok' => true, 'id' => $msgId]);
                break;

            case 'fetch':
                $sinceId = max(0, (int)($_GET['since_id'] ?? 0));
                $limit = (int)($_GET['limit'] ?? 100);
                if ($limit < 1 || $limit > 200) { $limit = 100; }

                $pdo = db();
                if ($sinceId > 0) {
                    $stmt = $pdo->prepare('SELECT m.id, m.content, m.created_at, u.name FROM messages m JOIN users u ON m.user_id = u.id WHERE m.id > ? ORDER BY m.id ASC LIMIT ?');
                    $stmt->execute([$sinceId, $limit]);
                } else {
                    // On first load, return only the most recent 100 messages
                    $stmt = $pdo->prepare('SELECT m.id, m.content, m.created_at, u.name FROM messages m JOIN users u ON m.user_id = u.id ORDER BY m.id DESC LIMIT ?');
                    $stmt->execute([$limit]);
                }
                $rows = $stmt->fetchAll();
                if ($sinceId === 0) {
                    // Reverse to chronological order if we fetched DESC
                    $rows = array_reverse($rows);
                }
                // Sanitize output
                $messages = array_map(function($r) {
                    return [
                        'id' => (int)$r['id'],
                        'name' => $r['name'],
                        'content' => $r['content'],
                        'created_at' => $r['created_at'],
                    ];
                }, $rows);
                jsonResponse(['ok' => true, 'messages' => $messages]);
                break;

            default:
                jsonResponse(['error' => 'Unknown action'], 400);
        }
    } catch (Throwable $e) {
        jsonResponse(['error' => 'Server error: ' . $e->getMessage()], 500);
    }
}

// ---------- If no action is specified, render the UI ----------
ensureSchema();
$csrf = $_SESSION['csrf'] ?? '';
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Chatroom</title>
  <style>
    :root {
      --bg: #0f172a;
      --panel: #111827;
      --panel-2: #0b1220;
      --text: #e5e7eb;
      --muted: #9ca3af;
      --accent: #4f46e5;
      --accent-2: #22d3ee;
      --danger: #ef4444;
      --ok: #10b981;
      --border: #1f2937;
    }
    * { box-sizing: border-box; }
    html, body { height: 100%; }
    body { margin: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji"; background: linear-gradient(180deg, var(--bg), #030712); color: var(--text); }

    .wrap { max-width: 900px; margin: 0 auto; padding: 16px; display: grid; gap: 14px; height: 100%; grid-template-rows: auto 1fr auto; }
    .header { display: flex; align-items: center; justify-content: space-between; padding: 12px 14px; border: 1px solid var(--border); border-radius: 16px; background: linear-gradient(180deg, var(--panel), var(--panel-2)); box-shadow: 0 8px 30px rgba(0,0,0,.3); }
    .brand { display: flex; gap: 10px; align-items: center; font-weight: 700; letter-spacing: .3px; }
    .brand .logo { width: 28px; height: 28px; border-radius: 8px; background: linear-gradient(135deg, var(--accent), var(--accent-2)); box-shadow: 0 2px 12px rgba(79,70,229,.5); }
    .status { font-size: 12px; color: var(--muted); }

    .messages { border: 1px solid var(--border); border-radius: 16px; background: rgba(17,24,39,.6); padding: 12px; overflow: auto; min-height: 300px; max-height: calc(100dvh - 280px); }
    .msg { display: grid; grid-template-columns: auto 1fr; gap: 8px 12px; padding: 10px 12px; border-bottom: 1px dashed rgba(255,255,255,.06); }
    .msg:last-child { border-bottom: none; }
    .avatar { width: 36px; height: 36px; border-radius: 10px; background: linear-gradient(135deg, #334155, #111827); display: grid; place-items: center; font-weight: 700; color: #cbd5e1; }
    .bubble { background: #0b1220; border: 1px solid var(--border); border-radius: 12px; padding: 10px 12px; box-shadow: inset 0 1px 0 rgba(255,255,255,.02); }
    .meta { display: flex; gap: 8px; align-items: baseline; margin-bottom: 6px; }
    .name { font-weight: 700; }
    .time { color: var(--muted); font-size: 12px; }
    .text { line-height: 1.5; white-space: pre-wrap; word-wrap: break-word; }

    .composer { display: grid; gap: 10px; border: 1px solid var(--border); border-radius: 16px; background: linear-gradient(180deg, var(--panel), var(--panel-2)); padding: 12px; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    label { font-size: 12px; color: var(--muted); display: block; margin-bottom: 6px; }
    input[type="text"], input[type="email"], textarea { width: 100%; background: #0b1220; border: 1px solid var(--border); color: var(--text); border-radius: 12px; padding: 10px 12px; outline: none; }
    input::placeholder, textarea::placeholder { color: #6b7280; }
    textarea { resize: vertical; min-height: 70px; }

    .actions { display: flex; gap: 8px; align-items: center; justify-content: space-between; }
    .left-actions { display: flex; gap: 8px; align-items: center; }
    .btn { cursor: pointer; border: 1px solid var(--border); background: #0b1220; color: var(--text); padding: 10px 14px; border-radius: 12px; font-weight: 600; transition: transform .05s ease; }
    .btn:hover { transform: translateY(-1px); }
    .btn.primary { background: linear-gradient(135deg, var(--accent), var(--accent-2)); border: none; }
    .btn.emoji { font-size: 20px; padding: 8px 10px; }

    .emoji-panel { position: absolute; bottom: 70px; left: 12px; right: 12px; max-width: 620px; background: #0b1220; border: 1px solid var(--border); border-radius: 16px; padding: 8px; box-shadow: 0 16px 40px rgba(0,0,0,.4); display: none; }
    .emoji-grid { display: grid; grid-template-columns: repeat(12, 1fr); gap: 6px; max-height: 220px; overflow: auto; }
    .emoji { cursor: pointer; padding: 6px; font-size: 20px; border-radius: 8px; text-align: center; }
    .emoji:hover { background: #111827; }

    .toast { position: fixed; bottom: 16px; right: 16px; background: #0b1220; border: 1px solid var(--border); color: var(--text); padding: 12px 14px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,.45); display: none; }

    @media (max-width: 700px) {
      .row { grid-template-columns: 1fr; }
      .emoji-grid { grid-template-columns: repeat(8, 1fr); }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <header class="header">
      <div class="brand">
        <div class="logo" aria-hidden="true"></div>
        <div>Modern PHP Chatroom</div>
      </div>
      <div class="status" id="status">Connecting…</div>
    </header>

    <main class="messages" id="messages" aria-live="polite"></main>

    <section class="composer">
      <div class="row">
        <div>
          <label for="name">Name</label>
          <input id="name" type="text" placeholder="Your name" maxlength="50" />
        </div>
        <div>
          <label for="email">Email address</label>
          <input id="email" type="email" placeholder="you@example.com" maxlength="255" />
        </div>
      </div>
      <div>
        <label for="message">Message</label>
        <textarea id="message" placeholder="Type something nice… 😊" maxlength="1000"></textarea>
      </div>
      <div class="actions" style="position: relative;">
        <div class="left-actions">
          <button class="btn emoji" id="emojiBtn" title="Insert emoji">😊</button>
          <div class="emoji-panel" id="emojiPanel" role="dialog" aria-label="Emoji picker">
            <div class="emoji-grid" id="emojiGrid"></div>
          </div>
        </div>
        <button class="btn primary" id="sendBtn">Send</button>
      </div>
    </section>
  </div>

  <div class="toast" id="toast" role="status"></div>

  <noscript style="color: white;">This chat needs JavaScript enabled.</noscript>

  <script>
    const csrf = <?php echo json_encode($csrf, JSON_UNESCAPED_UNICODE); ?>;
    const messagesEl = document.getElementById('messages');
    const statusEl = document.getElementById('status');
    const toastEl = document.getElementById('toast');
    const nameEl = document.getElementById('name');
    const emailEl = document.getElementById('email');
    const msgEl = document.getElementById('message');
    const sendBtn = document.getElementById('sendBtn');
    const emojiBtn = document.getElementById('emojiBtn');
    const emojiPanel = document.getElementById('emojiPanel');
    const emojiGrid = document.getElementById('emojiGrid');

    // Persist identity locally
    nameEl.value = localStorage.getItem('chat_name') || '';
    emailEl.value = localStorage.getItem('chat_email') || '';

    function showToast(text) {
      toastEl.textContent = text;
      toastEl.style.display = 'block';
      setTimeout(() => toastEl.style.display = 'none', 2600);
    }

    function escapeHtml(s) {
      return s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'}[c]));
    }

    function initials(name) {
      return (name || '?').trim().split(/\s+/).slice(0,2).map(p=>p[0]?.toUpperCase()||'').join('') || '?';
    }

    function formatTime(iso) {
      try {
        const d = new Date(iso.replace(' ', 'T') + 'Z');
        return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(d);
      } catch { return iso; }
    }

    function renderMessage(m) {
      const div = document.createElement('div');
      div.className = 'msg';
      div.innerHTML = `
        <div class="avatar" title="${escapeHtml(m.name)}">${escapeHtml(initials(m.name))}</div>
        <div class="bubble">
          <div class="meta"><span class="name">${escapeHtml(m.name)}</span><span class="time">${formatTime(m.created_at)}</span></div>
          <div class="text">${escapeHtml(m.content)}</div>
        </div>`;
      return div;
    }

    let sinceId = 0;
    let isFetching = false;

    async function api(path, opts = {}) {
      const res = await fetch(path, { headers: { 'Accept': 'application/json' }, ...opts });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    }

    async function init() {
      try {
        statusEl.textContent = 'Connecting…';
        await api('?action=init');
        statusEl.textContent = 'Connected';
        await fetchMessages();
        startPolling();
      } catch (e) {
        statusEl.textContent = 'Error connecting';
        showToast('Cannot connect to server. Check PHP/MySQL configuration.');
        console.error(e);
      }
    }

    async function fetchMessages() {
      if (isFetching) return; isFetching = true;
      try {
        const data = await api(`?action=fetch&since_id=${sinceId}`);
        if (data.ok) {
          const msgs = data.messages || [];
          for (const m of msgs) {
            messagesEl.appendChild(renderMessage(m));
            sinceId = Math.max(sinceId, m.id);
          }
          if (msgs.length) messagesEl.scrollTop = messagesEl.scrollHeight;
        }
      } catch (e) {
        console.error(e);
      } finally {
        isFetching = false;
      }
    }

    let pollTimer = null;
    function startPolling() {
      if (pollTimer) clearInterval(pollTimer);
      pollTimer = setInterval(fetchMessages, 1500);
    }

    async function sendMessage() {
      const name = nameEl.value.trim();
      const email = emailEl.value.trim();
      const content = msgEl.value.trim();

      if (!name) { showToast('Please enter your name.'); nameEl.focus(); return; }
      if (!email) { showToast('Please enter your email.'); emailEl.focus(); return; }
      if (!content) { showToast('Message cannot be empty.'); msgEl.focus(); return; }

      const form = new FormData();
      form.set('csrf', csrf);
      form.set('name', name);
      form.set('email', email);
      form.set('content', content);

      try {
        sendBtn.disabled = true;
        const data = await api('?action=send', { method: 'POST', body: form });
        if (data.ok) {
          localStorage.setItem('chat_name', name);
          localStorage.setItem('chat_email', email);
          msgEl.value = '';
          await fetchMessages();
        } else {
          showToast(data.error || 'Failed to send.');
        }
      } catch (e) {
        showToast('Failed to send message.');
        console.error(e);
      } finally {
        sendBtn.disabled = false;
      }
    }

    sendBtn.addEventListener('click', sendMessage);
    msgEl.addEventListener('keydown', (e) => {
      if ((e.key === 'Enter' || e.keyCode === 13) && (e.ctrlKey || e.metaKey)) {
        e.preventDefault(); sendMessage();
      }
    });

    // Emoji picker
    const EMOJIS = (
      '😀 😃 😄 😁 😆 😅 😂 🤣 😊 😇 🙂 🙃 😉 😌 😍 🥰 😘 😗 😙 😚 😋 😛 😝 😜 🤪 🤨 🧐 🤓 😎 🥸 🤩 🥳 😏 😒 😞 😔 😟 😕 🙁 ☹️ 😣 😖 😫 😩 🥺 😢 😭 😤 😠 😡 🤬 🤯 😳 🥶 🥵 🥴 😵 🤐 🤥 😶 😐 😑 😬 🙄 🤔 🤗 🤭 🤫 🤤 😴 🥱 🤒 🤕 🤧 🤮 🤢 🤠 👋 🤝 👍 👎 ✌️ 🤞 🤟 🤘 👌 🤌 👏 🙌 👐 🤲 🤜 🤛 💪 🙏 💯 🔥 ✨ 💥 🎉 🎊 💫 ❤️ 🧡 💛 💚 💙 💜 🖤 🤍 🤎 💔 ❣️ ❤️‍🔥 ❤️‍🩹 😊'
    ).split(/\s+/);

    function buildEmojiGrid() {
      emojiGrid.innerHTML = '';
      for (const e of EMOJIS) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'emoji';
        btn.textContent = e;
        btn.addEventListener('click', () => {
          const start = msgEl.selectionStart || msgEl.value.length;
          const end = msgEl.selectionEnd || msgEl.value.length;
          msgEl.value = msgEl.value.slice(0, start) + e + msgEl.value.slice(end);
          msgEl.focus();
          const pos = start + e.length;
          msgEl.setSelectionRange(pos, pos);
        });
        emojiGrid.appendChild(btn);
      }
    }

    emojiBtn.addEventListener('click', () => {
      const isOpen = emojiPanel.style.display === 'block';
      emojiPanel.style.display = isOpen ? 'none' : 'block';
      if (!isOpen) buildEmojiGrid();
    });

    document.addEventListener('click', (e) => {
      if (!emojiPanel.contains(e.target) && e.target !== emojiBtn) {
        emojiPanel.style.display = 'none';
      }
    });

    // Kick off
    init();
  </script>
<footer>www.perplex.click</footer>
</body>
</html>
