#!/bin/bash
set -euo pipefail

# UPJET SSH Panel - Final fixed full installer
# Features:
# - Web panel for SSH users
# - 30-day/default expiry, editable per user
# - Traffic quota in GB, editable per user
# - Stored SSH password display for users created/updated by this panel
# - Manual/random password change
# - Lock/unlock, reset usage, kick session, delete user
# - One simultaneous login per SSH user
# - Fixes SSH password login automatically: PasswordAuthentication/KbdInteractive/UsePAM
# - Quota monitor via cron + iptables owner counters

if [ "${EUID}" -ne 0 ]; then
    echo "Run as root: sudo bash install_upjet_ssh_panel_final_fixed.sh"
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

SUPPLIED_PANEL_ADMIN_USER="${PANEL_ADMIN_USER+x}"
SUPPLIED_PANEL_PASSWORD="${PANEL_PASSWORD+x}"
SUPPLIED_PANEL_HOST="${PANEL_HOST+x}"
SUPPLIED_PANEL_PORT="${PANEL_PORT+x}"
SUPPLIED_PANEL_SECRET="${PANEL_SECRET+x}"
SUPPLIED_DEFAULT_DAYS="${DEFAULT_DAYS+x}"
SUPPLIED_DEFAULT_QUOTA_GB="${DEFAULT_QUOTA_GB+x}"
SUPPLIED_SSH_PUBLIC_HOST="${SSH_PUBLIC_HOST+x}"
SUPPLIED_SSH_PORT="${SSH_PORT+x}"

PANEL_ADMIN_USER="${PANEL_ADMIN_USER:-admin}"
PANEL_PASSWORD="${PANEL_PASSWORD:-}"
PANEL_HOST="${PANEL_HOST:-0.0.0.0}"
PANEL_PORT="${PANEL_PORT:-9080}"
PANEL_SECRET="${PANEL_SECRET:-}"
DEFAULT_DAYS="${DEFAULT_DAYS:-30}"
DEFAULT_QUOTA_GB="${DEFAULT_QUOTA_GB:-100}"
SSH_PUBLIC_HOST="${SSH_PUBLIC_HOST:-}"
SSH_PORT="${SSH_PORT:-22}"

apt update
apt install -y python3-flask python3-qrcode python3-pil iptables openssl bc passwd procps curl openssh-server adduser

mkdir -p /opt/upjet-ssh-panel /var/lib/upjet-ssh-panel
chmod 700 /var/lib/upjet-ssh-panel

# One-login-per-user group
getent group sshclients >/dev/null || groupadd sshclients
if ! grep -q '^@sshclients hard maxlogins 1' /etc/security/limits.conf; then
    echo '@sshclients hard maxlogins 1' >> /etc/security/limits.conf
fi

# SSH/PAM settings:
# - password SSH login must work for panel-created users
# - PAM limits must work for one-login-per-user
# - MaxSessions limits multiple shell sessions inside one SSH connection
# - existing AllowUsers/Deny rules that block new dynamic users are neutralized
configure_sshd_for_panel() {
    mkdir -p /etc/ssh/sshd_config.d
    cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.upjet.$(date +%F-%H%M%S)" 2>/dev/null || true

    cat > /etc/ssh/sshd_config.d/99-upjet-ssh-panel.conf <<'EOFSSH'
PasswordAuthentication yes
KbdInteractiveAuthentication yes
UsePAM yes
PermitEmptyPasswords no
MaxSessions 1
EOFSSH

    if [ -f /etc/ssh/sshd_config ]; then
        sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config || true
        sed -i 's/^#\?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config || true
        sed -i 's/^#\?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config || true
        sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config || true
        sed -i 's/^#\?MaxSessions.*/MaxSessions 1/' /etc/ssh/sshd_config || true

        grep -q '^PasswordAuthentication' /etc/ssh/sshd_config || echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
        grep -q '^KbdInteractiveAuthentication' /etc/ssh/sshd_config || echo 'KbdInteractiveAuthentication yes' >> /etc/ssh/sshd_config
        grep -q '^UsePAM' /etc/ssh/sshd_config || echo 'UsePAM yes' >> /etc/ssh/sshd_config
        grep -q '^PermitEmptyPasswords' /etc/ssh/sshd_config || echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config
        grep -q '^MaxSessions' /etc/ssh/sshd_config || echo 'MaxSessions 1' >> /etc/ssh/sshd_config
    fi

    # If a previous hard restriction exists, future panel users may be blocked.
    # Backups are above; comment AllowUsers and Deny* rules, and ensure AllowGroups includes sshclients.
    for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        [ -f "$f" ] || continue
        sed -i -E 's/^[[:space:]]*(AllowUsers)[[:space:]]+/# UPJET disabled to allow dynamic panel users: &/' "$f" || true
        sed -i -E 's/^[[:space:]]*(DenyUsers|DenyGroups)[[:space:]]+/# UPJET disabled to avoid blocking panel users: &/' "$f" || true
        sed -i -E '/^[[:space:]]*AllowGroups[[:space:]]/ { /(^|[[:space:]])sshclients([[:space:]]|$)/! s/$/ sshclients/ }' "$f" || true
    done

    # Ensure pam_limits is applied by sshd; otherwise @sshclients maxlogins may not work.
    if [ -f /etc/pam.d/sshd ] && ! grep -q 'pam_limits.so' /etc/pam.d/sshd; then
        echo 'session required pam_limits.so' >> /etc/pam.d/sshd
    fi

    if command -v sshd >/dev/null 2>&1; then
        sshd -t
    elif [ -x /usr/sbin/sshd ]; then
        /usr/sbin/sshd -t
    fi

    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
}
configure_sshd_for_panel

cat > /opt/upjet-ssh-panel/app.py <<'PY'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re
import secrets
import subprocess
import datetime
import io
from urllib.parse import quote
from pathlib import Path
from functools import wraps
from flask import Flask, request, redirect, url_for, session, flash, render_template_string, abort, Response

BASE_DIR = Path('/var/lib/upjet-ssh-panel')
BASE_DIR.mkdir(parents=True, exist_ok=True)

USERNAME_RE = re.compile(r'^[a-z_][a-z0-9_-]{2,30}$')
PROTECTED_USERS = {
    'root', 'admin', 'ubuntu', 'debian', 'nobody', 'www-data', 'sshd',
    'systemd-network', 'systemd-resolve', 'messagebus', 'polkitd'
}

PANEL_ADMIN_USER = os.environ.get('PANEL_ADMIN_USER', 'admin')
PANEL_PASSWORD = os.environ.get('PANEL_PASSWORD', '')
PANEL_HOST = os.environ.get('PANEL_HOST', '127.0.0.1')
PANEL_PORT = int(os.environ.get('PANEL_PORT', '9080'))
DEFAULT_DAYS = int(os.environ.get('DEFAULT_DAYS', '30'))
DEFAULT_QUOTA_GB = int(os.environ.get('DEFAULT_QUOTA_GB', '100'))
SSH_PUBLIC_HOST = os.environ.get('SSH_PUBLIC_HOST', '').strip()
SSH_PORT = int(os.environ.get('SSH_PORT', '22'))

# UPJET_QR_FEATURE

try:
    import qrcode
    import qrcode.image.svg
except Exception:
    qrcode = None

app = Flask(__name__)
app.secret_key = os.environ.get('PANEL_SECRET', secrets.token_hex(32))


def run_cmd(args, input_text=None, check=True):
    return subprocess.run(args, input=input_text, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)


def cmd_ok(args):
    return subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def read_text(path, default=''):
    try:
        return Path(path).read_text(encoding='utf-8').strip()
    except Exception:
        return default


def write_text(path, value):
    p = Path(path)
    p.write_text(str(value), encoding='utf-8')
    os.chmod(p, 0o600)


def valid_username(username):
    return bool(USERNAME_RE.fullmatch(username or '')) and username not in PROTECTED_USERS


def user_exists(username):
    return cmd_ok(['id', username])


def ensure_quota_chain():
    run_cmd(['iptables', '-N', 'UPJETQUOTA'], check=False)
    if not cmd_ok(['iptables', '-C', 'OUTPUT', '-j', 'UPJETQUOTA']):
        run_cmd(['iptables', '-I', 'OUTPUT', '1', '-j', 'UPJETQUOTA'], check=False)


def add_quota_rule(username):
    if not user_exists(username):
        return
    ensure_quota_chain()
    uid = run_cmd(['id', '-u', username]).stdout.strip()
    if not cmd_ok(['iptables', '-C', 'UPJETQUOTA', '-m', 'owner', '--uid-owner', uid, '-j', 'RETURN']):
        run_cmd(['iptables', '-A', 'UPJETQUOTA', '-m', 'owner', '--uid-owner', uid, '-j', 'RETURN'], check=False)


def remove_quota_rule(username):
    if not user_exists(username):
        return
    uid = run_cmd(['id', '-u', username], check=False).stdout.strip()
    if not uid:
        return
    while cmd_ok(['iptables', '-C', 'UPJETQUOTA', '-m', 'owner', '--uid-owner', uid, '-j', 'RETURN']):
        run_cmd(['iptables', '-D', 'UPJETQUOTA', '-m', 'owner', '--uid-owner', uid, '-j', 'RETURN'], check=False)


def get_counter_bytes(username):
    if not user_exists(username):
        return 0
    uid = run_cmd(['id', '-u', username]).stdout.strip()
    out = run_cmd(['iptables', '-nvxL', 'UPJETQUOTA'], check=False).stdout
    for line in out.splitlines():
        if f'owner UID match {uid}' in line:
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1])
    return 0


def csrf_token():
    if '_csrf' not in session:
        session['_csrf'] = secrets.token_urlsafe(32)
    return session['_csrf']


app.jinja_env.globals['csrf_token'] = csrf_token


def check_csrf():
    if request.form.get('_csrf') != session.get('_csrf'):
        abort(400)


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get('auth'):
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return wrapper


def gb_to_bytes(gb):
    return int(gb) * 1024 * 1024 * 1024


def fmt_gb(value):
    try:
        return f'{int(value) / 1024 / 1024 / 1024:.2f}'
    except Exception:
        return '0.00'


def get_expiry(username):
    if not user_exists(username):
        return 'deleted'
    out = run_cmd(['chage', '-l', username], check=False).stdout
    for line in out.splitlines():
        if 'Account expires' in line:
            return line.split(':', 1)[1].strip()
    return 'unknown'


def is_online(username):
    if not user_exists(username):
        return False
    return subprocess.run(['pgrep', '-u', username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def safe_int(value, default, min_value, max_value):
    try:
        value = int(value)
        return max(min_value, min(max_value, value))
    except Exception:
        return default


def get_saved_password(username):
    password = read_text(BASE_DIR / f'{username}.password', '')
    return password if password else 'ذخیره نشده'


def set_user_password(username, password):
    run_cmd(['chpasswd'], input_text=f'{username}:{password}\n')
    write_text(BASE_DIR / f'{username}.password', password)


def get_connection_host():
    configured = (SSH_PUBLIC_HOST or '').strip()
    if configured:
        return configured.split('/')[0].split(':')[0]
    forwarded = request.headers.get('X-Forwarded-Host', '').strip()
    host = forwarded or request.host or ''
    return host.split(':')[0]


def build_ssh_command(username):
    return f'ssh -p {SSH_PORT} {username}@{get_connection_host()}'


def build_ssh_uri(username):
    password = read_text(BASE_DIR / f'{username}.password', '')
    if not password:
        return ''
    return f'ssh://{quote(username, safe="")}:{quote(password, safe="")}@{get_connection_host()}:{SSH_PORT}'


def list_panel_users():
    ensure_quota_chain()
    users = []
    for quota_file in sorted(BASE_DIR.glob('*.quota')):
        username = quota_file.stem
        if not valid_username(username):
            continue
        quota = int(read_text(quota_file, '0') or 0)
        total = int(read_text(BASE_DIR / f'{username}.total', '0') or 0)
        status = read_text(BASE_DIR / f'{username}.status', 'active')
        percent = min(100, round((total / quota) * 100, 1)) if quota else 0
        users.append({
            'username': username,
            'quota_gb': fmt_gb(quota),
            'used_gb': fmt_gb(total),
            'percent': percent,
            'status': status,
            'expiry': get_expiry(username),
            'exists': user_exists(username),
            'online': is_online(username),
            'password': get_saved_password(username),
            'ssh_command': build_ssh_command(username),
            'ssh_link': build_ssh_uri(username),
        })
    return users


BASE_HTML = """
<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }}</title>
<style>
:root{--bg:#07111f;--card:#0d1b2f;--card2:#101f35;--line:#263a56;--text:#edf4ff;--muted:#9fb1c9;--blue:#2f8cff;--cyan:#25d7ff;--green:#00b894;--red:#ff4d5e;--orange:#ffb020;--dark:#081426}
*{box-sizing:border-box}body{margin:0;min-height:100vh;font-family:Tahoma,Arial,sans-serif;background:radial-gradient(circle at top left,#123965 0,#07111f 36%,#050914 100%);color:var(--text)}
a{color:inherit}.wrap{max-width:1240px;margin:0 auto;padding:24px}.glass{background:linear-gradient(145deg,rgba(255,255,255,.08),rgba(255,255,255,.025));border:1px solid rgba(255,255,255,.1);box-shadow:0 22px 70px rgba(0,0,0,.35);backdrop-filter:blur(12px);border-radius:24px}
.top{padding:22px;display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:18px}.brand{display:flex;align-items:center;gap:14px}.logo{width:56px;height:56px;border-radius:18px;background:linear-gradient(135deg,var(--blue),var(--cyan));display:grid;place-items:center;font-weight:900;font-size:22px;color:#fff;box-shadow:0 0 35px rgba(47,140,255,.45)}.brand h1{margin:0;font-size:34px;letter-spacing:2px}.brand p{margin:4px 0 0;color:var(--muted)}
.btn{border:0;border-radius:14px;padding:11px 16px;background:linear-gradient(135deg,var(--blue),var(--cyan));color:#fff;font-weight:800;cursor:pointer;box-shadow:0 10px 25px rgba(47,140,255,.22);text-decoration:none;display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:42px}.btn:hover{filter:brightness(1.08)}.btn.secondary{background:#172842;color:var(--text);box-shadow:none;border:1px solid var(--line)}.btn.warn{background:linear-gradient(135deg,#d97706,var(--orange))}.btn.danger{background:linear-gradient(135deg,#dc2626,var(--red))}.btn.ok{background:linear-gradient(135deg,#059669,var(--green))}
input,select{width:100%;border:1px solid var(--line);background:#091629;color:var(--text);border-radius:14px;padding:12px 14px;outline:none;min-height:42px}input:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(47,140,255,.15)}::placeholder{color:#71839e}.msg{padding:13px 16px;border-radius:15px;margin-bottom:12px;background:rgba(47,140,255,.16);border:1px solid rgba(47,140,255,.28);line-height:1.8}.msg.err{background:rgba(255,77,94,.13);border-color:rgba(255,77,94,.32)}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:18px}.stat{padding:18px}.stat .num{font-size:30px;font-weight:900}.stat .label{color:var(--muted);margin-top:4px}.card{padding:20px;margin-bottom:18px}.card h2,.card h3{margin:0 0 14px}.create-grid{display:grid;grid-template-columns:1.4fr .7fr .7fr 1fr;gap:12px}.small{font-size:12px;color:var(--muted);line-height:1.9}.hint{margin-top:10px}.users{display:grid;grid-template-columns:1fr;gap:14px}.user-card{padding:18px;border-radius:22px;background:rgba(7,17,31,.58);border:1px solid var(--line)}.user-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;margin-bottom:14px}.username{font-size:23px;font-weight:900;direction:ltr;text-align:left}.badges{display:flex;gap:8px;flex-wrap:wrap}.badge{display:inline-flex;align-items:center;gap:6px;padding:7px 11px;border-radius:999px;font-size:12px;font-weight:900}.active{background:rgba(0,184,148,.18);color:#8ff5de}.locked{background:rgba(255,77,94,.16);color:#ff9aa4}.online{background:rgba(47,140,255,.18);color:#a8d0ff}.offline{background:rgba(255,255,255,.08);color:#b8c7db}.deleted{background:rgba(255,77,94,.16);color:#ff9aa4}.meta{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:14px}.m{padding:12px;border:1px solid var(--line);border-radius:16px;background:rgba(255,255,255,.035)}.m .k{color:var(--muted);font-size:12px;margin-bottom:6px}.m .v{font-weight:900;word-break:break-word}.password-box{direction:ltr;text-align:left;font-family:Consolas,monospace;background:#07101e;border:1px dashed #385577;border-radius:14px;padding:10px;min-height:42px;display:flex;align-items:center;overflow:auto}.progress{height:12px;background:#081222;border:1px solid var(--line);border-radius:999px;overflow:hidden;margin-top:8px}.bar{height:100%;background:linear-gradient(90deg,var(--blue),var(--cyan));border-radius:999px}.edit-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:12px}.actions{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-top:12px}.actions form,.edit-grid form{display:contents}.field label{display:block;color:var(--muted);font-size:12px;margin-bottom:6px}.login-page{display:grid;place-items:center;min-height:100vh;padding:20px}.login-box{width:100%;max-width:430px;padding:30px}.login-box .logo{margin:0 auto 14px;width:70px;height:70px}.login-box h1{text-align:center;margin:0;font-size:38px;letter-spacing:3px}.login-box p{text-align:center;color:var(--muted);margin:8px 0 22px}.login-box input,.login-box button{margin-top:10px}.login-box button{width:100%}.footer-note{color:var(--muted);font-size:12px;margin-top:14px;line-height:1.9}
@media(max-width:1000px){.meta{grid-template-columns:repeat(2,1fr)}.edit-grid{grid-template-columns:repeat(2,1fr)}.actions{grid-template-columns:repeat(2,1fr)}.create-grid{grid-template-columns:1fr 1fr}.wrap{padding:14px}.top{display:block}.brand h1{font-size:28px}}
@media(max-width:560px){.stats,.meta,.edit-grid,.actions,.create-grid{grid-template-columns:1fr}.user-head{display:block}.btn{width:100%}}
.share-grid{display:grid;grid-template-columns:1.4fr 1.4fr 140px;gap:10px;margin-top:12px;align-items:stretch}.link-box{direction:ltr;text-align:left;font-family:Consolas,monospace;background:#07101e;border:1px solid var(--line);border-radius:14px;padding:10px;min-height:42px;overflow:auto;white-space:nowrap}.qr-box{display:grid;place-items:center;background:#fff;border-radius:16px;padding:8px;min-height:132px}.qr-box img{width:118px;height:118px}.copy-row{display:grid;grid-template-columns:1fr auto;gap:8px}.copy-row .btn{min-width:84px}.share-title{color:var(--muted);font-size:12px;margin-bottom:6px}@media(max-width:900px){.share-grid{grid-template-columns:1fr}.copy-row{grid-template-columns:1fr}.qr-box img{width:160px;height:160px}}
</style>
</head>
<body>
{{ body|safe }}

<script>
function upjetCopy(id){
  var el=document.getElementById(id);
  if(!el){return false;}
  var text=(el.innerText||el.value||'').trim();
  if(!text){return false;}
  if(navigator.clipboard && window.isSecureContext){navigator.clipboard.writeText(text);}
  else{var t=document.createElement('textarea');t.value=text;document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);}
  return false;
}
</script>
</body></html>
"""

LOGIN_BODY = """
<div class="login-page">
  <div class="login-box glass">
    <div class="logo">UJ</div>
    <h1>UPJET</h1>
    <p>ورود امن به پنل مدیریت کاربران SSH</p>
    {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}{% for cat,m in messages %}<div class="msg {% if cat=='error' %}err{% endif %}">{{m}}</div>{% endfor %}{% endif %}
    {% endwith %}
    <form method="post">
      <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
      <input name="username" placeholder="نام کاربری پنل" autocomplete="username" autofocus required>
      <input name="password" type="password" placeholder="رمز عبور پنل" autocomplete="current-password" required>
      <button class="btn" type="submit">ورود به UPJET</button>
    </form>
    <div class="footer-note">برای امنیت بهتر، پنل را پشت فایروال یا فقط با SSH Tunnel استفاده کن.</div>
  </div>
</div>
"""

INDEX_BODY = """
<div class="wrap">
  <div class="top glass">
    <div class="brand">
      <div class="logo">UJ</div>
      <div>
        <h1>UPJET</h1>
        <p>SSH User Manager · محدودیت حجم، زمان، پسورد و اتصال همزمان</p>
      </div>
    </div>
    <form method="post" action="{{ url_for('logout') }}">
      <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
      <button class="btn secondary" type="submit">خروج</button>
    </form>
  </div>

  {% with messages = get_flashed_messages(with_categories=true) %}
  {% if messages %}{% for cat,m in messages %}<div class="msg {% if cat=='error' %}err{% endif %}">{{m}}</div>{% endfor %}{% endif %}
  {% endwith %}

  <div class="stats">
    <div class="stat glass"><div class="num">{{ stats.total }}</div><div class="label">کل کاربران</div></div>
    <div class="stat glass"><div class="num">{{ stats.active }}</div><div class="label">فعال</div></div>
    <div class="stat glass"><div class="num">{{ stats.locked }}</div><div class="label">قفل شده</div></div>
  </div>

  <div class="card glass">
    <h3>ساخت کاربر جدید</h3>
    <form method="post" action="{{ url_for('create_user') }}">
      <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
      <div class="create-grid">
        <input name="username" placeholder="نام کاربری مثل user1" required>
        <input name="days" type="number" min="1" max="3650" value="{{ default_days }}" placeholder="اعتبار - روز">
        <input name="quota_gb" type="number" min="1" max="100000" value="{{ default_quota_gb }}" placeholder="حجم - گیگ">
        <button class="btn" type="submit">ساخت کاربر</button>
      </div>
      <div class="small hint">پسورد جدید خودکار ساخته و ذخیره می‌شود. هر کاربر جدید عضو گروه sshclients می‌شود؛ یعنی یک اتصال همزمان مجاز دارد.</div>
    </form>
  </div>

  <div class="card glass">
    <h3>لیست کاربران</h3>
    <div class="users">
    {% for u in users %}
      <div class="user-card">
        <div class="user-head">
          <div>
            <div class="username">{{u.username}}</div>
            <div class="small">انقضا: {{u.expiry}}</div>
          </div>
          <div class="badges">
            <span class="badge {{u.status}}">{{u.status}}</span>
            {% if u.online %}<span class="badge online">online</span>{% else %}<span class="badge offline">offline</span>{% endif %}
            {% if not u.exists %}<span class="badge deleted">deleted</span>{% endif %}
          </div>
        </div>

        <div class="meta">
          <div class="m"><div class="k">مصرف</div><div class="v">{{u.used_gb}} GB</div></div>
          <div class="m"><div class="k">حجم</div><div class="v">{{u.quota_gb}} GB</div></div>
          <div class="m"><div class="k">درصد مصرف</div><div class="v">{{u.percent}}%</div><div class="progress"><div class="bar" style="width:{{u.percent}}%"></div></div></div>
          <div class="m"><div class="k">وضعیت اتصال</div><div class="v">{% if u.online %}وصل است{% else %}قطع است{% endif %}</div></div>
          <div class="m"><div class="k">پسورد ذخیره‌شده</div><div class="password-box">{{u.password}}</div><div class="small">پسوردهای قبل از نصب این نسخه قابل بازیابی نیستند.</div></div>
        </div>

        {% if u.ssh_link %}
        <div class="share-grid">
          <div>
            <div class="share-title">دستور اتصال SSH</div>
            <div class="copy-row">
              <div class="link-box" id="cmd-{{ loop.index }}">{{ u.ssh_command }}</div>
              <button class="btn secondary" type="button" onclick="return upjetCopy('cmd-{{ loop.index }}')">کپی</button>
            </div>
          </div>
          <div>
            <div class="share-title">لینک اتصال SSH</div>
            <div class="copy-row">
              <div class="link-box" id="link-{{ loop.index }}">{{ u.ssh_link }}</div>
              <button class="btn secondary" type="button" onclick="return upjetCopy('link-{{ loop.index }}')">کپی</button>
            </div>
          </div>
          <div>
            <div class="share-title">QR Code</div>
            <div class="qr-box"><img src="{{ url_for('qr_svg', username=u.username) }}" alt="QR {{u.username}}"></div>
          </div>
        </div>
        {% else %}
        <div class="msg err">برای ساخت لینک و QR، باید پسورد این کاربر داخل پنل ذخیره شده باشد. برای کاربران قدیمی، یک پسورد جدید تنظیم کن.</div>
        {% endif %}

        {% if u.exists %}
        <form method="post" action="{{ url_for('edit_user', username=u.username) }}">
          <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
          <div class="edit-grid">
            <div class="field"><label>حجم جدید - گیگ</label><input name="quota_gb" type="number" min="1" max="100000" placeholder="مثلاً 100"></div>
            <div class="field"><label>اعتبار جدید - روز از امروز</label><input name="days" type="number" min="1" max="3650" placeholder="مثلاً 30"></div>
            <div class="field"><label>پسورد جدید</label><input name="password" placeholder="خالی بماند تغییر نمی‌کند"></div>
            <div class="field"><label>&nbsp;</label><button class="btn" type="submit">ذخیره تغییرات</button></div>
          </div>
        </form>

        <div class="actions">
          <form method="post" action="{{ url_for('random_password', username=u.username) }}"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><button class="btn secondary" type="submit">پسورد تصادفی</button></form>
          <form method="post" action="{{ url_for('lock_user', username=u.username) }}"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><button class="btn warn" type="submit">قفل</button></form>
          <form method="post" action="{{ url_for('unlock_user', username=u.username) }}"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><button class="btn ok" type="submit">فعال ۳۰ روز</button></form>
          <form method="post" action="{{ url_for('reset_quota', username=u.username) }}"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><button class="btn secondary" type="submit">ریست حجم</button></form>
          <form method="post" action="{{ url_for('kick_user', username=u.username) }}"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><button class="btn secondary" type="submit">قطع اتصال</button></form>
          <form method="post" action="{{ url_for('delete_user', username=u.username) }}" onsubmit="return confirm('کاربر کامل حذف شود؟')"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><button class="btn danger" type="submit">حذف</button></form>
        </div>
        {% endif %}
      </div>
    {% else %}
      <div class="user-card">هنوز کاربری ساخته نشده است.</div>
    {% endfor %}
    </div>
  </div>
</div>
"""


def render_page(body_template, **context):
    body = render_template_string(body_template, **context)
    return render_template_string(BASE_HTML, body=body, **context)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        check_csrf()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        ok_user = secrets.compare_digest(username, PANEL_ADMIN_USER)
        ok_pass = secrets.compare_digest(password, PANEL_PASSWORD) if PANEL_PASSWORD else False
        if ok_user and ok_pass:
            session['auth'] = True
            session['admin'] = username
            return redirect(url_for('index'))
        flash('نام کاربری یا رمز عبور اشتباه است.', 'error')
    return render_page(LOGIN_BODY, title='UPJET Login')


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    check_csrf()
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    users = list_panel_users()
    stats = {
        'total': len(users),
        'active': sum(1 for u in users if u['status'] == 'active'),
        'locked': sum(1 for u in users if u['status'] == 'locked'),
    }
    return render_page(
        INDEX_BODY,
        title='UPJET Panel',
        users=users,
        stats=stats,
        default_days=DEFAULT_DAYS,
        default_quota_gb=DEFAULT_QUOTA_GB,
    )




@app.route('/qr/<username>.svg')
@login_required
def qr_svg(username):
    if not (valid_username(username) and user_exists(username)):
        abort(404)
    link = build_ssh_uri(username)
    if not link:
        abort(404)
    if qrcode is None:
        abort(500)
    img = qrcode.make(link, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    return Response(buf.getvalue(), mimetype='image/svg+xml')

@app.route('/create', methods=['POST'])
@login_required
def create_user():
    check_csrf()
    username = request.form.get('username', '').strip()
    if not valid_username(username):
        flash('نام کاربری نامعتبر است. فقط حروف کوچک انگلیسی، عدد، _ و - مجاز است و باید حداقل ۳ کاراکتر باشد.', 'error')
        return redirect(url_for('index'))
    if user_exists(username):
        flash('این کاربر از قبل وجود دارد.', 'error')
        return redirect(url_for('index'))

    days = safe_int(request.form.get('days'), DEFAULT_DAYS, 1, 3650)
    quota_gb = safe_int(request.form.get('quota_gb'), DEFAULT_QUOTA_GB, 1, 100000)
    expire_date = (datetime.date.today() + datetime.timedelta(days=days)).isoformat()
    password = run_cmd(['openssl', 'rand', '-base64', '12']).stdout.strip()

    try:
        run_cmd(['useradd', '-m', '-s', '/bin/bash', '-e', expire_date, username])
        set_user_password(username, password)
        run_cmd(['deluser', username, 'sudo'], check=False)
        run_cmd(['usermod', '-aG', 'sshclients', username], check=False)
        write_text(BASE_DIR / f'{username}.quota', gb_to_bytes(quota_gb))
        write_text(BASE_DIR / f'{username}.total', 0)
        write_text(BASE_DIR / f'{username}.last', 0)
        write_text(BASE_DIR / f'{username}.status', 'active')
        add_quota_rule(username)
        flash(f'کاربر ساخته شد | Username: {username} | Password: {password} | Expire: {expire_date} | Quota: {quota_gb}GB')
    except subprocess.CalledProcessError as e:
        flash(f'خطا در ساخت کاربر: {e.stderr}', 'error')
    return redirect(url_for('index'))


@app.route('/edit/<username>', methods=['POST'])
@login_required
def edit_user(username):
    check_csrf()
    if not (valid_username(username) and user_exists(username)):
        flash('کاربر نامعتبر است.', 'error')
        return redirect(url_for('index'))

    quota_raw = request.form.get('quota_gb', '').strip()
    days_raw = request.form.get('days', '').strip()
    password = request.form.get('password', '').strip()

    try:
        if quota_raw:
            quota_gb = safe_int(quota_raw, DEFAULT_QUOTA_GB, 1, 100000)
            write_text(BASE_DIR / f'{username}.quota', gb_to_bytes(quota_gb))
        if days_raw:
            days = safe_int(days_raw, DEFAULT_DAYS, 1, 3650)
            expire_date = (datetime.date.today() + datetime.timedelta(days=days)).isoformat()
            run_cmd(['chage', '-E', expire_date, username], check=False)
            run_cmd(['usermod', '-U', username], check=False)
            write_text(BASE_DIR / f'{username}.status', 'active')
        if password:
            set_user_password(username, password)
        run_cmd(['usermod', '-aG', 'sshclients', username], check=False)
        add_quota_rule(username)
        flash(f'تغییرات {username} ذخیره شد.')
    except subprocess.CalledProcessError as e:
        flash(f'خطا در ویرایش کاربر: {e.stderr}', 'error')
    return redirect(url_for('index'))


@app.route('/randompass/<username>', methods=['POST'])
@login_required
def random_password(username):
    check_csrf()
    if valid_username(username) and user_exists(username):
        password = run_cmd(['openssl', 'rand', '-base64', '12']).stdout.strip()
        set_user_password(username, password)
        flash(f'پسورد جدید {username}: {password}')
    return redirect(url_for('index'))


@app.route('/lock/<username>', methods=['POST'])
@login_required
def lock_user(username):
    check_csrf()
    if valid_username(username) and user_exists(username):
        run_cmd(['usermod', '-L', username], check=False)
        run_cmd(['chage', '-E', '0', username], check=False)
        run_cmd(['pkill', '-KILL', '-u', username], check=False)
        write_text(BASE_DIR / f'{username}.status', 'locked')
        flash(f'کاربر {username} قفل شد.')
    return redirect(url_for('index'))


@app.route('/unlock/<username>', methods=['POST'])
@login_required
def unlock_user(username):
    check_csrf()
    if valid_username(username) and user_exists(username):
        expire_date = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
        run_cmd(['usermod', '-U', username], check=False)
        run_cmd(['chage', '-E', expire_date, username], check=False)
        run_cmd(['usermod', '-aG', 'sshclients', username], check=False)
        write_text(BASE_DIR / f'{username}.status', 'active')
        add_quota_rule(username)
        flash(f'کاربر {username} فعال شد و تا {expire_date} اعتبار دارد.')
    return redirect(url_for('index'))


@app.route('/reset/<username>', methods=['POST'])
@login_required
def reset_quota(username):
    check_csrf()
    if valid_username(username) and user_exists(username):
        add_quota_rule(username)
        current = get_counter_bytes(username)
        write_text(BASE_DIR / f'{username}.last', current)
        write_text(BASE_DIR / f'{username}.total', 0)
        write_text(BASE_DIR / f'{username}.status', 'active')
        flash(f'حجم مصرفی {username} ریست شد.')
    return redirect(url_for('index'))


@app.route('/kick/<username>', methods=['POST'])
@login_required
def kick_user(username):
    check_csrf()
    if valid_username(username) and user_exists(username):
        run_cmd(['pkill', '-KILL', '-u', username], check=False)
        flash(f'اتصال‌های فعال {username} قطع شد.')
    return redirect(url_for('index'))


@app.route('/delete/<username>', methods=['POST'])
@login_required
def delete_user(username):
    check_csrf()
    if valid_username(username):
        if user_exists(username):
            remove_quota_rule(username)
            run_cmd(['pkill', '-KILL', '-u', username], check=False)
            run_cmd(['userdel', '-r', username], check=False)
        for suffix in ['quota', 'total', 'last', 'status', 'password']:
            try:
                (BASE_DIR / f'{username}.{suffix}').unlink()
            except FileNotFoundError:
                pass
        flash(f'کاربر {username} حذف شد.')
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host=PANEL_HOST, port=PANEL_PORT, debug=False)
PY

cat > /opt/upjet-ssh-panel/monitor_quota.sh <<'SH'
#!/bin/bash

BASE_DIR="/var/lib/upjet-ssh-panel"
LOG_FILE="$BASE_DIR/quota.log"

mkdir -p "$BASE_DIR"
chmod 700 "$BASE_DIR"

iptables -N UPJETQUOTA 2>/dev/null || true
iptables -C OUTPUT -j UPJETQUOTA 2>/dev/null || iptables -I OUTPUT 1 -j UPJETQUOTA

get_user_bytes() {
    local UID_NUMBER="$1"
    iptables -nvxL UPJETQUOTA | awk -v uid="$UID_NUMBER" '
    $0 ~ "owner UID match " uid {
        print $2
        found=1
        exit
    }
    END {
        if (!found) print 0
    }'
}

for QUOTA_FILE in "$BASE_DIR"/*.quota; do
    [ -e "$QUOTA_FILE" ] || continue

    USERNAME=$(basename "$QUOTA_FILE" .quota)

    if ! [[ "$USERNAME" =~ ^[a-z_][a-z0-9_-]{2,30}$ ]]; then
        continue
    fi

    if ! id "$USERNAME" &>/dev/null; then
        continue
    fi

    UID_NUMBER=$(id -u "$USERNAME")

    iptables -C UPJETQUOTA -m owner --uid-owner "$UID_NUMBER" -j RETURN 2>/dev/null || \
    iptables -A UPJETQUOTA -m owner --uid-owner "$UID_NUMBER" -j RETURN

    QUOTA=$(cat "$BASE_DIR/$USERNAME.quota" 2>/dev/null || echo 0)
    TOTAL_FILE="$BASE_DIR/$USERNAME.total"
    LAST_FILE="$BASE_DIR/$USERNAME.last"
    STATUS_FILE="$BASE_DIR/$USERNAME.status"

    TOTAL=$(cat "$TOTAL_FILE" 2>/dev/null || echo 0)
    LAST=$(cat "$LAST_FILE" 2>/dev/null || echo 0)
    CURRENT=$(get_user_bytes "$UID_NUMBER")

    if [ "$CURRENT" -ge "$LAST" ]; then
        DELTA=$((CURRENT - LAST))
    else
        # Counters reset after reboot/iptables restart.
        DELTA=$CURRENT
    fi

    TOTAL=$((TOTAL + DELTA))

    echo "$CURRENT" > "$LAST_FILE"
    echo "$TOTAL" > "$TOTAL_FILE"

    if [ "$QUOTA" -gt 0 ] && [ "$TOTAL" -ge "$QUOTA" ]; then
        STATUS=$(cat "$STATUS_FILE" 2>/dev/null || echo "active")

        if [ "$STATUS" != "locked" ]; then
            usermod -L "$USERNAME" 2>/dev/null || true
            chage -E 0 "$USERNAME" 2>/dev/null || true
            pkill -KILL -u "$USERNAME" 2>/dev/null || true
            echo "locked" > "$STATUS_FILE"
            echo "$(date '+%F %T') | LOCKED | $USERNAME | Used: $TOTAL bytes | Quota: $QUOTA bytes" >> "$LOG_FILE"
        fi
    fi

done
SH

chmod +x /opt/upjet-ssh-panel/app.py /opt/upjet-ssh-panel/monitor_quota.sh

# Environment setup
if [ -z "$PANEL_PASSWORD" ]; then
    PANEL_PASSWORD="$(openssl rand -base64 18)"
fi
if [ -z "$PANEL_SECRET" ]; then
    PANEL_SECRET="$(openssl rand -hex 32)"
fi

# If existing env exists, preserve it unless caller explicitly supplied vars.
if [ -f /etc/upjet-ssh-panel.env ]; then
    CURRENT_ADMIN=$(grep '^PANEL_ADMIN_USER=' /etc/upjet-ssh-panel.env | cut -d= -f2- || true)
    CURRENT_PASS=$(grep '^PANEL_PASSWORD=' /etc/upjet-ssh-panel.env | cut -d= -f2- || true)
    CURRENT_SECRET=$(grep '^PANEL_SECRET=' /etc/upjet-ssh-panel.env | cut -d= -f2- || true)
    CURRENT_HOST=$(grep '^PANEL_HOST=' /etc/upjet-ssh-panel.env | cut -d= -f2- || true)
    CURRENT_PORT=$(grep '^PANEL_PORT=' /etc/upjet-ssh-panel.env | cut -d= -f2- || true)
    CURRENT_DAYS=$(grep '^DEFAULT_DAYS=' /etc/upjet-ssh-panel.env | cut -d= -f2- || true)
    CURRENT_QUOTA=$(grep '^DEFAULT_QUOTA_GB=' /etc/upjet-ssh-panel.env | cut -d= -f2- || true)
    CURRENT_SSH_PUBLIC_HOST=$(grep '^SSH_PUBLIC_HOST=' /etc/upjet-ssh-panel.env | cut -d= -f2- || true)
    CURRENT_SSH_PORT=$(grep '^SSH_PORT=' /etc/upjet-ssh-panel.env | cut -d= -f2- || true)

    if [ -z "$SUPPLIED_PANEL_ADMIN_USER" ] && [ -n "$CURRENT_ADMIN" ]; then PANEL_ADMIN_USER="$CURRENT_ADMIN"; fi
    if [ -z "$SUPPLIED_PANEL_PASSWORD" ] && [ -n "$CURRENT_PASS" ]; then PANEL_PASSWORD="$CURRENT_PASS"; fi
    if [ -z "$SUPPLIED_PANEL_SECRET" ] && [ -n "$CURRENT_SECRET" ]; then PANEL_SECRET="$CURRENT_SECRET"; fi
    if [ -z "$SUPPLIED_PANEL_HOST" ] && [ -n "$CURRENT_HOST" ]; then PANEL_HOST="$CURRENT_HOST"; fi
    if [ -z "$SUPPLIED_PANEL_PORT" ] && [ -n "$CURRENT_PORT" ]; then PANEL_PORT="$CURRENT_PORT"; fi
    if [ -z "$SUPPLIED_DEFAULT_DAYS" ] && [ -n "$CURRENT_DAYS" ]; then DEFAULT_DAYS="$CURRENT_DAYS"; fi
    if [ -z "$SUPPLIED_DEFAULT_QUOTA_GB" ] && [ -n "$CURRENT_QUOTA" ]; then DEFAULT_QUOTA_GB="$CURRENT_QUOTA"; fi
    if [ -z "$SUPPLIED_SSH_PUBLIC_HOST" ] && [ -n "$CURRENT_SSH_PUBLIC_HOST" ]; then SSH_PUBLIC_HOST="$CURRENT_SSH_PUBLIC_HOST"; fi
    if [ -z "$SUPPLIED_SSH_PORT" ] && [ -n "$CURRENT_SSH_PORT" ]; then SSH_PORT="$CURRENT_SSH_PORT"; fi
fi

cat > /etc/upjet-ssh-panel.env <<EOFENV
PANEL_ADMIN_USER=$PANEL_ADMIN_USER
PANEL_PASSWORD=$PANEL_PASSWORD
PANEL_SECRET=$PANEL_SECRET
PANEL_HOST=$PANEL_HOST
PANEL_PORT=$PANEL_PORT
DEFAULT_DAYS=$DEFAULT_DAYS
DEFAULT_QUOTA_GB=$DEFAULT_QUOTA_GB
SSH_PUBLIC_HOST=$SSH_PUBLIC_HOST
SSH_PORT=$SSH_PORT
EOFENV
chmod 600 /etc/upjet-ssh-panel.env

cat > /root/upjet-panel-login.txt <<EOFLOGIN
UPJET Panel Login
Username: $PANEL_ADMIN_USER
Password: $PANEL_PASSWORD
Host: $PANEL_HOST
Port: $PANEL_PORT
Default days: $DEFAULT_DAYS
Default quota GB: $DEFAULT_QUOTA_GB
SSH public host: $SSH_PUBLIC_HOST
SSH port: $SSH_PORT
EOFLOGIN
chmod 600 /root/upjet-panel-login.txt

# Migrate old quota data if available.
if [ -d /var/lib/ssh-panel ] && ! compgen -G "/var/lib/upjet-ssh-panel/*.quota" >/dev/null; then
    cp -a /var/lib/ssh-panel/. /var/lib/upjet-ssh-panel/ 2>/dev/null || true
    chmod 700 /var/lib/upjet-ssh-panel
fi

cat > /etc/systemd/system/upjet-ssh-panel.service <<'EOFUNIT'
[Unit]
Description=UPJET SSH User Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/upjet-ssh-panel
EnvironmentFile=/etc/upjet-ssh-panel.env
ExecStart=/usr/bin/python3 /opt/upjet-ssh-panel/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOFUNIT

# Disable previous simple panel to avoid port conflict.
systemctl disable --now ssh-panel 2>/dev/null || true
pkill -f "/opt/ssh-panel/app.py" 2>/dev/null || true

systemctl daemon-reload
systemctl enable --now upjet-ssh-panel

# Cron monitor. Remove old duplicates first.
(
    crontab -l 2>/dev/null | grep -v '/opt/ssh-panel/monitor_quota.sh' | grep -v '/opt/upjet-ssh-panel/monitor_quota.sh' || true
    echo '@reboot /opt/upjet-ssh-panel/monitor_quota.sh'
    echo '*/5 * * * * /opt/upjet-ssh-panel/monitor_quota.sh'
) | crontab -

/opt/upjet-ssh-panel/monitor_quota.sh || true

# Ensure existing panel users are members of sshclients after update/reinstall.
for quota_file in /var/lib/upjet-ssh-panel/*.quota; do
    [ -e "$quota_file" ] || continue
    u="$(basename "$quota_file" .quota)"
    if id "$u" >/dev/null 2>&1; then
        usermod -aG sshclients "$u" 2>/dev/null || true
    fi
done

# Open firewall port if ufw is active.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
    ufw allow "${PANEL_PORT}/tcp" || true
fi

SERVER_IP=$(hostname -I | awk '{print $1}')

echo '----------------------------------------'
echo 'UPJET SSH Panel fixed full version installed.'
echo "Username: $PANEL_ADMIN_USER"
echo "Password: $PANEL_PASSWORD"
echo "Panel listens on: $PANEL_HOST:$PANEL_PORT"
echo "Generated SSH links use host: ${SSH_PUBLIC_HOST:-auto-from-panel-domain}, port: $SSH_PORT"
echo 'Login file: /root/upjet-panel-login.txt'
echo "Direct URL: http://${SERVER_IP}:${PANEL_PORT}"
echo 'Safer SSH tunnel access:'
echo "ssh -L ${PANEL_PORT}:127.0.0.1:${PANEL_PORT} root@${SERVER_IP}"
echo "Then open: http://127.0.0.1:${PANEL_PORT}"
echo '----------------------------------------'
