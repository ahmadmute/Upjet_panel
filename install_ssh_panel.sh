#!/bin/bash
set -euo pipefail

# UPJET SSH Panel - Professional themed installer
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
    echo "Run as root: sudo bash install_upjet_ssh_pro.sh"
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
import time
import shlex
import io
from urllib.parse import quote
from pathlib import Path
from functools import wraps
from flask import Flask, request, redirect, url_for, session, flash, render_template_string, abort, Response, send_file

BASE_DIR = Path('/var/lib/upjet-ssh-panel')
BASE_DIR.mkdir(parents=True, exist_ok=True)
BACKUP_DIR = Path('/var/backups/upjet-ssh-panel')
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
MIGRATION_TOOL = Path('/opt/upjet-ssh-panel/upjet_migration_tool.sh')
# UPJET_PANEL_BACKUP_UI
# UPJET_DOMAIN_SETTINGS_UI
# UPJET_COLLAPSIBLE_USERS_UI
# UPJET_PER_USER_COLLAPSE_ONLY

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




def human_size(num):
    try:
        num = float(num)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if num < 1024:
                return f'{num:.1f} {unit}'
            num /= 1024
        return f'{num:.1f} PB'
    except Exception:
        return '0 B'


def safe_backup_path(filename):
    name = os.path.basename(filename or '')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+\.tar\.gz', name):
        abort(400)
    path = BACKUP_DIR / name
    if path.parent != BACKUP_DIR:
        abort(400)
    return path


def list_backup_files():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    items = []
    for p in sorted(BACKUP_DIR.glob('*.tar.gz'), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            st = p.stat()
            items.append({
                'name': p.name,
                'size': human_size(st.st_size),
                'created': datetime.datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            })
        except Exception:
            continue
    return items




def read_env_file():
    env = {}
    try:
        for line in Path('/etc/upjet-ssh-panel.env').read_text(encoding='utf-8').splitlines():
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            k, v = line.split('=', 1)
            env[k.strip()] = v.strip()
    except Exception:
        pass
    return env


def update_env_values(values):
    env_path = Path('/etc/upjet-ssh-panel.env')
    old_lines = []
    if env_path.exists():
        old_lines = env_path.read_text(encoding='utf-8').splitlines()

    seen = set()
    new_lines = []
    for line in old_lines:
        if '=' in line and not line.strip().startswith('#'):
            key = line.split('=', 1)[0].strip()
            if key in values:
                new_lines.append(f'{key}={values[key]}')
                seen.add(key)
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)

    for key, value in values.items():
        if key not in seen:
            new_lines.append(f'{key}={value}')

    env_path.write_text('\n'.join(new_lines).rstrip() + '\n', encoding='utf-8')
    os.chmod(env_path, 0o600)


def clean_public_host(value):
    value = (value or '').strip()
    value = re.sub(r'^https?://', '', value)
    value = value.split('/')[0]
    value = value.split(':')[0]
    return value.strip()


def get_saved_public_host():
    env = read_env_file()
    return clean_public_host(env.get('SSH_PUBLIC_HOST') or SSH_PUBLIC_HOST or '')


def get_saved_ssh_port():
    env = read_env_file()
    try:
        return int(env.get('SSH_PORT') or SSH_PORT or 22)
    except Exception:
        return 22


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
    configured = get_saved_public_host()
    if configured:
        return configured
    forwarded = request.headers.get('X-Forwarded-Host', '').strip()
    host = forwarded or request.host or ''
    return host.split(':')[0]


def build_ssh_command(username):
    return f'ssh -p {get_saved_ssh_port()} {username}@{get_connection_host()}'


def build_ssh_uri(username):
    password = read_text(BASE_DIR / f'{username}.password', '')
    if not password:
        return ''
    return f'ssh://{quote(username, safe="")}:{quote(password, safe="")}@{get_connection_host()}:{get_saved_ssh_port()}'


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
@import url('https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap');

:root{
  --bg:#060914;
  --bg2:#0a1020;
  --surface:#0f172a;
  --surface2:#111c33;
  --surface3:#16233d;
  --line:rgba(148,163,184,.18);
  --line2:rgba(148,163,184,.28);
  --text:#eef4ff;
  --muted:#98a8bd;
  --muted2:#66758c;
  --primary:#4f8cff;
  --primary2:#22d3ee;
  --primary3:#8b5cf6;
  --success:#10b981;
  --warning:#f59e0b;
  --danger:#ef4444;
  --shadow:0 24px 70px rgba(0,0,0,.42);
  --shadow2:0 12px 35px rgba(0,0,0,.30);
  --radius:24px;
  --radius2:18px;
}

*{box-sizing:border-box}

html{
  scroll-behavior:smooth;
}

body{
  margin:0;
  min-height:100vh;
  color:var(--text);
  font-family:'Vazirmatn',Tahoma,Arial,sans-serif;
  background:
    radial-gradient(circle at 12% 0%, rgba(79,140,255,.24), transparent 32%),
    radial-gradient(circle at 88% 8%, rgba(34,211,238,.16), transparent 30%),
    radial-gradient(circle at 50% 100%, rgba(139,92,246,.14), transparent 36%),
    linear-gradient(135deg,#050814 0%,#08101f 42%,#060914 100%);
  letter-spacing:-.015em;
}

body:before{
  content:"";
  position:fixed;
  inset:0;
  pointer-events:none;
  opacity:.22;
  background-image:
    linear-gradient(rgba(255,255,255,.045) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.045) 1px, transparent 1px);
  background-size:42px 42px;
  mask-image:linear-gradient(to bottom, black 0%, transparent 78%);
}

a{color:inherit}

.wrap{
  width:min(1320px,100%);
  margin:0 auto;
  padding:28px;
  position:relative;
  z-index:1;
}

.glass{
  background:linear-gradient(145deg, rgba(15,23,42,.84), rgba(15,23,42,.52));
  border:1px solid var(--line);
  box-shadow:var(--shadow);
  backdrop-filter:blur(18px);
  -webkit-backdrop-filter:blur(18px);
  border-radius:var(--radius);
}

.top{
  padding:22px 24px;
  display:flex;
  justify-content:space-between;
  gap:18px;
  align-items:center;
  margin-bottom:20px;
  position:sticky;
  top:14px;
  z-index:20;
}

.brand{
  display:flex;
  align-items:center;
  gap:16px;
}

.logo{
  width:58px;
  height:58px;
  border-radius:20px;
  background:
    linear-gradient(135deg,rgba(255,255,255,.22),rgba(255,255,255,.06)),
    linear-gradient(135deg,var(--primary),var(--primary2) 52%,var(--primary3));
  display:grid;
  place-items:center;
  font-weight:950;
  font-size:20px;
  color:#fff;
  box-shadow:0 16px 42px rgba(79,140,255,.36), inset 0 1px 0 rgba(255,255,255,.36);
  position:relative;
  overflow:hidden;
}

.logo:after{
  content:"";
  position:absolute;
  width:80%;
  height:80%;
  border-radius:18px;
  border:1px solid rgba(255,255,255,.22);
}

.brand h1{
  margin:0;
  font-size:32px;
  line-height:1.1;
  letter-spacing:.08em;
  font-weight:950;
}

.brand p{
  margin:5px 0 0;
  color:var(--muted);
  font-size:13px;
  font-weight:500;
}

.btn{
  border:0;
  border-radius:16px;
  padding:11px 16px;
  background:linear-gradient(135deg,var(--primary),var(--primary2));
  color:#fff;
  font-weight:850;
  cursor:pointer;
  box-shadow:0 12px 28px rgba(79,140,255,.22);
  text-decoration:none;
  display:inline-flex;
  align-items:center;
  justify-content:center;
  gap:7px;
  min-height:44px;
  transition:transform .16s ease, filter .16s ease, border-color .16s ease, background .16s ease;
  white-space:nowrap;
  font-family:inherit;
}

.btn:hover{
  transform:translateY(-1px);
  filter:brightness(1.08);
}

.btn:active{
  transform:translateY(0);
}

.btn.secondary{
  background:rgba(15,23,42,.92);
  color:var(--text);
  box-shadow:none;
  border:1px solid var(--line2);
}

.btn.secondary:hover{
  background:rgba(30,41,59,.95);
}

.btn.warn{
  background:linear-gradient(135deg,#d97706,var(--warning));
  box-shadow:0 12px 28px rgba(245,158,11,.20);
}

.btn.danger{
  background:linear-gradient(135deg,#dc2626,var(--danger));
  box-shadow:0 12px 28px rgba(239,68,68,.20);
}

.btn.ok{
  background:linear-gradient(135deg,#059669,var(--success));
  box-shadow:0 12px 28px rgba(16,185,129,.20);
}

input,select{
  width:100%;
  border:1px solid var(--line);
  background:rgba(7,12,24,.84);
  color:var(--text);
  border-radius:16px;
  padding:12px 14px;
  outline:none;
  min-height:44px;
  font-family:inherit;
  font-size:14px;
  transition:border-color .16s ease, box-shadow .16s ease, background .16s ease;
}

input:focus,select:focus{
  border-color:rgba(34,211,238,.78);
  box-shadow:0 0 0 4px rgba(34,211,238,.12);
  background:rgba(7,12,24,.98);
}

::placeholder{color:#6f7f95}

.msg{
  padding:13px 16px;
  border-radius:18px;
  margin-bottom:14px;
  background:rgba(79,140,255,.13);
  border:1px solid rgba(79,140,255,.25);
  line-height:1.9;
  color:#dbeafe;
}

.msg.err{
  background:rgba(239,68,68,.12);
  border-color:rgba(239,68,68,.28);
  color:#fecaca;
}

.stats{
  display:grid;
  grid-template-columns:repeat(3,1fr);
  gap:14px;
  margin-bottom:20px;
}

.stat{
  padding:20px;
  position:relative;
  overflow:hidden;
}

.stat:before{
  content:"";
  position:absolute;
  inset:auto -30px -44px auto;
  width:120px;
  height:120px;
  border-radius:999px;
  background:rgba(79,140,255,.12);
}

.stat .num{
  font-size:34px;
  font-weight:950;
  letter-spacing:-.03em;
}

.stat .label{
  color:var(--muted);
  margin-top:5px;
  font-weight:600;
}

.card{
  padding:22px;
  margin-bottom:20px;
}

.card h2,.card h3{
  margin:0 0 16px;
  font-size:19px;
  font-weight:900;
}

.create-grid{
  display:grid;
  grid-template-columns:1.4fr .7fr .7fr 1fr;
  gap:12px;
}

.small{
  font-size:12px;
  color:var(--muted);
  line-height:1.9;
}

.hint{
  margin-top:10px;
}

.users{
  display:grid;
  grid-template-columns:1fr;
  gap:16px;
}

.user-card{
  padding:20px;
  border-radius:24px;
  background:
    linear-gradient(145deg,rgba(15,23,42,.90),rgba(8,14,28,.78));
  border:1px solid var(--line);
  box-shadow:var(--shadow2);
  position:relative;
  overflow:hidden;
}

.user-card:before{
  content:"";
  position:absolute;
  inset:0;
  height:3px;
  background:linear-gradient(90deg,var(--primary),var(--primary2),var(--primary3));
  opacity:.9;
}

.user-head{
  display:flex;
  justify-content:space-between;
  gap:14px;
  align-items:flex-start;
  margin-bottom:16px;
}

.username{
  font-size:25px;
  font-weight:950;
  direction:ltr;
  text-align:left;
  letter-spacing:.015em;
}

.badges{
  display:flex;
  gap:8px;
  flex-wrap:wrap;
  justify-content:flex-end;
}

.badge{
  display:inline-flex;
  align-items:center;
  gap:7px;
  padding:7px 11px;
  border-radius:999px;
  font-size:12px;
  font-weight:900;
  border:1px solid transparent;
}

.badge:before{
  content:"";
  width:7px;
  height:7px;
  border-radius:999px;
  background:currentColor;
  box-shadow:0 0 12px currentColor;
}

.active{
  background:rgba(16,185,129,.14);
  color:#86efac;
  border-color:rgba(16,185,129,.22);
}

.locked,.deleted{
  background:rgba(239,68,68,.14);
  color:#fca5a5;
  border-color:rgba(239,68,68,.22);
}

.online{
  background:rgba(79,140,255,.15);
  color:#bfdbfe;
  border-color:rgba(79,140,255,.25);
}

.offline{
  background:rgba(148,163,184,.10);
  color:#cbd5e1;
  border-color:rgba(148,163,184,.18);
}

.meta{
  display:grid;
  grid-template-columns:repeat(5,1fr);
  gap:12px;
  margin-bottom:16px;
}

.m{
  padding:13px;
  border:1px solid var(--line);
  border-radius:18px;
  background:rgba(255,255,255,.035);
}

.m .k{
  color:var(--muted);
  font-size:12px;
  margin-bottom:7px;
  font-weight:700;
}

.m .v{
  font-weight:950;
  word-break:break-word;
}

.password-box{
  direction:ltr;
  text-align:left;
  font-family:Consolas,'SFMono-Regular','Roboto Mono',monospace;
  background:#050b16;
  border:1px dashed rgba(34,211,238,.42);
  border-radius:15px;
  padding:10px;
  min-height:42px;
  display:flex;
  align-items:center;
  overflow:auto;
  color:#dbeafe;
}

.progress{
  height:12px;
  background:#050b16;
  border:1px solid var(--line);
  border-radius:999px;
  overflow:hidden;
  margin-top:9px;
}

.bar{
  height:100%;
  background:linear-gradient(90deg,var(--primary),var(--primary2));
  border-radius:999px;
  box-shadow:0 0 16px rgba(34,211,238,.35);
}

.edit-grid{
  display:grid;
  grid-template-columns:repeat(4,1fr);
  gap:11px;
  margin-top:14px;
  padding-top:14px;
  border-top:1px solid var(--line);
}

.actions{
  display:grid;
  grid-template-columns:repeat(6,1fr);
  gap:9px;
  margin-top:12px;
}

.actions form,.edit-grid form{
  display:contents;
}

.field label{
  display:block;
  color:var(--muted);
  font-size:12px;
  margin-bottom:7px;
  font-weight:750;
}

.share-grid{
  display:grid;
  grid-template-columns:1.35fr 1.35fr 150px;
  gap:12px;
  margin-top:14px;
  align-items:stretch;
  padding-top:14px;
  border-top:1px solid var(--line);
}

.link-box{
  direction:ltr;
  text-align:left;
  font-family:Consolas,'SFMono-Regular','Roboto Mono',monospace;
  background:#050b16;
  border:1px solid rgba(148,163,184,.20);
  border-radius:15px;
  padding:11px;
  min-height:44px;
  overflow:auto;
  white-space:nowrap;
  color:#dbeafe;
}

.qr-box{
  display:grid;
  place-items:center;
  background:#fff;
  border-radius:18px;
  padding:10px;
  min-height:142px;
  box-shadow:inset 0 0 0 1px rgba(15,23,42,.08);
}

.qr-box img{
  width:122px;
  height:122px;
}

.copy-row{
  display:grid;
  grid-template-columns:1fr auto;
  gap:8px;
}

.copy-row .btn{
  min-width:84px;
}

.share-title{
  color:var(--muted);
  font-size:12px;
  margin-bottom:7px;
  font-weight:800;
}

.login-page{
  display:grid;
  place-items:center;
  min-height:100vh;
  padding:20px;
  position:relative;
  z-index:1;
}

.login-box{
  width:100%;
  max-width:450px;
  padding:34px;
}

.login-box .logo{
  margin:0 auto 16px;
  width:76px;
  height:76px;
  border-radius:24px;
}

.login-box h1{
  text-align:center;
  margin:0;
  font-size:40px;
  letter-spacing:.12em;
  font-weight:950;
}

.login-box p{
  text-align:center;
  color:var(--muted);
  margin:9px 0 24px;
  font-weight:600;
}

.login-box input,.login-box button{
  margin-top:11px;
}

.login-box button{
  width:100%;
}

.footer-note{
  color:var(--muted);
  font-size:12px;
  margin-top:15px;
  line-height:1.9;
  text-align:center;
}

::-webkit-scrollbar{
  width:10px;
  height:10px;
}

::-webkit-scrollbar-track{
  background:rgba(15,23,42,.55);
}

::-webkit-scrollbar-thumb{
  background:rgba(148,163,184,.35);
  border-radius:999px;
}

::-webkit-scrollbar-thumb:hover{
  background:rgba(148,163,184,.55);
}

@media(max-width:1100px){
  .meta{grid-template-columns:repeat(2,1fr)}
  .edit-grid{grid-template-columns:repeat(2,1fr)}
  .actions{grid-template-columns:repeat(2,1fr)}
  .create-grid{grid-template-columns:1fr 1fr}
  .share-grid{grid-template-columns:1fr}
  .copy-row{grid-template-columns:1fr}
  .qr-box img{width:160px;height:160px}
}

@media(max-width:680px){
  .wrap{padding:14px}
  .top{display:block;position:relative;top:auto}
  .brand h1{font-size:28px}
  .stats,.meta,.edit-grid,.actions,.create-grid{grid-template-columns:1fr}
  .user-head{display:block}
  .badges{justify-content:flex-start;margin-top:10px}
  .btn{width:100%}
  .card,.user-card{padding:16px}
}

.backup-grid{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:12px;
  align-items:start;
}
.backup-panel{
  padding:14px;
  border:1px solid var(--line);
  border-radius:18px;
  background:rgba(255,255,255,.035);
}
.backup-panel h4{
  margin:0 0 10px;
  font-size:14px;
  font-weight:900;
}
.backup-list{
  display:grid;
  gap:10px;
  margin-top:14px;
}
.backup-item{
  display:grid;
  grid-template-columns:1fr auto;
  gap:12px;
  align-items:center;
  border:1px solid var(--line);
  border-radius:18px;
  padding:12px;
  background:rgba(5,11,22,.45);
}
.backup-name{
  direction:ltr;
  text-align:left;
  font-family:Consolas,'SFMono-Regular','Roboto Mono',monospace;
  font-size:13px;
  overflow:auto;
  white-space:nowrap;
}
.backup-actions{
  display:flex;
  gap:8px;
  flex-wrap:wrap;
  justify-content:flex-end;
}
.backup-danger-note{
  color:#fca5a5;
  font-size:12px;
  line-height:1.9;
  margin-top:10px;
}
@media(max-width:900px){
  .backup-grid,.backup-item{grid-template-columns:1fr}
  .backup-actions{justify-content:stretch}
}


.domain-preview{
  direction:ltr;
  text-align:left;
  font-family:Consolas,'SFMono-Regular','Roboto Mono',monospace;
  background:#050b16;
  border:1px solid rgba(34,211,238,.28);
  border-radius:15px;
  padding:12px;
  margin-top:12px;
  color:#dbeafe;
  overflow:auto;
  white-space:nowrap;
}


.user-summary{
  margin-top:8px;
  display:flex;
  gap:8px;
  flex-wrap:wrap;
  align-items:center;
  color:var(--muted);
  font-size:12px;
  font-weight:750;
}
.summary-pill{
  display:inline-flex;
  align-items:center;
  gap:6px;
  border:1px solid var(--line);
  background:rgba(255,255,255,.035);
  border-radius:999px;
  padding:6px 10px;
}
.user-tools{
  display:flex;
  gap:8px;
  align-items:center;
  justify-content:flex-end;
  flex-wrap:wrap;
}
.collapse-btn{
  min-width:106px;
}
.user-details{
  display:none;
  animation:upjetDrop .18s ease both;
}
.user-card.open .user-details{
  display:block;
}
.user-card.open .collapse-btn{
  border-color:rgba(34,211,238,.55);
  background:rgba(34,211,238,.11);
}
.list-toolbar{
  display:flex;
  justify-content:space-between;
  gap:12px;
  align-items:center;
  margin-bottom:14px;
}
.list-toolbar-actions{
  display:flex;
  gap:8px;
  flex-wrap:wrap;
  justify-content:flex-end;
}
@keyframes upjetDrop{
  from{opacity:0;transform:translateY(-6px)}
  to{opacity:1;transform:translateY(0)}
}
@media(max-width:680px){
  .user-tools,.list-toolbar{display:block}
  .list-toolbar-actions{justify-content:stretch;margin-top:10px}
  .collapse-btn{width:100%}
}

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
function upjetToggleUser(id, btn){
  var el=document.getElementById(id);
  if(!el){return false;}
  var card=el.closest('.user-card');
  var open=card.classList.toggle('open');
  btn.innerText=open?'جمع کردن':'جزئیات';
  btn.setAttribute('aria-expanded', open ? 'true' : 'false');
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
    <h3>بکاپ و ریستور برای انتقال سرور</h3>

    <div class="backup-grid">
      <div class="backup-panel">
        <h4>گرفتن بکاپ کامل</h4>
        <form method="post" action="{{ url_for('create_backup') }}">
          <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
          <button class="btn ok" type="submit">ساخت و دانلود بکاپ</button>
        </form>
        <div class="small hint">شامل کاربران SSH، هش پسوردها، تاریخ انقضا، حجم، وضعیت، پسوردهای ذخیره‌شده پنل و فایل‌های پنل.</div>
      </div>

      <div class="backup-panel">
        <h4>ریستور بکاپ</h4>
        <form method="post" action="{{ url_for('restore_backup') }}" enctype="multipart/form-data" onsubmit="return confirm('ریستور بکاپ می‌تواند کاربران و تنظیمات فعلی را تغییر دهد. ادامه می‌دهی؟')">
          <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
          <input type="file" name="backup_file" accept=".gz,.tar.gz" required>
          <button class="btn warn" type="submit" style="margin-top:10px">آپلود و ریستور</button>
        </form>
        <div class="backup-danger-note">هشدار: فایل بکاپ شامل اطلاعات حساس و هش پسوردهاست. آن را عمومی نکن.</div>
      </div>
    </div>

    {% if backups %}
    <div class="backup-list">
      {% for b in backups %}
      <div class="backup-item">
        <div>
          <div class="backup-name">{{ b.name }}</div>
          <div class="small">حجم: {{ b.size }} · تاریخ: {{ b.created }}</div>
        </div>
        <div class="backup-actions">
          <a class="btn secondary" href="{{ url_for('download_backup', filename=b.name) }}">دانلود</a>
          <form method="post" action="{{ url_for('restore_existing_backup', filename=b.name) }}" onsubmit="return confirm('این بکاپ ریستور شود؟')">
            <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
            <button class="btn warn" type="submit">ریستور</button>
          </form>
          <form method="post" action="{{ url_for('delete_backup', filename=b.name) }}" onsubmit="return confirm('این بکاپ حذف شود؟')">
            <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
            <button class="btn danger" type="submit">حذف</button>
          </form>
        </div>
      </div>
      {% endfor %}
    </div>
    {% else %}
      <div class="small hint">هنوز بکاپی ساخته نشده است.</div>
    {% endif %}
  </div>


  <div class="card glass">
    <h3>تنظیم دامنه اتصال کاربران</h3>
    <form method="post" action="{{ url_for('save_domain_settings') }}">
      <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
      <div class="create-grid">
        <input name="ssh_public_host" value="{{ ssh_public_host }}" placeholder="مثلاً: p.brandto.ir یا ssh.example.com">
        <input name="ssh_port" type="number" min="1" max="65535" value="{{ ssh_port }}" placeholder="پورت SSH">
        <button class="btn" type="submit">ذخیره دامنه</button>
        <a class="btn secondary" href="{{ url_for('index') }}">رفرش</a>
      </div>
      <div class="small hint">این دامنه در لینک اتصال و QR Code جای IP قرار می‌گیرد. DNS دامنه باید روی IP همین سرور A Record شده باشد.</div>
      <div class="domain-preview">ssh -p {{ ssh_port }} username@{{ ssh_public_host or request.host.split(':')[0] }}</div>
    </form>
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
    <div class="list-toolbar">
      <h3 style="margin:0">لیست کاربران</h3>
      <div class="small">هر کاربر جداگانه با دکمه خودش باز و بسته می‌شود.</div>
    </div>
    <div class="users">
    {% for u in users %}
      <div class="user-card">
        <div class="user-head">
          <div>
            <div class="username">{{u.username}}</div>
            <div class="user-summary">
              <span class="summary-pill">انقضا: {{u.expiry}}</span>
              <span class="summary-pill">مصرف: {{u.used_gb}} / {{u.quota_gb}} GB</span>
              <span class="summary-pill">{{u.percent}}%</span>
            </div>
          </div>
          <div class="user-tools">
            <div class="badges">
              <span class="badge {{u.status}}">{{u.status}}</span>
              {% if u.online %}<span class="badge online">online</span>{% else %}<span class="badge offline">offline</span>{% endif %}
              {% if not u.exists %}<span class="badge deleted">deleted</span>{% endif %}
            </div>
            <button class="btn secondary collapse-btn" type="button" aria-expanded="false" onclick="return upjetToggleUser('user-details-{{ u.username }}-{{ loop.index }}', this)">جزئیات</button>
          </div>
        </div>

        <div class="user-details" id="user-details-{{ u.username }}-{{ loop.index }}">
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
        backups=list_backup_files(),
        ssh_public_host=get_saved_public_host(),
        ssh_port=get_saved_ssh_port(),
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



@app.route('/backup/create', methods=['POST'])
@login_required
def create_backup():
    check_csrf()
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"upjet-migration-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.tar.gz"
    target = BACKUP_DIR / filename
    try:
        subprocess.run(
            ['bash', str(MIGRATION_TOOL), 'backup', str(target)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=True
        )
        if target.exists():
            return send_file(target, as_attachment=True, download_name=target.name)
        flash('بکاپ ساخته شد ولی فایل برای دانلود پیدا نشد.', 'error')
    except subprocess.CalledProcessError as e:
        flash(f'خطا در ساخت بکاپ: {e.stderr or e.stdout}', 'error')
    except Exception as e:
        flash(f'خطا در ساخت بکاپ: {e}', 'error')
    return redirect(url_for('index'))


@app.route('/backup/download/<path:filename>')
@login_required
def download_backup(filename):
    path = safe_backup_path(filename)
    if not path.exists():
        abort(404)
    return send_file(path, as_attachment=True, download_name=path.name)


@app.route('/backup/delete/<path:filename>', methods=['POST'])
@login_required
def delete_backup(filename):
    check_csrf()
    path = safe_backup_path(filename)
    if path.exists():
        path.unlink()
        flash(f'بکاپ حذف شد: {path.name}')
    return redirect(url_for('index'))


def start_restore_job(path):
    log_path = Path('/var/log/upjet-restore.log')
    log = open(log_path, 'ab')
    subprocess.Popen(
        ['bash', str(MIGRATION_TOOL), 'restore', str(path)],
        stdout=log,
        stderr=log,
        start_new_session=True
    )


@app.route('/backup/restore/<path:filename>', methods=['POST'])
@login_required
def restore_existing_backup(filename):
    check_csrf()
    path = safe_backup_path(filename)
    if not path.exists():
        abort(404)
    try:
        start_restore_job(path)
        flash('ریستور شروع شد. ۳۰ تا ۶۰ ثانیه صبر کن و صفحه را رفرش کن. لاگ: /var/log/upjet-restore.log')
    except Exception as e:
        flash(f'خطا در شروع ریستور: {e}', 'error')
    return redirect(url_for('index'))


@app.route('/backup/restore', methods=['POST'])
@login_required
def restore_backup():
    check_csrf()
    file = request.files.get('backup_file')
    if not file or not file.filename:
        flash('فایل بکاپ انتخاب نشده است.', 'error')
        return redirect(url_for('index'))

    original = os.path.basename(file.filename).replace(' ', '_')
    if not original.endswith('.tar.gz'):
        flash('فرمت بکاپ باید .tar.gz باشد.', 'error')
        return redirect(url_for('index'))

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"uploaded-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}-{original}"
    target = BACKUP_DIR / filename
    file.save(target)
    os.chmod(target, 0o600)

    try:
        start_restore_job(target)
        flash('فایل بکاپ آپلود شد و ریستور شروع شد. ۳۰ تا ۶۰ ثانیه صبر کن و صفحه را رفرش کن. لاگ: /var/log/upjet-restore.log')
    except Exception as e:
        flash(f'خطا در شروع ریستور: {e}', 'error')
    return redirect(url_for('index'))



@app.route('/settings/domain', methods=['POST'])
@login_required
def save_domain_settings():
    check_csrf()
    host = clean_public_host(request.form.get('ssh_public_host', ''))
    port_raw = (request.form.get('ssh_port', '22') or '22').strip()

    if host and not re.fullmatch(r'[A-Za-z0-9.-]{3,253}', host):
        flash('دامنه معتبر نیست. فقط دامنه یا ساب‌دامین وارد کن، بدون http و بدون /', 'error')
        return redirect(url_for('index'))

    try:
        port = int(port_raw)
        if port < 1 or port > 65535:
            raise ValueError()
    except Exception:
        flash('پورت SSH معتبر نیست.', 'error')
        return redirect(url_for('index'))

    update_env_values({
        'SSH_PUBLIC_HOST': host,
        'SSH_PORT': str(port),
    })

    flash('دامنه اتصال ذخیره شد. از این به بعد لینک‌ها و QR Code با دامنه ساخته می‌شوند.')
    return redirect(url_for('index'))

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

cat > /opt/upjet-ssh-panel/upjet_migration_tool.sh <<'MIGRATION'
#!/bin/bash
set -euo pipefail

DATA_DIR="/var/lib/upjet-ssh-panel"
APP_DIR="/opt/upjet-ssh-panel"
ENV_FILE="/etc/upjet-ssh-panel.env"
SERVICE_FILE="/etc/systemd/system/upjet-ssh-panel.service"
BACKUP_DIR="/var/backups/upjet-ssh-panel"
GROUP_NAME="sshclients"

usage() {
cat <<'EOF'
UPJET Migration Tool

Usage:
  sudo bash upjet_migration_tool.sh backup
  sudo bash upjet_migration_tool.sh backup /root/upjet-backup.tar.gz
  sudo bash upjet_migration_tool.sh restore /root/upjet-backup.tar.gz
  sudo bash upjet_migration_tool.sh list

This backup is usable on another server.
It includes panel data, stored panel passwords, Linux managed users,
their SSH password hashes, quotas, expiry dates, status files and app config.
EOF
}

require_root() {
    if [ "${EUID}" -ne 0 ]; then
        echo "Run as root."
        exit 1
    fi
}

valid_username() {
    [[ "$1" =~ ^[a-z_][a-z0-9_-]{2,30}$ ]]
}

managed_users() {
    [ -d "$DATA_DIR" ] || return 0
    for quota_file in "$DATA_DIR"/*.quota; do
        [ -e "$quota_file" ] || continue
        user="$(basename "$quota_file" .quota)"
        valid_username "$user" || continue
        echo "$user"
    done | sort -u
}

ensure_ssh_login_rules() {
    getent group "$GROUP_NAME" >/dev/null || groupadd "$GROUP_NAME"

    if ! grep -q "^@${GROUP_NAME} hard maxlogins 1" /etc/security/limits.conf; then
        echo "@${GROUP_NAME} hard maxlogins 1" >> /etc/security/limits.conf
    fi

    if grep -qE '^#?PasswordAuthentication' /etc/ssh/sshd_config; then
        sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    else
        echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
    fi

    if grep -qE '^#?KbdInteractiveAuthentication' /etc/ssh/sshd_config; then
        sed -i 's/^#\?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config
    else
        echo 'KbdInteractiveAuthentication yes' >> /etc/ssh/sshd_config
    fi

    if grep -qE '^#?UsePAM' /etc/ssh/sshd_config; then
        sed -i 's/^#\?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config
    else
        echo 'UsePAM yes' >> /etc/ssh/sshd_config
    fi

    if grep -qE '^#?PermitEmptyPasswords' /etc/ssh/sshd_config; then
        sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
    else
        echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config
    fi

    if grep -qE '^#?MaxSessions' /etc/ssh/sshd_config; then
        sed -i 's/^#\?MaxSessions.*/MaxSessions 1/' /etc/ssh/sshd_config
    else
        echo 'MaxSessions 1' >> /etc/ssh/sshd_config
    fi

    sshd -t
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
}

backup_cmd() {
    require_root

    mkdir -p "$BACKUP_DIR"

    out="${1:-}"
    ts="$(date +%Y%m%d-%H%M%S)"

    if [ -z "$out" ]; then
        out="$BACKUP_DIR/upjet-migration-$ts.tar.gz"
    fi

    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT

    mkdir -p "$tmp/rootfs" "$tmp/meta"

    [ -d "$DATA_DIR" ] && mkdir -p "$tmp/rootfs/var/lib" && cp -a "$DATA_DIR" "$tmp/rootfs/var/lib/upjet-ssh-panel"
    [ -d "$APP_DIR" ] && mkdir -p "$tmp/rootfs/opt" && cp -a "$APP_DIR" "$tmp/rootfs/opt/upjet-ssh-panel"
    [ -f "$ENV_FILE" ] && mkdir -p "$tmp/rootfs/etc" && cp -a "$ENV_FILE" "$tmp/rootfs/etc/upjet-ssh-panel.env"
    [ -f "$SERVICE_FILE" ] && mkdir -p "$tmp/rootfs/etc/systemd/system" && cp -a "$SERVICE_FILE" "$tmp/rootfs/etc/systemd/system/upjet-ssh-panel.service"

    {
        echo "UPJET_BACKUP_VERSION=4"
        echo "CREATED_AT=$(date -Iseconds)"
        echo "HOSTNAME=$(hostname)"
        echo "SOURCE_IP=$(hostname -I | awk '{print $1}')"
    } > "$tmp/meta/backup.info"

    : > "$tmp/meta/users.tsv"

    while IFS= read -r user; do
        [ -n "$user" ] || continue
        id "$user" >/dev/null 2>&1 || continue

        uid="$(id -u "$user")"
        gid="$(id -g "$user")"
        home="$(getent passwd "$user" | cut -d: -f6)"
        shell="$(getent passwd "$user" | cut -d: -f7)"
        hash="$(getent shadow "$user" | cut -d: -f2)"
        expire="$(getent shadow "$user" | cut -d: -f8)"
        groups="$(id -nG "$user" | tr ' ' ',')"

        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$user" "$uid" "$gid" "$home" "$shell" "$hash" "${expire:-}" "$groups" >> "$tmp/meta/users.tsv"

        if [ -d "$home" ]; then
            mkdir -p "$tmp/rootfs/home"
            cp -a "$home" "$tmp/rootfs/home/" 2>/dev/null || true
        fi
    done < <(managed_users)

    chmod -R go-rwx "$tmp"
    tar -C "$tmp" -czf "$out" .
    chmod 600 "$out"

    echo "$out"
}

restore_cmd() {
    require_root

    archive="${1:-}"
    if [ -z "$archive" ] || [ ! -f "$archive" ]; then
        echo "Backup file not found."
        usage
        exit 1
    fi

    export DEBIAN_FRONTEND=noninteractive
    apt update
    apt install -y python3-flask python3-qrcode python3-pil iptables openssl bc passwd procps curl openssh-server adduser tar

    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT

    tar -C "$tmp" -xzf "$archive"

    if [ ! -f "$tmp/meta/backup.info" ]; then
        echo "Invalid backup."
        exit 1
    fi

    echo "Restoring:"
    cat "$tmp/meta/backup.info"
    echo

    ensure_ssh_login_rules

    systemctl stop upjet-ssh-panel 2>/dev/null || true

    if [ -d "$tmp/rootfs/var/lib/upjet-ssh-panel" ]; then
        mkdir -p /var/lib
        rm -rf "$DATA_DIR"
        cp -a "$tmp/rootfs/var/lib/upjet-ssh-panel" "$DATA_DIR"
        chmod 700 "$DATA_DIR"
        chmod 600 "$DATA_DIR"/* 2>/dev/null || true
    fi

    if [ -d "$tmp/rootfs/opt/upjet-ssh-panel" ]; then
        mkdir -p /opt
        rm -rf "$APP_DIR"
        cp -a "$tmp/rootfs/opt/upjet-ssh-panel" "$APP_DIR"
        chmod +x "$APP_DIR"/*.py "$APP_DIR"/*.sh 2>/dev/null || true
    fi

    if [ -f "$tmp/rootfs/etc/upjet-ssh-panel.env" ]; then
        cp -a "$tmp/rootfs/etc/upjet-ssh-panel.env" "$ENV_FILE"
        chmod 600 "$ENV_FILE"
    fi

    if [ -f "$tmp/rootfs/etc/systemd/system/upjet-ssh-panel.service" ]; then
        cp -a "$tmp/rootfs/etc/systemd/system/upjet-ssh-panel.service" "$SERVICE_FILE"
    else
        cat > "$SERVICE_FILE" <<'EOF'
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
EOF
    fi

    if [ -f "$tmp/meta/users.tsv" ]; then
        while IFS=$'\t' read -r user uid gid home shell hash expire groups; do
            [ -n "$user" ] || continue
            valid_username "$user" || continue

            if ! getent group "$gid" >/dev/null 2>&1; then
                groupadd -g "$gid" "$user" 2>/dev/null || groupadd "$user" 2>/dev/null || true
            fi

            if ! id "$user" >/dev/null 2>&1; then
                if getent group "$gid" >/dev/null 2>&1; then
                    useradd -m -d "$home" -s "${shell:-/bin/bash}" -u "$uid" -g "$gid" "$user" 2>/dev/null || \
                    useradd -m -d "$home" -s "${shell:-/bin/bash}" "$user"
                else
                    useradd -m -d "$home" -s "${shell:-/bin/bash}" "$user"
                fi
            else
                usermod -s "${shell:-/bin/bash}" "$user" 2>/dev/null || true
            fi

            if [ -n "${hash:-}" ] && [ "$hash" != "!" ] && [ "$hash" != "*" ]; then
                usermod -p "$hash" "$user" 2>/dev/null || true
            fi

            if [ -n "${expire:-}" ] && [[ "$expire" =~ ^[0-9]+$ ]]; then
                chage -E "$expire" "$user" 2>/dev/null || true
            fi

            usermod -aG "$GROUP_NAME" "$user" 2>/dev/null || true
        done < "$tmp/meta/users.tsv"
    fi

    if [ -d "$tmp/rootfs/home" ]; then
        cp -a "$tmp/rootfs/home/." /home/ 2>/dev/null || true
    fi

    systemctl daemon-reload
    systemctl enable upjet-ssh-panel >/dev/null 2>&1 || true
    systemctl restart upjet-ssh-panel

    if [ -x "$APP_DIR/monitor_quota.sh" ]; then
        "$APP_DIR/monitor_quota.sh" || true
    fi

    (
        crontab -l 2>/dev/null | grep -v '/opt/upjet-ssh-panel/monitor_quota.sh' || true
        echo '@reboot /opt/upjet-ssh-panel/monitor_quota.sh'
        echo '*/5 * * * * /opt/upjet-ssh-panel/monitor_quota.sh'
    ) | crontab -

    echo "Restore completed."
}

list_cmd() {
    require_root
    mkdir -p "$BACKUP_DIR"
    ls -1 "$BACKUP_DIR"/*.tar.gz 2>/dev/null || true
}

case "${1:-}" in
    backup)
        backup_cmd "${2:-}"
        ;;
    restore)
        restore_cmd "${2:-}"
        ;;
    list)
        list_cmd
        ;;
    help|-h|--help|"")
        usage
        ;;
    *)
        echo "Unknown command: ${1:-}"
        usage
        exit 1
        ;;
esac

MIGRATION

chmod +x /opt/upjet-ssh-panel/app.py /opt/upjet-ssh-panel/monitor_quota.sh /opt/upjet-ssh-panel/upjet_migration_tool.sh

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
