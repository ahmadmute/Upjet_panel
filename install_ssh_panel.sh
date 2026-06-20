#!/bin/bash
set -euo pipefail

if [ "${EUID}" -ne 0 ]; then
    echo "Run this script as root: sudo bash install_ssh_panel.sh"
    exit 1
fi

apt update
apt install -y python3-flask iptables openssl

mkdir -p /opt/ssh-panel /var/lib/ssh-panel
chmod 700 /var/lib/ssh-panel

cat > /opt/ssh-panel/app.py <<'PY'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re
import secrets
import subprocess
import datetime
from pathlib import Path
from functools import wraps
from flask import Flask, request, redirect, url_for, session, flash, render_template_string, abort

BASE_DIR = Path("/var/lib/ssh-panel")
BASE_DIR.mkdir(parents=True, exist_ok=True)

USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{2,30}$")
PROTECTED_USERS = {"root", "admin", "ubuntu", "debian", "nobody", "www-data", "sshd"}

PANEL_PASSWORD = os.environ.get("PANEL_PASSWORD", "")
PANEL_HOST = os.environ.get("PANEL_HOST", "127.0.0.1")
PANEL_PORT = int(os.environ.get("PANEL_PORT", "8080"))

app = Flask(__name__)
app.secret_key = os.environ.get("PANEL_SECRET", secrets.token_hex(32))


def run_cmd(args, input_text=None, check=True):
    return subprocess.run(
        args,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


def cmd_ok(args):
    return subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def read_text(path, default=""):
    try:
        return Path(path).read_text().strip()
    except Exception:
        return default


def write_text(path, value):
    p = Path(path)
    p.write_text(str(value))
    os.chmod(p, 0o600)


def valid_username(username):
    return bool(USERNAME_RE.fullmatch(username)) and username not in PROTECTED_USERS


def user_exists(username):
    return cmd_ok(["id", username])


def ensure_iptables_chain():
    run_cmd(["iptables", "-N", "SSHQUOTA"], check=False)
    if not cmd_ok(["iptables", "-C", "OUTPUT", "-j", "SSHQUOTA"]):
        run_cmd(["iptables", "-I", "OUTPUT", "1", "-j", "SSHQUOTA"], check=False)


def add_iptables_rule(username):
    if not user_exists(username):
        return
    ensure_iptables_chain()
    uid = run_cmd(["id", "-u", username]).stdout.strip()
    if not cmd_ok(["iptables", "-C", "SSHQUOTA", "-m", "owner", "--uid-owner", uid, "-j", "RETURN"]):
        run_cmd(["iptables", "-A", "SSHQUOTA", "-m", "owner", "--uid-owner", uid, "-j", "RETURN"], check=False)


def get_counter_bytes(username):
    if not user_exists(username):
        return 0
    uid = run_cmd(["id", "-u", username]).stdout.strip()
    out = run_cmd(["iptables", "-nvxL", "SSHQUOTA"], check=False).stdout
    for line in out.splitlines():
        if f"owner UID match {uid}" in line:
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1])
    return 0


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


def check_csrf():
    if request.form.get("_csrf") != session.get("_csrf"):
        abort(400)


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("auth"):
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


def fmt_gb(value):
    try:
        return f"{int(value) / 1024 / 1024 / 1024:.2f}"
    except Exception:
        return "0.00"


def get_expiry(username):
    if not user_exists(username):
        return "deleted"
    out = run_cmd(["chage", "-l", username], check=False).stdout
    for line in out.splitlines():
        if "Account expires" in line:
            return line.split(":", 1)[1].strip()
    return "unknown"


def list_panel_users():
    users = []
    for quota_file in sorted(BASE_DIR.glob("*.quota")):
        username = quota_file.stem
        if not valid_username(username):
            continue
        quota = int(read_text(quota_file, "0") or 0)
        total = int(read_text(BASE_DIR / f"{username}.total", "0") or 0)
        status = read_text(BASE_DIR / f"{username}.status", "active")
        users.append({
            "username": username,
            "quota_gb": fmt_gb(quota),
            "used_gb": fmt_gb(total),
            "percent": min(100, round((total / quota) * 100, 1)) if quota else 0,
            "status": status,
            "expiry": get_expiry(username),
            "exists": user_exists(username),
        })
    return users


LOGIN_TEMPLATE = """
<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SSH Panel Login</title>
<style>
body{font-family:Tahoma,Arial,sans-serif;background:#f3f4f6;margin:0;padding:40px;color:#111827}
.box{max-width:420px;margin:auto;background:white;padding:24px;border-radius:12px;box-shadow:0 4px 18px #0001}
input,button{width:100%;padding:12px;margin-top:10px;border-radius:8px;border:1px solid #d1d5db;box-sizing:border-box}
button{background:#111827;color:white;cursor:pointer}
.msg{background:#fee2e2;padding:10px;border-radius:8px;margin-bottom:10px}
</style>
</head>
<body>
<div class="box">
<h2>ورود به پنل SSH</h2>
{% with messages = get_flashed_messages() %}{% if messages %}{% for m in messages %}<div class="msg">{{m}}</div>{% endfor %}{% endif %}{% endwith %}
<form method="post">
<input type="hidden" name="_csrf" value="{{ csrf_token() }}">
<input type="password" name="password" placeholder="رمز پنل" autofocus required>
<button type="submit">ورود</button>
</form>
</div>
</body>
</html>
"""

INDEX_TEMPLATE = """
<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SSH Panel</title>
<style>
body{font-family:Tahoma,Arial,sans-serif;background:#f3f4f6;margin:0;color:#111827}
.container{max-width:1180px;margin:auto;padding:24px}
.card{background:white;padding:18px;border-radius:12px;box-shadow:0 3px 14px #0001;margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
input,button,select{padding:10px;border-radius:8px;border:1px solid #d1d5db;box-sizing:border-box}
button{background:#111827;color:white;cursor:pointer;border:0}
button.danger{background:#991b1b}
button.warn{background:#92400e}
button.ok{background:#065f46}
table{width:100%;border-collapse:collapse;background:white}
th,td{border-bottom:1px solid #e5e7eb;padding:10px;text-align:right;vertical-align:middle}
th{background:#f9fafb}
.badge{padding:4px 8px;border-radius:999px;background:#e5e7eb;font-size:12px}
.active{background:#dcfce7}.locked{background:#fee2e2}
.progress{height:10px;background:#e5e7eb;border-radius:999px;overflow:hidden;min-width:120px}.bar{height:100%;background:#111827}
.actions{display:flex;gap:6px;flex-wrap:wrap}
.actions form{display:inline}
.msg{background:#e0f2fe;padding:10px;border-radius:8px;margin-bottom:10px}
.err{background:#fee2e2}
@media(max-width:800px){.grid{grid-template-columns:1fr}table{font-size:13px}.actions{display:block}.actions form{display:block;margin:4px 0}}
</style>
</head>
<body>
<div class="container">
<div class="card">
<h2>پنل ساده مدیریت SSH</h2>
<p>ساخت کاربر، محدودیت حجم، تاریخ انقضا، قفل، آزادسازی و حذف کاربر.</p>
<form method="post" action="{{ url_for('logout') }}">
<input type="hidden" name="_csrf" value="{{ csrf_token() }}">
<button class="warn" type="submit">خروج</button>
</form>
</div>

{% with messages = get_flashed_messages(with_categories=true) %}
{% if messages %}
{% for cat,m in messages %}<div class="msg {% if cat=='error' %}err{% endif %}">{{m}}</div>{% endfor %}
{% endif %}
{% endwith %}

<div class="card">
<h3>ساخت کاربر جدید</h3>
<form method="post" action="{{ url_for('create_user') }}">
<input type="hidden" name="_csrf" value="{{ csrf_token() }}">
<div class="grid">
<input name="username" placeholder="نام کاربری مثل user1" required>
<input name="days" type="number" min="1" max="3650" value="30" placeholder="مدت اعتبار - روز">
<input name="quota_gb" type="number" min="1" max="100000" value="100" placeholder="حجم - گیگ">
<button type="submit">ساخت کاربر</button>
</div>
</form>
</div>

<div class="card">
<h3>کاربران</h3>
<table>
<thead>
<tr>
<th>کاربر</th><th>مصرف</th><th>حجم</th><th>درصد</th><th>وضعیت</th><th>انقضا</th><th>عملیات</th>
</tr>
</thead>
<tbody>
{% for u in users %}
<tr>
<td><b>{{u.username}}</b></td>
<td>{{u.used_gb}} GB</td>
<td>{{u.quota_gb}} GB</td>
<td><div class="progress"><div class="bar" style="width:{{u.percent}}%"></div></div>{{u.percent}}%</td>
<td><span class="badge {{u.status}}">{{u.status}}</span></td>
<td>{{u.expiry}}</td>
<td>
<div class="actions">
<form method="post" action="{{ url_for('lock_user', username=u.username) }}"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><button class="warn" type="submit">قفل</button></form>
<form method="post" action="{{ url_for('unlock_user', username=u.username) }}"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><button class="ok" type="submit">آزادسازی ۳۰ روز</button></form>
<form method="post" action="{{ url_for('reset_quota', username=u.username) }}"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><button type="submit">ریست حجم</button></form>
<form method="post" action="{{ url_for('delete_user', username=u.username) }}" onsubmit="return confirm('حذف کامل کاربر؟')"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><button class="danger" type="submit">حذف</button></form>
</div>
</td>
</tr>
{% else %}
<tr><td colspan="7">هنوز کاربری ساخته نشده است.</td></tr>
{% endfor %}
</tbody>
</table>
</div>
</div>
</body>
</html>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        check_csrf()
        if request.form.get("password") == PANEL_PASSWORD and PANEL_PASSWORD:
            session["auth"] = True
            return redirect(url_for("index"))
        flash("رمز پنل اشتباه است.")
    return render_template_string(LOGIN_TEMPLATE)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    check_csrf()
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    ensure_iptables_chain()
    return render_template_string(INDEX_TEMPLATE, users=list_panel_users())


@app.route("/create", methods=["POST"])
@login_required
def create_user():
    check_csrf()
    username = request.form.get("username", "").strip()
    if not valid_username(username):
        flash("نام کاربری نامعتبر است. فقط حروف کوچک انگلیسی، عدد، _ و - مجاز است.", "error")
        return redirect(url_for("index"))
    if user_exists(username):
        flash("این کاربر از قبل وجود دارد.", "error")
        return redirect(url_for("index"))
    try:
        days = max(1, min(3650, int(request.form.get("days", "30"))))
        quota_gb = max(1, min(100000, int(request.form.get("quota_gb", "100"))))
    except ValueError:
        flash("عدد روز یا حجم نامعتبر است.", "error")
        return redirect(url_for("index"))

    expire_date = (datetime.date.today() + datetime.timedelta(days=days)).isoformat()
    quota_bytes = quota_gb * 1024 * 1024 * 1024
    password = run_cmd(["openssl", "rand", "-base64", "12"]).stdout.strip()

    try:
        run_cmd(["useradd", "-m", "-s", "/bin/bash", "-e", expire_date, username])
        run_cmd(["chpasswd"], input_text=f"{username}:{password}\n")
        run_cmd(["deluser", username, "sudo"], check=False)
        write_text(BASE_DIR / f"{username}.quota", quota_bytes)
        write_text(BASE_DIR / f"{username}.total", 0)
        write_text(BASE_DIR / f"{username}.last", 0)
        write_text(BASE_DIR / f"{username}.status", "active")
        add_iptables_rule(username)
        flash(f"کاربر ساخته شد | Username: {username} | Password: {password} | Expire: {expire_date} | Quota: {quota_gb}GB")
    except subprocess.CalledProcessError as e:
        flash(f"خطا در ساخت کاربر: {e.stderr}", "error")
    return redirect(url_for("index"))


@app.route("/lock/<username>", methods=["POST"])
@login_required
def lock_user(username):
    check_csrf()
    if valid_username(username) and user_exists(username):
        run_cmd(["usermod", "-L", username], check=False)
        run_cmd(["chage", "-E", "0", username], check=False)
        run_cmd(["pkill", "-KILL", "-u", username], check=False)
        write_text(BASE_DIR / f"{username}.status", "locked")
        flash(f"کاربر {username} قفل شد.")
    return redirect(url_for("index"))


@app.route("/unlock/<username>", methods=["POST"])
@login_required
def unlock_user(username):
    check_csrf()
    if valid_username(username) and user_exists(username):
        expire_date = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
        run_cmd(["usermod", "-U", username], check=False)
        run_cmd(["chage", "-E", expire_date, username], check=False)
        write_text(BASE_DIR / f"{username}.status", "active")
        add_iptables_rule(username)
        flash(f"کاربر {username} آزاد شد و تا {expire_date} اعتبار دارد.")
    return redirect(url_for("index"))


@app.route("/reset/<username>", methods=["POST"])
@login_required
def reset_quota(username):
    check_csrf()
    if valid_username(username) and user_exists(username):
        add_iptables_rule(username)
        current = get_counter_bytes(username)
        write_text(BASE_DIR / f"{username}.last", current)
        write_text(BASE_DIR / f"{username}.total", 0)
        write_text(BASE_DIR / f"{username}.status", "active")
        flash(f"حجم مصرفی {username} ریست شد.")
    return redirect(url_for("index"))


@app.route("/delete/<username>", methods=["POST"])
@login_required
def delete_user(username):
    check_csrf()
    if valid_username(username):
        run_cmd(["pkill", "-KILL", "-u", username], check=False)
        run_cmd(["userdel", "-r", username], check=False)
        for suffix in ["quota", "total", "last", "status"]:
            try:
                (BASE_DIR / f"{username}.{suffix}").unlink()
            except FileNotFoundError:
                pass
        flash(f"کاربر {username} حذف شد.")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host=PANEL_HOST, port=PANEL_PORT, debug=False)
PY

cat > /opt/ssh-panel/monitor_quota.sh <<'SH'
#!/bin/bash

BASE_DIR="/var/lib/ssh-panel"
LOG_FILE="$BASE_DIR/quota.log"

mkdir -p "$BASE_DIR"
chmod 700 "$BASE_DIR"

iptables -N SSHQUOTA 2>/dev/null || true
iptables -C OUTPUT -j SSHQUOTA 2>/dev/null || iptables -I OUTPUT 1 -j SSHQUOTA

get_user_bytes() {
    local UID_NUMBER="$1"
    iptables -nvxL SSHQUOTA | awk -v uid="$UID_NUMBER" '
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

    iptables -C SSHQUOTA -m owner --uid-owner "$UID_NUMBER" -j RETURN 2>/dev/null || \
    iptables -A SSHQUOTA -m owner --uid-owner "$UID_NUMBER" -j RETURN

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

chmod +x /opt/ssh-panel/app.py /opt/ssh-panel/monitor_quota.sh

if [ ! -f /etc/ssh-panel.env ]; then
    PANEL_PASSWORD="$(openssl rand -base64 18)"
    PANEL_SECRET="$(openssl rand -hex 32)"
    cat > /etc/ssh-panel.env <<EOF
PANEL_PASSWORD=$PANEL_PASSWORD
PANEL_SECRET=$PANEL_SECRET
PANEL_HOST=127.0.0.1
PANEL_PORT=8080
EOF
    chmod 600 /etc/ssh-panel.env
    echo "$PANEL_PASSWORD" > /root/ssh-panel-admin-password.txt
    chmod 600 /root/ssh-panel-admin-password.txt
fi

cat > /etc/systemd/system/ssh-panel.service <<'EOF'
[Unit]
Description=Simple SSH User Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ssh-panel
EnvironmentFile=/etc/ssh-panel.env
ExecStart=/usr/bin/python3 /opt/ssh-panel/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ssh-panel

(
    crontab -l 2>/dev/null | grep -v '/opt/ssh-panel/monitor_quota.sh' || true
    echo '@reboot /opt/ssh-panel/monitor_quota.sh'
    echo '*/5 * * * * /opt/ssh-panel/monitor_quota.sh'
) | crontab -

/opt/ssh-panel/monitor_quota.sh || true

SERVER_IP=$(hostname -I | awk '{print $1}')

echo "----------------------------------------"
echo "SSH Panel installed."
echo "Admin password: $(cat /root/ssh-panel-admin-password.txt)"
echo "Panel is listening on: 127.0.0.1:8080"
echo "Safe access from your computer:"
echo "ssh -L 8080:127.0.0.1:8080 root@$SERVER_IP"
echo "Then open: http://127.0.0.1:8080"
echo "----------------------------------------"
