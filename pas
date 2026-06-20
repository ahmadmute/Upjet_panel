sudo bash -c 'SECRET=$(grep "^PANEL_SECRET=" /etc/upjet-ssh-panel.env 2>/dev/null | cut -d= -f2-)
[ -z "$SECRET" ] && SECRET=$(openssl rand -hex 32)

cat > /etc/upjet-ssh-panel.env <<EOF
PANEL_ADMIN_USER=****
PANEL_PASSWORD=****
PANEL_SECRET=$SECRET
PANEL_HOST=0.0.0.0
PANEL_PORT=9080
EOF

chmod 600 /etc/upjet-ssh-panel.env
systemctl restart upjet-ssh-panel
'
