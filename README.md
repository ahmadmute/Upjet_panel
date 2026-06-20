# UPJET SSH Panel

UPJET SSH Panel is a lightweight web panel for creating and managing Linux SSH users with expiration dates, traffic quotas, saved passwords, and one-login-per-user limits.

> Use this tool only on servers you own or are authorized to administer.

## Features

- Create SSH users from a web panel
- Set account expiration, such as 30 days
- Set traffic quota, such as 100 GB
- View each user's used traffic
- Store and display passwords created or changed through the panel
- Change a user's SSH password manually
- Generate a random SSH password
- Edit user quota in GB
- Extend or change account validity in days
- Lock users
- Unlock users
- Reset traffic usage
- Kill active user sessions
- Delete users completely
- Limit each SSH user to one simultaneous login
- Automatically enable SSH password login
- Disable conflicts from an older `ssh-panel` service
- Card-based responsive UI for desktop and mobile

## Supported Systems

Tested for Debian/Ubuntu-style systems:

- Ubuntu 20.04+
- Ubuntu 22.04+
- Ubuntu 24.04+
- Debian 11+
- Debian 12+

## What the Installer Does

The installer:

- Installs required packages
- Creates `/opt/upjet-ssh-panel`
- Creates `/var/lib/upjet-ssh-panel`
- Creates the `upjet-ssh-panel` systemd service
- Creates a traffic monitor script
- Adds cron jobs for quota checks
- Enables SSH password login
- Sets `PasswordAuthentication yes`
- Sets `KbdInteractiveAuthentication yes`
- Sets `UsePAM yes`
- Sets `PermitEmptyPasswords no`
- Sets `MaxSessions 1`
- Creates the `sshclients` group
- Adds `@sshclients hard maxlogins 1`
- Stops the old `ssh-panel` service if it exists

## Installation

Clone the repository or upload the installer to your server.

```bash
sudo bash install_upjet_ssh.sh
```

After installation, read the panel login credentials:

```bash
sudo cat /root/upjet-panel-login.txt
```

Default panel URL:

```text
http://SERVER_IP:9080
```

## Install With Custom Panel Credentials

You can set the panel username, password, host, and port during installation:

```bash
sudo env PANEL_ADMIN_USER=admin PANEL_PASSWORD=StrongPassword123 PANEL_PORT=9080 PANEL_HOST=0.0.0.0 bash install_upjet_ssh.sh
```

Example:

```bash
sudo env PANEL_ADMIN_USER=ahmadmute PANEL_PASSWORD=ahmad2405 PANEL_PORT=9080 PANEL_HOST=0.0.0.0 bash install_upjet_ssh.sh
```

## Panel Access

If the panel is listening publicly:

```text
http://SERVER_IP:9080
```

The panel port is only for the web interface. It is not the SSH port.

## Safer Access With SSH Tunnel

For better security, run the panel on localhost only.

Edit the environment file:

```bash
sudo nano /etc/upjet-ssh-panel.env
```

Set:

```text
PANEL_HOST=127.0.0.1
PANEL_PORT=9080
```

Restart the service:

```bash
sudo systemctl restart upjet-ssh-panel
```

From your local machine, open a tunnel:

```bash
ssh -L 9080:127.0.0.1:9080 root@SERVER_IP
```

Then open:

```text
http://127.0.0.1:9080
```

## Connecting as an SSH User

Users created by the panel connect through the SSH port, not the panel port.

Default SSH port:

```bash
ssh username@SERVER_IP
```

Custom SSH port example:

```bash
ssh -p 2222 username@SERVER_IP
```

## Change Panel Username or Password

Edit:

```bash
sudo nano /etc/upjet-ssh-panel.env
```

Example:

```text
PANEL_ADMIN_USER=admin
PANEL_PASSWORD=StrongPassword123
PANEL_SECRET=random_secret
PANEL_HOST=0.0.0.0
PANEL_PORT=9080
```

Restart:

```bash
sudo systemctl restart upjet-ssh-panel
```

Update the saved login file if needed:

```bash
sudo cat /root/upjet-panel-login.txt
```

## Change Panel Port

Edit:

```bash
sudo nano /etc/upjet-ssh-panel.env
```

Change:

```text
PANEL_PORT=9080
```

Example:

```text
PANEL_PORT=9090
```

Restart:

```bash
sudo systemctl restart upjet-ssh-panel
```

If UFW is enabled:

```bash
sudo ufw allow 9090/tcp
sudo ufw reload
```

## Service Management

Check status:

```bash
sudo systemctl status upjet-ssh-panel --no-pager
```

Restart:

```bash
sudo systemctl restart upjet-ssh-panel
```

Stop:

```bash
sudo systemctl stop upjet-ssh-panel
```

Enable at boot:

```bash
sudo systemctl enable upjet-ssh-panel
```

View logs:

```bash
sudo journalctl -u upjet-ssh-panel -n 100 --no-pager
```

Follow logs:

```bash
sudo journalctl -u upjet-ssh-panel -f
```

## Traffic Quota Monitor

The quota monitor runs every 5 minutes through cron.

Manual run:

```bash
sudo /opt/upjet-ssh-panel/monitor_quota.sh
```

Quota lock log:

```bash
sudo cat /var/lib/upjet-ssh-panel/quota.log
```

## Stored User Data

Panel data is stored in:

```text
/var/lib/upjet-ssh-panel
```

Files per user may include:

```text
username.quota
username.total
username.last
username.status
username.password
```

Important: Linux does not store real user passwords in readable form. It stores password hashes. The panel can only display passwords that were created or changed through the panel after password storage was enabled.

## One Login Per User

The installer creates this group:

```text
sshclients
```

It also adds this limit:

```text
@sshclients hard maxlogins 1
```

And sets:

```text
MaxSessions 1
```

Check the settings:

```bash
grep sshclients /etc/security/limits.conf
grep MaxSessions /etc/ssh/sshd_config
```

If a user is not in the group:

```bash
sudo usermod -aG sshclients username
```

## SSH Password Login Settings

The installer tries to make SSH password login work by applying these settings:

```text
PasswordAuthentication yes
KbdInteractiveAuthentication yes
UsePAM yes
PermitEmptyPasswords no
```

Check active config lines:

```bash
sudo grep -RniE 'PasswordAuthentication|KbdInteractiveAuthentication|UsePAM|PermitEmptyPasswords' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null
```

Validate and restart SSH:

```bash
sudo sshd -t
sudo systemctl restart ssh 2>/dev/null || sudo systemctl restart sshd
```

## Troubleshooting SSH User Login

If a user is created but cannot connect:

```bash
id username
sudo passwd -S username
sudo chage -l username
grep username /etc/passwd
```

Unlock and extend the user:

```bash
sudo usermod -U username
sudo chage -E $(date -d "+30 days" +%F) username
```

Reset password:

```bash
sudo passwd username
```

Check SSH listening port:

```bash
sudo ss -ltnp | grep ssh
```

Test from inside the server:

```bash
ssh username@127.0.0.1
```

Check SSH logs:

```bash
sudo journalctl -u ssh -n 80 --no-pager
```

If your system uses `sshd` as the service name:

```bash
sudo journalctl -u sshd -n 80 --no-pager
```

## Old Panel Conflict

If an older panel service named `ssh-panel` exists, stop it:

```bash
sudo systemctl disable --now ssh-panel 2>/dev/null
sudo pkill -f "/opt/ssh-panel/app.py" 2>/dev/null
sudo systemctl restart upjet-ssh-panel
```

Check ports:

```bash
sudo ss -ltnp | grep -E '9080|python'
```

## Security Notes

- Do not expose the panel publicly with a weak password.
- Prefer `PANEL_HOST=127.0.0.1` and access it through an SSH tunnel.
- If you expose the panel publicly, restrict the port with a firewall.
- Keep `/etc/upjet-ssh-panel.env` readable only by root.
- Keep `/var/lib/upjet-ssh-panel` readable only by root.
- This panel is intended for simple SSH user management, not high-scale commercial billing.

## Firewall Examples

Allow panel port:

```bash
sudo ufw allow 9080/tcp
sudo ufw reload
```

Allow default SSH port:

```bash
sudo ufw allow 22/tcp
sudo ufw reload
```

Check firewall status:

```bash
sudo ufw status
```

## Uninstall

Stop and remove the service:

```bash
sudo systemctl disable --now upjet-ssh-panel
sudo rm -f /etc/systemd/system/upjet-ssh-panel.service
sudo systemctl daemon-reload
```

Remove application files:

```bash
sudo rm -rf /opt/upjet-ssh-panel
```

Remove panel data:

```bash
sudo rm -rf /var/lib/upjet-ssh-panel
```

Remove environment and login files:

```bash
sudo rm -f /etc/upjet-ssh-panel.env
sudo rm -f /root/upjet-panel-login.txt
```

This does not automatically delete Linux users created by the panel. Delete users manually if needed.

## Suggested Repository Structure

```text
.
├── install_upjet_ssh.sh
├── README.md
└── LICENSE
```

## License

MIT License

## Disclaimer

This tool is provided for authorized server administration. You are responsible for securing the panel, credentials, firewall rules, SSH configuration, and server access.
