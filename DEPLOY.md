# Deploying ssh-honeypot on a VPS

🇹🇷 [Türkçe](DEPLOY.tr.md)

This guide assumes an Ubuntu 24.04 (or Debian 12) VPS. It is written for the
hard case: a server that **also runs a production website and mail**. On a
dedicated, disposable VPS the same steps work, you just have less to lose.

| What the honeypot does | What it does not do |
|---|---|
| listens on TCP port 2222 and records SSH login attempts | it never changes sshd, nginx, the firewall, mail or any other service |
| writes its own SQLite database and `/var/log/ssh-honeypot/auth.log` | it never executes attacker commands or downloads anything |
| optionally sends HTTPS requests to `api.telegram.org` | it does not run as root and has no capabilities |
| uses at most 25 % of one CPU and 256 MB of RAM (hard limits) | it does not open the dashboard to the internet (`127.0.0.1` only) |

> **Before you start: should this run next to production at all?**
> The isolation is real (no real shell, no capabilities, sandboxed, hidden
> production paths, resource limits), but the honeypot is still code that
> strangers talk to, on the same kernel and IP address as your website and
> mail. **If you can, use a separate cheap VPS.** If you use the production
> server, keep the default `reject` policy and option (a) below. The full
> discussion is in [README: Should you run this next to production?](README.md#should-you-run-this-next-to-production).

---

## 0. Preparation

1. **Update the system** and make sure security updates install
   automatically. The sandbox shares the kernel with everything else.

   ```bash
   sudo apt update && sudo apt upgrade
   sudo apt install unattended-upgrades
   ```

2. **Check that port 2222 is free:**

   ```bash
   sudo ss -ltnp 'sport = :2222'      # no output = free
   ```

3. **Know your firewall.** Make sure your real SSH port is allowed before
   you change anything:

   ```bash
   sudo ufw status verbose
   ```

   Many VPS providers also have a firewall / security group in their web
   panel. Port 2222 must be allowed there too.

4. (Optional) **Telegram:** talk to `@BotFather`, send `/newbot`, copy the
   token. Send your bot a message, open
   `https://api.telegram.org/bot<TOKEN>/getUpdates` and copy `chat.id`.
   Notifications only happen when a session reaches the fake shell, so with
   the default `reject` policy there are none.

5. (Optional) **GeoIP:** see README "GeoIP". Without it, countries are
   "unknown".

---

## 1. Choose how attackers reach the honeypot

The honeypot always listens on **2222**, an unprivileged port, so it needs no
root rights and no capabilities. There are two ways to expose it.

### Option (a): just open port 2222 (recommended)

```bash
sudo ufw allow 2222/tcp comment 'ssh-honeypot'
```

Your real sshd stays exactly where it is. Fewer bots try 2222 than 22, but
plenty do: a new IP usually sees attempts within hours. Risk: low. To stop,
remove the rule (`sudo ufw delete allow 2222/tcp`) or stop the service.

### Option (b): move the real sshd and redirect port 22 (advanced)

> ⚠️ **LOCK-OUT WARNING.** This changes how *you* reach your server. One
> mistake (a typo in the port, a firewall rule in the wrong order, the
> Ubuntu 24.04 socket-activation detail below) and you lose SSH access to a
> server that runs your website and mail. Only do this if you understand
> every line, keep your current session open the whole time, and have the
> provider's web/VNC console ready. **The install script deliberately does
> not automate any of this.**

The idea: the real sshd moves to a different port (say 22222), and the
firewall redirects incoming port 22 to the honeypot on 2222. Outline:

1. Keep your current SSH session open. Open a second one as a lifeline.
2. Allow the new port **first**: `sudo ufw allow 22222/tcp`.
3. Move sshd. On Ubuntu 24.04 sshd is socket-activated, and the listening
   port comes from `sshd_config` through a systemd generator:

   ```bash
   echo 'Port 22222' | sudo tee /etc/ssh/sshd_config.d/10-port.conf
   sudo sshd -t                                   # syntax check, must print nothing
   sudo systemctl daemon-reload
   sudo systemctl restart ssh.socket              # Debian 12 / no socket: sudo systemctl restart ssh
   ```

4. From a **new** terminal on your laptop: `ssh -p 22222 you@server`. Do not
   continue until this works. Put `Port 22222` into your laptop's
   `~/.ssh/config` for this host, so you never type your real password into
   the honeypot on port 22 by accident (it would be recorded like any other).
5. Add the redirect. With ufw, insert this block at the top of
   `/etc/ufw/before.rules` (before the `*filter` line; replace `eth0` with
   your interface from `ip -br link`):

   ```text
   *nat
   :PREROUTING ACCEPT [0:0]
   -A PREROUTING -i eth0 -p tcp --dport 22 -j REDIRECT --to-ports 2222
   COMMIT
   ```

   then `sudo ufw allow 2222/tcp` and `sudo ufw reload`. For IPv6, the same
   block goes into `/etc/ufw/before6.rules`.
6. Check from outside: `ssh root@server` (port 22) must now show the
   honeypot (any password fails), and `ssh -p 22222 you@server` must still be
   your real server.

To undo: remove the `*nat` block, `sudo ufw reload`, delete
`10-port.conf`, `daemon-reload` and restart `ssh.socket`, while your session
on 22222 is still open.

With Docker you can skip the redirect and publish `"22:2222"` instead of
`"2222:2222"` in `docker-compose.yml`, *after* moving sshd. The lock-out
warning applies in the same way.

---

## 2A. Install with systemd (recommended on a production host)

Needs Python 3.11+ (Ubuntu 24.04 and Debian 12 have it).

```bash
sudo apt install python3-venv git
git clone https://github.com/rosko35/ssh-honeypot.git
cd ssh-honeypot
sudo ./deploy/install.sh                       # installs, does not start
sudo nano /etc/ssh-honeypot/config.yml         # policy, banner, limits, retention
sudo nano /etc/ssh-honeypot/env                # optional Telegram / dashboard credentials
sudo systemctl enable --now ssh-honeypot
journalctl -u ssh-honeypot -f                  # look for "SSH honeypot listening on 0.0.0.0:2222"
```

The script creates the system user `sshhoneypot` (no shell, no home, no
groups), installs the code and a virtualenv into `/opt/ssh-honeypot`
(root-owned), writes `/etc/ssh-honeypot/config.yml` and `env` only if they do
not exist (listening on `0.0.0.0:2222`), installs two units and validates the
configuration. It installs no packages and touches no other service. Host
keys are generated on the first start into `/var/lib/ssh-honeypot` (never
copy them into the repository).

The units are heavily sandboxed. Check the score with
`systemd-analyze security ssh-honeypot`. The important lines:

- `User=sshhoneypot`, `CapabilityBoundingSet=` (empty), `NoNewPrivileges=yes`
- `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
  `PrivateDevices=yes`; writable only `/var/lib/ssh-honeypot` and
  `/var/log/ssh-honeypot`
- `InaccessiblePaths=` for `/var/www`, `/etc/letsencrypt`, `/etc/ssl/private`,
  `/etc/nginx`, mail spools and configs (`/var/mail`, `/etc/postfix`,
  `/etc/dovecot`, ...), database directories and `/etc/ssh`
- `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `SocketBindAllow=tcp:2222`
- `CPUQuota=25%`, `MemoryMax=256M`, `TasksMax=32`, `Nice=10`

**Changing the port:** edit `listen.port` and allow binding it with a
drop-in (`sudo systemctl edit ssh-honeypot`, add `[Service]` and
`SocketBindAllow=tcp:NEWPORT`), then restart.

Update: `git pull && sudo ./deploy/install.sh && sudo systemctl restart ssh-honeypot`
(config, env, database and host keys are kept). Remove:
`sudo ./deploy/install.sh --uninstall` (add `--purge` to also delete config,
database, host keys, logs and the user).

## 2B. Install with Docker

Needs Docker Engine with Compose v2.24 or newer (`docker compose version`).

```bash
git clone https://github.com/rosko35/ssh-honeypot.git ~/ssh-honeypot
cd ~/ssh-honeypot
cp .env.example .env && chmod 600 .env
nano .env                                   # optional Telegram / dashboard credentials
nano config.yml                             # policy, banner, limits (listen address is set by the image)
docker compose up -d --build
docker compose logs -f                      # "SSH honeypot listening on 0.0.0.0:2222"
docker compose --profile dashboard up -d    # optional dashboard on 127.0.0.1:8081
```

The container runs as uid 10001 with all capabilities dropped,
`no-new-privileges`, a read-only root filesystem, a small tmpfs and CPU,
memory and PID limits. Database, host keys and `auth.log` live in the
`honeypot-data` volume.

> **Docker bypasses ufw.** Published ports get their own iptables rules, so
> `2222` is reachable even though `ufw status` does not list it. That is
> intended here, but remember it - and never publish the dashboard on
> anything but `127.0.0.1`.

Update: `git pull && docker compose up -d --build`. Remove everything:
`docker compose down -v`.

---

## 3. Optional: forbid outbound connections (egress filter)

The honeypot never connects anywhere on an attacker's behalf. Its only
possible outbound traffic is the optional Telegram notification. If you do
not use Telegram, you can make the kernel enforce "no new outbound
connections" for the service user. This is defence in depth: even if
someone found a bug that let them run code as `sshhoneypot`, they could not
download a second stage or attack other hosts from your IP.

systemd cannot express this itself (`IPAddressDeny=` filters inbound and
outbound by remote address, and inbound must stay open to everyone). For the
systemd install with ufw, add to `/etc/ufw/before.rules` (and
`before6.rules`), inside the `*filter` section, after the
`-A ufw-before-output -o lo -j ACCEPT` line:

```text
-A ufw-before-output -m owner --uid-owner sshhoneypot -m conntrack --ctstate NEW -j REJECT
```

then `sudo ufw reload`. Replies to incoming connections are `ESTABLISHED`
and keep working; new outbound connections (including DNS) are rejected.
Telegram notifications will then fail (they are logged as warnings).

For Docker, the equivalent is a rule in the `DOCKER-USER` chain matching the
container's IP address; see the Docker documentation for your setup.

---

## 4. Connect mini-siem (optional)

[mini-siem](https://github.com/rosko35/mini-siem) can tail the honeypot's
`auth.log` with its existing `auth` parser.

**systemd installs of both:**

```bash
sudo usermod -aG sshhoneypot minisiem          # read access to /var/log/ssh-honeypot
sudo nano /etc/mini-siem/config.yml            # add the source below
sudo systemctl restart mini-siem
```

```yaml
sources:
  - type: file
    path: /var/log/ssh-honeypot/auth.log
    parser: auth
```

Events carry the hostname `honeypot`. mini-siem's SSH rules will fire for
honeypot traffic too (that is the point: early warning about who is
scanning). If you want alerts only for the real sshd, add
`exclude: {host: honeypot}` to those rules.

**Docker installs:** let the honeypot write its auth log to the host, where
mini-siem's container (which mounts `/var/log` read-only as group `adm`) can
read it:

```bash
sudo install -d -o 10001 -g adm -m 2750 /var/log/ssh-honeypot
```

and in `docker-compose.yml` under `honeypot:` add the volume
`- /var/log/ssh-honeypot:/logs` and the environment variable
`HONEYPOT_AUTH_LOG: /logs/auth.log`, then `docker compose up -d`.

---

## 5. Open the dashboard

The dashboard never listens on a public interface. Start it
(`sudo systemctl enable --now ssh-honeypot-dashboard`, or the Docker
profile) and use an SSH tunnel from your laptop:

```bash
ssh -N -L 8081:127.0.0.1:8081 you@your-server      # with option (b): add -p 22222
# then open http://localhost:8081
```

The systemd unit additionally drops every packet that does not come from
the machine itself (`IPAddressDeny=any`, `IPAddressAllow=localhost`).
`HONEYPOT_DASHBOARD_USER` / `HONEYPOT_DASHBOARD_PASSWORD` add basic auth as a
second layer.

---

## 6. Check that it works

From another machine (never type a real password):

```bash
ssh -p 2222 -o PubkeyAuthentication=no root@your-server     # type any fake password
```

Then on the server:

```bash
journalctl -u ssh-honeypot -n 20
sudo tail -n 5 /var/log/ssh-honeypot/auth.log
sudo -u sshhoneypot HONEYPOT_CONFIG=/etc/ssh-honeypot/config.yml \
    /opt/ssh-honeypot/venv/bin/honeypot stats --days 1 --min-sources 1
```

## 7. Operations

| Task | systemd | Docker |
|---|---|---|
| Logs | `journalctl -u ssh-honeypot -f` | `docker compose logs -f` |
| README statistics | `sudo -u sshhoneypot HONEYPOT_CONFIG=/etc/ssh-honeypot/config.yml /opt/ssh-honeypot/venv/bin/honeypot stats --days 30` | `docker compose exec honeypot honeypot stats --days 30` |
| Apply retention now | `... honeypot prune --days 30` | `docker compose exec honeypot honeypot prune --days 30` |
| Validate config | `... honeypot check-config` | `docker compose exec honeypot honeypot check-config` |
| Apply config changes | `sudo systemctl restart ssh-honeypot` | `docker compose restart honeypot` |
| Disk usage | `sudo du -sh /var/lib/ssh-honeypot /var/log/ssh-honeypot` | `docker system df -v` |

Retention (`retention_days`, default 90) is applied every hour. The text
logs rotate at 20 MB (3 old files kept).

## 8. Privacy and legal

Read README "Legal and privacy notes". In short: attacker IPs and typed
credentials are personal data, attackers sometimes type real credentials,
keep data only as long as needed, restrict access, never use captured
credentials anywhere, and never fetch the recorded URLs on this server.

## 9. Troubleshooting

- **Service does not start** - `journalctl -u ssh-honeypot -e`.
  "Address already in use": something else listens on 2222 (`sudo ss -ltnp`).
  "Permission denied" on bind: the configured port is not 2222 and the unit
  does not allow it (see "Changing the port").
- **No connections at all** - port 2222 is blocked: check `ufw status` and
  the provider's firewall panel; test from outside with `nc -vz server 2222`.
- **Telegram silent** - the default `reject` policy never reaches the fake
  shell, so there is nothing to notify; the egress rule from step 3 also
  blocks Telegram. Errors are logged without the token.
- **HASSH / cipher columns empty** - an asyncssh upgrade changed internal
  attributes; everything else still works. See `fingerprint.py`.
- **The database grows fast** - lower `retention_days` and run
  `honeypot prune`; consider `max_connections_per_ip`.
