# ProtonPort - automatic qBittorrent port sync with ProtonVPN

Automatically keeps **qBittorrent's listening port** in sync with **ProtonVPN's forwarded port** (port forwarding). When a new VPN connection changes the assigned port, the script finds it on its own in the ProtonVPN app log and sets it in qBittorrent through the Web API - no manual work and no restart needed.

It is a single script in **pure Python 3** (standard library only -> **no extra dependencies**) plus a background systemd user service.

---

## 1. What the program does

In short: **the script makes sure qBittorrent listens on the same port that ProtonVPN assigned to you.**

ProtonVPN with port forwarding lets you accept incoming connections (e.g. for torrenting) only on the port assigned by the VPN. qBittorrent, however, does not know about that port by itself - it must be set as its "listen port". This script does it for you automatically.

The program has two modes:

- **Diagnostics** - [`protonport.py`](protonport.py) with the `--check` switch inspects the state without changing anything.
- **Watcher** - runs continuously in the background as a service and watches for port changes.

> Design details, algorithms and rationale are in the technical specification [`DESIGN.md`](DESIGN.md).

## 2. How it works

1. The **ProtonVPN (GUI)** app with port forwarding writes the assigned port into its log (`~/.cache/Proton/VPN/logs/vpn-app.log`). The record is renewed roughly every 60 seconds and the port changes **only on a new connection** (reconnect).
2. The **script** follows this log and reads the current forwarded port from it.
3. As soon as it detects a new port, it **authenticates to the qBittorrent Web UI** (`http://127.0.0.1:8080`) and sets the port as the listening port through the Web API (`setPreferences`). When the qBittorrent Web UI uses **HTTPS**, it connects to `https://127.0.0.1:8080` - the port stays the same (HTTPS runs on the same port, just over TLS) and `insecure_https: true` is enabled in the config (self-signed certificate), see [Configuration](#5-configuration).
4. The change takes effect immediately - on a running graphical qBittorrent the port can only be changed through the Web API.

What happens on a **VPN reconnect**:

- The connection resumes and ProtonVPN assigns (usually) a different port.
- The script catches it from the log and sets it in qBittorrent within ~15-60 seconds.
- Until then qBittorrent stays on the old port - that is normal.

The script **self-heals**:

- On every start it runs a "self-healing" sync - it compares the current port from the log with the port in qBittorrent and fixes it right away if needed.
- If qBittorrent is temporarily unavailable, it remembers the port and retries with an increasing delay (backoff) until it recovers.

## 3. Requirements

- **Python 3** - already in the system (the ProtonVPN app runs on it too). The program uses **only the standard library**, so **nothing else needs to be installed** (no `pip`, no `curl`/`jq`).
- **qBittorrent** running as a GUI with the **Web UI enabled** at `http://127.0.0.1:8080` (with an HTTPS Web UI: `https://127.0.0.1:8080` + `insecure_https: true`; the port does not change) and authentication configured - via the **API key** (recommended) or a username/password.
- **ProtonVPN (GUI)** with **port forwarding** enabled (without it no port appears in the log).
- The `Session\Interface=proton0` setting in qBittorrent (so it only listens on the VPN tunnel) - usually already set for a normal user.

> The program targets Linux (tested on CachyOS/Arch with KDE). The service runs at the user level (systemd --user), so it works while you are logged into the graphical session.

## 4. Step-by-step installation

The easiest way is to run the installer [`install.sh`](install.sh). It does everything needed for you. Because the project path contains **spaces** (`qBittorrent port updater for ProtonVPN`), run it **from the project directory** and quote the path if needed:

```bash
cd "/path/to/qBittorrent port updater for ProtonVPN"
./install.sh
```

What the installer does:

1. Copies the script to `~/.local/bin/protonport.py` (mode `0700`). The copy into a path without spaces matters - the systemd service refers to it.
2. Creates the config `~/.config/protonport/protonport.conf` from the template (mode `0600`). **If the config already exists, it is not overwritten** - only a notice is shown.
3. Copies the systemd service to `~/.config/systemd/user/protonport.service`.
4. Verifies the syntax of the installed script (`py_compile`).
5. Runs `daemon-reload` and enables and starts the service (`systemctl --user enable --now`).

> ⚠️ After installing you **still need to fill in the qBittorrent Web UI credentials** in the config - either `api_key` (recommended) or `username` + `password` - see [Configuration](#5-configuration). Until you do, the watcher will not start (it exits with an error), because secrets are never stored in the code or in the template.

### Installer options

| Command | Meaning |
|---|---|
| `./install.sh` | Full install + start the service |
| `./install.sh --install-only` | Only copies the files, does **not** start the service (start it yourself later) |
| `./install.sh --uninstall` | Removes the service and the files (see [Uninstall](#11-uninstall)) |
| `./install.sh -h` / `--help` | Shows the installer help |

Example - install files only (without starting the service):

```bash
cd "/path/to/qBittorrent port updater for ProtonVPN"
./install.sh --install-only
```

> 💡 **Tip:** `--install-only` is handy when you want to fill in the credentials first and start the service manually later (see *Running in the background*).

## 5. Configuration

The configuration lives in **`~/.config/protonport/protonport.conf`** (JSON, mode `0600`, readable only by your user). It is created automatically from the template [`protonport.conf.example`](protonport.conf.example). Edit it with any editor:

```bash
$EDITOR ~/.config/protonport/protonport.conf
```

### Meaning of the keys

```jsonc
{
  // - Paths -
  "log_path": "~/.cache/Proton/VPN/logs/vpn-app.log",
  //   Log of the ProtonVPN app, from which the forwarded port is read.
  //   The template uses "~"; the script expands it to the home directory itself.
  "state_dir": "~/.local/state/protonport",
  //   Directory for the internal state (how far the script read the log, last port, lock).
  "own_log_file": "",
  //   Empty = the log goes to the service output (journalctl). Only for running without
  //   systemd would you put your own file here, e.g. "~/.local/state/protonport/protonport.log".

  // - Logging -
  "log_level": "INFO",
  //   Log level: DEBUG | INFO | WARNING | ERROR.

  // - qBittorrent Web UI -
  "qbittorrent": {
    "base_url": "http://127.0.0.1:8080",
    //   Address of the qBittorrent Web UI (including the port). If the Web UI runs elsewhere, change it here.
    //   If qBittorrent has an HTTPS Web UI, use https://127.0.0.1:8080 (the port does not change -
    //   HTTPS runs on the same port just over TLS) and enable insecure_https: true.
    "username": "user",
    //   Username - ONLY NEEDED in the user/password mode (when there is no api_key).
    "password": "__CHANGE_ME__",
    //   Password - ONLY NEEDED in the user/password mode (when there is no api_key). The
    //   __CHANGE_ME__ placeholder MUST be replaced with a real password, or the password can be
    //   given via the environment variable. The recommended choice is however api_key (below) -
    //   then no password is needed.
    "api_key": "",
    //   qBittorrent API key (RECOMMENDED) - see "Authentication - two options" below.
    //   A filled-in api_key takes PRIORITY: authentication happens ONLY via the key (Bearer) and
    //   username/password are ignored. An empty string / the __CHANGE_ME__ placeholder means "not set".
    "http_timeout_s": 10,
    //   Timeout (s) for communicating with qBittorrent.
    "insecure_https": false
    //   true when qBittorrent has a self-signed HTTPS certificate (the default for loopback);
    //   the script then does not verify the certificate for https URLs. Ignored for http.
  },

  // - Intervals and waits (seconds) - usually no need to change -
  "intervals": {
    "connected_s": 15,          // how often to read the log while the VPN is running
    "offline_s": 60,            // how often to retry when the log/VPN is absent
    "qbit_backoff_base_s": 5,   // wait when qBittorrent is unavailable (start)
    "qbit_backoff_max_s": 120,  // maximum wait when qBittorrent is unavailable
    "auth_backoff_base_s": 60,  // wait on a failed login (start)
    "auth_backoff_max_s": 600   // maximum wait on a failed login
  },

  // - Behaviour -
  "tail_scan_bytes": 1048576,
  //   How many bytes at the end of the log the script scans during the startup "self-healing" (1 MiB).
  "dry_run": false,
  //   true = nothing is changed in qBittorrent, only what would happen is logged.
  "force_on_start": false
  //   true = always set the port at startup, even when it already matches (default false = only when it differs).
}
```

> ℹ️ The configuration is **validated** at startup - an unknown or missing key, a typo or an empty password is rejected with a clear message. That protects you from a silent failure.

### Authentication - two options

Authentication to the qBittorrent Web UI is **never stored in the code or in the template**. Just fill in **EITHER** `api_key` (recommended) **OR** `username` + `password`. A set `api_key` takes **priority** - when present, ONLY the key is used and `username`/`password` are ignored.

**Option 1 (recommended): API key - `qbittorrent.api_key`**

qBittorrent 5.2+ supports a native API key: *Tools -> Options -> Web UI -> Authentication -> **API Key*** (the **Copy** button). The generated key starts with `qbt_` and is 32 characters long. Put it into `qbittorrent.api_key`:

```json
"api_key": "qbt_<32_character_key>"
```

The script then sends the key on **every** request as the HTTP header `Authorization: Bearer <key>`. The session created by the key **never expires** (no re-login) and the server **skips the CSRF check** in this mode. Advantages: no plaintext password on disk and you can **revoke / regenerate** the key in qBittorrent at any time (then just update the config and restart the service). After switching to the key you can safely delete both `username` and `password` from the config.

**Option 2: username + password - `qbittorrent.username` + `qbittorrent.password`**

The classic Web UI login with a username and password (SID cookie + CSRF `Referer`). Give the password in one of two ways:

1. **In the config** - replace the `__CHANGE_ME__` placeholder with a real password in `~/.config/protonport/protonport.conf`. The file has mode `0600`, so only you can read it.

   ```json
   "username": "user",
   "password": "YOUR_REAL_PASSWORD"
   ```

2. **Via the environment variable** `PROTONPORT_QBIT_PASSWORD` - it takes priority over the config and lets you keep the password off the disk entirely:

   ```bash
   export PROTONPORT_QBIT_PASSWORD='your_password'
   ```

   The password in the config can then stay empty or with the placeholder. Note: for a systemd service the variable must also be set for the service (e.g. in `~/.config/environment.d/`) so that the service can see it.

> The config is valid when **`api_key` OR (`username` AND `password`)** is set. Watcher modes (`--once`, the service) without either exit with a clear error; `--check` still runs (diagnostics) and only reports that qBittorrent was not contacted because the credentials are missing.

### Changing the qBittorrent Web UI port / credentials

If you change the **port**, **password** or **API key** of the qBittorrent Web UI (in qBittorrent: *Tools -> Options -> Web UI*), mirror the change here too:

- new **port/URL** -> the `qbittorrent.base_url` key,
- new **password** -> the `qbittorrent.password` key (or the environment variable),
- rotation/new **API key** -> the `qbittorrent.api_key` key (used instead of username/password).

Restart the service after every config change - see *Running in the background*.

## 6. Testing before running

Before starting the service you can try everything risk-free.

### Diagnostics without credentials: `--check`

The [`--check`](protonport.py) switch **works even without `api_key` or a password** - it only runs diagnostics on the log and the system, **changes nothing** and does **not contact qBittorrent** until the credentials are set (otherwise it just reports what is missing):

```bash
~/.local/bin/protonport.py --config ~/.config/protonport/protonport.conf --check
```

It prints:

- does the ProtonVPN log exist? (when missing, the VPN is probably not running),
- the latest forwarded port found in the log,
- which authentication mode will be used (`Auth: API key` / `Auth: user/password`) - without printing the key or password,
- (when credentials are set) the qBittorrent version and its current `listen_port`, plus whether everything is in sync.

### A test that does not touch qBittorrent: `--once --dry-run`

[`--dry-run`](protonport.py) guarantees that **no setting is ever changed** - the script only inspects the state and logs what it would do. [`--once`](protonport.py) runs one synchronization cycle and exits (no long-running process).

```bash
~/.local/bin/protonport.py --config ~/.config/protonport/protonport.conf --once --dry-run
```

In the log you will then see e.g. `DRY-RUN: would set listen_port=...` - **nothing was actually changed.**

> ⚠️ Note: `--once` (even with `--dry-run`) already requires the credentials (`api_key` OR `username`+`password`), because it logs into the Web UI to compare ports. Only `--check` runs without them.

## 7. Running in the background

### Starting the service

Enable and start the service with one command:

```bash
systemctl --user enable --now protonport.service
```

This starts the service immediately **and** makes it start automatically at every login into the graphical session. (The service is user-level - without so-called linger it runs only while you are logged in. That is fine, because both ProtonVPN and qBittorrent are GUI apps that start with the KDE session.)

### Checking the status

```bash
systemctl --user status protonport.service
```

### Watching the log (live)

```bash
journalctl --user -u protonport.service -f
```

Or just the last lines:

```bash
journalctl --user -u protonport.service -n 50
```

### Restart after a config change

After every edit of `~/.config/protonport/protonport.conf`, restart the service so the changes take effect:

```bash
systemctl --user restart protonport.service
```

### Stopping / disabling

```bash
# temporarily stop (without disabling auto-start):
systemctl --user stop protonport.service

# fully disable (stop + disable auto-start):
systemctl --user disable --now protonport.service
```

## 8. Command line overview (CLI)

The script [`protonport.py`](protonport.py) is called with an optional `--config` (the default path is `~/.config/protonport/protonport.conf`):

```bash
protonport.py [--config PATH] [--dry-run] [--force] [--once] [--check] [--version]
```

| Switch | Meaning |
|---|---|
| `--config PATH` | Path to the config (default `~/.config/protonport/protonport.conf`) |
| `--dry-run` | Never calls `setPreferences` - only logs what would happen |
| `--force` | Self-healing at startup applies the port even when it matches qBittorrent |
| `--once` | Runs one synchronization cycle and exits (test / cron) |
| `--check` | Diagnostics: log? port from the log? qBittorrent `listen_port`? then exit |
| `--version` | Prints the version and exits |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success / normal end (including `Ctrl+C` interruption) |
| `1` | Error - e.g. a bad config, missing `api_key`/placeholder password (in watcher modes), an unexpected error |
| `2` | Incorrect usage - an unknown switch (shows help) |
| `3` | Another instance is already running (the `flock` single-instance lock) |

## 9. Troubleshooting (FAQ)

**Login to qBittorrent fails / I get an "IP ban"?**
In the user/password mode it is most often a wrong password or username in `~/.config/protonport/protonport.conf`. Check the values (file mode `0600`) or the `PROTONPORT_QBIT_PASSWORD` variable. On a failed login the script waits with a long interval (backoff 60 -> 600 s) so that it does **not hammer a possible temporary IP ban** - after too many failed attempts qBittorrent's Web UI temporarily blocks the IP. The ban usually clears by itself; in the meantime do not run anything repeatedly.

**"HTTP 401/403 - the API key is invalid"?**
When you use `qbittorrent.api_key`, it means the key is **invalid / revoked / mistyped**. Generate a new one in qBittorrent (*Tools -> Options -> Web UI -> Authentication -> API Key* -> the **Copy** button), put it into `qbittorrent.api_key` (the key starts with `qbt_`, 32 characters) and restart the service. The key is a secret - never put it into logs, commits or display it.

**qBittorrent is unavailable?**
The script remembers the port and retries with an increasing delay (backoff 5 -> 120 s) - as soon as qBittorrent comes back (or the Web UI is enabled), the state catches up by itself. Verify that qBittorrent is running and the Web UI is enabled (`http://127.0.0.1:8080`; with an HTTPS Web UI: `https://127.0.0.1:8080` + `insecure_https: true`). [`--check`](protonport.py) gives a hint.

**The VPN log does not exist?**
The log `~/.cache/Proton/VPN/logs/vpn-app.log` is only created while the ProtonVPN (GUI) app is running. When missing, the script just waits calmly (the `offline_s` interval) and reports that the VPN is probably not running. Start ProtonVPN and connect - everything then starts on its own.

**The log rotates (~3 MiB) and the script loses it?**
No. The script handles rotation (`.log`, `.log.1` ... `.log.3`) - it can read the boundary records, recognize a new file, and at startup scan the log tails to find the current port. There is nothing to configure.

**"The script does not see the port" from the log?**
The port only appears in the log after connecting the VPN **with port forwarding enabled**. Verify:

- the VPN is connected and port forwarding is enabled in ProtonVPN,
- the log contains a `Receiving Response { ... internal_port: ... external_port: ... }` line (the `port_forwarding.rs` module),
- run [`--check`](protonport.py) - it shows whether the log exists and which port the script found in it.

**How do I try the script without affecting the running qBittorrent?**
Use [`--once --dry-run`](protonport.py) - the script sets nothing, it only logs what it would do. `dry_run: true` in the config serves the same purpose.

**How do I find out the current forwarded port manually?**
The port is only visible in the ProtonVPN log. In `~/.cache/Proton/VPN/logs/vpn-app.log` find the line with `Receiving Response` and `internal_port:` - the number is your port. The ProtonVPN GUI also sometimes shows it in the "Port forwarding" notification. (The port only changes on a new connection; during one connection it is only renewed roughly every 60 seconds.)

## 10. Security notes

- **No secret (password or API key) is in the code or in the repository.** Secrets are stored in the config with mode `0600`; the password can also be passed via the `PROTONPORT_QBIT_PASSWORD` environment variable. It is never passed as a command-line argument (it would be visible in the process list).
- **The config with the secrets has mode `0600`** (only the owner can read it). At startup the script checks the mode and warns on wider access - recommending `chmod 600`.
- **The API key is a secret just like the password** - never print it into the output, the log or git. When you switch to `api_key`, you can **delete both `password` and `username`** from the config (the key has priority and the password is no longer stored in plaintext on disk).
- **No secrets are logged** - neither the key nor the password ever appears in the log or in the service output (journalctl).
- The script targets Linux and only reads files outside its own state directory (the log).

Further technical details (Web UI CSRF/Referer protection, host header validation, log format, backoff) are in [`DESIGN.md`](DESIGN.md). The project is licensed under **MIT** - see [`LICENSE`](LICENSE).

## 11. Uninstall

The installer handles the uninstall:

```bash
cd "/path/to/qBittorrent port updater for ProtonVPN"
./install.sh --uninstall
```

The installer:

1. Stops and disables the systemd service and removes the unit file.
2. Deletes the script `~/.local/bin/protonport.py`.
3. Deletes the state files in `~/.local/state/protonport`.

**It does NOT delete the config `~/.config/protonport/protonport.conf`** (it holds the password/API key). If you want to remove it together with the secrets, delete it manually:

```bash
rm -i ~/.config/protonport/protonport.conf
```
