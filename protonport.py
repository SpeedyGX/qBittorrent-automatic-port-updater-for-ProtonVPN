#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
protonport.py - automatic qBittorrent listen-port updater based on the
ProtonVPN port-forwarding port.

Port source: parsed from the protonvpn-app log (~/.cache/Proton/VPN/logs/vpn-app.log).
qBittorrent update: exclusively through the Web API (setPreferences, form field `json`).
Details and rationale: see DESIGN.md.

Implementation: Python 3.8+, pure standard library (urllib, http.cookiejar,
json, re, os, fcntl, time, logging, argparse, hashlib). No pip packages, no
external curl/jq.
"""

from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import json
import logging
import os
import re
import socket
import ssl
import sys
import time
from logging.handlers import RotatingFileHandler
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

try:
    import fcntl
except ImportError:  # pragma: no cover - watcher is Linux-only
    fcntl = None  # type: ignore[assignment]

APP_NAME = "protonport"
VERSION = "1.2.0"

# Default paths / names (no spaces in these paths - see DESIGN.md §4).
DEFAULT_CONFIG = os.path.join(os.path.expanduser("~"), ".config", "protonport", "protonport.conf")
DEFAULT_LOG = os.path.join(os.path.expanduser("~"), ".cache", "Proton", "VPN", "logs", "vpn-app.log")
DEFAULT_STATE_DIR = os.path.join(os.path.expanduser("~"), ".local", "state", "protonport")
STATE_FILE = "protonport.state.json"
LOCK_FILE = "protonport.lock"

# Secrets.
ENV_PASSWORD = "PROTONPORT_QBIT_PASSWORD"
ENV_API_KEY = "PROTONPORT_QBIT_API_KEY"
PASSWORD_PLACEHOLDER = "__CHANGE_ME__"

# Valid port range (0 or out-of-range values are ignored with a WARNING).
PORT_MIN, PORT_MAX = 1024, 65535

# Follow-the-log limits (defense against a corrupt / pathological log).
READ_CHUNK_BYTES = 4 * 1024 * 1024   # max bytes read from the log per tick
MAX_PENDING_BYTES = 1024 * 1024      # max incomplete trailing line kept in memory
PREFIX_BYTES = 256                   # prefix fingerprint (copytruncate detection)

# Exit codes.
EXIT_OK = 0
EXIT_ERROR = 1       # unexpected error
EXIT_USAGE = 2       # argparse uses 2 itself
EXIT_RUNNING = 3     # another instance is already running (flock)
EXIT_UNSYNC = 4      # --once/--check: qBittorrent could not be brought in sync
EXIT_CONFIG = 78     # configuration/credentials error (sysexits EX_CONFIG)

log = logging.getLogger(APP_NAME)


# ---------------------------------------------------------------------------
# 6.3  Regexes (compiled once, re.MULTILINE flag per DESIGN.md)
# ---------------------------------------------------------------------------

# A) Direct port source: both renewals and new assignments, filtered by the
#    port_forwarding.rs module and the text "Receiving Response" (Sending
#    Request lines from the same module never pass - see DESIGN.md §6.3).
#    The body is captured whole and the fields are parsed separately, so the
#    order of internal_port/external_port does not matter (a ProtonVPN update
#    may reorder them).
PORT_RENEW_RE = re.compile(
    r"\|\s*proton\.vpn\.platform/port_forwarding\.rs:\d+\s*\|\s*\w+\s*\|\s*"
    r"Receiving Response\s*\{([^{}]*)\}",
    re.MULTILINE,
)
INTERNAL_PORT_RE = re.compile(r"\binternal_port:\s*(\d{1,5})")
EXTERNAL_PORT_RE = re.compile(r"\bexternal_port:\s*(\d{1,5})")

# B) Marker of a new assignment - OBSERVABILITY ONLY (it carries no port).
ASSIGNED_RE = re.compile(
    r"\|\s*proton\.vpn\.platform/listener\.rs:\d+\s*\|\s*\w+\s*\|\s*"
    r"Forwarded port updated\.?\s*",
    re.MULTILINE,
)

# C) Optional connection markers - INFO ONLY, they do not drive the logic.
CONNECTED_RE = re.compile(r"CONN:STATE_CHANGED\s*\|\s*Connected")


def port_from_match(match: "re.Match[str]") -> "int | None":
    """Parse and validate a port from a full "Receiving Response" body.

    ``internal_port`` is authoritative (and required); ``external_port`` is
    optional and only used for an anomaly warning.
    """
    body = match.group(1)
    internal_match = INTERNAL_PORT_RE.search(body)
    if internal_match is None:
        return None
    try:
        internal = int(internal_match.group(1))
    except ValueError:
        return None
    external_match = EXTERNAL_PORT_RE.search(body)
    if external_match is not None:
        try:
            external = int(external_match.group(1))
        except ValueError:
            external = internal
        if internal != external:
            # In the Proton model they are equal (port forwarding without NAT).
            log.warning("Anomaly: internal_port %s != external_port %s - using internal_port.",
                        internal, external)
    if not (PORT_MIN <= internal <= PORT_MAX):
        log.warning("Port %s is outside the valid range %d-%d - ignoring.", internal, PORT_MIN, PORT_MAX)
        return None
    return internal


def extract_port(line: bytes) -> "int | None":
    """Process ONE binary line; fast path without the full regex (§6.4)."""
    if b"port_forwarding.rs" not in line or b"Receiving Response" not in line:
        return None
    match = PORT_RENEW_RE.search(line.decode("utf-8", "replace"))
    if not match:
        return None
    return port_from_match(match)


def extract_ports(data: bytes) -> "list[int]":
    """Split a raw blob on \\n and return all valid ports (incl. the last partial line)."""
    ports = []
    for line in data.split(b"\n"):
        p = extract_port(line)
        if p is not None:
            ports.append(p)
    return ports


# ---------------------------------------------------------------------------
# 7.4  Self-healing: the latest forwarded port from the tails of .log..log.3
# ---------------------------------------------------------------------------

def current_forwarded_port(cfg: dict) -> "int | None":
    """Walk from the NEWEST to the oldest file and return the last valid port."""
    tail_bytes = int(cfg["tail_scan_bytes"])
    for suffix in ("", ".1", ".2", ".3"):
        path = cfg["log_path"] + suffix
        try:
            with open(path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - tail_bytes))
                data = fh.read()
        except OSError:
            continue  # file missing / unreadable
        text = data.decode("utf-8", "replace")
        last_valid = None
        for match in PORT_RENEW_RE.finditer(text):
            p = port_from_match(match)
            if p is not None:
                last_valid = p  # we want the NEWEST valid occurrence
        if last_valid is not None:
            return last_valid
    return None


# ---------------------------------------------------------------------------
# qBittorrent client errors (distinguished so backoff can be handled per type,
# §7.6)
# ---------------------------------------------------------------------------

class AuthError(Exception):
    """Bad credentials / IP ban / persistent 403 / bad API key."""


class QbitUnavailable(Exception):
    """qBittorrent unavailable (network, timeout, HTTP error, Web UI off)."""


# Hint for the auth error in API-key (Bearer) mode - see §8.5.
API_KEY_AUTH_HINT = ("The API key is invalid/revoked/incorrect - check "
                     "Options->Web UI->Authentication->API Key in qBittorrent "
                     "or generate a new one")


# ---------------------------------------------------------------------------
# 7.6  Exponential backoff (separate: qBittorrent vs. auth/ban)
# ---------------------------------------------------------------------------

class Backoff:
    """Exponential backoff with a cap; reset on success."""

    def __init__(self, base_s: float, cap_s: float) -> None:
        self.base = max(1.0, float(base_s))
        self.cap = float(cap_s)
        self._current = None  # type: "float | None"
        self._until = 0.0

    def ok(self) -> None:
        """Success - reset back to the base."""
        self._current = None
        self._until = 0.0

    def fail(self) -> float:
        """Failure - double the wait; return the current wait in seconds."""
        if self._current is None:
            self._current = self.base
        else:
            self._current = min(self.cap, self._current * 2.0)
        self._until = time.time() + self._current
        return self._current

    def in_wait(self) -> bool:
        """Are we still in the waiting phase (avoid hammering)?"""
        return time.time() < self._until


# ---------------------------------------------------------------------------
# 8  qBittorrent Web API client (5.2.x - api_key Bearer OR login + CSRF
#     Referer; form field `json`)
# ---------------------------------------------------------------------------

class QBittorrent:
    """Web API client - either API-key mode (Bearer, no login/CSRF), or the
    user/password mode with a shared cookie jar (SID session). §8"""

    def __init__(self, cfg: dict, logger: logging.Logger) -> None:
        qb = cfg["qbittorrent"]
        self.base_url = str(qb["base_url"]).rstrip("/")
        self.username = qb["username"]
        self.password = qb["password"]  # type: "str | None"
        self.api_key = qb.get("api_key") or ""  # type: str  # secret - never log it
        # A set api_key means BEARER ONLY; otherwise username+password (unchanged).
        self.auth_mode = "api_key" if self.api_key else "user_pass"
        self.timeout = float(qb["http_timeout_s"])
        self.log = logger
        self.jar = http.cookiejar.CookieJar()
        self.insecure_https = bool(qb["insecure_https"])
        # An empty ProxyHandler disables the env proxies (HTTP_PROXY/HTTPS_PROXY):
        # qBittorrent is (by default) local, and the API key must never be sent
        # to a proxy just because one is configured in the environment.
        handlers = [urlrequest.ProxyHandler({}), urlrequest.HTTPCookieProcessor(self.jar)]
        if self.insecure_https:
            # HTTPS with a self-signed cert (loopback): non-verifying SSL context
            # (insecure_https: true in the config) - see §8 / DESIGN. Plain HTTP
            # is unaffected; the handler only applies to https URLs.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            handlers.append(urlrequest.HTTPSHandler(context=context))
        # Default: verifying SSL context (HTTP and HTTPS with a valid cert).
        self.opener = urlrequest.build_opener(*handlers)
        # API-key mode: no login is needed - on a matching key the server creates
        # a session by itself (and the session NEVER expires), so authed = True
        # right from the start.
        self.authed = bool(self.api_key)

    # -- low-level request --------------------------------------------------
    def _request(self, method: str, path: str, data: "bytes | None" = None):
        """Return (status, body). Network errors raise QbitUnavailable.

        Headers depend on the authentication mode (§8):
        - api_key: `Authorization: Bearer <key>` on EVERY request, no
          Referer/CSRF (the server skips the CSRF check in this mode).
        - username/password: Referer = base_url + "/" (CSRF, 5.x default),
          then the SID cookie from the cookie jar.
        The Authorization header is never logged (the key is a secret).
        """
        headers = {"User-Agent": "%s/%s" % (APP_NAME, VERSION)}
        if self.api_key:
            headers["Authorization"] = "Bearer %s" % self.api_key
        else:
            headers["Referer"] = self.base_url + "/"
        if data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        request = urlrequest.Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as resp:
                return resp.status, resp.read()
        except urlerror.HTTPError as exc:
            try:
                body = exc.read()
            except Exception:
                body = b""
            return exc.code, body
        except (urlerror.URLError, TimeoutError, ConnectionError, socket.timeout,
                OSError, ValueError) as exc:
            raise QbitUnavailable("qBittorrent unavailable: %s" % exc) from exc

    # -- login (§8.2) - only in username/password mode; never called for api_key ---
    def _login(self) -> None:
        if self.auth_mode == "api_key":
            # /api/v2/auth/login is rejected via the API key (Forbidden).
            raise AuthError("login is not performed in API-key mode")
        if not self.username or not self.password:
            raise AuthError("missing credentials (username/password)")
        data = urlparse.urlencode({"username": self.username, "password": self.password}).encode("utf-8")
        status, body = self._request("POST", "/api/v2/auth/login", data)
        # Success: HTTP 200/204 (5.x returns 204 No Content with no body; 4.x
        # returned 200 + "Ok.") AND a session cookie with a value is present in
        # the cookie jar - the session cookie is the decisive sign of success.
        # Cookie name: qB 4.x = "SID", qB 5.x = "QBT_SID_<port>" (e.g. QBT_SID_8080).
        sid_ok = any(c.value and (c.name == "SID" or c.name.startswith("QBT_SID_"))
                     for c in self.jar)
        if status in (200, 204) and sid_ok:
            self.authed = True
            return
        # Login failure: 401 (bad credentials), 403 (ban/CSRF), or body "Fails.".
        if status in (401, 403) or b"Fails." in body:
            self.authed = False
            if status == 403:
                raise AuthError("HTTP 403 during login - possible temporary IP ban "
                                "(WebUI\\MaxAuthenticationFailCount) or a CSRF/Referer problem")
            raise AuthError("incorrect username or password (HTTP %s)" % status)
        self.authed = False
        raise QbitUnavailable("unexpected login response: HTTP %s" % status)

    def ensure_login(self) -> None:
        if self.authed:
            return
        self._login()

    # API-key mode: HTTP 401/403 = invalid/revoked/incorrect key - raise
    # AuthError with a clear message (no re-login; the key is never logged).
    # User/pass mode: no effect (401/403 are handled by _login and re-login below).
    def _raise_if_auth_failed(self, status: int) -> None:
        if self.auth_mode == "api_key" and status in (401, 403):
            raise AuthError(API_KEY_AUTH_HINT)

    # -- reading the current port (§8.3) ------------------------------------
    def get_listen_port(self) -> int:
        self.ensure_login()
        for attempt in (0, 1):
            status, body = self._request("GET", "/api/v2/app/preferences")
            if status == 200:
                try:
                    data = json.loads(body)
                    return int(data["listen_port"])
                except (ValueError, KeyError, TypeError) as exc:
                    raise QbitUnavailable("invalid /preferences response: %s" % exc) from exc
            # api_key: 401/403 - AuthError (no re-login); otherwise cookie mode.
            self._raise_if_auth_failed(status)
            if status == 403:
                # Session expired/revoked - re-login + 1 retry (user/pass only).
                self.authed = False
                if attempt == 0:
                    self.log.warning("HTTP 403 on /preferences - re-login and retry.")
                    try:
                        self._login()
                    except AuthError:
                        raise
                    continue
                raise AuthError("HTTP 403 even after re-login - insufficient session or ban")
            raise QbitUnavailable("HTTP %s from /preferences" % status)
        raise QbitUnavailable("get_listen_port finished without a result")  # unreachable

    # -- setting the port (§8.4) --------------------------------------------
    def apply_port(self, port: int) -> None:
        self.ensure_login()
        # Critical: the form field `json` = urlencoded JSON string (not a raw body).
        payload = urlparse.urlencode({"json": json.dumps({"listen_port": port})}).encode("utf-8")
        for attempt in (0, 1):
            status, body = self._request("POST", "/api/v2/app/setPreferences", payload)
            # Success = HTTP 200/204 (5.x returns 204 No Content without the body
            # "Ok."; 4.x returned 200 + "Ok."). qBittorrent reports errors via a
            # non-2xx status.
            if status in (200, 204):
                return
            # api_key: 401/403 - AuthError (no re-login); otherwise cookie mode.
            self._raise_if_auth_failed(status)
            if status == 403:
                self.authed = False
                if attempt == 0:
                    self.log.warning("HTTP 403 on setPreferences - re-login and retry.")
                    try:
                        self._login()
                    except AuthError:
                        raise
                    continue
                raise AuthError("HTTP 403 even after re-login on setPreferences - session or ban")
            raise QbitUnavailable("HTTP %s from setPreferences (expected 200/204)" % status)

    # -- version (for --check / the "is the Web UI up" heuristic) ----------
    def get_version(self) -> str:
        self.ensure_login()
        status, body = self._request("GET", "/api/v2/app/version")
        if status == 200:
            return body.decode("utf-8", "replace").strip()
        # api_key: 401/403 - AuthError (the key is wrong/revoked), no re-login.
        self._raise_if_auth_failed(status)
        raise QbitUnavailable("HTTP %s from /app/version" % status)


# ---------------------------------------------------------------------------
# 7  Watcher: follow-the-log, rotation, self-healing, dedup, backoff
# ---------------------------------------------------------------------------

class Watcher:
    """Main run state machine (single instance thanks to the flock)."""

    def __init__(self, cfg: dict, state: dict, logger: logging.Logger) -> None:
        self.cfg = cfg
        self.state = state
        self.log = logger
        self.qbit = QBittorrent(cfg, logger)
        # Binary buffer for an incomplete trailing line (kept in memory, §7.3.1).
        self.pending_bytes = b""
        # The port we want to push into qBittorrent but have not applied yet.
        self.pending_port = None  # type: "int | None"
        intervals = cfg["intervals"]
        self.qbit_bo = Backoff(intervals["qbit_backoff_base_s"], intervals["qbit_backoff_max_s"])
        self.auth_bo = Backoff(intervals["auth_backoff_base_s"], intervals["auth_backoff_max_s"])
        self.reconcile_s = float(intervals["reconcile_s"])
        self._next_reconcile = time.monotonic() + self.reconcile_s

    # -- state --------------------------------------------------------------
    def save_state(self) -> None:
        save_state_file(self.cfg["state_dir"], self.state)

    def _remember_port(self, port: int) -> None:
        self.state["last_seen_port"] = port
        self.save_state()

    def has_pending_work(self) -> bool:
        """True when the sync is not finished (--once uses this for its exit code)."""
        return (self.pending_port is not None
                or self.qbit_bo.in_wait() or self.auth_bo.in_wait())

    @staticmethod
    def _prefix_hash(path: str, length: int) -> "str | None":
        """SHA-256 of exactly ``length`` bytes from the start of the file."""
        try:
            with open(path, "rb") as fh:
                data = fh.read(max(0, length))
        except OSError:
            return None
        if len(data) != length:
            return None
        return hashlib.sha256(data).hexdigest()

    # -- main tick ----------------------------------------------------------
    def tick(self) -> float:
        """One pass through the loop; returns the recommended sleep in seconds."""
        cfg = self.cfg
        try:
            st = os.stat(cfg["log_path"])
        except FileNotFoundError:
            self.log.warning("ProtonVPN log not found (%s) - the VPN app is probably "
                             "not running; waiting %s s.",
                             cfg["log_path"], cfg["intervals"]["offline_s"])
            return float(cfg["intervals"]["offline_s"])
        except OSError as exc:
            self.log.warning("Cannot read the log (%s): %s", cfg["log_path"], exc)
            return float(cfg["intervals"]["offline_s"])

        follow = self.state.get("follow")
        key = (st.st_dev, st.st_ino)

        # Rotation (rename) OR the first start (§7.3.2).
        if follow is None or (follow.get("dev"), follow.get("ino")) != key:
            self.handle_file_change(st)
            # §7.3.3: after a change we know no port - tail-scan across .1..log.3
            if self.state.get("last_seen_port") is None:
                self.self_heal()
            self.flush_pending()
            return float(cfg["intervals"]["connected_s"])

        # Guard against the copytruncate rotation variant. The size check alone is
        # not enough: the file can be truncated and grow back past the old offset
        # between two ticks. The prefix fingerprint detects that reliably.
        prefix_len = min(PREFIX_BYTES, st.st_size)
        prefix = self._prefix_hash(cfg["log_path"], prefix_len)
        expected_prefix = follow.get("prefix_sha256")
        expected_len = follow.get("prefix_len")
        offset = follow.get("offset", 0)
        if prefix is not None:
            if expected_prefix is None or offset == 0:
                # Migration from an older state file / nothing read yet: nothing
                # was skipped, so just remember the fingerprint.
                follow["prefix_sha256"] = prefix
                follow["prefix_len"] = prefix_len
                self.save_state()
            elif expected_len is None:
                # State with a fingerprint but without its length - migrate.
                follow["prefix_sha256"] = prefix
                follow["prefix_len"] = prefix_len
                self.save_state()
            else:
                # Compare only the bytes covered by the stored fingerprint; a
                # grown file therefore does not produce a false positive.
                same_len = self._prefix_hash(cfg["log_path"], expected_len)
                if same_len is None or same_len != expected_prefix:
                    self.log.warning("The log was truncated/rewritten "
                                     "(content prefix changed) - self-healing.")
                    follow["offset"] = 0
                    follow["prefix_sha256"] = prefix
                    follow["prefix_len"] = prefix_len
                    self.pending_bytes = b""
                    self.save_state()
                    self.self_heal()
                    self.flush_pending()
                    return float(cfg["intervals"]["connected_s"])
                if prefix_len > expected_len:
                    # The file grew beyond the fingerprinted prefix - extend it.
                    follow["prefix_sha256"] = prefix
                    follow["prefix_len"] = prefix_len
                    self.save_state()

        # Belt and braces: offset past EOF (e.g. a state file without fingerprint).
        if follow.get("offset", 0) > st.st_size:
            self.log.warning("File was truncated (offset %s > size %s) - self-healing.",
                             follow.get("offset"), st.st_size)
            follow["offset"] = 0
            if prefix is not None:
                follow["prefix_sha256"] = prefix
            self.pending_bytes = b""
            self.save_state()
            self.self_heal()
            self.flush_pending()
            return float(cfg["intervals"]["connected_s"])

        # Normal follow: read new lines from the stored offset.
        for port in self.read_new_lines():
            self.on_new_port(port)

        # §7.3.3: the log exists, but we do not know any port yet - tail-scan
        # (also covers a freshly emptied log where the real state is in .log.1).
        if self.state.get("last_seen_port") is None:
            self.self_heal()
        elif time.monotonic() >= self._next_reconcile:
            # Periodic reconciliation: catches a manual change in qBittorrent
            # (or a restart with an old listen_port) even while the forwarded
            # port stays the same. The comparison itself is cheap and dedup'd.
            self._next_reconcile = time.monotonic() + self.reconcile_s
            self.self_heal()

        self.flush_pending()
        return float(cfg["intervals"]["connected_s"])

    # -- rotation / file change ----------------------------------------------
    def handle_file_change(self, st: os.stat_result) -> None:
        cfg = self.cfg
        old = self.state.get("follow")

        if old is not None:
            # Rename rotation: the rest of the old content is in vpn-app.log.1.
            # Read from our offset to EOF - process the boundary events.
            path1 = cfg["log_path"] + ".1"
            try:
                with open(path1, "rb") as fh:
                    info = os.fstat(fh.fileno())
                    if (info.st_dev, info.st_ino) == (old.get("dev"), old.get("ino")):
                        size = info.st_size
                        offset = old.get("offset", 0)
                        if offset < size:
                            self.log.info("Reading trailing boundary events from %s (offset %s).", path1, offset)
                            fh.seek(offset)
                            for port in extract_ports(fh.read()):
                                self.on_new_port(port)
            except FileNotFoundError:
                pass  # fallback: self-healing below (last_seen None) catches up
            except OSError as exc:
                self.log.debug("Cannot read the rotated file %s: %s", path1, exc)
        else:
            self.log.info("First run - starting to watch %s.", cfg["log_path"])

        if old is None:
            # First run: we do NOT replay the whole file history (it could contain
            # an older port from a previous connection); the current state is found
            # by the self-healing tail-scan, and we continue past the current EOF.
            offset = st.st_size
        else:
            # Rotation: the new file is chronologically NEWER - read from the start.
            offset = 0

        prefix_len = min(PREFIX_BYTES, st.st_size)
        self.state["follow"] = {
            "dev": st.st_dev,
            "ino": st.st_ino,
            "offset": offset,
            "prefix_sha256": self._prefix_hash(cfg["log_path"], prefix_len),
            "prefix_len": prefix_len,
        }
        self.pending_bytes = b""
        self.save_state()
        self.log.info("Watching a new file (dev=%s, ino=%s), offset=%s.", st.st_dev, st.st_ino, offset)

    # -- follow-by-offset with a binary pending buffer (§7.3.1) ---------------
    def read_new_lines(self) -> "list[int]":
        cfg = self.cfg
        follow = self.state["follow"]
        try:
            fh = open(cfg["log_path"], "rb")
        except OSError:
            return []
        with fh:
            info = os.fstat(fh.fileno())
            if (info.st_dev, info.st_ino) != (follow["dev"], follow["ino"]):
                return []  # the file changed between stat and open - tick handles rotation
            size = info.st_size
            offset = follow["offset"]
            if offset >= size:
                return []  # nothing new
            if offset > size:
                return []  # truncated - the guard in tick triggers self-healing
            fh.seek(offset)
            data = fh.read(READ_CHUNK_BYTES)
            follow["offset"] = offset + len(data)  # the rest is read on the next tick

        # We never cut through the middle of a UTF-8 character: the buffer is kept
        # binary and complete lines are only split after a \n.
        raw = self.pending_bytes + data
        nl = raw.rfind(b"\n")
        if nl == -1:
            if len(raw) > MAX_PENDING_BYTES:
                self.log.warning("Incomplete log line exceeds %d bytes - discarding it.",
                                 MAX_PENDING_BYTES)
                raw = b""
            self.pending_bytes = raw  # incomplete trailing line - next tick
            self.save_state()
            return []
        chunk = raw[: nl + 1]
        self.pending_bytes = raw[nl + 1:]
        self.save_state()

        ports = []
        for line in chunk.split(b"\n")[:-1]:
            p = extract_port(line)
            if p is not None:
                ports.append(p)
        return ports

    # -- dedup / apply (§7.5) -------------------------------------------------
    def on_new_port(self, port: int) -> None:
        if port == self.state.get("last_seen_port"):
            return  # duplicate renewal (or an older line) - done
        self._remember_port(port)
        self.log.info("New forwarded port from the log: %s.", port)
        self.pending_port = port
        self.flush_pending()

    def self_heal(self, force: bool = False) -> None:
        """§7.4 - tail-scan and bring qBittorrent into sync.

        Always compares qBittorrent's current listen_port with the forwarded port
        (attempt_sync dedups a match itself - so no unnecessary POST). Called at
        startup, after a rotation/truncation and periodically (``reconcile_s``),
        so it also covers "qBittorrent was changed manually in the meantime"
        (DESIGN.md §1.3 / §7.4 / §10.6). ``force`` (--force) forces a POST even
        on a match.
        """
        fwd = current_forwarded_port(self.cfg)
        if fwd is None:
            self.log.info("No forwarded port in the log yet - waiting for a renewal.")
            return
        if self.state.get("last_seen_port") != fwd:
            self._remember_port(fwd)
        self.pending_port = fwd
        self.flush_pending(force=force)

    def flush_pending(self, force: bool = False) -> None:
        """Retry an unfinished sync (qBittorrent may have come back meanwhile)."""
        if self.pending_port is None:
            return
        result = self.attempt_sync(self.pending_port, force=force)
        if result in ("ok", "dry"):
            self.pending_port = None

    # -- compare and apply with dedup/backoff (§7.5, §7.6) --------------------
    def attempt_sync(self, port: int, force: bool = False) -> str:
        """Compare with qBittorrent's current listen_port and set it if needed.

        Returns a status: ok | dry | unavail | authfail | wait.
        """
        if self.qbit_bo.in_wait() or self.auth_bo.in_wait():
            return "wait"  # do not hammer (backoff is running)

        try:
            current = self.qbit.get_listen_port()
        except AuthError as exc:
            self._auth_failure(exc)
            return "authfail"
        except QbitUnavailable as exc:
            self._qbit_failure(exc)
            return "unavail"

        if current == port and not force:
            self._qbit_ok()
            # DEBUG: the periodic reconciliation would otherwise log this every
            # reconcile_s seconds.
            self.log.debug("Port %s is already set in qBittorrent - no unnecessary call.", port)
            return "ok"

        if self.cfg["dry_run"]:
            self._qbit_ok()
            self.log.info("DRY-RUN: would set listen_port=%s (currently %s).", port, current)
            return "dry"

        try:
            self.qbit.apply_port(port)
        except AuthError as exc:
            self._auth_failure(exc)
            return "authfail"
        except QbitUnavailable as exc:
            self._qbit_failure(exc)
            return "unavail"

        self.state["last_applied_port"] = port
        self.save_state()
        self._qbit_ok()
        self.log.info("listen_port in qBittorrent set to %s.", port)
        return "ok"

    # -- backoff helpers ------------------------------------------------------
    def _qbit_ok(self) -> None:
        self.qbit_bo.ok()
        self.auth_bo.ok()

    def _qbit_failure(self, exc: Exception) -> None:
        wait = self.qbit_bo.fail()
        self.log.warning("qBittorrent unavailable (%s) - I remember the port and will retry "
                         "in %d s (without hammering).", exc, int(wait))

    def _auth_failure(self, exc: Exception) -> None:
        wait = self.auth_bo.fail()
        self.log.error("Authentication to qBittorrent failed: %s. Check in %s (mode 0600) "
                       "'qbittorrent.api_key' (API key - recommended) OR "
                       "'username'/'password' (password also via env %s). Next attempt in %d s "
                       "(slow backoff because of a possible temporary IP ban).",
                       exc, self.cfg["_config_path"], ENV_PASSWORD, int(wait))


# ---------------------------------------------------------------------------
# 5  Configuration (JSON, 0600), 7.1 state + lock, logging
# ---------------------------------------------------------------------------

class ConfigError(Exception):
    """Configuration error - readable report, no start."""


TOP_KEYS = {
    "log_path", "state_dir", "own_log_file", "log_level", "qbittorrent",
    "intervals", "tail_scan_bytes", "dry_run", "force_on_start",
}
QB_KEYS = {"base_url", "username", "password", "api_key", "http_timeout_s", "insecure_https"}
INTERVAL_KEYS = {
    "connected_s", "offline_s", "reconcile_s", "qbit_backoff_base_s",
    "qbit_backoff_max_s", "auth_backoff_base_s", "auth_backoff_max_s",
}


def default_config() -> dict:
    return {
        "log_path": DEFAULT_LOG,
        "state_dir": DEFAULT_STATE_DIR,
        "own_log_file": "",
        "log_level": "INFO",
        "qbittorrent": {
            "base_url": "http://127.0.0.1:8080",
            "username": "",      # only for the user/password mode
            "password": "",      # only for the user/password mode (config/env)
            "api_key": "",       # preferred: Bearer API key (then the password is ignored)
            "http_timeout_s": 10,
            "insecure_https": False,
        },
        "intervals": {
            "connected_s": 15,
            "offline_s": 60,
            "reconcile_s": 300,
            "qbit_backoff_base_s": 5,
            "qbit_backoff_max_s": 120,
            "auth_backoff_base_s": 60,
            "auth_backoff_max_s": 600,
        },
        "tail_scan_bytes": 1048576,
        "dry_run": False,
        "force_on_start": False,
        "_config_path": DEFAULT_CONFIG,  # internal (never written to the file)
    }


def _merge_section(target: dict, section: dict, allowed: set, path_label: str) -> None:
    if not isinstance(section, dict):
        raise ConfigError("%s must be a JSON object." % path_label)
    for key, value in section.items():
        if key not in allowed:
            raise ConfigError("Unknown key '%s' in %s (typo?)." % (key, path_label))
        target[key] = value


def load_config(path: str, require_credentials: bool = True) -> dict:
    """Load and validate the configuration; return the full dict (defaults + file).

    Authentication: EITHER api_key OR username+password (see below). When
    require_credentials=False (--check), missing credentials are not reported as
    an error - the diagnostics just lists what is missing and does not contact
    qBittorrent.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            user = json.load(fh)
    except FileNotFoundError:
        raise ConfigError("Configuration not found: %s\n"
                          "Copy protonport.conf.example and fill in the credentials." % path) from None
    except json.JSONDecodeError as exc:
        raise ConfigError("Invalid JSON in %s: %s" % (path, exc)) from exc
    if not isinstance(user, dict):
        raise ConfigError("Configuration %s must be a JSON object." % path)

    cfg = default_config()
    cfg["_config_path"] = os.path.abspath(path)
    # The nested sections are merged INTO the defaults (never replace them), so a
    # partial "qbittorrent"/"intervals" section keeps the built-in values.
    top_level = {key: value for key, value in user.items()
                 if key not in ("qbittorrent", "intervals")}
    _merge_section(cfg, top_level, TOP_KEYS, "the configuration")

    qb = cfg["qbittorrent"]
    _merge_section(qb, user.get("qbittorrent", {}), QB_KEYS, "'qbittorrent'")
    _merge_section(cfg["intervals"], user.get("intervals", {}), INTERVAL_KEYS, "'intervals'")

    # --- normalization and validation ---
    # Paths: support ~ and variables ($HOME) for a portable template.
    for path_key in ("log_path", "state_dir", "own_log_file"):
        if not isinstance(cfg[path_key], str):
            raise ConfigError("'%s' must be a string path." % path_key)
        cfg[path_key] = os.path.expanduser(os.path.expandvars(cfg[path_key]))
    if not cfg["log_path"].strip():
        raise ConfigError("'log_path' is empty.")
    if not cfg["state_dir"].strip():
        raise ConfigError("'state_dir' is empty.")

    if not isinstance(cfg["log_level"], str):
        raise ConfigError("'log_level' must be a string (DEBUG|INFO|WARNING|ERROR).")
    cfg["log_level"] = cfg["log_level"].upper()
    if cfg["log_level"] not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        raise ConfigError("Unknown log level '%s' (DEBUG|INFO|WARNING|ERROR)." % cfg["log_level"])

    if not isinstance(qb["base_url"], str) or not qb["base_url"].strip():
        raise ConfigError("Key 'qbittorrent.base_url' is empty or not a string.")
    qb["base_url"] = qb["base_url"].strip().rstrip("/")
    parsed_url = urlparse.urlsplit(qb["base_url"])
    if parsed_url.scheme not in ("http", "https") or not parsed_url.netloc:
        raise ConfigError("'qbittorrent.base_url' must be an http:// or https:// URL, got %r."
                          % qb["base_url"])
    for name in ("username", "password", "api_key"):
        if qb[name] is not None and not isinstance(qb[name], str):
            raise ConfigError("'qbittorrent.%s' must be a string." % name)

    for name, value in list(qb.items()):
        if name in ("username", "password", "api_key", "base_url", "insecure_https"):
            continue
        if not isinstance(value, (int, float)) or float(value) <= 0:
            raise ConfigError("'qbittorrent.%s' must be a positive number." % name)
    for name, value in cfg["intervals"].items():
        if not isinstance(value, (int, float)) or float(value) <= 0:
            raise ConfigError("'intervals.%s' must be a positive number (seconds)." % name)
    if not isinstance(cfg["tail_scan_bytes"], int) or cfg["tail_scan_bytes"] <= 0:
        raise ConfigError("'tail_scan_bytes' must be a positive integer.")
    for name in ("dry_run", "force_on_start"):
        if not isinstance(cfg[name], bool):
            raise ConfigError("'%s' must be true/false." % name)
    if not isinstance(qb["insecure_https"], bool):
        raise ConfigError("'qbittorrent.insecure_https' must be true/false.")

    # --- authentication: EITHER api_key (Bearer) OR username+password (§8.5) ---
    # api_key: an empty string / the __CHANGE_ME__ placeholder = not set (the
    # same convention as the password). The env variable takes priority (it lets
    # you keep the key off the disk, just like the password). A set api_key takes
    # PRIORITY and the password is then ignored completely (it is never sent to
    # qBittorrent).
    api_key = str(qb.get("api_key") or "").strip()
    env_api_key = (os.environ.get(ENV_API_KEY) or "").strip()
    if env_api_key:
        api_key = env_api_key
    if api_key in ("", PASSWORD_PLACEHOLDER):
        api_key = ""

    username = str(qb.get("username") or "").strip()
    raw_pw = qb.get("password")
    if str(raw_pw or "") in ("", PASSWORD_PLACEHOLDER):
        raw_pw = None

    if api_key:
        qb["api_key"] = api_key
        qb["username"] = username or None
        qb["password"] = None  # API-key mode does not use the password
        have_creds = True
    else:
        # Username/password mode: the env password wins; then the config one.
        qb["api_key"] = ""
        qb["username"] = username or None
        env_pw = os.environ.get(ENV_PASSWORD)
        if env_pw is not None and env_pw != "":
            qb["password"] = env_pw
        else:
            qb["password"] = raw_pw
        have_creds = bool(qb["username"]) and bool(qb["password"])

    if not have_creds and require_credentials:
        raise ConfigError(
            "qBittorrent authentication is not configured.\n"
            "In %s (mode 0600) add EITHER:\n"
            "  * 'qbittorrent.api_key'  - API key (recommended): in qBittorrent\n"
            "    Options -> Web UI -> Authentication -> API Key (Copy button),\n"
            "  * OR 'qbittorrent.username' + 'qbittorrent.password'\n"
            "    (the key/password can also be passed via %s / %s).\n"
            "Secrets are never stored in the code."
            % (path, ENV_API_KEY, ENV_PASSWORD))

    return cfg


def check_config_permissions(path: str, logger: logging.Logger) -> None:
    """§10.1 - check the config permissions; WARNING only, fixing is on the user."""
    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError:
        return
    if mode & 0o077:
        logger.warning("Config %s has mode %o - I recommend chmod 600 (it contains "
                       "a password/API key).", path, mode)


def init_logger(cfg: dict) -> logging.Logger:
    """Log to stderr/stdout (systemd journal), optionally to own_log_file."""
    logger = logging.getLogger(APP_NAME)
    if logger.handlers:  # already initialized (protection against duplicates)
        return logger
    level = getattr(logging, cfg["log_level"], logging.INFO)
    logger.setLevel(level)
    fmt = logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s", "%Y-%m-%d %H:%M:%S")
    own = cfg.get("own_log_file") or ""
    if own:
        parent = os.path.dirname(own)
        if parent:
            os.makedirs(parent, mode=0o700, exist_ok=True)
        handler = RotatingFileHandler(own, maxBytes=1024 * 1024, backupCount=3,
                                      encoding="utf-8")
    else:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    logger.propagate = False
    return logger


# ---------------------------------------------------------------------------
# 7.1  Single-instance lock + persistent state
# ---------------------------------------------------------------------------

def acquire_lock(state_dir: str) -> "int | None":
    """flock on state_dir/protonport.lock; return the fd, or None (another runs)."""
    if fcntl is None:
        raise RuntimeError("fcntl is not available - this tool targets Linux.")
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    lock_path = os.path.join(state_dir, LOCK_FILE)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def load_state(state_dir: str) -> dict:
    """Load the state; corrupted/missing - reset (follow=None), full self-healing."""
    default = {"follow": None, "last_seen_port": None, "last_applied_port": None}
    path = os.path.join(state_dir, STATE_FILE)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        return dict(default)
    except (OSError, json.JSONDecodeError):
        log.warning("Corrupted state (%s) - reset and full self-healing.", path)
        return dict(default)

    state = dict(default)
    if not isinstance(raw, dict):
        log.warning("Corrupted state (%s) - reset and full self-healing.", path)
        return state
    for key in default:
        if key in raw:
            state[key] = raw[key]

    follow = state["follow"]
    if follow is not None:
        if not isinstance(follow, dict) or not all(k in follow for k in ("dev", "ino", "offset")):
            follow = None
        else:
            try:
                follow["offset"] = int(follow["offset"])
                follow["dev"] = int(follow["dev"])
                follow["ino"] = int(follow["ino"])
            except (TypeError, ValueError):
                follow = None
            if follow is not None:
                # Optional (state from an older version has none - it is filled
                # in on the next tick without a reset).
                if not isinstance(follow.get("prefix_sha256"), str):
                    follow["prefix_sha256"] = None
                prefix_len = follow.get("prefix_len")
                if not isinstance(prefix_len, int) or not 0 <= prefix_len <= PREFIX_BYTES:
                    follow["prefix_len"] = None
        state["follow"] = follow
    if state["last_seen_port"] is not None:
        try:
            state["last_seen_port"] = int(state["last_seen_port"])
        except (TypeError, ValueError):
            state["last_seen_port"] = None
    if state["last_applied_port"] is not None:
        try:
            state["last_applied_port"] = int(state["last_applied_port"])
        except (TypeError, ValueError):
            state["last_applied_port"] = None
    return state


def save_state_file(state_dir: str, state: dict) -> None:
    """Atomic state write (tmp + os.replace), mode 0600."""
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    path = os.path.join(state_dir, STATE_FILE)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# --check  (§5.4, §11) - diagnostics without a lock, read-only vs. the system
# ---------------------------------------------------------------------------

def do_check(cfg: dict, logger: logging.Logger) -> int:
    lines = ["=== %s %s - diagnostics ===" % (APP_NAME, VERSION)]

    log_path = cfg["log_path"]
    if os.path.exists(log_path):
        lines.append("ProtonVPN log:    exists (%d B)\n                  %s" % (os.path.getsize(log_path), log_path))
    else:
        lines.append("ProtonVPN log:    MISSING - the VPN app is probably not running (%s)" % log_path)

    fwd = current_forwarded_port(cfg)
    if fwd is None:
        lines.append("Forwarded port from the log:  unknown yet (no valid 'Receiving Response')")
    else:
        lines.append("Forwarded port from the log:  %d" % fwd)

    state = load_state(cfg["state_dir"])
    if state.get("last_applied_port") is not None:
        lines.append("Last port applied by protonport:  %d" % state["last_applied_port"])

    qb = cfg["qbittorrent"]
    if qb.get("api_key"):
        auth_label = "Auth: API key (Bearer)"
        has_creds = True
    elif qb.get("username") and qb.get("password"):
        auth_label = "Auth: user/password"
        has_creds = True
    else:
        auth_label = None
        has_creds = False

    if not has_creds:
        lines.append("qBittorrent:  skipped - neither 'api_key' nor 'username'/'password' is set.")
        lines.append("              In %s (mode 0600) add EITHER 'qbittorrent.api_key'" % cfg["_config_path"])
        lines.append("              (recommended - Options->Web UI->Authentication->API Key),")
        lines.append("              OR 'username' + 'password' (key/password also via env %s / %s)."
                     % (ENV_API_KEY, ENV_PASSWORD))
        lines.append("=== done (the Web API was NOT contacted - read-only) ===")
        print("\n".join(lines))
        return EXIT_OK

    # Only the auth-mode type is printed - the key or password never is.
    lines.append("qBittorrent:  %s" % auth_label)

    qbit = QBittorrent(cfg, logger)
    try:
        lines.append("qBittorrent version:      %s" % qbit.get_version())
    except AuthError as exc:
        lines.append("qBittorrent version:      AUTH FAILED - %s" % exc)
        lines.append("=== done ===")
        print("\n".join(lines))
        return EXIT_ERROR
    except QbitUnavailable as exc:
        lines.append("qBittorrent version:      UNAVAILABLE - %s" % exc)
        lines.append("=== done ===")
        print("\n".join(lines))
        return EXIT_ERROR

    exit_code = EXIT_OK
    try:
        current = qbit.get_listen_port()
        lines.append("qBittorrent listen_port:  %d" % current)
        if fwd is not None and fwd != current:
            lines.append("Status:  OUT OF SYNC - qBittorrent (%d) != log (%d)." % (current, fwd))
            lines.append("         It will be fixed automatically on the next reconciliation "
                         "(reconcile_s), or run:  --once")
            exit_code = EXIT_UNSYNC
        elif fwd is not None:
            lines.append("Status:  in sync (%d)." % fwd)
        else:
            lines.append("Status:  cannot compare - the port from the log is still unknown.")
    except (AuthError, QbitUnavailable) as exc:
        lines.append("qBittorrent listen_port:  cannot be read - %s" % exc)
        exit_code = EXIT_ERROR

    lines.append("=== done ===")
    print("\n".join(lines))
    return exit_code


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="protonport.py",
        description="Keeps the qBittorrent listen port in sync with the ProtonVPN "
                    "port-forwarding port (source: vpn-app.log, applied via the Web API).",
    )
    parser.add_argument("--config", metavar="PATH", default=DEFAULT_CONFIG,
                        help="Path to the configuration (default %s)" % DEFAULT_CONFIG)
    parser.add_argument("--dry-run", action="store_true",
                        help="Never call setPreferences - only log what would happen.")
    parser.add_argument("--force", action="store_true",
                        help="Self-healing at startup applies the port even when it matches qBittorrent.")
    parser.add_argument("--once", action="store_true",
                        help="Run one synchronization cycle and exit (test/cron).")
    parser.add_argument("--check", action="store_true",
                        help="Diagnostics: log? port from the log? qBittorrent listen_port? then exit.")
    parser.add_argument("--version", action="store_true", help="Print the version and exit.")
    return parser


def main(argv: "list[str] | None" = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print("%s %s" % (APP_NAME, VERSION))
        return EXIT_OK

    # --check may run even without credentials (only log + read-only diagnostics,
    # no lock; qBittorrent is only contacted when credentials exist).
    require_credentials = not args.check
    try:
        cfg = load_config(args.config or DEFAULT_CONFIG, require_credentials=require_credentials)
    except ConfigError as exc:
        print("%s: configuration error: %s" % (APP_NAME, exc), file=sys.stderr)
        return EXIT_CONFIG

    if args.dry_run:
        cfg["dry_run"] = True
    if args.force:
        cfg["force_on_start"] = True

    logger = init_logger(cfg)
    check_config_permissions(cfg["_config_path"], logger)

    if args.check:
        return do_check(cfg, logger)

    # Watcher modes (--once / run): the single-instance lock applies.
    lock_fd = acquire_lock(cfg["state_dir"])
    if lock_fd is None:
        logger.error("Another instance is already running (lock %s/%s) - exiting (exit %d).",
                     cfg["state_dir"], LOCK_FILE, EXIT_RUNNING)
        return EXIT_RUNNING
    try:
        state = load_state(cfg["state_dir"])
        watcher = Watcher(cfg, state, logger)

        # §1.3 / §7.4: self-healing sync at startup (applies only on a difference;
        # --force forces it even on a match). The stricter DESIGN.md intent is
        # followed (startup sync EVERY time) - see the deviations notes.
        watcher.self_heal(force=cfg["force_on_start"])

        if args.once:
            # One synchronization cycle (follow + self-healing in a single pass).
            try:
                watcher.tick()
            except Exception:
                logger.exception("Unexpected error during the one-shot cycle.")
                return EXIT_ERROR
            # A cron/test caller must be able to tell "synced" from "could not sync".
            if (watcher.has_pending_work()
                    or watcher.state.get("last_seen_port") is None
                    or current_forwarded_port(cfg) is None):
                logger.warning("The one-shot cycle finished without a completed "
                               "synchronization (exit %d).", EXIT_UNSYNC)
                return EXIT_UNSYNC
            return EXIT_OK

        while True:
            try:
                sleep_s = watcher.tick()
            except Exception:
                logger.exception("Unexpected error in the loop - continuing "
                                 "(thanks to try/except the watcher never crashes).")
                sleep_s = float(cfg["intervals"]["connected_s"])
            time.sleep(max(0.5, float(sleep_s)))
    finally:
        try:
            os.close(lock_fd)
        except OSError:
            pass
    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log.info("Interrupted by the user (SIGINT).")
        sys.exit(EXIT_OK)
