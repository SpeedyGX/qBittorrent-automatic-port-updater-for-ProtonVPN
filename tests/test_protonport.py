"""Unit/integration tests for protonport.py (standard library only).

Run with:  python3 -m unittest discover -s tests -v
"""

import importlib.util
import json
import logging
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock
from urllib.parse import parse_qs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SPEC = importlib.util.spec_from_file_location("protonport", os.path.join(ROOT, "protonport.py"))
pp = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(pp)

API_KEY = "test-api-key"


def setUpModule():
    # Keep the test output clean: main()'s init_logger() sees an existing handler
    # and returns early, so nothing is written to stderr during the tests.
    pp.log.addHandler(logging.NullHandler())
    pp.log.propagate = False
    pp.log.setLevel(logging.CRITICAL)


def log_line(port, internal_first=True, external=None):
    external = port if external is None else external
    fields = ("internal_port: %d, external_port: %d" % (port, external)
              if internal_first else
              "external_port: %d, internal_port: %d" % (external, port))
    return ("2026-01-01T00:00:00+00:00 | proton.vpn.platform/port_forwarding.rs:240 | "
            "INFO | Receiving Response { version: 0, operation: 130, response_code: 0, "
            + fields + ", lifetime_seconds: 60 }\n")


class QbitState:
    def __init__(self, port=1):
        self.port = port
        self.sets = []
        self.logins = 0
        self.fail_login = False


def make_handler(state, api_key=API_KEY):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format, *_args):  # silence the test output
            pass

        def _send(self, code, body=b"", headers=()):
            self.send_response(code)
            for key, value in headers:
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self):
            if self.headers.get("Authorization") == "Bearer %s" % api_key:
                return True
            cookie = self.headers.get("Cookie") or ""
            return "SID=" in cookie or "QBT_SID_" in cookie

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length)
            if self.path == "/api/v2/auth/login":
                state.logins += 1
                if state.fail_login:
                    return self._send(401)
                return self._send(204, b"", [("Set-Cookie", "QBT_SID_8080=abc; Path=/")])
            if not self._authorized():
                return self._send(403)
            if self.path == "/api/v2/app/setPreferences":
                data = json.loads(parse_qs(body.decode())["json"][0])
                state.port = data["listen_port"]
                state.sets.append(state.port)
                return self._send(204)
            return self._send(404)

        def do_GET(self):
            if not self._authorized():
                return self._send(403)
            if self.path == "/api/v2/app/preferences":
                return self._send(200, json.dumps({"listen_port": state.port}).encode())
            if self.path == "/api/v2/app/version":
                return self._send(200, b"v5.2.0")
            return self._send(404)

    return Handler


class FakeServer(ThreadingHTTPServer):
    daemon_threads = True


def free_port():
    """A TCP port that is currently closed (for the unavailable-qBittorrent test)."""
    import socket
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class BaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log_path = os.path.join(self.tmp.name, "vpn-app.log")
        self.state_dir = os.path.join(self.tmp.name, "state")
        self.qbit_state = QbitState()
        self.server = FakeServer(("127.0.0.1", 0), make_handler(self.qbit_state))
        threading.Thread(target=self.server.serve_forever,
                         kwargs={"poll_interval": 0.01}, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base_url = "http://127.0.0.1:%d" % self.server.server_address[1]
        self.logger = pp.log

    def write_log(self, *ports, path=None, internal_first=True):
        with open(path or self.log_path, "w", encoding="utf-8") as fh:
            for port in ports:
                fh.write(log_line(port, internal_first=internal_first))

    def append_log(self, port, path=None):
        with open(path or self.log_path, "a", encoding="utf-8") as fh:
            fh.write(log_line(port))

    def make_config(self, **overrides):
        cfg = pp.default_config()
        cfg["log_path"] = self.log_path
        cfg["state_dir"] = self.state_dir
        cfg["_config_path"] = os.path.join(self.tmp.name, "protonport.conf")
        cfg["qbittorrent"].update({
            "base_url": self.base_url,
            "username": "user",
            "password": "pass",
            "api_key": "",
            "http_timeout_s": 2,
        })
        cfg["intervals"].update({
            "connected_s": 0.01,
            "offline_s": 0.01,
            "reconcile_s": 300,
            "qbit_backoff_base_s": 0.01,
            "qbit_backoff_max_s": 0.01,
            "auth_backoff_base_s": 0.01,
            "auth_backoff_max_s": 0.01,
        })
        cfg.update(overrides)
        return cfg

    def make_watcher(self, cfg=None):
        cfg = cfg or self.make_config()
        state = pp.load_state(cfg["state_dir"])
        return pp.Watcher(cfg, state, self.logger)


class ParsingTests(BaseTest):
    def test_extract_ports_ignores_invalid_and_foreign_lines(self):
        data = (
            log_line(43991)
            + "some unrelated line with internal_port: 1234\n"
            + log_line(80)                      # below PORT_MIN
            + log_line(70000)                   # above PORT_MAX (5 digits)
        ).encode()
        self.assertEqual(pp.extract_ports(data), [43991])

    def test_both_field_orders_are_accepted(self):
        for internal_first in (True, False):
            data = log_line(43991, internal_first=internal_first).encode()
            self.assertEqual(pp.extract_ports(data), [43991], internal_first)

    def test_internal_port_wins_on_mismatch(self):
        data = log_line(40000, external=50000).encode()
        self.assertEqual(pp.extract_ports(data), [40000])

    def test_current_forwarded_port_prefers_the_newest_file(self):
        self.write_log(50000, path=self.log_path + ".1")
        self.write_log(60000)
        cfg = self.make_config()
        self.assertEqual(pp.current_forwarded_port(cfg), 60000)


class ConfigTests(BaseTest):
    def write_config(self, data):
        path = os.path.join(self.tmp.name, "test.conf")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        return path

    def test_partial_sections_keep_defaults(self):
        path = self.write_config({
            "intervals": {"connected_s": 10},
            "qbittorrent": {"base_url": "http://127.0.0.1:8080"},
        })
        cfg = pp.load_config(path, require_credentials=False)
        self.assertEqual(cfg["intervals"]["connected_s"], 10)
        self.assertEqual(cfg["intervals"]["reconcile_s"], 300)
        self.assertEqual(cfg["intervals"]["qbit_backoff_base_s"], 5)
        self.assertFalse(cfg["qbittorrent"]["insecure_https"])
        self.assertEqual(cfg["qbittorrent"]["http_timeout_s"], 10)
        # The watcher must be constructible from such a config.
        pp.Watcher(cfg, pp.load_state(cfg["state_dir"]), self.logger)

    def test_non_object_sections_are_rejected_cleanly(self):
        for data in ({"qbittorrent": 5}, {"intervals": []}):
            with self.assertRaises(pp.ConfigError):
                pp.load_config(self.write_config(data), require_credentials=False)

    def test_unknown_key_is_rejected(self):
        with self.assertRaises(pp.ConfigError):
            pp.load_config(self.write_config({"log_paht": "x"}), require_credentials=False)

    def test_wrong_path_type_is_rejected(self):
        with self.assertRaises(pp.ConfigError):
            pp.load_config(self.write_config({"log_path": 5}), require_credentials=False)

    def test_invalid_base_url_scheme_is_rejected(self):
        data = {"qbittorrent": {"base_url": "file:///etc/passwd"}}
        with self.assertRaises(pp.ConfigError):
            pp.load_config(self.write_config(data), require_credentials=False)

    def test_api_key_from_environment_has_priority(self):
        path = self.write_config({"qbittorrent": {"api_key": "config-key"}})
        env = {"PROTONPORT_QBIT_API_KEY": "env-key"}
        with mock.patch.dict(os.environ, env):
            cfg = pp.load_config(path)
        self.assertEqual(cfg["qbittorrent"]["api_key"], "env-key")
        self.assertIsNone(cfg["qbittorrent"]["password"])

    def test_credentials_are_required_in_watcher_mode(self):
        path = self.write_config({"qbittorrent": {"username": "user",
                                                  "password": "__CHANGE_ME__"}})
        with self.assertRaises(pp.ConfigError):
            pp.load_config(path)
        # --check may run without credentials.
        pp.load_config(path, require_credentials=False)


class WatcherTests(BaseTest):
    def test_startup_sync_applies_the_forwarded_port(self):
        self.write_log(43991)
        watcher = self.make_watcher()
        watcher.self_heal()
        self.assertEqual(self.qbit_state.port, 43991)
        self.assertEqual(self.qbit_state.sets, [43991])

    def test_duplicate_renewal_does_not_call_setpreferences(self):
        self.write_log(43991)
        watcher = self.make_watcher()
        watcher.self_heal()
        watcher.tick()
        self.append_log(43991)
        watcher.tick()
        self.assertEqual(self.qbit_state.sets, [43991])

    def test_new_port_is_applied(self):
        self.write_log(43991)
        watcher = self.make_watcher()
        watcher.self_heal()
        watcher.tick()
        self.append_log(50000)
        watcher.tick()
        self.assertEqual(self.qbit_state.sets, [43991, 50000])

    def test_rename_rotation_reads_boundary_events(self):
        self.write_log(43991)
        watcher = self.make_watcher()
        watcher.self_heal()
        watcher.tick()
        self.append_log(50000)
        os.rename(self.log_path, self.log_path + ".1")
        with open(self.log_path, "w", encoding="utf-8"):
            pass
        watcher.tick()
        self.assertEqual(self.qbit_state.sets[-1], 50000)

    def test_copytruncate_with_same_size_is_detected(self):
        self.write_log(43991)
        watcher = self.make_watcher()
        watcher.self_heal()
        watcher.tick()
        # Same inode, same length, different content: only the prefix
        # fingerprint can notice this.
        self.write_log(50000)
        watcher.tick()
        self.assertEqual(self.qbit_state.port, 50000)
        self.assertEqual(self.qbit_state.sets[-1], 50000)

    def test_copytruncate_with_regrowth_past_the_old_offset(self):
        self.write_log(43991)
        watcher = self.make_watcher()
        watcher.self_heal()
        watcher.tick()
        self.write_log(50000, 50000)  # truncated and regrown beyond the old offset
        watcher.tick()
        self.assertEqual(self.qbit_state.port, 50000)
        self.assertEqual(self.qbit_state.sets[-1], 50000)

    def test_short_log_growth_does_not_reset_the_offset(self):
        self.write_log(43991)
        watcher = self.make_watcher()
        watcher.self_heal()
        watcher.tick()
        self.assertLess(watcher.state["follow"]["prefix_len"], pp.PREFIX_BYTES)
        self.append_log(43991)
        watcher.tick()
        self.assertEqual(watcher.state["follow"]["prefix_len"], pp.PREFIX_BYTES)
        self.assertEqual(watcher.state["follow"]["offset"],
                         os.path.getsize(self.log_path))
        self.assertEqual(self.qbit_state.sets, [43991])

    def test_state_from_an_older_version_is_migrated(self):
        self.write_log(43991)
        watcher = self.make_watcher()
        watcher.tick()
        follow = dict(watcher.state["follow"])
        follow.pop("prefix_sha256")
        follow.pop("prefix_len")
        pp.save_state_file(self.state_dir, {
            "follow": follow,
            "last_seen_port": 43991,
            "last_applied_port": 43991,
        })
        migrated = self.make_watcher()
        migrated.tick()
        self.assertIsNotNone(migrated.state["follow"]["prefix_sha256"])
        self.assertIsNotNone(migrated.state["follow"]["prefix_len"])

    def test_periodic_reconcile_fixes_a_manual_change(self):
        self.write_log(43991)
        watcher = self.make_watcher()
        watcher.self_heal()
        watcher.tick()
        self.qbit_state.port = 7777  # changed manually in qBittorrent
        watcher._next_reconcile = 0.0
        watcher.tick()
        self.assertEqual(self.qbit_state.port, 43991)
        self.assertEqual(self.qbit_state.sets[-1], 43991)

    def test_dry_run_never_calls_setpreferences(self):
        self.write_log(43991)
        watcher = self.make_watcher(self.make_config(dry_run=True))
        watcher.self_heal()
        self.assertEqual(self.qbit_state.port, 1)
        self.assertEqual(self.qbit_state.sets, [])

    def test_api_key_mode(self):
        self.write_log(43991)
        cfg = self.make_config()
        cfg["qbittorrent"].update({"api_key": API_KEY, "username": "", "password": ""})
        watcher = self.make_watcher(cfg)
        watcher.self_heal()
        self.assertEqual(self.qbit_state.port, 43991)
        self.assertEqual(self.qbit_state.logins, 0)

    def test_environment_proxy_is_ignored(self):
        bad_proxy = "http://127.0.0.1:%d" % free_port()
        env = {"HTTP_PROXY": bad_proxy, "http_proxy": bad_proxy,
               "NO_PROXY": "", "no_proxy": ""}
        with mock.patch.dict(os.environ, env):
            self.write_log(43991)
            watcher = self.make_watcher()
            watcher.self_heal()
        self.assertEqual(self.qbit_state.port, 43991)


class CliTests(BaseTest):
    def write_cli_config(self, base_url=None, with_credentials=True, extra=None):
        data = {
            "log_path": self.log_path,
            "state_dir": self.state_dir,
            "log_level": "ERROR",
            "qbittorrent": {
                "base_url": base_url or self.base_url,
                "http_timeout_s": 2,
            },
            "intervals": {
                "connected_s": 0.01,
                "offline_s": 0.01,
                "reconcile_s": 300,
            },
        }
        if with_credentials:
            data["qbittorrent"].update({"username": "user", "password": "pass"})
        if extra:
            data.update(extra)
        path = os.path.join(self.tmp.name, "cli.conf")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.chmod(path, 0o600)
        return path

    def test_check_reports_in_sync(self):
        self.write_log(43991)
        self.qbit_state.port = 43991
        path = self.write_cli_config()
        self.assertEqual(pp.main(["--config", path, "--check"]), pp.EXIT_OK)

    def test_check_returns_unsync_when_out_of_sync(self):
        self.write_log(43991)
        self.qbit_state.port = 1111
        path = self.write_cli_config()
        self.assertEqual(pp.main(["--config", path, "--check"]), pp.EXIT_UNSYNC)

    def test_check_returns_error_when_qbittorrent_is_unavailable(self):
        self.write_log(43991)
        path = self.write_cli_config(base_url="http://127.0.0.1:%d" % free_port())
        self.assertEqual(pp.main(["--config", path, "--check"]), pp.EXIT_ERROR)

    def test_check_without_credentials_is_read_only(self):
        path = self.write_cli_config(with_credentials=False)
        self.assertEqual(pp.main(["--config", path, "--check"]), pp.EXIT_OK)
        self.assertEqual(self.qbit_state.logins, 0)

    def test_once_returns_zero_after_a_successful_sync(self):
        self.write_log(43991)
        path = self.write_cli_config()
        self.assertEqual(pp.main(["--config", path, "--once"]), pp.EXIT_OK)
        self.assertEqual(self.qbit_state.port, 43991)

    def test_once_returns_unsync_when_qbittorrent_is_unavailable(self):
        self.write_log(43991)
        path = self.write_cli_config(base_url="http://127.0.0.1:%d" % free_port())
        self.assertEqual(pp.main(["--config", path, "--once"]), pp.EXIT_UNSYNC)

    def test_config_error_exit_code(self):
        path = self.write_cli_config(extra={"unknown_key": True})
        self.assertEqual(pp.main(["--config", path, "--once"]), pp.EXIT_CONFIG)


if __name__ == "__main__":
    unittest.main()
