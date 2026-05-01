from unittest.mock import MagicMock, patch

import paramiko

from core.actions import (
    Action,
    DISCOVER_HOST,
    ENUM_HTTP,
    EXPLOIT_UPLOAD,
    READ_SENSITIVE_FILE,
    TRY_DEFAULT_CREDS,
    USE_CREDS_SSH,
)
from core.state import Credential, State
from executors import HybridExecutor, MockExecutor, RealExecutor
from executors.base import ExecutionResult
from executors.real import parse_creds_from_body, parse_nmap_services

SAMPLE_NMAP_SV = """\
Starting Nmap 7.94 ( https://nmap.org ) at 2026-04-29 16:00 PDT
Nmap scan report for target.htb (10.10.10.75)
Host is up (0.045s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
"""


def test_parse_nmap_services_extracts_port_and_name():
    ports, services = parse_nmap_services(SAMPLE_NMAP_SV)
    assert ports == [22, 80]
    assert services == {22: "ssh", 80: "http"}


def test_parse_nmap_services_empty_output():
    assert parse_nmap_services("") == ([], {})


def test_hybrid_falls_through_on_not_implemented():
    primary = RealExecutor()
    fallback = MockExecutor()
    hybrid = HybridExecutor(primary, fallback)

    scenario = {"hosts": [{"id": "h1", "ip": "1.2.3.4", "exposure": "external"}]}
    # exploit_upload isn't yet implemented in RealExecutor so it should fall to
    # mock which fails for its own reason ("vuln_not_identified"). 
    # Either way we should NOT see "not_implemented" surface up
    result = hybrid.execute(Action("exploit_upload", "h1"), State(), scenario)
    assert result.error != "not_implemented"


def test_hybrid_does_not_fall_through_on_other_failures():
    class AlwaysFails:
        def execute(self, action, state, scenario):
            return ExecutionResult(action, False, error="real_failure")

    class ShouldNotBeCalled:
        def execute(self, action, state, scenario):
            raise AssertionError("fallback called when it shouldn't be")

    hybrid = HybridExecutor(AlwaysFails(), ShouldNotBeCalled())
    result = hybrid.execute(Action(DISCOVER_HOST, "h1"), State(), {})
    assert result.error == "real_failure"


def _fake_response(status_code: int):
    class _R:
        def __init__(self, code):
            self.status_code = code

    return _R(status_code)


def test_enumerate_http_collects_non_404_paths():
    scenario = {"hosts": [{"id": "h1", "ip": "10.0.0.5"}]}
    # Tiny wordlist for the test so we can name every URL we expect
    executor = RealExecutor(http_wordlist=["/", "/admin", "/missing"])

    def fake_get(url, **kwargs):
        if url.endswith("/missing"):
            return _fake_response(404)
        return _fake_response(200)

    with patch("executors.real.requests.get", side_effect=fake_get):
        result = executor.execute(Action(ENUM_HTTP, "h1", 80), State(), scenario)

    assert result.success
    assert set(result.observed["paths"]) == {"/", "/admin"}


def test_enumerate_http_fails_when_all_404():
    scenario = {"hosts": [{"id": "h1", "ip": "10.0.0.5"}]}
    executor = RealExecutor(http_wordlist=["/admin", "/login"])

    with patch(
        "executors.real.requests.get",
        return_value=_fake_response(404),
    ):
        result = executor.execute(Action(ENUM_HTTP, "h1", 80), State(), scenario)

    assert not result.success
    assert result.error == "http_enum_failed"


def _state_with_ssh_cred(user="nibbler", pw="hunter2"):
    s = State()
    s.creds_found.append(Credential(user, pw, "ssh", "user", "personal.php", "high"))
    return s


def _fake_ssh_client(whoami_output="nibbler\n", auth_ok=True):
    """MagicMock paramiko client that auths and returns a whoami stub."""
    client = MagicMock()
    if not auth_ok:
        client.connect.side_effect = paramiko.AuthenticationException("nope")
    stdout = MagicMock()
    stdout.read.return_value = whoami_output.encode()
    client.exec_command.return_value = (MagicMock(), stdout, MagicMock())
    return client


def test_use_credentials_ssh_succeeds_with_valid_cred():
    scenario = {"hosts": [{"id": "h1", "ip": "10.0.0.5"}]}
    state = _state_with_ssh_cred()
    executor = RealExecutor()
    fake = _fake_ssh_client(whoami_output="nibbler\n")

    with patch("executors.real.paramiko.SSHClient", return_value=fake):
        result = executor.execute(Action(USE_CREDS_SSH, "h1", 22), state, scenario)

    assert result.success
    assert result.observed["access_level"] == "ssh_user"
    assert result.observed["compromised"] is True
    assert result.artifacts["ssh_user"] == "nibbler"


def test_use_credentials_ssh_fails_when_auth_rejected():
    scenario = {"hosts": [{"id": "h1", "ip": "10.0.0.5"}]}
    state = _state_with_ssh_cred()
    executor = RealExecutor()
    fake = _fake_ssh_client(auth_ok=False)

    with patch("executors.real.paramiko.SSHClient", return_value=fake):
        result = executor.execute(Action(USE_CREDS_SSH, "h1", 22), state, scenario)

    assert not result.success
    assert result.error == "ssh_auth_failed"


def test_use_credentials_ssh_fails_when_no_ssh_creds():
    scenario = {"hosts": [{"id": "h1", "ip": "10.0.0.5"}]}
    state = State()  # no creds at all
    result = RealExecutor().execute(Action(USE_CREDS_SSH, "h1", 22), state, scenario)
    assert not result.success
    assert result.error == "no_ssh_creds"


def _nibbleblog_state():
    """State that triggers the Nibbleblog KB rule's preconditions."""
    s = State()
    s.discovered_paths["target"] = {"/nibbleblog/admin.php"}
    return s


def _login_response(body="welcome admin, click logout to exit", code=200):
    r = MagicMock()
    r.status_code = code
    r.text = body
    return r


def test_try_default_creds_succeeds_when_indicator_present():
    scenario = {"hosts": [{"id": "target", "ip": "10.10.10.75"}]}
    state = _nibbleblog_state()
    executor = RealExecutor()

    sess = MagicMock()
    sess.post.return_value = _login_response()

    with patch("executors.real.requests.Session", return_value=sess):
        result = executor.execute(
            Action(TRY_DEFAULT_CREDS, "target", 80), state, scenario
        )

    assert result.success
    creds = result.observed["creds"]
    assert len(creds) == 1
    assert creds[0]["username"] == "admin"
    assert creds[0]["password"] == "nibbles"
    assert creds[0]["access"] == "http"


def test_try_default_creds_fails_when_indicator_absent():
    scenario = {"hosts": [{"id": "target", "ip": "10.10.10.75"}]}
    state = _nibbleblog_state()
    executor = RealExecutor()

    sess = MagicMock()
    sess.post.return_value = _login_response(body="invalid login", code=200)

    with patch("executors.real.requests.Session", return_value=sess):
        result = executor.execute(
            Action(TRY_DEFAULT_CREDS, "target", 80), state, scenario
        )

    assert not result.success
    assert result.error == "default_creds_failed"


def test_try_default_creds_fails_when_no_recipe():
    # No paths discovered -> KB doesn't match -> no recipe
    scenario = {"hosts": [{"id": "target", "ip": "10.10.10.75"}]}
    state = State()
    result = RealExecutor().execute(
        Action(TRY_DEFAULT_CREDS, "target", 80), state, scenario
    )
    assert not result.success
    assert result.error == "recipe_missing"


def _state_ready_for_upload():
    """state with nibbleblog detected + http cred already collected."""
    s = _nibbleblog_state()
    s.creds_found.append(
        Credential("admin", "nibbles", "http", "user", "default", "medium")
    )
    return s


def _http_response(text="", status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    return r


def test_exploit_upload_succeeds_when_shell_returns_uid():
    scenario = {"hosts": [{"id": "target", "ip": "10.10.10.75"}]}
    state = _state_ready_for_upload()
    executor = RealExecutor()

    sess = MagicMock()
    sess.post.return_value = _http_response(status=200)
    sess.get.return_value = _http_response(text="uid=33(www-data) gid=33...")

    with patch("executors.real.requests.Session", return_value=sess):
        result = executor.execute(Action(EXPLOIT_UPLOAD, "target", 80), state, scenario)

    assert result.success
    assert result.observed["access_level"] == "web_shell"
    assert "shell_url" in result.artifacts


def test_exploit_upload_fails_when_shell_does_not_execute():
    scenario = {"hosts": [{"id": "target", "ip": "10.10.10.75"}]}
    state = _state_ready_for_upload()
    executor = RealExecutor()

    sess = MagicMock()
    sess.post.return_value = _http_response(status=200)
    # shell page comes back but no uid= in body → execution didn't happen
    sess.get.return_value = _http_response(text="404 not found", status=404)

    with patch("executors.real.requests.Session", return_value=sess):
        result = executor.execute(Action(EXPLOIT_UPLOAD, "target", 80), state, scenario)

    assert not result.success
    assert result.error == "shell_unreachable"


def test_exploit_upload_fails_without_http_creds():
    scenario = {"hosts": [{"id": "target", "ip": "10.10.10.75"}]}
    # nibbleblog detected but no creds yet
    state = _nibbleblog_state()
    result = RealExecutor().execute(
        Action(EXPLOIT_UPLOAD, "target", 80), state, scenario
    )
    assert not result.success
    assert result.error == "no_http_creds"


def test_parse_creds_from_body_php_style():
    body = """
    <?php
    $user = "webadmin";
    $pass = "Welcome123!";
    """
    creds = parse_creds_from_body(body)
    assert creds[0]["username"] == "webadmin"
    assert creds[0]["password"] == "Welcome123!"


def test_parse_creds_from_body_keyvalue_style():
    body = "username=admin\npassword=hunter2\n"
    creds = parse_creds_from_body(body)
    assert creds[0]["username"] == "admin"
    assert creds[0]["password"] == "hunter2"


def test_parse_creds_from_body_returns_empty_when_nothing_matches():
    assert parse_creds_from_body("just some random text") == []


def _state_ready_to_read():
    s = _nibbleblog_state()
    s.access_levels["target"] = "web_shell"
    return s


def test_read_sensitive_file_succeeds_when_file_has_creds():
    scenario = {"hosts": [{"id": "target", "ip": "10.10.10.75"}]}
    state = _state_ready_to_read()
    executor = RealExecutor()

    body = '<?php $user = "webadmin"; $pass = "Welcome123!"; ?>'

    with patch(
        "executors.real.requests.get",
        return_value=_http_response(text=body),
    ):
        result = executor.execute(
            Action(READ_SENSITIVE_FILE, "target", 80), state, scenario
        )

    assert result.success
    creds = result.observed["creds"]
    assert any(c["username"] == "webadmin" for c in creds)


def test_read_sensitive_file_fails_when_no_web_shell():
    scenario = {"hosts": [{"id": "target", "ip": "10.10.10.75"}]}
    # nibbleblog detected but no shell yet
    state = _nibbleblog_state()
    result = RealExecutor().execute(
        Action(READ_SENSITIVE_FILE, "target", 80), state, scenario
    )
    assert not result.success
    assert result.error == "no_web_shell"


def test_read_sensitive_file_fails_when_no_creds_in_body():
    scenario = {"hosts": [{"id": "target", "ip": "10.10.10.75"}]}
    state = _state_ready_to_read()
    executor = RealExecutor()

    with patch(
        "executors.real.requests.get",
        return_value=_http_response(text="nothing useful here"),
    ):
        result = executor.execute(
            Action(READ_SENSITIVE_FILE, "target", 80), state, scenario
        )

    assert not result.success
    assert result.error == "file_read_failed"