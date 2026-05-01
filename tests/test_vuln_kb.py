from core.state import Credential, State
from knowledge import recipe_for, vuln_reqs_met, vulns_for


def _state_with_nibbleblog():
    s = State()
    s.discovered_paths["target"] = {"/nibbleblog/admin.php"}
    s.creds_found.append(
        Credential("admin", "nibbles", "http", "user", "default", "medium")
    )
    return s


def test_kb_matches_nibbleblog_when_signals_present():
    host = {"id": "target"}
    state = _state_with_nibbleblog()

    matched = vulns_for(host, state)
    assert any(v["id"] == "VF-UPLOAD-001" for v in matched)


def test_kb_matches_app_before_creds_but_requires_them_for_exploit():
    # rule shouldn't see the app from the path alone
    # that's what lets try_default_creds fetch
    # the recipe before any creds exist
    host = {"id": "target"}
    state = State()
    state.discovered_paths["target"] = {"/nibbleblog/admin.php"}

    matched = vulns_for(host, state)
    assert any(v["id"] == "VF-UPLOAD-001" for v in matched)

    # but the vuln still can't be identified yet because requires has a cred
    vuln = next(v for v in matched if v["id"] == "VF-UPLOAD-001")
    paths = state.discovered_paths["target"]
    assert vuln_reqs_met(vuln, paths, state) is False

    # once an http cred shows up the reqs are met
    state.creds_found.append(
        Credential("admin", "nibbles", "http", "user", "default", "medium")
    )
    assert vuln_reqs_met(vuln, paths, state) is True


def test_recipe_for_returns_exploit_fields():
    host = {"id": "target"}
    state = _state_with_nibbleblog()

    recipe = recipe_for(host, state, "web_shell")
    assert recipe is not None
    assert recipe["id"] == "VF-UPLOAD-001"
    assert recipe["default_credentials"] == ("admin", "nibbles")
    assert "upload_endpoint" in recipe
    assert "shell_path_after_upload" in recipe


def test_recipe_for_returns_none_when_no_matching_capability():
    host = {"id": "target"}
    state = _state_with_nibbleblog()
    # no rule on this host gives "domain_admin"
    assert recipe_for(host, state, "domain_admin") is None


def test_vuln_reqs_met_access_prefix_passes_when_level_matches():
    vuln = {"requires": ["access:web_shell"]}
    state = State()
    state.access_levels["target"] = "web_shell"
    assert vuln_reqs_met(vuln, set(), state, host_id="target") is True


def test_vuln_reqs_met_access_prefix_fails_when_level_lower():
    vuln = {"requires": ["access:web_shell"]}
    state = State()
    state.access_levels["target"] = "none"
    assert vuln_reqs_met(vuln, set(), state, host_id="target") is False


def test_vuln_reqs_met_access_prefix_fails_when_host_id_missing():
    vuln = {"requires": ["access:web_shell"]}
    state = State()
    state.access_levels["target"] = "web_shell"
    # without host_id we can't verify, must fail closed
    assert vuln_reqs_met(vuln, set(), state) is False
