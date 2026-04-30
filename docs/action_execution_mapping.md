# Action → Real Operation Mapping

Bridge spec between the **planner** (`agent/`, `core/`) and the future **executor layer** (`executors/`, `runner.py`).

For each action emitted by the planner, this doc defines:
- **Real op**: the tool/command that implements it against a live lab VM
- **State inputs**: fields the executor reads from `State` to know what to target
- **State outputs**: fields the executor writes back after a successful run
- **Failure modes**: how the executor signals failure to `runner.py`
- **Target VM requirements**: what the AWS lab build must provide for this action to succeed

All actions target VMs the team owns (CSUF AWS account `csuf-cpsc362-group2`, us-west-2). No third-party targets, ever.

---

## Conventions

- The runner walks `State.actions_taken` in order, calling the matching executor for each `Action`.
- Each executor receives `(action: Action, state: State, scenario: dict) -> ExecutionResult`.
- `ExecutionResult` carries: `success: bool`, `observed: dict` (real-world data to merge into State), `error: str | None`.
- Host IP lookup: the executor resolves `action.target_host` → IP via `scenario["hosts"][...]["ip"]`. In the AWS lab these are the VPC-private IPs.
- Network reach: the runner is expected to run from inside the VPC (jump host or SSM tunnel) so private IPs are routable.

---

## Action table

### 1. `discover_host(host_id)`
- **Real op**: `nmap -sn -PE <ip>` (ICMP echo) OR `arp-scan` against the subnet
- **State inputs**: `target_host` → resolve to IP
- **State outputs**: confirms host is alive (no state mutation beyond what the planner already wrote)
- **Failure modes**: host doesn't respond → executor returns `success=False, error="host_unreachable"`. Real-world cause: VM stopped, security group blocking ICMP.
- **Target VM**: must respond to ICMP from inside the VPC. Default Ubuntu does; security group inbound rule must allow ICMP from the runner's subnet.

### 2. `scan_host(host_id)`
- **Real op**: `nmap -sV -p- <ip>` (all ports + version detection)
- **State inputs**: `target_host` → IP
- **State outputs**: real `open_ports[host_id]` and `discovered_services[host_id][port] -> name`. Compare against scenario JSON; flag drift.
- **Failure modes**: scan times out, no ports open. `success=False, error="scan_failed"`.
- **Target VM**: services from scenario JSON must actually be listening. For `web01`: ssh on 22, apache on 80. For `file02`: ssh, samba, xrdp, jenkins on 8080.

### 3. `enumerate_http(host_id, port)`
- **Real op**: `gobuster dir -u http://<ip>:<port> -w <wordlist>` (or `ffuf`)
- **State inputs**: `target_host`, `target_port`
- **State outputs**: `discovered_paths[host_id]` ← real paths found. Should match the scenario's `services[].paths`.
- **Failure modes**: HTTP not responding, no paths found. `success=False, error="http_enum_failed"`.
- **Target VM**: web server serves the paths declared in scenario. For `web01` Apache: `/`, `/login`, `/admin`, `/uploads` must all return non-404. For `file02` Jenkins: `/script`, `/manage`, `/login`.

### 4. `enumerate_smb(host_id, port=445)`
- **Real op**: `smbclient -L //<ip> -N` (anonymous list) + `enum4linux <ip>`
- **State inputs**: `target_host`
- **State outputs**: `discovered_paths[host_id]` += `"smb://shares"` (matches planner's symbolic representation)
- **Failure modes**: SMB requires auth, no shares listable anonymously. `success=False, error="smb_enum_failed"`.
- **Target VM** (`file02`): Samba configured with at least one anonymous-listable share. Build script must `apt install samba` and add a `[shares]` section in `smb.conf` with `guest ok = yes`.

### 5. `identify_vuln(host_id)`
- **Real op**: heuristic — match observed service banners (from `discovered_services` versions) and discovered paths against a small CVE/vuln knowledge base. Examples:
  - Apache 2.4.x + `/admin` returning an upload form → `VF-UPLOAD-001`
  - Jenkins 2.289 + `/script` reachable → `VF-JENKINS-001`
  - Existing webadmin creds + ssh service → `VF-REUSE-001`
- **State inputs**: `discovered_services[host_id]`, `discovered_paths[host_id]`, `creds_found`
- **State outputs**: `discovered_vulns[host_id]` ← matched vuln IDs
- **Failure modes**: nothing matches. `success=False, error="no_vulns_identified"`.
- **Target VM**: vuln must actually exist (versions installed, configs in place). See per-host build sections below.

### 6. `exploit_upload(host_id)`
- **Real op**: `curl -F "file=@webshell.php" http://<ip>/admin/upload` then verify shell at `http://<ip>/uploads/webshell.php?cmd=id`
- **State inputs**: `target_host`; requires `VF-UPLOAD-001` in `discovered_vulns[host_id]`
- **State outputs**: `access_levels[host_id] = "web_shell"`. Executor must persist the shell URL somewhere the runner can reuse (e.g. an `artifacts` dict on `ExecutionResult`).
- **Failure modes**: upload rejected, shell not reachable, file extension blocked. `success=False, error="upload_blocked"`.
- **Target VM** (`web01`): `/admin/upload` endpoint accepts arbitrary file types and writes to web-readable `/uploads/`. Build script: deploy a deliberately broken PHP upload handler (no MIME check, no extension filter).

### 7. `exploit_jenkins(host_id)`
- **Real op**: POST Groovy payload to `/script` endpoint with default creds (`admin/admin` or unauth in old Jenkins); payload spawns reverse shell or runs commands.
- **State inputs**: `target_host`; requires `VF-JENKINS-001` in `discovered_vulns[host_id]`
- **State outputs**: `access_levels[host_id] = "web_shell"`
- **Failure modes**: creds wrong, `/script` requires auth we don't have, payload sandboxed. `success=False, error="jenkins_exploit_failed"`.
- **Target VM** (`file02`): Jenkins 2.289 installed (vulnerable version), default admin/admin or unauth `/script`, no script approval. **This is genuinely dangerous software — keep it isolated, never on a public IP.**

### 8. `read_sensitive_file(host_id)`
- **Real op**: via existing web shell, `curl 'http://<ip>/uploads/webshell.php?cmd=cat%20/var/www/html/config.php'`, parse output for credential patterns.
- **State inputs**: `target_host`; requires `access_levels[host_id] == "web_shell"`. Reads scenario's `loot[]` to know which files to read and what to extract.
- **State outputs**: `creds_found` ← parsed `Credential` objects
- **Failure modes**: file not present, parse fails, shell lost. `success=False, error="file_read_failed"`.
- **Target VM** (`web01`): `config.php` exists at a readable path, contains `$user = "webadmin"; $pass = "Welcome123!";` (or whatever format the parser expects — define this format with the team).

### 9. `read_smb_share(host_id)`
- **Real op**: `smbclient //<ip>/shares -N -c "get db.conf -"` then parse for credentials.
- **State inputs**: `target_host`; requires `"smb://shares"` in `discovered_paths[host_id]`.
- **State outputs**: `creds_found` ← parsed `Credential` objects
- **Failure modes**: share requires auth, file missing. `success=False, error="smb_read_failed"`.
- **Target VM** (`file02`): `[shares]` Samba share contains `db.conf` with credential payload. Build script must place the file with the right contents.

### 10. `use_credentials_ssh(host_id, port=22)`
- **Real op**: `paramiko.SSHClient().connect(<ip>, 22, username, password)`. Iterate over `state.creds_found` where `access == "ssh"`.
- **State inputs**: `target_host`, `creds_found`
- **State outputs**: `access_levels[host_id] = "ssh_user"`, `compromised_hosts.add(host_id)`. Executor should hold the SSH session for downstream actions.
- **Failure modes**: every cred fails. `success=False, error="ssh_auth_failed"`.
- **Target VM**: SSH user account exists with the password from scenario `loot`. Build script: `useradd webadmin && echo 'webadmin:Welcome123!' | chpasswd`. PasswordAuthentication=yes in sshd_config.

### 11. `bruteforce_ssh(host_id, port=22)`
- **Real op**: `hydra -L users.txt -P passwords.txt ssh://<ip>` (small wordlists, lab-only). **Slow on purpose** — A* already penalizes this with cost 15.
- **State inputs**: `target_host`
- **State outputs**: on success, `access_levels[host_id] = "ssh_user"`, `compromised_hosts.add(host_id)`, plus a new `Credential` in `creds_found`.
- **Failure modes**: wordlists exhausted, account lockout, fail2ban triggered. `success=False, error="bruteforce_exhausted"`.
- **Target VM**: SSH account whose password is in the lab wordlist. **Never enable fail2ban on lab boxes** or this never succeeds.

### 12. `bruteforce_rdp(host_id, port=3389)`
- **Real op**: `hydra rdp://<ip>` or `crowbar -b rdp -s <ip>/32 -u admin -C passwords.txt`. Even slower; A* penalizes with cost 12.
- **State inputs**: `target_host`
- **State outputs**: `access_levels[host_id] = "rdp_user"`, `compromised_hosts.add(host_id)`
- **Failure modes**: as above. `success=False, error="bruteforce_exhausted"`.
- **Target VM**: xrdp running (Linux) or actual Windows VM with RDP enabled and a guessable password. Note the medium scenario expects this path to be *rejected* by the planner, so this executor may rarely run — but it must exist for completeness.

### 13. `pivot_to_host(host_id)`
- **Real op**: from a compromised "source" host (one that `reaches` the target), establish network reach to the target. Concretely:
  - Set up an SSH tunnel through the source: `ssh -L <local_port>:<target_ip>:<target_port> source_user@source_ip` for each port we'll touch on the target, OR
  - Use `sshuttle -r source_user@source_ip <target_subnet>/24` for transparent routing.
- **State inputs**: `target_host`. Source = any host in `compromised_hosts` that has `target_host` in its `reaches` list (read from scenario).
- **State outputs**: `reachable_hosts.add(host_id)`. Executor must remember the tunnel/proxy and prepend it to subsequent ops against this host.
- **Failure modes**: source SSH session lost, source can't reach target. `success=False, error="pivot_failed"`.
- **Target VM**: the AWS VPC must reflect the `reaches` topology. Practically: `web01` in a public-ish subnet, `file02` in a private subnet, with a security group allowing `web01 → file02` on the relevant ports and **denying** runner-direct → file02. That enforces "must pivot through web01."

---

## Per-host build checklist (medium scenario)

### `web01` — VF-VM1-Web01 (Ubuntu 22.04, public subnet)
- [ ] OpenSSH 8.9 listening on 22, password auth enabled
- [ ] Apache 2.4.x on 80, serving paths: `/`, `/login`, `/admin`, `/uploads`
- [ ] `/admin/upload` endpoint with no file-type validation (the VF-UPLOAD-001 vuln)
- [ ] `/var/www/html/config.php` contains creds `webadmin / Welcome123!` in a parseable format
- [ ] Linux user `webadmin` with password `Welcome123!`
- [ ] Security group: ICMP + 22 + 80 from runner subnet; egress to `file02` on 22, 445, 3389, 8080

### `file02` — VF-VM2-File02 (Ubuntu 22.04, private subnet)
- [ ] OpenSSH 8.2 on 22, password auth enabled
- [ ] Linux user `webadmin` with password `Welcome123!` (the credential reuse the planner relies on)
- [ ] Linux user `dbadmin` with password `Db@dminPass!`
- [ ] Samba 4.13 on 445 with `[shares]` share, anonymous list allowed, containing `db.conf` with `dbadmin / Db@dminPass!`
- [ ] xrdp 0.9 on 3389
- [ ] Jenkins 2.289 on 8080 with default admin/admin (or unauth) `/script` console
- [ ] `/etc/secrets/db.conf` readable by `webadmin` (or whatever access tier the planner gets first)
- [ ] Security group: only inbound from `web01`'s SG. **No public IP. No runner-direct ingress.**

---

## Questions 

1. **Wordlists**: which password lists for hydra runs? Keep small (10-50 entries) so bruteforce stays slow but tractable.
2. **Credential parsing format**: standardize on `KEY=VALUE` or JSON in loot files so one parser handles all of them.
3. **Executor failure → planner replan?**: if `read_sensitive_file` fails on web01, does runner abort, or does it call `plan()` again with the partial state? Decision needed before runner is built.
4. **Artifacts**: web shell URLs, SSH session handles, tunnels — where do they live across executor calls? Probably on `runner.py`, not `State` (these aren't part of planning).
5. **Logging / evidence**: what does each executor record (raw command, stdout, timestamp) for the final report? Suggest a structured log per action.