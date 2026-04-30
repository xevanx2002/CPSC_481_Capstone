# CPSC 481 Capstone Proposal: VectorForge – Intelligent Attack Planning and Execution Agent

**Daniel Jochum**

**Mánu Uribe**

**Evan Wenzel**

CPSC 481

Mr. Paul Oginni

April 2026

---

# Problem Statement

Modern computer systems are constantly exposed to security risks due to misconfigurations, weak credentials, and unpatched vulnerabilities. While many tools exist to assist penetration testers, these tools require manual decision-making and do not effectively model how attackers prioritize and sequence actions.

Penetration testing is not just about finding vulnerabilities — it is about choosing the most effective path to reach high-value targets under constraints such as limited time, access restrictions, and detection risk. Existing automated frameworks (e.g., Metasploit, Cobalt Strike) execute well but plan poorly: a human still has to decide *what* to do and *in what order*. Existing planners are mostly academic and never touch a real machine, so it is hard to know whether their plans would actually work.

The goal of this project is to design and implement an intelligent system that both **plans and executes** credential-based attacks in a controlled, owned environment. The system models attacker decision-making with a search-based agent, then validates each plan by carrying it out against real lab virtual machines that the team builds and controls.

---

# Project Overview

VectorForge is a penetration testing system that combines an intelligent planning agent with a real execution layer operating against owned lab infrastructure.

The system has three cooperating layers:

1. **Planner** — A heuristic-search agent that models the network as a state space, generates legal actions, and uses A* to choose an optimal attack path before any operation runs against a live host.
2. **Runner** — A driver that walks the planner's chosen action sequence and dispatches each step to the appropriate executor. It also handles failures, replanning, and evidence collection.
3. **Executors** — A library of small modules that map each abstract action (e.g., `enumerate_http`, `exploit_upload`) to a real tool invocation (`gobuster`, `curl`, `paramiko`, etc.) against a live lab VM.

The lab itself is a small isolated network of virtual machines that the team builds in the CSUF-provided AWS account. Each VM is configured to match a scenario description in JSON, so the planner's symbolic model and the real environment stay aligned. Vulnerabilities, services, credentials, and network reachability are reproduced deliberately on hosts that the team owns end to end.

The focus of the system is on:

- decision-making and strategy selection
- modeling attacker reasoning
- evaluating tradeoffs between actions
- demonstrating that planned attack paths are *executable*, not just plausible

---

# AI Concepts Used

## Heuristic Search (A*)

The agent uses the A* search algorithm to evaluate possible attack paths. Each candidate sequence of actions is assigned a cost based on the actions taken plus a heuristic estimate of remaining work to reach the goal.

The algorithm balances:

- cost of actions (time, effort, detection risk encoded as numeric cost)
- expected reward (access level gained, vulnerability severity, host value)

This allows the agent to prioritize cheap high-value paths (e.g., reusing discovered credentials) over expensive low-value ones (e.g., blind brute force).

---

## State Space Representation

The penetration testing process is modeled as a state space. Each state captures everything the agent currently knows, including:

- discovered, scanned, and reachable hosts
- open ports and identified services
- discovered web paths and identified vulnerabilities
- obtained credentials and their access type
- access levels per host (`none`, `web_shell`, `ssh_user`, `rdp_user`)
- compromised hosts
- the action history that produced this state

Actions taken by the agent transition the system from one state to another according to deterministic preconditions and effects defined in the transition function.

---

## Intelligent Agent Architecture

The system is designed as an intelligent agent that:

- perceives the environment through reconnaissance actions
- updates its internal state based on new information
- selects actions that maximize its objective
- executes those actions and incorporates the real-world result

The agent operates in a loop:

1. observe environment (or load scenario description)
2. update knowledge base
3. plan an action sequence using A*
4. execute the next action via the runner
5. update state from the executor's observed results
6. replan if reality diverges from the model; otherwise continue
7. repeat until the goal state is reached or no plan exists

---

## Rule-Based Reasoning

The agent uses rules encoded in the action generator and transition function to determine which actions are legal given the current state.

Examples:

- if a host is reachable but not discovered, it can be discovered
- if HTTP is identified on a host, that port can be enumerated
- if a vulnerability is discovered, a matching exploit becomes available
- if credentials are obtained for an SSH service, they can be used for access
- if a host is not reachable, only a pivot through a compromised neighbor can make it reachable

These rules define the structure of the decision space and keep the planner's choices coherent with the executor's real-world capabilities.

---

# Approach and Design Plan

## Lab Network Environment (AWS)

The system runs against a small lab network built in the CSUF-provided AWS account (`csuf-cpsc362-group2`, region `us-west-2`). The team configures each VM to match a structured scenario description.

Each scenario VM represents a different role in a realistic environment:

- a public-facing web server with an exploitable upload vulnerability
- an internal file/admin server reachable only via a compromised pivot host
- additional higher-value targets in future scenarios

Each VM is configured with:

- exposed services (e.g., SSH, HTTP, SMB, RDP, Jenkins)
- deliberately introduced vulnerabilities (file upload, default credentials, credential reuse)
- credential opportunities planted in files and shares
- realistic version banners that match the scenario JSON

Network topology is enforced at the AWS layer: the public host lives in a routable subnet; the internal host has no public IP and is only reachable from the public host's security group. This means the planner cannot "cheat" by reaching internal hosts directly — it must produce a plan that pivots through a compromised neighbor, and the executor must build that pivot for real.

The same JSON description that defines the scenario for the planner also drives a per-host build script that configures the AWS VM. This keeps the model and reality in sync.

---

## Scanning and Enumeration

The agent performs reconnaissance both symbolically (in the planner) and practically (in the executor):

- host discovery (`nmap -sn` / arp-scan)
- port scanning (`nmap -sV`)
- service identification (banner grabbing via nmap)
- web enumeration (`gobuster` / `ffuf`)
- SMB enumeration (`smbclient`, `enum4linux`)

Each action reveals new information about the live environment, which the runner merges back into the planner's state representation.

---

## Knowledge Base

The agent maintains two distinct knowledge stores.

The first is **per-run state** (the `State` object): everything observed about the current target during a single engagement — discovered hosts, open ports, identified services, web paths, credentials obtained, access levels per host, and the running action history with accumulated cost. State is updated after each action, both by the planner during search and by the runner during real-world execution.

The second is a **generic vulnerability knowledge base**: a reusable set of rules that match observed evidence (service banners, discovered paths, available credentials) to known vulnerability classes. Each rule fires only when its preconditions are present in current state, so the same rule set works across arbitrary targets.

Separating these two stores is what lets the agent operate against environments that are not pre-described. The per-scenario JSON declares the world that exists; the knowledge base names the vulnerabilities the agent recognizes in that world. Without this separation, every target would have to be hand-described down to the vulnerability level — defeating the purpose of having a planner reason about unknown infrastructure.

---

## Planning and Decision Engine

The decision engine is the core contribution of this project.

The agent:

- generates legal actions from the current state via the action generator
- evaluates each candidate using A* with an admissible-style heuristic
- selects a complete action sequence from start to goal before execution begins
- assigns numeric cost to each action based on effort and noise (e.g., brute force costs 15, credential reuse costs 1)

Action prioritization considers:

- vulnerability severity (severity multiplier on exploit cost)
- likelihood of success (cheaper paths preferred)
- access gained (higher access level lowers heuristic toward goal)
- cost of execution (encoded per-action)

A clean separation is maintained between the planner (a fast, deterministic, in-memory simulation) and the executor (slow, network-bound, fallible). The planner expands thousands of states cheaply; the executor only ever runs the single chosen path.

---

## Action Execution (Real Lab VMs)

Each abstract action from the planner has a corresponding executor module that performs the equivalent real operation against the lab VM:

- `discover_host` → ICMP/arp probe
- `scan_host` → `nmap -sV`
- `enumerate_http` → directory enumeration
- `exploit_upload` → curl-based file upload + webshell verification
- `read_sensitive_file` → command execution via webshell, credential parsing
- `use_credentials_ssh` → SSH login via paramiko
- `pivot_to_host` → SSH tunnel through a compromised neighbor
- `bruteforce_ssh` / `bruteforce_rdp` → hydra against small lab wordlists

The full mapping, including state inputs, expected outputs, failure modes, and target VM requirements, is documented separately in `docs/action_execution_mapping.md`.

The runner walks the planned action sequence, calls the matching executor for each step, and merges observed results back into state. If a real action fails (e.g., the upload endpoint blocks the payload), the runner can either abort or trigger a replan with the updated knowledge base.

---

# Evaluation Method

The system is evaluated in two operating modes.

In **declared mode**, the world is fully specified ahead of time in a scenario JSON file (hosts, services, vulnerabilities, loot, reachability). The planner's task is to find the optimal action sequence through this known world; this mode isolates planner quality from execution noise and supports fast, repeatable benchmarking.

In **discover mode**, only an entry point is provided. The agent infers services, paths, vulnerabilities, and credentials at runtime from real reconnaissance output, exercising the full plan–execute–observe–replan loop. This mode tests whether the planner generalizes beyond hand-authored scenarios.

The effectiveness of the system is evaluated along two complementary dimensions:

**Planner quality** (measured in simulation, fast, repeatable):

- optimality of the chosen action sequence (cost vs. known optimal)
- nodes expanded by A* (search efficiency)
- robustness across scenarios (does the same heuristic produce sensible plans for small, medium, and larger networks?)
- correct rejection of low-quality paths (e.g., refusing to brute-force when credentials are reachable)

**End-to-end execution** (measured against the real AWS lab):

- success rate of the planned path against the live environment
- time to first compromise and time to goal
- number of executor failures and how the runner recovers (abort vs. replan)
- alignment between the planner's modeled outcome and the real result (drift detection)

Each vulnerability in the environment carries a value, and each host carries an importance score. The agent is evaluated on how quickly and reliably it converts those values into compromise — both in the model and on the wire.

---

# Roles and Responsibilities

## Systems Architect (Offensive Security Simulation) — Daniel Jochum

Designs the overall system architecture: how planner, runner, executors, and lab infrastructure interact. Owns the AWS lab build (VPC, subnets, security groups), per-host configuration scripts, and the runner that bridges plans to live operations. Responsible for keeping the scenario JSON and the real VM configurations in sync.

---

## Agent Logic and Decision System Engineer — Mánu Uribe

Implements the core decision-making system: state space representation, action vocabulary, transition function, A* search, and the heuristic. Owns the planner output contract that the runner consumes (structured `Action` objects in `actions_taken`). Responsible for ensuring that what the planner produces is faithfully executable by the downstream layer.

---

## Evaluation and Analysis Engineer — Evan Wenzel

Designs evaluation metrics for both planner quality and end-to-end execution. Builds the harness that runs scenarios repeatedly, collects timing and success data, and produces the comparative analysis (e.g., A* vs. greedy baseline, planner-modeled cost vs. observed cost). Owns the final write-up of results.

---

# Project Goals

The main goals of this project are to:

- model real-world attacker decision-making with explainable, search-based reasoning
- demonstrate that planned attack paths can be executed end to end against real (owned) infrastructure
- show A* heuristic search applied effectively to a non-trivial, non-toy domain
- produce clear evidence of the planner's quality through measurable evaluation
- separate planning from execution cleanly enough that either layer can be improved independently

---

# Ethical Scope

This project operates strictly within infrastructure the team owns or is explicitly authorized to attack.

The system:

- runs against virtual machines built and operated by the team in the CSUF-provided AWS account
- additionally runs against commercial training platforms whose terms of service explicitly authorize attacks against their hosted machines, as a check that the planner generalizes to infrastructure the team did not author
- never targets external systems, production services, or any host outside this authorized scope
- uses no real-world credentials, no production data, and no public-internet targets
- keeps all team-built vulnerable services in a private subnet with no public IP and no inbound internet access; only the team's authorized runner reaches them via authenticated AWS access

Where dangerous tools are involved (e.g., a deliberately vulnerable Jenkins instance, brute-force tools), they are isolated from the public internet by AWS security groups and tied to lab-only wordlists. The team will tear down the lab between work sessions to limit exposure and cost.

The expanded scope (real execution against lab VMs, in addition to symbolic planning) was reviewed and approved by the course instructor before infrastructure work began. The educational goal — understanding attacker reasoning to improve defensive awareness — is unchanged.

---

# Summary

VectorForge is an intelligent system that **plans and executes** credential-based attacks against a self-owned lab network. It combines heuristic search, state-space modeling, and rule-based reasoning to choose strong attack paths, and a thin executor layer to validate those paths against real virtual machines.

This project goes beyond a paper exercise: by tying the planner's output to a runner that performs each chosen action for real, VectorForge demonstrates that AI-driven attack planning can produce results that hold up outside of simulation. The cleanly separated architecture — planner, runner, executors, lab — also makes the system a useful starting point for future work on automated red-team reasoning, defensive countermeasures, and explainable security tooling.
