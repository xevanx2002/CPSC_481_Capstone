# VectorForge

**CPSC 481 — Artificial Intelligence · Capstone Project**

VectorForge is an intelligent agent that **plans and executes** credential-based attack chains against authorized lab networks. It models penetration testing as a state-space search problem and uses **A\*** with a domain-specific heuristic to choose an optimal sequence of reconnaissance and exploitation actions before any operation runs against a live host.

The system covers Track C (Cross-Course / Capstone Integration): AI planning combined with real systems/security execution against owned virtual machines.

> _"every machine has a path. find it."_

---

## Demo

![VectorForge live run against HackTheBox](docs/figures/demo.gif)

_Earlier build — current version takes the target IP as a `--target <IP>` CLI flag instead of prompting._

---

## What it does

Given a scenario describing a target network (hosts, services, vulnerabilities, credentials, reachability), VectorForge:

1. Models the network as a **state space** — discovered hosts, open ports, services, web paths, credentials, per-host access levels, compromised hosts.
2. Generates legal actions via rule-based reasoning (e.g., _if HTTP is identified, it can be enumerated; if credentials are found for SSH, they can be used_).
3. Searches with **A\*** over `(g(n) = action cost) + (h(n) = distance-to-goal heuristic)` to find a cheap, high-value path to compromise.
4. Executes the chosen plan through a pluggable executor layer — **MockExecutor** for fast repeatable evaluation, **RealExecutor** for live lab VMs (nmap, gobuster, curl, paramiko).
5. Replans on failure when reality diverges from the model.

Each chosen action is tagged with its corresponding **MITRE ATT&CK** technique for explainability.

---

## AI concepts used

| Concept                                                 | Where it lives                                                                 |
| ------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Heuristic search (A\*)                                  | [agent/planner.py](agent/planner.py)                                           |
| Admissible heuristic                                    | [agent/heuristic.py](agent/heuristic.py)                                       |
| State-space representation                              | [core/state.py](core/state.py)                                                 |
| Action vocabulary & transition function                 | [core/actions.py](core/actions.py), [agent/transition.py](agent/transition.py) |
| Rule-based action legality                              | [agent/action_generator.py](agent/action_generator.py)                         |
| Vulnerability knowledge base (rule-driven)              | [knowledge/vuln_kb.py](knowledge/vuln_kb.py)                                   |
| Intelligent agent loop (perceive → plan → act → update) | [agent/agent.py](agent/agent.py), [executors/runner.py](executors/runner.py)   |

---

## Repository layout

```
agent/         A* planner, heuristic, transition function, action generator
core/          State, Action, ATT&CK technique mapping, type defs
environment/   Simulated host/network/vulnerability models
executors/     Mock + Real executors that turn abstract actions into operations
knowledge/     Generic vulnerability rule base (target-agnostic)
scenarios/     JSON network descriptions (simple, medium, complex, HTB)
evaluation/    Metrics, benchmark harness, comparative reports
tests/         pytest suite covering planner, transitions, KB, executor
docs/          Proposal + action-to-real-operation mapping spec
main.py        CLI entry point
```

---

## Setup

Requires **Python 3.10+**.

```bash
python -m venv .venv
.venv\Scripts\activate         # Windows PowerShell
# or: source .venv/bin/activate  on macOS/Linux

pip install -r requirements.txt
```

Dependencies: `pytest`, `requests`, `paramiko`.

---

## Running

### Planning mode (no network — pure A\* over a scenario)

```bash
python main.py scenarios/simple_network.json
python main.py scenarios/medium_network.json
python main.py scenarios/complex_network.json
```

Prints the banner, the optimal action chain, per-action ATT&CK tagging, accumulated cost, A\* search statistics, and a loot summary.

### Live mode (executes the plan against a real target)

```bash
python main.py scenarios/htb_bootstrap.json --live --target <IP>
```

> Use **only** against infrastructure you own or are explicitly authorized to attack (team-built AWS lab, or commercial training platforms whose ToS permit attacks on hosted machines). See _Ethical scope_ below.

### Comparative benchmark (A\* vs. greedy vs. random)

```bash
python -m evaluation.benchmark
python -m evaluation.benchmark --runs 10
```

Prints a Markdown table comparing decision strategies on success rate, actions taken, total cost, planning time, and A\* nodes expanded.

### Test suite

```bash
pytest
```

Covers planner correctness, transition function, vulnerability KB, severity scoring, real-executor wiring, and end-to-end flag capture.

---

## Evaluation evidence

The system reports quantitative metrics aligned with the rubric:

- **Optimality** — total action cost vs. known-optimal hand-traced cost per scenario
- **Search efficiency** — nodes expanded by A\* per scenario
- **Strategy comparison** — A\* vs. greedy vs. random baseline (success rate, cost, actions)
- **Execution success** — % of planned steps that succeed against real lab VMs
- **Time-to-compromise** — wall-clock from plan start to goal state
- **Loot / value captured** — sum of host values and vulnerability severities exploited

See [evaluation/benchmark.py](evaluation/benchmark.py), [evaluation/metrics.py](evaluation/metrics.py), [evaluation/report.py](evaluation/report.py).

---

## System architecture

```
        ┌─────────────────┐
        │  scenarios/*.json│       ← declarative world
        └────────┬────────┘
                 │ load
        ┌────────▼────────┐
        │      Agent      │       ← perceive → plan → act → update
        └────────┬────────┘
                 │ A* (g + h)
   ┌─────────────┼─────────────┐
   │             │             │
┌──▼──┐     ┌────▼────┐    ┌───▼───┐
│State│◄────┤ Planner │    │ Vuln  │
└──▲──┘     └────┬────┘    │  KB   │
   │             │ plan     └───────┘
   │       ┌─────▼─────┐
   │       │  Runner   │            ← walks plan, dispatches steps
   │       └─────┬─────┘
   │             │
   │  ┌──────────┼──────────┐
   │  │          │          │
   │┌─▼──┐   ┌──▼───┐  ┌───▼────┐
   ││Mock│   │ Real │  │ Hybrid │   ← executors
   │└─┬──┘   └──┬───┘  └────┬───┘
   │  │         │           │
   └──┴─────────┴───────────┘
        observed results → merge into State (or replan)
```

---

## Roles

### Systems Architect — Daniel Jochum

Overall system architecture; AWS lab build (VPC, subnets, security groups); per-host configuration scripts; the runner that bridges plans to live operations; scenario ↔ real VM consistency.

### Agent Logic & Decision System Engineer — Mánu Uribe

Core decision-making: state representation, action vocabulary, transition function, A\* search and heuristic, planner-to-runner output contract.

### Evaluation & Analysis Engineer — Evan Wenzel

Evaluation harness, metrics collection across scenarios, comparative analysis (A\* vs. baselines, modeled vs. observed cost), final results write-up.

---

## Ethical scope

VectorForge operates **only** within infrastructure the team owns or is explicitly authorized to attack:

- team-built virtual machines in the CSUF-provided AWS account (private subnet, no public IP)
- commercial training platforms whose terms of service explicitly authorize attacks on their hosted machines

No external systems, no production services, no real credentials, no public-internet targets. The expanded scope (real execution against lab VMs in addition to symbolic planning) was reviewed and approved by the course instructor before infrastructure work began.

---

## Further reading

- [docs/proposal.md](docs/proposal.md) — full project proposal
- [docs/action_execution_mapping.md](docs/action_execution_mapping.md) — abstract-action → real-tool spec
