# VectorForge

**CPSC 481 — Artificial Intelligence · Capstone Project**

VectorForge is an intelligent agent that **plans and executes** credential-based attack chains against authorized lab networks. It models penetration testing as a state-space search problem and uses **A\*** with a domain-specific heuristic to choose an optimal sequence of reconnaissance and exploitation actions before any operation runs against a live host.

The system covers Track C (Cross-Course / Capstone Integration): AI planning combined with real systems/security execution against authorized training-platform machines (HackTheBox).

> *"every machine has a path. find it."*

---

## Demo

![VectorForge live run against HackTheBox](docs/figures/demo.gif)

*Earlier build — current version takes the target IP as a `--target <IP>` CLI flag instead of prompting.*

---

## What it does

Given a scenario describing a target network (hosts, services, vulnerabilities, credentials, reachability), VectorForge:

1. Models the network as a **state space** — discovered hosts, open ports, services, web paths, credentials, per-host access levels, compromised hosts.
2. Generates legal actions via rule-based reasoning (e.g., *if HTTP is identified, it can be enumerated; if credentials are found for SSH, they can be used*).
3. Searches with **A\*** over `(g(n) = action cost) + (h(n) = distance-to-goal heuristic)` to find a cheap, high-value path to compromise.
4. Executes the chosen plan through a pluggable executor layer — **MockExecutor** for fast repeatable evaluation, **RealExecutor** for live targets (nmap, gobuster, curl, paramiko), and **HybridExecutor** that falls through Real → Mock for actions not yet wired live.
5. Replans on failure when reality diverges from the model.

Each chosen action is tagged with its corresponding **MITRE ATT&CK** technique for explainability.

---

## AI concepts used

| Concept | Where it lives |
|---|---|
| Heuristic search (A\*) | [agent/planner.py](agent/planner.py) |
| Admissible heuristic | [agent/heuristic.py](agent/heuristic.py) |
| State-space representation | [core/state.py](core/state.py) |
| Action vocabulary & transition function | [core/actions.py](core/actions.py), [agent/transition.py](agent/transition.py) |
| Rule-based action legality | [agent/action_generator.py](agent/action_generator.py) |
| Vulnerability knowledge base (rule-driven) | [knowledge/vuln_kb.py](knowledge/vuln_kb.py) |
| Intelligent agent loop (perceive → plan → act → update) | [agent/agent.py](agent/agent.py), [executors/runner.py](executors/runner.py) |

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
docs/          Proposal, technical report, action-to-real-operation mapping, figures/
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

> Use **only** against infrastructure you are explicitly authorized to attack — in this project, HackTheBox machines under their permitted-use terms of service. See *Ethical scope* below.

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
- **Execution success** — % of planned steps that succeed against the live target
- **Time-to-compromise** — wall-clock from plan start to goal state
- **Loot / value captured** — sum of host values and vulnerability severities exploited

See [evaluation/benchmark.py](evaluation/benchmark.py), [evaluation/metrics.py](evaluation/metrics.py), [evaluation/report.py](evaluation/report.py).

---

## System architecture

```
        ┌─────────────────┐
        │ scenarios/*.json│       ← declarative world
        └────────┬────────┘
                 │ load
        ┌────────▼────────┐
        │      Agent      │       ← perceive → plan → act → update
        └────────┬────────┘
                 │ A* (g + h)
   ┌─────────────┼─────────────┐
   │             │             │
┌──▼──┐     ┌────▼────┐    ┌───▼───┐
│State│◄────┤ Planner │◄───┤ Vuln  │
└──▲──┘     └────┬────┘    │  KB   │
   │             │ plan    └────▲──┘
   │       ┌─────▼─────┐        │
   │       │  Runner   │        │    ← walks plan, dispatches steps
   │       └─────┬─────┘        │
   │             │              │
   │  ┌──────────┼─────────┐    │
   │  │          │         │    │
   │┌─▼──┐   ┌──▼───┐  ┌───▼──┐ │   ← executors also consult the KB
   ││Mock│   │ Real │  │Hybrid│ │     (vuln recipes, loot files, default creds)
   │└─┬──┘   └──┬───┘  └───┬──┘ │
   │  │         │          │    │
   │  └─────────┴──────────┴────┘
   │            │
   └────────────┘
        observed results → merge into State (or replan)
```

---

## Roles

### Agent Logic & Decision System Engineer — Mánu Uribe
Core AI: state representation, action vocabulary, transition function, rule-based action generator, A\* search and severity-aware heuristic, vulnerability knowledge base, and the replan loop that recovers when real-world results diverge from the model.

### Systems Architect & Integration Engineer — Evan Wenzel
Overall architecture, the Mock/Real/Hybrid executor layer, the runner that dispatches each plan step, the action-to-real-tool mapping spec, HackTheBox engagement setup, and MITRE ATT&CK technique tagging for explainability.

### Evaluation & Analysis Engineer — Daniel Jochum
Comparative benchmark harness (A\* vs. greedy vs. random), evaluation metrics, test scenarios at three complexity levels, the pytest suite, and the final results write-up for the technical report.

---

## Ethical scope

VectorForge operates **only** against infrastructure explicitly authorized for attack — HackTheBox machines under their permitted-use terms of service. No external systems, no production services, no real credentials, and no public-internet targets. Brute-force tools are tied to small lab-only wordlists. The scope was reviewed with the course instructor before live work began.

---

## Further reading

- [docs/proposal.md](docs/proposal.md) — full project proposal
- [docs/technical_report.md](docs/technical_report.md) — technical report
- [docs/action_execution_mapping.md](docs/action_execution_mapping.md) — abstract-action → real-tool spec
