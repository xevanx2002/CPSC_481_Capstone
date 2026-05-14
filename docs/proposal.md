# CPSC 481 Capstone Proposal: VectorForge – Autonomous Penetration Agent

**Mánu Uribe · Evan Wenzel · Daniel Jochum**

CPSC 481 · Mr. Paul Oginni · April 2026

---

## Problem Statement

Offensive security tools like Metasploit and Cobalt Strike are well known for their use and execute exceptionally well, but the caveat is they don't plan well— a human still decides what to do and in what order. Academic planners reason well but rarely touch a real machine. VectorForge addresses both of these gaps: an intelligent agent that plans and executes credential-based attack chains against authorized live infrastructure (HackTheBox, under their permitted-use terms). This places the project under Track C — AI planning combined with real systems and security execution.

## Project Overview

VectorForge has three cooperating layers. The **Planner** is a heuristic-search agent that models the network as a state space and uses A\* to choose the most optimal attack path before any live operation actually runs. The **Runner** then walks the chosen action sequence, dispatches each step, merges observed results into state, and replans when reality diverges from the model. The **Executors** are modules mapping abstract actions (`enumerate_http`, `exploit_upload`, `use_credentials_ssh`, `exploit_privesc`, and others) to real tools (`nmap`, `gobuster`, `curl`, `paramiko`). A **Hybrid** executor falls through from Real to Mock for actions not yet wired live, supporting incremental development. Each chosen action is tagged with its corresponding MITRE ATT&CK technique for explainability.

## AI Concepts Used

**Heuristic search (A\*)** scores paths by `g(n) + h(n)`: accumulated action cost plus an admissible distance-to-goal estimate. This makes the agent prefer cheap high-value paths (credential reuse, cost 1) over expensive low-value ones (brute force, cost 15+).

**State-space representation** captures everything the agent currently knows: discovered hosts, open ports, services, web paths, credentials, per-host access levels (`none`, `web_shell`, `ssh_user`, `root`), compromised hosts, and the action history. Deterministic preconditions and effects drive transitions between states.

**Rule-based reasoning** is provided by a generic vulnerability knowledge base that matches observed evidence (banners, paths, credentials) to vulnerability classes. Rules fire only when their preconditions are met, so the same knowledge base works against targets that were never hand-described.

The **intelligent agent loop** is perceive → update → plan → act → observe → replan, in two modes: **declared** (world fully specified for benchmarking) and **discover** (only an entry-point IP, everything else inferred at runtime from real reconnaissance).

## Approach and Design Plan

The live target is a HackTheBox box reached over the platform's authorized VPN. Only an entry-point IP is provided; services, paths, vulnerabilities, and credentials are discovered at runtime.

The action vocabulary contains roughly 16 abstract actions covering reconnaissance, web and SMB enumeration, exploitation (file upload, Jenkins, default credentials), credential use, lateral movement (`pivot_to_host`), privilege escalation, and `capture_flags` as the terminal goal. Each action has both a Mock implementation for fast planning evaluation and a Real implementation for live execution.

A complete privilege escalation chain is then implemented: from initial `web_shell` access on a compromised host, the agent escalates to root via shell-command-shaped rules in the knowledge base, then captures proof-of-compromise flags.

The system keeps two distinct knowledge stores. Per-run state holds what was observed during a single engagement. The generic vulnerability knowledge base holds reusable rules that fire against evidence in any state. This is the separation that lets the agent operate against targets it was not pre-described against.

## Evaluation Method

The system is evaluated along two axes with quantitative metrics.

**Planner quality** is measured using the Mock executor for fast, repeatable runs: optimality of the chosen action sequence versus a hand-traced optimum, A\* nodes expanded as a measure of search efficiency, success rate across simple, medium, and complex scenarios, and correct rejection of low-quality paths (for example, declining brute force when credentials are reachable).

**End-to-end execution** is measured against the live HackTheBox target: success rate of the planned path on the live machine, time to first compromise and time to goal, number of executor failures and whether the runner recovers via replan or aborts, and alignment between the planner-modeled outcome and the observed real result.

A comparative **benchmark harness** runs each scenario through three decision strategies — A\*, greedy (cheapest-legal-first), and seeded-random — and reports success rate, actions taken, total cost, planning time, and nodes expanded. A `pytest` suite covers planner correctness, the transition function, knowledge-base rules, severity scoring, and end-to-end flag capture.

## Roles and Responsibilities

**Mánu Uribe — Agent Logic and Decision System Engineer.** Owns the core AI: state-space model, action vocabulary, transition function, rule-based action generator, A\* search and severity-aware heuristic, the generic vulnerability knowledge base, and the replan loop that recovers when real-world results diverge from the model.

**Evan Wenzel — Systems Architect and Integration Engineer.** Owns the overall architecture, the Mock/Real/Hybrid executor abstraction, the runner that dispatches each plan step, the action-to-real-tool mapping specification, the HackTheBox engagement setup, and MITRE ATT&CK technique tagging for explainability.

**Daniel Jochum — Evaluation and Analysis Engineer.** Owns the comparative benchmark harness (A\* versus greedy versus random), evaluation metrics, test scenarios at three complexity levels, the pytest suite, and the final results write-up for the technical report.

## Ethical Scope

VectorForge operates only against infrastructure explicitly authorized for attack — HackTheBox machines under their permitted-use terms of service. No external systems, no production services, no real credentials, and no public-internet targets. Brute-force tools are tied to small lab-only wordlists. The educational goal — understanding attacker reasoning to inform defensive awareness — is the unchanged motivation behind the project.
