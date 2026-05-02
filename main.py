import argparse

from core.attack_techniques import technique_for
from evaluation.runner import run_evaluation, run_live
from evaluation.report import print_live_report, print_report


# ANSI color codes for modern terminals (Windows Terminal, WSL, iTerm, gnome-terminal)
# all handle these fine. cmd.exe legacy console may not, but nobody demos there.
_RED = "\033[1;31m"
_GREEN = "\033[1;32m"
_CYAN = "\033[36m"
_DIM = "\033[2m"
_YELLOW = "\033[33m"
_ORANGE = "\033[38;5;208m"
_RESET = "\033[0m"

BANNER = (
    f"{_RED}"
    "\n ██╗   ██╗███████╗ ██████╗████████╗ ██████╗ ██████╗ ███████╗ ██████╗ ██████╗  ██████╗ ███████╗\n"
    " ██║   ██║██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝\n"
    " ██║   ██║█████╗  ██║        ██║   ██║   ██║██████╔╝█████╗  ██║   ██║██████╔╝██║  ███╗█████╗\n"
    " ╚██╗ ██╔╝██╔══╝  ██║        ██║   ██║   ██║██╔══██╗██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝\n"
    "  ╚████╔╝ ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗\n"
    "   ╚═══╝  ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝\n"
    f"{_RESET}{_CYAN}"
    "            autonomous pentest agent  ·  A* planning  ·  KB-driven exploits\n"
    f"{_RESET}{_DIM}"
    '                       "every machine has a path.  find it."\n'
    f"{_RESET}{_RED}"
    "            ═════════════════════════════════════════════════════════════════\n"
    f"{_RESET}{_DIM}"
    "              CPSC 481 capstone build · authorized lab targets only\n"
    "                                     created by:\n"
    "                       Mánu Uribe   ·   Evan Wenzel   ·   Daniel Jochum\n"
    f"{_RESET}"
)


def main():
    parser = argparse.ArgumentParser(
        prog="vectorforge",
        description="Plan and execute pentest action chains against simulated or live targets.",
    )
    parser.add_argument(
        "scenario",
        nargs="?",
        default="scenarios/simple_network.json",
        help="path to scenario JSON (default: scenarios/simple_network.json)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="execute actions against a real target (requires VPN/network access)",
    )
    parser.add_argument(
        "--target",
        metavar="IP",
        help="fill placeholder host IPs with this value instead of prompting",
    )
    args = parser.parse_args()

    print(BANNER)
    print(f"  scenario : {args.scenario}")
    print(f"  mode     : {'live' if args.live else 'planning-only'}")
    if args.target:
        print(f"  target   : {args.target}")
    print()

    if args.live:
        print(f"{_YELLOW}[*] engaging target  ·  plan-execute-replan loop active …{_RESET}\n")

        def _on_action_start(action, idx):
            tech = technique_for(action.name)
            print(f"{_CYAN}[{idx}] {action}{_RESET}")
            if tech is not None:
                print(
                    f"    {_DIM}{tech['technique_id']} {tech['technique_name']}  "
                    f"({tech['tactic_id']} {tech['tactic_name']}){_RESET}"
                )

        def _on_action_complete(result, idx):
            if result.success:
                print(f"    {_GREEN}-> OK{_RESET}\n")
            elif result.error == "not_implemented":
                print(f"    {_ORANGE}-> SKIP (not_implemented){_RESET}\n")
            else:
                print(f"    {_RED}-> FAIL ({result.error}){_RESET}\n")

        scenario, runtime_state, log, score = run_live(
            args.scenario,
            args.target,
            on_action_start=_on_action_start,
            on_action_complete=_on_action_complete,
        )
        print_live_report(scenario, runtime_state, log, score)
    else:
        print(f"{_YELLOW}[*] computing optimal action chain (A* planner) …{_RESET}\n")
        scenario, result, score = run_evaluation(args.scenario, args.target)
        print_report(scenario, result, score)


if __name__ == "__main__":
    main()
