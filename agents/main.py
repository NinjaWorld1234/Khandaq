"""
SOC Platform - Main Entry Point
نقطة الدخول الرئيسية لمنصة وكلاء مركز العمليات الأمنية

Starts all configured agents in separate threads.
Handles graceful shutdown and provides a summary of running agents.

Usage:
    python main.py                    # Start all agents
    python main.py --agent w37        # Start only w37_brute_force
    python main.py --list             # List available agents
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
import time
from typing import Any

# Force UTF-8 encoding for stdout
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

# ---------------------------------------------------------------------------
# Setup logging before any other imports
# إعداد التسجيل قبل أي استيرادات أخرى
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)7s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("soc.main")

# ---------------------------------------------------------------------------
# Agent Registry
# سجل الوكلاء المتاحين
# ---------------------------------------------------------------------------

import importlib
import pkgutil
import inspect
import os
from shared.base_agent import BaseAgent

# Registry: agent_key -> (class, description)
AGENT_REGISTRY: dict[str, tuple[type, str]] = {}

def _discover_agents():
    # Add current dir to sys.path if not there
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)

    for package_name in ["workers", "supervisors", "commander"]:
        try:
            package = importlib.import_module(package_name)
        except ImportError as exc:
            logger.error("Could not import package '%s': %s", package_name, exc)
            continue

        if hasattr(package, "__path__"):
            for _, module_name, is_pkg in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
                try:
                    module = importlib.import_module(module_name)
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if issubclass(obj, BaseAgent) and obj is not BaseAgent:
                            try:
                                temp_instance = obj()
                                AGENT_REGISTRY[temp_instance.name] = (obj, temp_instance.description)
                            except Exception as e:
                                logger.debug("Skipping %s.%s during discovery: %s", module_name, obj.__name__, e)
                except Exception as exc:
                    logger.debug("Failed to import module '%s': %s", module_name, exc)

_discover_agents()


def list_agents() -> None:
    """Print all available agents. طباعة جميع الوكلاء المتاحين"""
    print("\n" + "=" * 70)
    print("  SOC AI Agent Framework - Available Agents")
    print("  إطار عمل وكلاء مركز العمليات الأمنية - الوكلاء المتاحون")
    print("=" * 70)
    for key, (cls, desc) in AGENT_REGISTRY.items():
        print(f"\n  [{key}]")
        print(f"    Class: {cls.__name__}")
        print(f"    Description: {desc}")
    print("\n" + "=" * 70 + "\n")


def start_agents(
    agent_keys: list[str] | None = None,
) -> tuple[list[Any], list[threading.Thread]]:
    """
    Instantiate and start agents in background threads.

    Args:
        agent_keys: List of agent keys to start. None = start all.

    Returns:
        Tuple of (agent_instances, threads).
    """
    keys = agent_keys or list(AGENT_REGISTRY.keys())
    agents: list[Any] = []
    threads: list[threading.Thread] = []

    logger.info("=" * 60)
    logger.info("  SOC AI Agent Framework - Starting Up")
    logger.info("  إطار عمل وكلاء مركز العمليات الأمنية - بدء التشغيل")
    logger.info("=" * 60)

    for key in keys:
        if key not in AGENT_REGISTRY:
            logger.error("Unknown agent key: '%s' — skipping", key)
            continue

        agent_class, description = AGENT_REGISTRY[key]
        try:
            agent = agent_class()
            agents.append(agent)

            thread = agent.start_in_thread()
            threads.append(thread)

            logger.info(
                "Started agent '%s' in thread '%s'",
                agent.name, thread.name,
            )
        except Exception as exc:
            logger.error(
                "Failed to start agent '%s': %s", key, exc, exc_info=True
            )

    logger.info("-" * 60)
    logger.info(
        "  %d/%d agents running", len(agents), len(keys)
    )
    logger.info("-" * 60)

    return agents, threads


def main() -> None:
    """Main entry point with CLI argument parsing."""
    parser = argparse.ArgumentParser(
        description="SOC AI Agent Framework - مركز العمليات الأمنية",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                     # Start all agents
  python main.py --agent w37         # Start only brute force agent
  python main.py --agent w37 w46     # Start specific agents
  python main.py --list              # List available agents
        """,
    )
    parser.add_argument(
        "--agent", "-a",
        nargs="*",
        metavar="KEY",
        help="Specific agent(s) to start (default: all)",
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="List available agents and exit",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Set log level (default: INFO)",
    )

    args = parser.parse_args()

    # Set log level
    logging.getLogger().setLevel(getattr(logging, args.log_level))

    # List mode
    if args.list:
        list_agents()
        return

    # Resolve agent keys
    agent_keys = None
    if args.agent is not None:
        # Expand short names: "w37" -> "w37_brute_force"
        agent_keys = []
        for key in args.agent:
            if key in AGENT_REGISTRY:
                agent_keys.append(key)
            else:
                # Try prefix match
                matches = [k for k in AGENT_REGISTRY if k.startswith(key)]
                if len(matches) == 1:
                    agent_keys.append(matches[0])
                elif len(matches) > 1:
                    logger.error(
                        "Ambiguous agent key '%s' — matches: %s", key, matches
                    )
                    sys.exit(1)
                else:
                    logger.error("Unknown agent key: '%s'", key)
                    sys.exit(1)

    # Start agents
    agents, threads = start_agents(agent_keys)

    if not agents:
        logger.error("No agents started — exiting.")
        sys.exit(1)

    # Shutdown coordination
    shutdown_event = threading.Event()

    def _handle_signal(signum: int, frame: Any) -> None:
        sig_name = signal.Signals(signum).name
        logger.info("Received %s — initiating graceful shutdown...", sig_name)
        # Signal all agents to stop
        for agent in agents:
            agent._running = False
        shutdown_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    # Wait for shutdown signal
    logger.info("All agents running. Press Ctrl+C to stop.")
    try:
        while not shutdown_event.is_set():
            # Periodically check thread health
            alive = sum(1 for t in threads if t.is_alive())
            if alive == 0:
                logger.warning("All agent threads have exited — shutting down.")
                break
            shutdown_event.wait(timeout=10)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt — shutting down...")
        for agent in agents:
            agent._running = False

    # Wait for threads to finish
    logger.info("Waiting for agent threads to finish...")
    for thread in threads:
        thread.join(timeout=30)

    # Final status
    still_alive = [t for t in threads if t.is_alive()]
    if still_alive:
        logger.warning(
            "%d threads still running after timeout: %s",
            len(still_alive),
            [t.name for t in still_alive],
        )
    else:
        logger.info("All agent threads stopped cleanly.")

    logger.info("=" * 60)
    logger.info("  SOC AI Agent Framework - Shutdown Complete")
    logger.info("  إطار عمل وكلاء مركز العمليات الأمنية - اكتمل الإيقاف")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
