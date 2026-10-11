"""Use native Hermes inference credentials with a restricted PhantomVeil home.

Credentials stay in their native store. Only model/provider configuration is
shared in memory; tools, memory and task artifacts use the isolated home.
"""

from __future__ import annotations

import hermes_bootstrap  # noqa: F401

import argparse
from contextlib import contextmanager
from copy import deepcopy
import os
from pathlib import Path


@contextmanager
def native_credentials(source_home: Path):
    """Route every credential refresh through Hermes' existing resolver."""
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override
    from hermes_cli import runtime_provider

    original = runtime_provider.resolve_runtime_provider

    def resolve(**kwargs):
        token = set_hermes_home_override(source_home)
        try:
            return original(**kwargs)
        finally:
            reset_hermes_home_override(token)

    runtime_provider.resolve_runtime_provider = resolve
    try:
        yield
    finally:
        runtime_provider.resolve_runtime_provider = original


def run_chat(profile: Path, prompt_file: Path | None = None, max_turns: int = 6,
             oneshot: bool = False):
    # Import the official entry before replacing HERMES_HOME: it applies the
    # same active-profile selection and dotenv loader as a bare `hermes`.
    import hermes_cli.main  # noqa: F401
    from hermes_constants import get_hermes_home
    from hermes_cli.config import load_config

    source_home = get_hermes_home()
    source_config = load_config()
    os.environ["HERMES_HOME"] = str(profile.resolve())
    os.environ["HERMES_IGNORE_RULES"] = "1"
    os.environ["HERMES_SESSION_SOURCE"] = "pveil-reconlab" if oneshot else "pveil-hermes-chat"

    with native_credentials(source_home):
        # This is the same REPL called by hermes_cli.main.cmd_chat. Import it
        # only after isolation so MCP/tools/session state use the task profile.
        import cli

        for name in ("model", "providers", "custom_providers"):
            if name in source_config:
                cli.CLI_CONFIG[name] = deepcopy(source_config[name])
        # No seeded query for daily chat: the persona lives in agent.system_prompt
        # and the native REPL waits for the first actual user message.
        cli.main(query=prompt_file.read_text(encoding="utf-8") if prompt_file else None,
                 toolsets="phantomveil-hermes", max_turns=max_turns,
                 run_budget=150, ignore_rules=True, oneshot=oneshot, quiet=oneshot)


def main(argv=None):
    parser = argparse.ArgumentParser(description="PhantomVeil restricted Hermes runtime")
    parser.add_argument("--session-home", type=Path, required=True)
    parser.add_argument("--query-file", type=Path)
    parser.add_argument("--max-turns", type=int, default=6)
    parser.add_argument("--oneshot", action="store_true",
                        help="Run one restricted task and exit for the ReconLab bridge")
    args = parser.parse_args(argv)
    if args.oneshot and not args.query_file:
        parser.error("--oneshot requires --query-file")
    run_chat(args.session_home, args.query_file, args.max_turns, args.oneshot)


if __name__ == "__main__":
    main()
