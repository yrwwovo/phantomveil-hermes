"""PhantomVeil's restricted Hermes terminal entry point.

The security core stays in the adjacent TypeScript project during this migration
slice. This module only selects that core and this fork's Hermes executable.
"""

from __future__ import annotations

import hermes_bootstrap  # noqa: F401 - Windows UTF-8 console setup

import os
from pathlib import Path
import shutil
import subprocess
import sys


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args in (["-h"], ["--help"], ["help"]):
        print("pveil [chat]  进入 PhantomVeil Hermes 受限会话")
        return 0
    if args not in ([], ["chat"]):
        print("仅支持 pveil 或 pveil chat；不提供 OpenCode 运行时入口。", file=sys.stderr)
        return 2

    fork_root = Path(__file__).resolve().parent
    core_root = fork_root.parent / "security-agent-lab"
    launcher = core_root / "scripts" / "hermes-chat.mjs"
    if not launcher.is_file():
        print("PhantomVeil 受限能力项目不可用：缺少 Hermes 启动器。", file=sys.stderr)
        return 2

    node = shutil.which("node")
    if node is None:
        print("未找到 Node.js，无法启动 PhantomVeil 受限能力。", file=sys.stderr)
        return 2

    hermes_name = "hermes.exe" if os.name == "nt" else "hermes"
    hermes = Path(sys.executable).with_name(hermes_name)
    if not hermes.is_file():
        print("当前 PhantomVeil fork 的 Hermes 可执行文件不可用。", file=sys.stderr)
        return 2

    env = os.environ.copy()
    env["HERMES_BIN"] = str(hermes)
    env["PVEIL_HERMES_PYTHON"] = sys.executable
    env["PVEIL_HERMES_RUNTIME"] = str(fork_root / "phantomveil_runtime.py")
    try:
        return subprocess.call(
            [node, str(launcher)],
            cwd=core_root,
            env=env,
        )
    except OSError as exc:
        print(f"PhantomVeil 启动失败：{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
