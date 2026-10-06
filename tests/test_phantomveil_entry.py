"""Focused tests for the fork-owned PhantomVeil command route."""

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pveil


def test_rejects_opencode_runtime_without_launching():
    with patch.object(pveil.subprocess, "call") as launch:
        assert pveil.main(["chat", "--runtime", "opencode"]) == 2
        launch.assert_not_called()


def test_help_does_not_launch():
    with patch.object(pveil.subprocess, "call") as launch:
        assert pveil.main(["--help"]) == 0
        launch.assert_not_called()


def test_default_and_chat_route_to_restricted_launcher():
    with TemporaryDirectory() as temp:
        fork_root = Path(temp) / "phantomveil-hermes"
        launcher = fork_root.parent / "security-agent-lab" / "scripts" / "hermes-chat.mjs"
        launcher.parent.mkdir(parents=True)
        launcher.touch()
        fake_python = fork_root / ".venv" / "Scripts" / "python.exe"
        fake_python.parent.mkdir(parents=True)
        hermes_name = "hermes.exe" if pveil.os.name == "nt" else "hermes"
        fake_hermes = fake_python.with_name(hermes_name)
        fake_hermes.touch()

        with patch.object(pveil, "__file__", str(fork_root / "pveil.py")), \
             patch.object(pveil.sys, "executable", str(fake_python)), \
             patch.object(pveil.shutil, "which", return_value="node"), \
             patch.object(pveil.subprocess, "call", return_value=0) as launch:
            for args in ([], ["chat"]):
                assert pveil.main(args) == 0
            assert launch.call_count == 2
            for call in launch.call_args_list:
                assert call.args[0] == ["node", str(launcher)]
                assert call.kwargs["env"]["HERMES_BIN"] == str(fake_hermes)
                assert call.kwargs["cwd"] == launcher.parent.parent


def test_missing_core_fails_closed():
    with TemporaryDirectory() as temp:
        fork_root = Path(temp) / "phantomveil-hermes"
        with patch.object(pveil, "__file__", str(fork_root / "pveil.py")), \
             patch.object(pveil.subprocess, "call") as launch:
            assert pveil.main([]) == 2
            launch.assert_not_called()


def test_missing_fork_hermes_never_falls_back_to_another_runtime():
    with TemporaryDirectory() as temp:
        fork_root = Path(temp) / "phantomveil-hermes"
        launcher = fork_root.parent / "security-agent-lab" / "scripts" / "hermes-chat.mjs"
        launcher.parent.mkdir(parents=True)
        launcher.touch()
        fake_python = fork_root / ".venv" / "Scripts" / "python.exe"
        with patch.object(pveil, "__file__", str(fork_root / "pveil.py")), \
             patch.object(pveil.sys, "executable", str(fake_python)), \
             patch.object(pveil.shutil, "which", return_value="node"), \
             patch.object(pveil.subprocess, "call") as launch:
            assert pveil.main([]) == 2
            launch.assert_not_called()
