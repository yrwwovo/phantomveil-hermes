"""Native saved credentials must work without a terminal DeepSeek export."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest
import yaml

from phantomveil_runtime import native_credentials


@pytest.mark.parametrize("storage", ["dotenv", "key_pointer", "pool", "global_pool", "config"])
def test_native_resolver_reuses_saved_credentials_without_export(tmp_path, monkeypatch, storage):
    from hermes_constants import get_hermes_home
    from hermes_cli import runtime_provider

    native_root = tmp_path / "native"
    source = native_root / "profiles" / "saved" if storage == "global_pool" else native_root
    isolated = tmp_path / "session"
    source.mkdir(parents=True)
    isolated.mkdir()
    key = "fixture-phantomveil-saved-credential"
    model = {"default": "deepseek-saved-fixture", "provider": "deepseek"}
    if storage == "key_pointer":
        model["key_env"] = "SAVED_FIXTURE_API_KEY"
        (source / ".env").write_text(f"SAVED_FIXTURE_API_KEY={key}\n", encoding="utf-8")
    elif storage == "dotenv":
        (source / ".env").write_text(f"DEEPSEEK_API_KEY={key}\n", encoding="utf-8")
    elif storage == "config":
        model = {"default": "saved-custom-model", "provider": "custom",
                 "base_url": "https://fixture.invalid/v1", "api_key": key}
    else:
        (native_root / "auth.json").write_text(json.dumps({"credential_pool": {
            "deepseek": [{"id": "fixture", "auth_type": "api_key", "source": "manual",
                          "access_token": key}]}}), encoding="utf-8")
    (source / "config.yaml").write_text(yaml.safe_dump({"model": model}), encoding="utf-8")
    (isolated / "config.yaml").write_text("model:\n  provider: custom\n", encoding="utf-8")
    (isolated / ".env").write_text("DEEPSEEK_API_KEY=fixture-wrong-profile\n", encoding="utf-8")
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(source))
    native = runtime_provider.resolve_runtime_provider()
    monkeypatch.setenv("HERMES_HOME", str(isolated))
    with native_credentials(source):
        resolved = runtime_provider.resolve_runtime_provider()
        assert resolved["api_key"] == key
        assert resolved["provider"] == native["provider"]
        assert resolved["base_url"] == native["base_url"]
        assert get_hermes_home() == isolated
    assert get_hermes_home() == isolated
    assert "DEEPSEEK_API_KEY" not in os.environ


@pytest.mark.parametrize("entry", ["pveil", "powershell"])
def test_no_argument_entry_uses_saved_hermes_key_and_only_restricted_tools(tmp_path, entry):
    root = Path(__file__).resolve().parents[1]
    native_root = tmp_path / "native"
    source = native_root / "profiles" / "saved-ds" if entry == "pveil" else native_root
    source.mkdir(parents=True)
    if entry == "pveil":
        (native_root / "active_profile").write_text("saved-ds", encoding="utf-8")
    key = "fixture-only-saved-deepseek-key"
    calls = []
    other_calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if self.path == "/api/show":
                # Hermes checks Ollama-compatible metadata for a loopback model endpoint.
                reply = json.dumps({"model_info": {"fixture.context_length": 131072},
                                    "capabilities": ["completion", "tools"]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)
                return
            if "model" not in body:
                other_calls.append((self.path, sorted(body.keys())))
                self.send_error(404)
                return
            calls.append((self.headers.get("Authorization"), body))
            reply = json.dumps({"id": "fixture-reply", "object": "chat.completion",
                "created": 0, "model": body["model"], "choices": [{"index": 0,
                "message": {"role": "assistant", "content": "你好，我是 PhantomVeil。请说明已授权目标与测试任务。"},
                "finish_reason": "stop"}], "usage": {"prompt_tokens": 10,
                "completion_tokens": 10, "total_tokens": 20}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    (source / "config.yaml").write_text(yaml.safe_dump({"model": {
        "default": "deepseek-saved-fixture", "provider": "deepseek"},
        "toolsets": ["terminal", "web", "browser"]}), encoding="utf-8")
    (source / ".env").write_text(f"DEEPSEEK_API_KEY={key}\n"
        f"DEEPSEEK_BASE_URL=http://127.0.0.1:{server.server_port}/v1\n", encoding="utf-8")
    env = {**os.environ, "HERMES_HOME": str(native_root), "LOCALAPPDATA": str(tmp_path / "appdata"),
           "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    if os.name == "nt":
        node = shutil.which("node")
        assert node
        env["PATH"] = str(Path(node).parent) + os.pathsep + env.get("PATH", "")
        env["PATHEXT"] = ".COM;.EXE;.BAT;.CMD"
    env.pop("DEEPSEEK_API_KEY", None)
    if entry == "pveil":
        command = [sys.executable, str(root / "pveil.py")]
    else:
        shell = shutil.which("pwsh") or shutil.which("powershell")
        if not shell:
            server.shutdown()
            server.server_close()
            pytest.skip("PowerShell is unavailable")
        command = [shell, "-NoProfile", "-File",
                   str(root.parent / "security-agent-lab" / "scripts" / "hermes-chat.ps1")]
    try:
        if os.name == "nt":
            # An unseeded native Hermes REPL needs an actual Windows console.
            from tests.test_phantomveil_session_start import idle_windows_terminal
            output = idle_windows_terminal(command, root, env)
        else:
            result = subprocess.run(command, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                    capture_output=True, text=True, encoding="utf-8", timeout=60)
            output = result.stdout + result.stderr
            assert result.returncode == 0, output[-2000:]
        assert key not in output
        assert "你好，我是 PhantomVeil" not in output
        assert calls == []
        # Startup is now idle. Submit an explicit fixture user message before
        # exercising the existing saved-credential and restricted-tool checks.
        runs = tmp_path / "appdata" / "PhantomVeil" / "hermes-chat-runs"
        profiles = list(runs.glob("*/profile"))
        assert len(profiles) == 1
        user_query = tmp_path / "first-user-message.txt"
        user_query.write_text("你好，请说明已授权目标登记流程。", encoding="utf-8")
        result = subprocess.run([sys.executable, str(root / "phantomveil_runtime.py"),
            "--session-home", str(profiles[0]), "--query-file", str(user_query)],
            cwd=root, env=env, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, encoding="utf-8", timeout=60)
        output = result.stdout + result.stderr
        assert key not in output
        assert result.returncode == 0, output[-2000:]
        assert "你好，我是 PhantomVeil" in output
        assert calls
        assert not other_calls, other_calls
        seen_tools = set()
        for authorization, body in calls:
            assert authorization == f"Bearer {key}"
            assert body["model"] == "deepseek-saved-fixture"
            names = {tool["function"]["name"].split("__")[-1] for tool in body.get("tools", [])}
            seen_tools.update(names)
            assert all(name.endswith(("authorized_target_bind", "authorized_web_observe",
                                      "evidence_entry_inventory")) for name in names)
        assert seen_tools, [sorted(body.keys()) for _, body in calls]
        for profile in runs.glob("*/profile/config.yaml"):
            assert key not in profile.read_text(encoding="utf-8")
        for log in tmp_path.rglob("*.log"):
            assert key not in log.read_text(encoding="utf-8", errors="replace")
        tasks = list(runs.glob("*/task.json"))
        assert len(tasks) == 1
        assert json.loads(tasks[0].read_text(encoding="utf-8"))["allowed_urls"] == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
