"""Daily chat must stay idle until a real terminal message arrives."""

import json
import os
from pathlib import Path
import re
import shutil
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event, Thread
from time import monotonic

import pytest
import yaml


def idle_windows_terminal(command, cwd, env):
    """Run an idle entry in a real console, then quit without a user turn."""
    from winpty import PtyProcess

    terminal = PtyProcess.spawn(command, cwd=str(cwd), env=env, dimensions=(35, 120))
    output = []
    ready = Event()

    def read_terminal():
        try:
            while terminal.isalive():
                output.append(terminal.read(4096))
                text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", "".join(output))
                if "Type your message" in text:
                    ready.set()
        except (EOFError, OSError):
            pass

    reader = Thread(target=read_terminal, daemon=True)
    reader.start()
    try:
        assert ready.wait(40), "".join(output)[-3000:]
        terminal.write("/quit\r")
        deadline = monotonic() + 15
        while terminal.isalive() and monotonic() < deadline:
            Event().wait(0.1)
        assert not terminal.isalive(), "Terminal failed to quit"
        reader.join(timeout=2)
        return "".join(output)
    finally:
        if terminal.isalive():
            terminal.close(force=True)


@pytest.mark.windows_only
@pytest.mark.parametrize("entry", ["pveil", "powershell"])
def test_terminal_waits_without_completion_then_answers_first_user(tmp_path, entry):
    from winpty import PtyProcess

    root = Path(__file__).resolve().parents[1]
    source = tmp_path / "native"
    source.mkdir()
    calls = []
    completed = Event()
    reply_text = "收到你的第一条消息，当前目标尚未绑定。"

    class Model(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if self.path == "/api/show":
                reply = {"model_info": {"fixture.context_length": 131072},
                         "capabilities": ["completion", "tools"]}
            else:
                calls.append((self.path, body))
                reply = {"id": "fixture-id", "object": "chat.completion", "created": 0,
                         "model": body.get("model"), "choices": [{"index": 0,
                         "message": {"role": "assistant", "content": reply_text},
                         "finish_reason": "stop"}], "usage": {"prompt_tokens": 10,
                         "completion_tokens": 10, "total_tokens": 20}}
                completed.set()
            streaming = self.path != "/api/show" and body.get("stream")
            if streaming:
                chunks = [
                    {"id": "fixture-id", "object": "chat.completion.chunk", "created": 0,
                     "model": body["model"], "choices": [{"index": 0,
                     "delta": {"role": "assistant", "content": reply_text},
                     "finish_reason": None}]},
                    {"id": "fixture-id", "object": "chat.completion.chunk", "created": 0,
                     "model": body["model"], "choices": [{"index": 0,
                     "delta": {}, "finish_reason": "stop"}], "usage": reply["usage"]},
                ]
                payload = ("".join(f"data: {json.dumps(chunk)}\n\n" for chunk in chunks)
                           + "data: [DONE]\n\n").encode()
            else:
                payload = json.dumps(reply).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream" if streaming else "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Model)
    model_thread = Thread(target=server.serve_forever, daemon=True)
    model_thread.start()
    (source / "config.yaml").write_text(yaml.safe_dump({"model": {
        "default": "session-start-fixture", "provider": "custom",
        "base_url": f"http://127.0.0.1:{server.server_port}/v1",
        "api_key": "fixture-only"}}), encoding="utf-8")
    env = {**os.environ, "HERMES_HOME": str(source),
           "LOCALAPPDATA": str(tmp_path / "appdata"), "PYTHONUTF8": "1",
           "PYTHONIOENCODING": "utf-8"}
    # The canonical runner may provide a Git Bash PATH; PowerShell needs a
    # native Windows entry for Node when it starts the same launcher.
    node = shutil.which("node")
    assert node
    env["PATH"] = str(Path(node).parent) + os.pathsep + env.get("PATH", "")
    env["PATHEXT"] = ".COM;.EXE;.BAT;.CMD"
    if entry == "pveil":
        command = [sys.executable, str(root / "pveil.py")]
    else:
        shell = shutil.which("pwsh") or shutil.which("powershell")
        assert shell, "PowerShell is required for its entry test"
        command = [shell, "-NoProfile", "-File",
                   str(root.parent / "security-agent-lab" / "scripts" / "hermes-chat.ps1")]

    terminal = None
    output = []
    ready = Event()
    replied = Event()

    def read_terminal():
        try:
            while terminal.isalive():
                output.append(terminal.read(4096))
                text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", "".join(output))
                if "Type your message" in text:
                    ready.set()
                if reply_text in text:
                    replied.set()
        except (EOFError, OSError):
            pass

    try:
        terminal = PtyProcess.spawn(command, cwd=str(root), env=env, dimensions=(35, 120))
        reader = Thread(target=read_terminal, daemon=True)
        reader.start()
        assert ready.wait(40), "".join(output)[-3000:]
        assert terminal.isalive()
        # Keep an actual terminal open at the input prompt, not just an EOF process.
        assert not completed.wait(2), "Startup unexpectedly generated an assistant turn"
        assert calls == []

        user_message = "你好，请说明当前授权状态。"
        terminal.write(user_message + "\r")
        assert completed.wait(30), "".join(output)[-3000:]
        assert replied.wait(15), "".join(output)[-3000:]
        # Native Hermes may name the session after the first user message.
        # The actual conversational request is the one carrying restricted tools.
        chat_calls = [(route, body) for route, body in calls if body.get("tools")]
        assert len(chat_calls) == 1
        request_path, body = chat_calls[0]
        assert request_path.endswith("/chat/completions")
        users = [m["content"] for m in body["messages"] if m["role"] == "user"]
        assert len(users) == 1
        assert user_message in str(users[0])
        system = "\n".join(str(m["content"]) for m in body["messages"] if m["role"] == "system")
        assert "你是 Phant0mV3il" in system
        assert "未绑定或未经确认时不得请求目标" in system
        assert not any(m["role"] == "assistant" for m in body["messages"])
        names = [tool["function"]["name"] for tool in body["tools"]]
        assert len(names) == 6
        assert {name.split("__")[-1] for name in names} == {
            "authorized_target_bind", "authorized_web_observe", "evidence_entry_inventory",
            "authorized_task_authorize", "authorized_web_crawl", "evidence_input_inventory"}
        runs = tmp_path / "appdata" / "PhantomVeil" / "hermes-chat-runs"
        tasks = list(runs.glob("*/task.json"))
        assert len(tasks) == 1
        grant = json.loads(tasks[0].read_text(encoding="utf-8"))
        assert grant["pending_target"] is True
        assert grant["allowed_urls"] == []
        assert not list(runs.glob("*/start-prompt.txt"))
        for audit in runs.glob("*/request-decisions.jsonl"):
            assert not audit.read_text(encoding="utf-8").strip()
        terminal.write("/quit\r")
        deadline = monotonic() + 15
        while terminal.isalive() and monotonic() < deadline:
            Event().wait(0.1)
        assert not terminal.isalive(), "Terminal failed to quit"
    finally:
        if terminal and terminal.isalive():
            terminal.close(force=True)
        server.shutdown()
        server.server_close()
        model_thread.join(timeout=2)
