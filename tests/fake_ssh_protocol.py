"""A shell-free process double for the SSH protocol, never a real connection."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import shlex
import sys
import tarfile
import time


def main() -> int:
    root = Path(os.environ["TMUXGATE_PROTOCOL_ROOT"])
    arguments = shlex.split(sys.argv[-1])
    phase = arguments[3] if arguments[0] == "/bin/sh" else arguments[0]
    with (root / "calls.jsonl").open("a", encoding="utf-8") as log:
        log.write(json.dumps({
            "options": sys.argv[1:-2], "destination": sys.argv[-2],
            "arguments": arguments,
            "bearer": any(name in os.environ for name in ("TMUXGATE_MCP_TOKEN", "TMUXGATE_BEARER_TOKEN")),
        }) + "\n")
    if sys.argv[-2] == "hostkey-fail":
        sys.stderr.buffer.write(b"Host key verification failed.\n")
        return 255
    if phase == "echo":
        sys.stdout.buffer.write(sys.stdin.buffer.read())
        sys.stderr.buffer.write(b"error\r\n\x00\xff")
        return 0
    if phase == "sleep":
        (root / "sleeping").touch()
        time.sleep(60)
        return 0
    if phase == "flood":
        (root / "sleeping").touch()
        while True:
            sys.stdout.buffer.write(b"x" * 65536)
            sys.stderr.buffer.write(b"x" * 65536)
    if phase == "sudo":
        if "-n" in arguments:
            sys.stderr.write("sudo: a password is required\n")
            return 1
        return 0 if sys.stdin.buffer.read() == b"synthetic-password\n" else 1
    if phase == "tmuxgate-stage":
        (root / "staged").write_bytes(sys.stdin.buffer.read())
        return 0
    if phase in {"tmuxgate-start", "tmuxgate-sudo-start"}:
        if phase == "tmuxgate-sudo-start" and sys.stdin.buffer.read() != b"synthetic-password\n":
            return 1
        with (root / "starts").open("a") as starts:
            starts.write("start\n")
        if (root / "disconnect").exists():
            sys.stderr.write("connection lost after possible start\n")
            return 255
        return 0
    if phase == "tmuxgate-done":
        return 0 if (root / "done").exists() else 1
    if phase == "tmux":
        return 0 if (root / "running").exists() else 1
    if phase == "tmuxgate-collect":
        if (root / "fail-collection").exists():
            return 1
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            for name, payload in (
                ("stdout", b"out\r\n\x00\xff"), ("stderr", b"err\r\n\xfe"), ("exit-code", b"17\n"),
            ):
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        sys.stdout.buffer.write(output.getvalue())
        return 0
    if phase == "tmuxgate-cleanup":
        (root / "cleaned").touch()
        return 0
    raise AssertionError(f"unexpected fake SSH command: {arguments}")


if __name__ == "__main__":
    raise SystemExit(main())
