"""One guarded tmux input dispatch, with explicit uncertainty and no retries."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import unicodedata

from tmuxgate import panes, ssh


MAX_TEXT_BYTES = 4096
KEYS = frozenset({"Enter", "Tab", "Escape", "BSpace", "Up", "Down", "Left", "Right", "Home", "End", "PPage", "NPage", "C-c", "C-d", "C-u"})
SENT = b"TMUXGATE_INPUT_SENT_V1\n"
REJECTED = b"TMUXGATE_INPUT_REJECTED_V1\n"


@dataclass(slots=True)
class Dispatch:
    """In-memory attempt state; starting SSH means delivery may be uncertain."""

    started: bool = False
    acknowledged: bool = False


def validate_pid(pane_pid: int) -> None:
    if type(pane_pid) is not int or not 0 < pane_pid < 10**20:
        raise ValueError("pane_pid must be the positive process ID returned by discovery")


def text_keys(text: str, multiline: bool, submit: bool) -> str:
    if type(multiline) is not bool or type(submit) is not bool:
        raise ValueError("multiline and submit must be bools")
    if not isinstance(text, str) or not text:
        raise ValueError("text must be non-empty")
    try:
        payload = text.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("text must be valid Unicode") from exc
    if len(payload) > MAX_TEXT_BYTES:
        raise ValueError("text must not exceed 4096 UTF-8 bytes")
    if any(unicodedata.category(character) in {"Cc", "Cs"} and not (character == "\n" and multiline) for character in text):
        raise ValueError("text must not contain control characters; LF requires multiline=true and can execute lines")
    # Hex bytes separate literal UTF-8 from tmux key names and both command parsers.
    return " ".join(f"{byte:02x}" for byte in payload)


def validate_key(key: str) -> None:
    if not isinstance(key, str) or key not in KEYS:
        raise ValueError("key must be one of: " + ", ".join(sorted(KEYS)))


def target_guard(server: str, session: str, window: str, pane: str, pane_pid: int) -> str:
    """Construct only from validated numeric identities and fixed tmux formats."""
    conditions = [
        f"#{{==:#{{pid}}:#{{start_time}},{server}}}",
        f"#{{==:#{{session_id}},{session}}}",
        f"#{{==:#{{window_id}},{window}}}",
        f"#{{==:#{{pane_id}},{pane}}}",
        f"#{{==:#{{pane_pid}},{pane_pid}}}",
        "#{==:#{pane_dead},0}", "#{==:#{pane_in_mode},0}",
    ]
    guard = conditions.pop()
    for condition in reversed(conditions):
        guard = f"#{{&&:{condition},{guard}}}"
    return guard


def outcome(status: str, code: str | None = None) -> dict[str, object]:
    view: dict[str, object] = {"status": status, "retryable": False}
    if code is not None:
        view["error_code"] = code
    if status == "unknown":
        view["error_detail"] = "input may have reached the pane; inspect and obtain a new explicit decision, never automatically retry"
    return view


async def send(
    destination: str, server: str, session: str, window: str, pane: str,
    pane_pid: int, keys: str, *, literal: bool, submit: bool, dispatch: Dispatch,
) -> dict[str, object]:
    selected = panes._select(await panes.list_panes(destination), server, session, window, pane)
    if selected.pane_pid != pane_pid:
        raise panes.PaneError("stale_target", "pane process changed; discover and select again explicitly")
    command = f"send-keys {'-H ' if literal else ''}-t {pane} {keys}"
    if submit:
        command += f" ; send-keys -t {pane} Enter"
    command += " ; display-message -p TMUXGATE_INPUT_SENT_V1"
    arguments = [
        "tmux", "-u", "if-shell", "-F", "-t", f"{session}:{window}.{pane}",
        target_guard(server, session, window, pane, pane_pid), command,
        "display-message -p TMUXGATE_INPUT_REJECTED_V1",
    ]
    dispatch.started = True
    try:
        result = await ssh.run(destination, arguments, output_limit=panes.MAX_RESPONSE_BYTES)
    except asyncio.CancelledError:
        raise
    except Exception:
        return outcome("unknown", "dispatch_unknown")
    if result.returncode == 0 and result.stdout == SENT and not result.stderr:
        dispatch.acknowledged = True
        return outcome("sent")
    if result.returncode == 0 and result.stdout == REJECTED and not result.stderr:
        return outcome("not_sent", "stale_target")
    return outcome("unknown", "dispatch_unknown")
