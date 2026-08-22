"""Minimal file configuration for tmuxgate."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import tomllib


DEFAULT_MCP_PORT = 8765


class ConfigError(ValueError):
    """The configuration is missing or invalid."""


@dataclass(frozen=True, slots=True)
class Config:
    """Configured OpenSSH destinations and the local MCP port."""

    machines: dict[str, str]
    mcp_port: int = DEFAULT_MCP_PORT

    def destination(self, machine: str) -> str:
        try:
            return self.machines[machine]
        except KeyError as exc:
            aliases = ", ".join(sorted(self.machines)) or "(none)"
            raise ConfigError(
                f"unknown_machine: {machine!r}; configured aliases: {aliases}"
            ) from exc


def default_config_path(environ: dict[str, str] | None = None) -> Path:
    values = os.environ if environ is None else environ
    base = values.get("XDG_CONFIG_HOME")
    if base:
        return Path(base) / "tmuxgate" / "config.toml"
    return Path.home() / ".config" / "tmuxgate" / "config.toml"


def default_state_dir(environ: dict[str, str] | None = None) -> Path:
    values = os.environ if environ is None else environ
    base = values.get("XDG_STATE_HOME")
    if base:
        return Path(base) / "tmuxgate"
    return Path.home() / ".local" / "state" / "tmuxgate"


def _machine_mapping(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or not value:
        raise ConfigError("[machines] must contain at least one alias")
    machines: dict[str, str] = {}
    for alias, destination in value.items():
        if not isinstance(alias, str) or not alias or "\x00" in alias:
            raise ConfigError("machine aliases must be non-empty strings without NUL")
        if not isinstance(destination, str) or not destination:
            raise ConfigError(f"machine {alias!r} must map to an OpenSSH destination")
        if destination.startswith("-") or any(
            character.isspace() or character == "\x00" for character in destination
        ):
            raise ConfigError(
                f"machine {alias!r} has an unsafe OpenSSH destination"
            )
        machines[alias] = destination
    return machines


def load_config(path: Path | str | None = None) -> Config:
    selected = default_config_path() if path is None else Path(path)
    try:
        with selected.open("rb") as handle:
            raw = tomllib.load(handle)
    except FileNotFoundError as exc:
        raise ConfigError(f"configuration file not found: {selected}") from exc
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read configuration {selected}: {exc}") from exc

    unexpected = set(raw) - {"machines", "mcp"}
    if unexpected:
        names = ", ".join(sorted(unexpected))
        raise ConfigError(f"unsupported configuration sections: {names}")
    machines = _machine_mapping(raw.get("machines"))
    mcp = raw.get("mcp", {})
    if not isinstance(mcp, dict):
        raise ConfigError("[mcp] must be a table")
    unexpected_mcp = set(mcp) - {"port"}
    if unexpected_mcp:
        names = ", ".join(sorted(unexpected_mcp))
        raise ConfigError(f"unsupported [mcp] keys: {names}")
    port = mcp.get("port", DEFAULT_MCP_PORT)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ConfigError("mcp.port must be an integer between 1 and 65535")
    return Config(machines=machines, mcp_port=port)
