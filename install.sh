#!/bin/sh
set -eu

tmuxgate_launcher=$0
case "$tmuxgate_launcher" in
    /*) ;;
    *) tmuxgate_launcher=$PWD/$tmuxgate_launcher ;;
esac
tmuxgate_source=$(
    unset CDPATH
    cd -- "$(dirname -- "$tmuxgate_launcher")"
    pwd -P
)
tmuxgate_python=${TMUXGATE_INSTALL_PYTHON:-python3}

if ! command -v "$tmuxgate_python" >/dev/null 2>&1; then
    echo "tmuxgate installer: Python 3.11 or newer is required" >&2
    exit 127
fi

exec "$tmuxgate_python" "$tmuxgate_source/scripts/install.py" \
    --source "$tmuxgate_source" "$@"
