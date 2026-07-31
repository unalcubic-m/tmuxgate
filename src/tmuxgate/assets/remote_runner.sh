#!/usr/bin/env bash
set -u
umask 077

if [ "$#" -ne 2 ]; then
    echo 'tmuxgate runner requires JOB_DIR and WAIT_CHANNEL' >&2
    exit 125
fi
job_dir=$1
wait_channel=$2
tmux_bin=${TMUXGATE_TMUX_BIN:-/usr/bin/tmux}
job_id=${job_dir##*/}
if [[ ! $job_id =~ ^[0-9a-f]{32}$ ]] || \
   [ "$job_dir" != "$HOME/.cache/tmuxgate/jobs/$job_id" ] || \
   [ "$wait_channel" != "tmuxgate-start-$job_id" ]; then
    echo 'tmuxgate runner refused job identity' >&2
    exit 125
fi
if [ ! -d "$job_dir" ] || [ -L "$job_dir" ]; then
    echo 'tmuxgate runner refused missing or linked job directory' >&2
    exit 125
fi
if [ "$(stat -c '%a:%u' "$job_dir")" != "700:$(id -u)" ]; then
    echo 'tmuxgate runner refused unsafe job directory metadata' >&2
    exit 125
fi
cd "$job_dir" || exit 125

for required in mode cwd.bin environment.bin timeout; do
    if [ ! -f "$required" ] || [ -L "$required" ]; then
        echo "tmuxgate runner missing $required" >&2
        exit 125
    fi
    if [ "$(stat -c '%a:%u' "$required")" != "600:$(id -u)" ]; then
        echo "tmuxgate runner refused unsafe $required metadata" >&2
        exit 125
    fi
done
mode=$(<mode)
case "$mode" in
    exec) payload=argv.bin ;;
    script) payload=payload.sh ;;
    *) echo 'tmuxgate runner refused execution mode' >&2; exit 125 ;;
esac
if [ ! -f "$payload" ] || [ -L "$payload" ] || \
   [ "$(stat -c '%a:%u' "$payload")" != "600:$(id -u)" ]; then
    echo 'tmuxgate runner refused unsafe payload metadata' >&2
    exit 125
fi

IFS= read -r -d '' cwd < cwd.bin || {
    echo 'tmuxgate runner refused cwd encoding' >&2
    exit 125
}
[[ $cwd == /* ]] || { echo 'tmuxgate runner refused cwd' >&2; exit 125; }

environment=()
mapfile -d '' -t environment < environment.bin
if ((${#environment[@]} % 2 != 0)); then
    echo 'tmuxgate runner refused environment encoding' >&2
    exit 125
fi
for ((index=0; index<${#environment[@]}; index+=2)); do
    name=${environment[index]}
    value=${environment[index+1]}
    [[ $name =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || exit 125
    export "$name=$value"
done
unset environment name value index

timeout_seconds=$(tr -d '\n' < timeout)
if [ -n "$timeout_seconds" ] && [[ ! $timeout_seconds =~ ^[1-9][0-9]*$ ]]; then
    echo 'tmuxgate runner refused timeout' >&2
    exit 125
fi

rm -f -- stdout.fifo stderr.fifo
mkfifo -m 600 stdout.fifo stderr.fifo || exit 125
: > stdout.raw
: > stderr.raw
printf '%s\n' gated > state
runner_complete=0
cleanup_runner() {
    set +e
    if [ -n "${stdout_tee:-}" ]; then kill "$stdout_tee" 2>/dev/null; wait "$stdout_tee" 2>/dev/null; fi
    if [ -n "${stderr_tee:-}" ]; then kill "$stderr_tee" 2>/dev/null; wait "$stderr_tee" 2>/dev/null; fi
    rm -f -- stdout.fifo stderr.fifo
    if [ "$runner_complete" -ne 1 ]; then
        printf '%s\n' capture-incomplete > state.tmp
        mv -f -- state.tmp state
    fi
    return 0
}
trap cleanup_runner EXIT
trap 'exit 125' HUP INT TERM
tee stdout.raw < stdout.fifo &
stdout_tee=$!
tee stderr.raw < stderr.fifo >&2 &
stderr_tee=$!

"$tmux_bin" wait-for "$wait_channel" || exit 125
printf '%s\n' running > state
set +e
if [ "$mode" = exec ]; then
    argv=()
    mapfile -d '' -t argv < argv.bin
    if ((${#argv[@]} == 0)); then
        command_rc=125
    else
        if [ -n "$timeout_seconds" ]; then
            (cd "$cwd" && /usr/bin/timeout --foreground --kill-after=5s \
                "$timeout_seconds" "${argv[@]}") > stdout.fifo 2> stderr.fifo
        else
            (cd "$cwd" && "${argv[@]}") > stdout.fifo 2> stderr.fifo
        fi
        command_rc=$?
    fi
else
    if [ -n "$timeout_seconds" ]; then
        (cd "$cwd" && /usr/bin/timeout --foreground --kill-after=5s \
            "$timeout_seconds" /bin/bash "$job_dir/payload.sh") > stdout.fifo 2> stderr.fifo
    else
        (cd "$cwd" && /bin/bash "$job_dir/payload.sh") > stdout.fifo 2> stderr.fifo
    fi
    command_rc=$?
fi
wait "$stdout_tee"; stdout_tee_rc=$?; stdout_tee=''
wait "$stderr_tee"; stderr_tee_rc=$?; stderr_tee=''
rm -f -- stdout.fifo stderr.fifo
if [ "$stdout_tee_rc" -ne 0 ] || [ "$stderr_tee_rc" -ne 0 ]; then
    printf '%s\n' capture-incomplete > state
    exit 125
fi
printf '%s\n' "$command_rc" > exit-code.tmp
mv -f -- exit-code.tmp exit-code
printf '%s\n' complete > state.tmp
mv -f -- state.tmp state
runner_complete=1
exit "$command_rc"
