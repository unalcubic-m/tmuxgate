#!/usr/bin/env bash
set -u
umask 077

if [ "$#" -ne 3 ]; then
    echo 'tmuxgate runner requires JOB_DIR, WAIT_CHANNEL, and TMUX_BIN' >&2
    exit 125
fi
job_dir=$1
wait_channel=$2
tmux_bin=$3
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
if [ "$(/usr/bin/stat -c '%a:%u' "$job_dir")" != "700:$(/usr/bin/id -u)" ]; then
    echo 'tmuxgate runner refused unsafe job directory metadata' >&2
    exit 125
fi
cd "$job_dir" || exit 125

for required in mode cwd.bin environment.bin timeout result-limits; do
    if [ ! -f "$required" ] || [ -L "$required" ]; then
        echo "tmuxgate runner missing $required" >&2
        exit 125
    fi
    if [ "$(/usr/bin/stat -c '%a:%u' "$required")" != "600:$(/usr/bin/id -u)" ]; then
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
   [ "$(/usr/bin/stat -c '%a:%u' "$payload")" != "600:$(/usr/bin/id -u)" ]; then
    echo 'tmuxgate runner refused unsafe payload metadata' >&2
    exit 125
fi

IFS= read -r -d '' cwd < cwd.bin || {
    echo 'tmuxgate runner refused cwd encoding' >&2
    exit 125
}
[[ $cwd == /* ]] || { echo 'tmuxgate runner refused cwd' >&2; exit 125; }

environment_entries=()
mapfile -d '' -t environment_entries < environment.bin
if ((${#environment_entries[@]} % 2 != 0)); then
    echo 'tmuxgate runner refused environment encoding' >&2
    exit 125
fi
request_environment=()
for ((index=0; index<${#environment_entries[@]}; index+=2)); do
    name=${environment_entries[index]}
    value=${environment_entries[index+1]}
    [[ $name =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || exit 125
    request_environment+=("$name=$value")
done
unset environment_entries name value index

timeout_seconds=$(/usr/bin/tr -d '\n' < timeout)
if [ -n "$timeout_seconds" ] && [[ ! $timeout_seconds =~ ^[1-9][0-9]*$ ]]; then
    echo 'tmuxgate runner refused timeout' >&2
    exit 125
fi

mapfile -t result_limits < result-limits
if [ "${#result_limits[@]}" -ne 3 ]; then
    echo 'tmuxgate runner refused result limits' >&2
    exit 125
fi
stdout_limit=${result_limits[0]}
stderr_limit=${result_limits[1]}
remote_capture_limit=${result_limits[2]}
for limit in "$stdout_limit" "$stderr_limit" "$remote_capture_limit"; do
    if [[ ! $limit =~ ^[1-9][0-9]*$ ]]; then
        echo 'tmuxgate runner refused result limits' >&2
        exit 125
    fi
done
unset result_limits limit

/usr/bin/rm -f -- stdout.fifo stderr.fifo
/usr/bin/mkfifo -m 600 stdout.fifo stderr.fifo || exit 125
: > stdout.raw
: > stderr.raw
printf '%s\n' gated > state
runner_complete=0
# shellcheck disable=SC2317
# This function is reached indirectly through the EXIT trap below.
cleanup_runner() {
    set +e
    if [ -n "${quota_monitor:-}" ]; then kill "$quota_monitor" 2>/dev/null; wait "$quota_monitor" 2>/dev/null; fi
    if [ -n "${stdout_tee:-}" ]; then kill "$stdout_tee" 2>/dev/null; wait "$stdout_tee" 2>/dev/null; fi
    if [ -n "${stderr_tee:-}" ]; then kill "$stderr_tee" 2>/dev/null; wait "$stderr_tee" 2>/dev/null; fi
    /usr/bin/rm -f -- stdout.fifo stderr.fifo
    if [ "$runner_complete" -ne 1 ]; then
        printf '%s\n' capture-incomplete > state.tmp
        /usr/bin/mv -f -- state.tmp state
    fi
    return 0
}
trap cleanup_runner EXIT
trap 'exit 125' HUP INT TERM
capture_stream() {
    set -o pipefail
    /usr/bin/head -c "$(( $1 + 1 ))" | /usr/bin/tee "$2"
}
capture_stream "$stdout_limit" stdout.raw < stdout.fifo &
stdout_tee=$!
capture_stream "$stderr_limit" stderr.raw < stderr.fifo >&2 &
stderr_tee=$!

monitor_capture_limit() {
    monitored_pid=$1
    while /bin/kill -0 "$monitored_pid" 2>/dev/null; do
        stdout_size=$(/usr/bin/stat -c '%s' stdout.raw 2>/dev/null) || stdout_size=0
        stderr_size=$(/usr/bin/stat -c '%s' stderr.raw 2>/dev/null) || stderr_size=0
        if [ "$stdout_size" -gt "$stdout_limit" ] || \
           [ "$stderr_size" -gt "$stderr_limit" ] || \
           [ "$((stdout_size + stderr_size))" -gt "$remote_capture_limit" ]; then
            : > capture-limit-exceeded
            /bin/kill "$monitored_pid" "$stdout_tee" "$stderr_tee" 2>/dev/null || true
            return 0
        fi
        /usr/bin/sleep 0.05
    done
}

"$tmux_bin" wait-for "$wait_channel" || exit 125
printf '%s\n' running > state
set +e
if [ "$mode" = exec ]; then
    argv=()
    mapfile -d '' -t argv < argv.bin
    if ((${#argv[@]} == 0)); then
        command_rc=125
    else
        submitted_command=(
            /usr/bin/env -i "HOME=$HOME" PATH=/usr/bin:/bin
            "${request_environment[@]}" "${argv[@]}"
        )
        if [ -n "$timeout_seconds" ]; then
            (cd "$cwd" && /usr/bin/timeout --foreground --kill-after=5s \
                "$timeout_seconds" "${submitted_command[@]}") \
                > stdout.fifo 2> stderr.fifo &
        else
            (cd "$cwd" && "${submitted_command[@]}") \
                > stdout.fifo 2> stderr.fifo &
        fi
        command_pid=$!
        monitor_capture_limit "$command_pid" & quota_monitor=$!
        wait "$command_pid"
        command_rc=$?
        kill "$quota_monitor" 2>/dev/null; wait "$quota_monitor" 2>/dev/null
        quota_monitor=''
    fi
else
    submitted_command=(
        /usr/bin/env -i "HOME=$HOME" PATH=/usr/bin:/bin
        "${request_environment[@]}" /bin/bash --noprofile --norc
        "$job_dir/payload.sh"
    )
    if [ -n "$timeout_seconds" ]; then
        (cd "$cwd" && /usr/bin/timeout --foreground --kill-after=5s \
            "$timeout_seconds" "${submitted_command[@]}") \
            > stdout.fifo 2> stderr.fifo &
    else
        (cd "$cwd" && "${submitted_command[@]}") \
            > stdout.fifo 2> stderr.fifo &
    fi
    command_pid=$!
    monitor_capture_limit "$command_pid" & quota_monitor=$!
    wait "$command_pid"
    command_rc=$?
    kill "$quota_monitor" 2>/dev/null; wait "$quota_monitor" 2>/dev/null
    quota_monitor=''
fi
wait "$stdout_tee"; stdout_tee_rc=$?; stdout_tee=''
wait "$stderr_tee"; stderr_tee_rc=$?; stderr_tee=''
/usr/bin/rm -f -- stdout.fifo stderr.fifo
stdout_size=$(/usr/bin/stat -c '%s' stdout.raw) || exit 125
stderr_size=$(/usr/bin/stat -c '%s' stderr.raw) || exit 125
if [ -f capture-limit-exceeded ] || \
   [ "$stdout_size" -gt "$stdout_limit" ] || \
   [ "$stderr_size" -gt "$stderr_limit" ] || \
   [ "$((stdout_size + stderr_size))" -gt "$remote_capture_limit" ]; then
    /usr/bin/rm -f -- capture-limit-exceeded
    printf '%s\n' capture-limit-exceeded > state.tmp
    /usr/bin/mv -f -- state.tmp state
    runner_complete=1
    exit 125
fi
if [ "$stdout_tee_rc" -ne 0 ] || [ "$stderr_tee_rc" -ne 0 ]; then
    printf '%s\n' capture-incomplete > state
    exit 125
fi
printf '%s\n' "$command_rc" > exit-code.tmp
/usr/bin/mv -f -- exit-code.tmp exit-code
printf '%s\n' complete > state.tmp
/usr/bin/mv -f -- state.tmp state
runner_complete=1
exit "$command_rc"
