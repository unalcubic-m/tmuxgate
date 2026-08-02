#!/usr/bin/env bash
# Fixed single-quoted child programs intentionally expand only in those child
# shells.
# shellcheck disable=SC2016
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

# The submitted command runs in a dedicated session/process group. Once its
# primary process exits, every process that remains in that group gets TERM,
# one second to exit, and then KILL. A process that deliberately escapes the
# group can never turn an open capture descriptor into successful completion:
# collectors have a separate two-second drain bound below.
descendant_term_attempts=20
capture_drain_seconds=2
group_start_seconds=5

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
    exec 2>/dev/null
    if [ -z "${command_group:-}" ] && [ -n "${command_group_fd:-}" ]; then
        read_group_id "$command_group_fd" 0.1 && command_group=$process_group
    fi
    if [ -z "${stdout_group:-}" ] && [ -n "${stdout_group_fd:-}" ]; then
        read_group_id "$stdout_group_fd" 0.1 && stdout_group=$process_group
    fi
    if [ -z "${stderr_group:-}" ] && [ -n "${stderr_group_fd:-}" ]; then
        read_group_id "$stderr_group_fd" 0.1 && stderr_group=$process_group
    fi
    if [ -n "${command_group_fd:-}" ]; then exec {command_group_fd}>&-; fi
    if [ -n "${stdout_group_fd:-}" ]; then exec {stdout_group_fd}>&-; fi
    if [ -n "${stderr_group_fd:-}" ]; then exec {stderr_group_fd}>&-; fi
    if [ -n "${command_group:-}" ]; then terminate_command_group "$command_group"; fi
    if [ -n "${command_pid:-}" ]; then kill "$command_pid" 2>/dev/null; wait "$command_pid" 2>/dev/null; fi
    if [ -n "${quota_monitor:-}" ]; then kill "$quota_monitor" 2>/dev/null; wait "$quota_monitor" 2>/dev/null; fi
    if [ -n "${stdout_group:-}" ]; then terminate_capture_group "$stdout_group"; fi
    if [ -n "${stderr_group:-}" ]; then terminate_capture_group "$stderr_group"; fi
    if [ -n "${stdout_tee:-}" ]; then kill "$stdout_tee" 2>/dev/null; wait "$stdout_tee" 2>/dev/null; fi
    if [ -n "${stderr_tee:-}" ]; then kill "$stderr_tee" 2>/dev/null; wait "$stderr_tee" 2>/dev/null; fi
    /usr/bin/rm -f -- \
        stdout.fifo stderr.fifo command-group.fifo \
        stdout-group.fifo stderr-group.fifo \
        capture-drain-expired
    if [ "$runner_complete" -ne 1 ]; then
        printf '%s\n' capture-incomplete > state.tmp
        /usr/bin/mv -f -- state.tmp state
    fi
    return 0
}
terminate_command_group() {
    group_pid=$1
    [[ $group_pid =~ ^[1-9][0-9]*$ ]] || return 0
    if /bin/kill -0 -- "-$group_pid" 2>/dev/null; then
        /bin/kill -TERM -- "-$group_pid" 2>/dev/null || true
        for ((_attempt=0; _attempt<descendant_term_attempts; _attempt++)); do
            /bin/kill -0 -- "-$group_pid" 2>/dev/null || break
            /usr/bin/sleep 0.05
        done
        /bin/kill -KILL -- "-$group_pid" 2>/dev/null || true
    fi
}
terminate_capture_group() {
    capture_group_pid=$1
    [[ $capture_group_pid =~ ^[1-9][0-9]*$ ]] || return 0
    /bin/kill -TERM -- "-$capture_group_pid" 2>/dev/null || true
    if /bin/kill -0 -- "-$capture_group_pid" 2>/dev/null; then
        /bin/kill -KILL -- "-$capture_group_pid" 2>/dev/null || true
    fi
}
read_group_id() {
    group_descriptor=$1
    group_timeout=$2
    process_group=''
    IFS= read -r -t "$group_timeout" process_group <&"$group_descriptor" || return 1
    [[ $process_group =~ ^[1-9][0-9]*$ ]]
}

trap cleanup_runner EXIT
trap 'exit 125' HUP INT TERM
/usr/bin/rm -f -- command-group.fifo stdout-group.fifo stderr-group.fifo
/usr/bin/mkfifo -m 600 command-group.fifo stdout-group.fifo stderr-group.fifo || exit 125
exec {command_group_fd}<>command-group.fifo || exit 125
exec {stdout_group_fd}<>stdout-group.fifo || exit 125
exec {stderr_group_fd}<>stderr-group.fifo || exit 125
/usr/bin/rm -f -- command-group.fifo stdout-group.fifo stderr-group.fifo
/usr/bin/setsid --fork --wait /bin/bash --noprofile --norc -c '
    limit=$1
    output=$2
    shift 2
    printf "%s\n" "$$" >&4 || exit 125
    exec 4>&-
    for inherited_descriptor in "$@"; do
        [[ $inherited_descriptor =~ ^[1-9][0-9]*$ ]] || exit 125
        fd_to_close=$inherited_descriptor
        exec {fd_to_close}>&-
    done
    set -o pipefail
    /usr/bin/head -c "$((limit + 1))" | /usr/bin/tee "$output" >&3
' tmuxgate-capture "$stdout_limit" stdout.raw \
    "$command_group_fd" "$stdout_group_fd" "$stderr_group_fd" \
    < stdout.fifo 3>&1 4>&${stdout_group_fd} 2>/dev/null &
stdout_tee=$!
/usr/bin/setsid --fork --wait /bin/bash --noprofile --norc -c '
    limit=$1
    output=$2
    shift 2
    printf "%s\n" "$$" >&4 || exit 125
    exec 4>&-
    for inherited_descriptor in "$@"; do
        [[ $inherited_descriptor =~ ^[1-9][0-9]*$ ]] || exit 125
        fd_to_close=$inherited_descriptor
        exec {fd_to_close}>&-
    done
    set -o pipefail
    /usr/bin/head -c "$((limit + 1))" | /usr/bin/tee "$output" >&3
' tmuxgate-capture "$stderr_limit" stderr.raw \
    "$command_group_fd" "$stdout_group_fd" "$stderr_group_fd" \
    < stderr.fifo 3>&2 4>&${stderr_group_fd} 2>/dev/null &
stderr_tee=$!
stdout_group=''
stderr_group=''

monitor_capture_limit() {
    monitored_pid=$1
    monitored_group=$2
    while /bin/kill -0 "$monitored_pid" 2>/dev/null; do
        stdout_size=$(/usr/bin/stat -c '%s' stdout.raw 2>/dev/null) || stdout_size=0
        stderr_size=$(/usr/bin/stat -c '%s' stderr.raw 2>/dev/null) || stderr_size=0
        if [ "$stdout_size" -gt "$stdout_limit" ] || \
           [ "$stderr_size" -gt "$stderr_limit" ] || \
           [ "$((stdout_size + stderr_size))" -gt "$remote_capture_limit" ]; then
            : > capture-limit-exceeded
            terminate_capture_group "$stdout_group"
            terminate_capture_group "$stderr_group"
            terminate_command_group "$monitored_group"
            /bin/kill "$monitored_pid" 2>/dev/null || true
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
        exit 125
    else
        submitted_command=(
            /usr/bin/env -i "HOME=$HOME" PATH=/usr/bin:/bin
            "${request_environment[@]}" "${argv[@]}"
        )
    fi
else
    submitted_command=(
        /usr/bin/env -i "HOME=$HOME" PATH=/usr/bin:/bin
        "${request_environment[@]}" /bin/bash --noprofile --norc
        "$job_dir/payload.sh"
    )
fi

if [ -n "$timeout_seconds" ]; then
    supervised_command=(
        /usr/bin/timeout --foreground --kill-after=5s
        "$timeout_seconds" "${submitted_command[@]}"
    )
else
    supervised_command=("${submitted_command[@]}")
fi

/usr/bin/setsid --fork --wait /bin/bash --noprofile --norc -c '
    requested_cwd=$1
    command_descriptor=$2
    stdout_descriptor=$3
    stderr_descriptor=$4
    shift 4
    printf "%s\n" "$$" >&4 || exit 125
    exec 4>&-
    for inherited_descriptor in \
        "$command_descriptor" "$stdout_descriptor" "$stderr_descriptor"; do
        [[ $inherited_descriptor =~ ^[1-9][0-9]*$ ]] || exit 125
        fd_to_close=$inherited_descriptor
        exec {fd_to_close}>&-
    done
    cd "$requested_cwd" || exit 125
    exec "$@"
' tmuxgate-command-group "$cwd" \
    "$command_group_fd" "$stdout_group_fd" "$stderr_group_fd" \
    "${supervised_command[@]}" \
    > stdout.fifo 2> stderr.fifo 4>&${command_group_fd} &
command_pid=$!
command_group=''
read_group_id "$command_group_fd" "$group_start_seconds" || exit 125
command_group=$process_group
read_group_id "$stdout_group_fd" "$group_start_seconds" || exit 125
stdout_group=$process_group
read_group_id "$stderr_group_fd" "$group_start_seconds" || exit 125
stderr_group=$process_group
exec {command_group_fd}>&-
exec {stdout_group_fd}>&-
exec {stderr_group_fd}>&-
monitor_capture_limit "$command_pid" "$command_group" & quota_monitor=$!
wait "$command_pid"
command_rc=$?
command_pid=''
wait "$quota_monitor" 2>/dev/null
quota_monitor=''
terminate_command_group "$command_group"
command_group=''

capture_drain_expired=1
for ((_attempt=0; _attempt<capture_drain_seconds * 20; _attempt++)); do
    if ! /bin/kill -0 "$stdout_tee" 2>/dev/null && \
       ! /bin/kill -0 "$stderr_tee" 2>/dev/null; then
        capture_drain_expired=0
        break
    fi
    /usr/bin/sleep 0.05
done
if [ "$capture_drain_expired" -eq 1 ]; then
    terminate_capture_group "$stdout_group"
    terminate_capture_group "$stderr_group"
fi
wait "$stdout_tee"; stdout_tee_rc=$?; stdout_tee=''
wait "$stderr_tee"; stderr_tee_rc=$?; stderr_tee=''
stdout_group=''
stderr_group=''
/usr/bin/rm -f -- \
    stdout.fifo stderr.fifo
if [ "$capture_drain_expired" -eq 1 ]; then
    printf '%s\n' capture-incomplete > state.tmp
    /usr/bin/mv -f -- state.tmp state
    runner_complete=1
    trap - EXIT
    exit 125
fi
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
    trap - EXIT
    exit 125
fi
if [ "$stdout_tee_rc" -ne 0 ] || [ "$stderr_tee_rc" -ne 0 ]; then
    printf '%s\n' capture-incomplete > state.tmp
    /usr/bin/mv -f -- state.tmp state
    runner_complete=1
    trap - EXIT
    exit 125
fi
printf '%s\n' "$command_rc" > exit-code.tmp
/usr/bin/mv -f -- exit-code.tmp exit-code
printf '%s\n' complete > state.tmp
/usr/bin/mv -f -- state.tmp state
runner_complete=1
trap - EXIT
exit "$command_rc"
