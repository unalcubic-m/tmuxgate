#!/usr/bin/env bash
set -u
umask 077

if [ "$#" -ne 2 ]; then
    echo 'tmuxgate control requires OPERATION and JOB_ID' >&2
    exit 125
fi
operation=$1
job_id=$2
tmux_bin=${TMUXGATE_TMUX_BIN:-/usr/bin/tmux}

if [[ ! $job_id =~ ^[0-9a-f]{32}$ ]]; then
    echo 'tmuxgate control refused job ID' >&2
    exit 125
fi
parent=$HOME/.cache/tmuxgate/jobs
job_dir=$parent/$job_id
session=tmuxgate-${job_id:0:12}
wait_channel=tmuxgate-start-$job_id

if [ ! -d "$parent" ] || [ -L "$parent" ] ||
   [ "$(stat -c '%a:%u' "$parent")" != "700:$(id -u)" ]; then
    echo 'tmuxgate control refused jobs parent' >&2
    exit 125
fi
if [ ! -d "$job_dir" ] || [ -L "$job_dir" ] ||
   [ "$(stat -c '%a:%u' "$job_dir")" != "700:$(id -u)" ]; then
    echo 'tmuxgate control refused job directory' >&2
    exit 125
fi

safe_file() {
    [ -f "$job_dir/$1" ] && [ ! -L "$job_dir/$1" ] &&
        [ "$(stat -c '%a:%u' "$job_dir/$1")" = "600:$(id -u)" ]
}

read_state() {
    if safe_file state; then
        tr -d '\n' < "$job_dir/state"
    else
        printf '%s' missing
    fi
}

session_exists=0
attached=0
if "$tmux_bin" has-session -t "$session" 2>/dev/null; then
    session_exists=1
    attached=$("$tmux_bin" display-message -p -t "$session" '#{session_attached}' 2>/dev/null) || attached=0
    [[ $attached =~ ^[0-9]+$ ]] || attached=0
fi

case "$operation" in
    validate)
        for required in mode cwd.bin environment.bin timeout remote_runner.sh remote_control.sh; do
            safe_file "$required" || {
                echo "tmuxgate control refused unsafe $required" >&2
                exit 125
            }
        done
        mode=$(tr -d '\n' < "$job_dir/mode")
        case "$mode" in
            exec) safe_file argv.bin || exit 125 ;;
            script) safe_file payload.sh || exit 125 ;;
            *) exit 125 ;;
        esac
        ;;
    create)
        [ "$session_exists" -eq 0 ] || {
            echo 'tmuxgate session already exists' >&2
            exit 125
        }
        "$tmux_bin" new-session -d -s "$session" -- \
            /usr/bin/env -i HOME="$HOME" PATH=/usr/bin:/bin \
            /bin/bash --noprofile --norc "$job_dir/remote_runner.sh" \
            "$job_dir" "$wait_channel" "$tmux_bin" ||
            exit 125
        # A completed foreground command must close its viewer automatically.
        # Canonical stdout/stderr and exit status live in the protected job
        # directory, so keeping a dead pane provides no recovery value.
        "$tmux_bin" set-option -t "$session" remain-on-exit off || exit 125
        for _attempt in {1..100}; do
            [ "$(read_state)" = gated ] && exit 0
            /usr/bin/sleep 0.05
        done
        echo 'tmuxgate runner did not reach its gate' >&2
        exit 125
        ;;
    observe)
        state=$(read_state)
        gate_released=0
        safe_file gate-released && gate_released=1
        command_running=0
        completion_proven=0
        exit_status=
        stdout_size=
        stderr_size=
        stdout_sha256=
        stderr_sha256=
        if [ "$gate_released" -eq 1 ] &&
           [ "$state" != complete ] && [ "$state" != capture-incomplete ]; then
            command_running=1
        fi
        if [ "$state" = complete ] && safe_file exit-code &&
           safe_file stdout.raw && safe_file stderr.raw; then
            exit_status=$(tr -d '\n' < "$job_dir/exit-code")
            if [[ $exit_status =~ ^[0-9]+$ ]] && [ "$exit_status" -le 255 ]; then
                completion_proven=1
                stdout_size=$(stat -c '%s' "$job_dir/stdout.raw")
                stderr_size=$(stat -c '%s' "$job_dir/stderr.raw")
                stdout_sha256=$(sha256sum "$job_dir/stdout.raw")
                stdout_sha256=${stdout_sha256%% *}
                stderr_sha256=$(sha256sum "$job_dir/stderr.raw")
                stderr_sha256=${stderr_sha256%% *}
            fi
        fi
        printf 'session_exists=%s\n' "$session_exists"
        printf 'attached_clients=%s\n' "$attached"
        printf 'gate_released=%s\n' "$gate_released"
        printf 'command_running=%s\n' "$command_running"
        printf 'completion_proven=%s\n' "$completion_proven"
        printf 'exit_status=%s\n' "$exit_status"
        printf 'stdout_size=%s\n' "$stdout_size"
        printf 'stderr_size=%s\n' "$stderr_size"
        printf 'stdout_sha256=%s\n' "$stdout_sha256"
        printf 'stderr_sha256=%s\n' "$stderr_sha256"
        ;;
    release)
        [ "$session_exists" -eq 1 ] && [ "$attached" -ge 1 ] ||
            { echo 'tmuxgate release requires attached viewer' >&2; exit 125; }
        [ "$(read_state)" = gated ] || {
            echo 'tmuxgate release requires gated runner' >&2
            exit 125
        }
        : > "$job_dir/gate-released"
        chmod 600 "$job_dir/gate-released"
        "$tmux_bin" wait-for -S "$wait_channel"
        ;;
    attach)
        [ "$session_exists" -eq 1 ] || {
            echo 'tmuxgate session does not exist' >&2
            exit 125
        }
        exec "$tmux_bin" attach-session -t "$session"
        ;;
    collect)
        [ "$(read_state)" = complete ] && [ "$attached" -eq 0 ] ||
            { echo 'tmuxgate collection requires complete detached job' >&2; exit 125; }
        for required in stdout.raw stderr.raw exit-code state; do
            safe_file "$required" || exit 125
        done
        exec tar -cf - -C "$job_dir" stdout.raw stderr.raw exit-code state
        ;;
    cleanup)
        [ "$(read_state)" = complete ] && [ "$attached" -eq 0 ] ||
            { echo 'tmuxgate cleanup refused active or incomplete job' >&2; exit 125; }
        if [ "$session_exists" -eq 1 ]; then
            "$tmux_bin" kill-session -t "$session" || exit 125
        fi
        for entry in "$job_dir"/* "$job_dir"/.[!.]* "$job_dir"/..?*; do
            [ -e "$entry" ] || continue
            name=${entry##*/}
            case "$name" in
                mode|cwd.bin|environment.bin|timeout|argv.bin|payload.sh|remote_runner.sh|remote_control.sh|stdout.raw|stderr.raw|state|exit-code|gate-released)
                    [ -f "$entry" ] && [ ! -L "$entry" ] || exit 125
                    ;;
                *)
                    echo "tmuxgate cleanup refused unexpected entry: $name" >&2
                    exit 125
                    ;;
            esac
        done
        rm -f -- \
            "$job_dir/mode" "$job_dir/cwd.bin" "$job_dir/environment.bin" \
            "$job_dir/timeout" "$job_dir/argv.bin" "$job_dir/payload.sh" \
            "$job_dir/remote_runner.sh" "$job_dir/remote_control.sh" \
            "$job_dir/stdout.raw" "$job_dir/stderr.raw" "$job_dir/state" \
            "$job_dir/exit-code" "$job_dir/gate-released"
        rmdir -- "$job_dir"
        ;;
    *)
        echo 'tmuxgate control refused operation' >&2
        exit 125
        ;;
esac
