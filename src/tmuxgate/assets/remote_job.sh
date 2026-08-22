#!/bin/bash
set -u
umask 077

sudo_mode=${1:?missing sudo mode}
owner_uid=${2-}
owner_gid=${3-}
job_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd) || exit 125
stdout_file=$job_dir/stdout
stderr_file=$job_dir/stderr
exit_file=$job_dir/exit-code
done_file=$job_dir/done

(
__TMUXGATE_SETUP__
__TMUXGATE_COMMAND__
) </dev/null >"$stdout_file" 2>"$stderr_file"
command_status=$?

exit_temporary=$job_dir/.exit-code.$$
if ! printf '%s\n' "$command_status" >"$exit_temporary"; then
    exit 125
fi
if ! mv -f -- "$exit_temporary" "$exit_file"; then
    exit 125
fi

if [[ "$sudo_mode" == 1 ]]; then
    case $owner_uid:$owner_gid in
        *[!0-9:]*|:|:*|*:)
            exit 125
            ;;
    esac
    if ! chown -- "$owner_uid:$owner_gid" \
        "$stdout_file" "$stderr_file" "$exit_file"; then
        exit 125
    fi
fi

done_temporary=$job_dir/.done.$$
if ! : >"$done_temporary"; then
    exit 125
fi
if [[ "$sudo_mode" == 1 ]] && \
    ! chown -- "$owner_uid:$owner_gid" "$done_temporary"; then
    exit 125
fi
if ! mv -f -- "$done_temporary" "$done_file"; then
    exit 125
fi
exit "$command_status"
# __TMUXGATE_PAYLOAD__
