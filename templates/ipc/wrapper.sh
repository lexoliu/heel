#!/bin/sh
# {{ command }}: forwards to the heel IPC handler running on the host.
#
# All argument handling happens in `heel ipc`, which either binds words to the
# declared argument names or forwards them verbatim for raw-args commands.
# Standard input is passed through untouched rather than captured here, so
# piped data is neither truncated at NUL nor limited by the argument-length
# ceiling.
SELF_DIR="$(CDPATH= cd -- "${0%/*}" && pwd)"
exec "$SELF_DIR/heel" ipc {{ command }}{% if raw_args %} --raw-args{% else %}{% for arg in positional_args %} --positional {{ arg }}{% endfor %}{% endif %}{% if let Some(stdin_arg) = stdin_arg %} --stdin-arg {{ stdin_arg }}{% endif %} -- "$@"
