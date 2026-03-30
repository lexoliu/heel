#!/bin/sh
# {{ command }} - positional args: [{% for arg in positional_args %}{{ arg.name }}{% if !loop.last %}, {% endif %}{% endfor %}]
SELF_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

# If first arg is a flag, pass through directly
if [ $# -gt 0 ] && [ "${1#-}" != "$1" ]; then
    exec "$SELF_DIR/heel" ipc {{ command }} -- "$@"
fi

{% for arg in positional_args %}
{{ arg.shell_var }}="$1"
shift 2>/dev/null || true
{% endfor %}
exec "$SELF_DIR/heel" ipc {{ command }} --{% for arg in positional_args %} --{{ arg.name }} "{{ arg.shell_ref }}"{% endfor %} "$@"
