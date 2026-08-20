#!/bin/sh
# {{ command }} - supports stdin piping: cat file | {{ command }} "prompt"
# stdin_arg: {{ stdin_arg }}, primary_arg: {{ primary_arg }}
SELF_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

# Short-circuit help before probing stdin so `command --help` never blocks on
# non-tty stdin in agent-driven shells.
for arg in "$@"; do
    if [ "$arg" = "--" ]; then
        break
    fi
    case "$arg" in
        --help|-h)
            exec "$SELF_DIR/heel" ipc {{ command }} -- "$@"
            ;;
        -*)
            case "$arg" in
                *h*)
                    exec "$SELF_DIR/heel" ipc {{ command }} -- "$@"
                    ;;
            esac
            ;;
    esac
done

STDIN_CONTENT=""
if [ ! -t 0 ]; then
    STDIN_CONTENT=$(cat)
fi

if [ -n "$STDIN_CONTENT" ]; then
    if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then
        PRIMARY_ARG="$1"
        shift 2>/dev/null || true
        exec "$SELF_DIR/heel" ipc {{ command }} -- --{{ stdin_arg }} "$STDIN_CONTENT" --{{ primary_arg }} "$PRIMARY_ARG" "$@"
    else
        exec "$SELF_DIR/heel" ipc {{ command }} -- --{{ stdin_arg }} "$STDIN_CONTENT" "$@"
    fi
else
    if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then
        PRIMARY_ARG="$1"
        shift 2>/dev/null || true
        exec "$SELF_DIR/heel" ipc {{ command }} -- --{{ primary_arg }} "$PRIMARY_ARG" "$@"
    else
        exec "$SELF_DIR/heel" ipc {{ command }} -- "$@"
    fi
fi
