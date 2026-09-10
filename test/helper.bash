# Shared setup and assertions for the skm suites.
#
# Every test runs against a throwaway HOME, so nothing here can touch a real
# ~/.ssh or a real vault. SKM_PORT selects the implementation under test:
# "bash" (the default) or "zsh"; test/run.sh runs the suites against both.

skm_setup() {
    SKM_ROOT=$(cd "$BATS_TEST_DIRNAME/.." && pwd)

    case ${SKM_PORT:-bash} in
        bash) SKM_SHELL=bash ; SKM_SCRIPT="$SKM_ROOT/skm.bash" ;;
        zsh)  SKM_SHELL=zsh  ; SKM_SCRIPT="$SKM_ROOT/skm.zsh"  ;;
        *)    printf 'SKM_PORT must be bash or zsh, got: %s\n' "$SKM_PORT" >&2
              return 1 ;;
    esac

    # Scoped agents put their socket in $SSH_DIR/agents, and a unix socket path
    # is capped at ~104 bytes, so the sandbox needs a shallow root: the temp
    # dirs bats hands out are already too deep on macOS.
    SKM_TMP=$(mktemp -d "${SKM_TEST_TMPDIR:-/tmp}/skm-test.XXXXXX")
    export HOME="$SKM_TMP"
    export SSH_DIR="$SKM_TMP/.ssh"
    export XDG_CONFIG_HOME="$SKM_TMP/config"   # keepassxc-cli settings land here
    mkdir -p "$SSH_DIR" "$XDG_CONFIG_HOME"
    chmod 700 "$SSH_DIR"

    # An agent inherited from whoever ran the suite would show up in the
    # "is the key loaded?" checks and make results depend on the environment.
    unset SSH_AUTH_SOCK SSH_AGENT_PID

    DB="$SKM_TMP/vault.kdbx"
    DB_PW='correct horse'   # a space, because passwords have them

    # A PATH entry whose `chmod` does nothing. Prefixing it lets a test see the
    # mode a file was *created* with, rather than one applied to it afterwards:
    #     PATH="$NOCHMOD:$PATH" skm add box user@example.com
    NOCHMOD="$SKM_TMP/nochmod"
    mkdir -p "$NOCHMOD"
    printf '#!/bin/sh\nexit 0\n' > "$NOCHMOD/chmod"
    chmod +x "$NOCHMOD/chmod"
}

skm_teardown() {
    # Scope tests start real agents; leaving them behind would leak processes
    # holding keys for as long as the machine is up.
    local pidf pid
    for pidf in "$SSH_DIR"/agents/*.pid; do
        [ -f "$pidf" ] || continue
        pid=$(cat "$pidf")
        [ -n "$pid" ] && kill "$pid" 2>/dev/null
    done
    rm -rf "$SKM_TMP"
    return 0
}

# ------------------------------------------------------------------ running

# Run skm with nothing on stdin: any prompt sees EOF, which is what a
# non-interactive caller (a script, a pipeline) gets.
skm() { "$SKM_SHELL" "$SKM_SCRIPT" "$@" </dev/null; }

# Run skm with answers queued for its prompts, one per line, in the order the
# command asks for them:  skm_answer "$DB_PW" y -- drop box "$DB"
skm_answer() {
    local answers=()
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do
        answers+=("$1")
        shift
    done
    shift   # drop the --
    if [ ${#answers[@]} -gt 0 ]; then
        printf '%s\n' "${answers[@]}" | "$SKM_SHELL" "$SKM_SCRIPT" "$@"
    else
        "$SKM_SHELL" "$SKM_SCRIPT" "$@" </dev/null
    fi
}

# ------------------------------------------------------------------- layout

keyfile()  { printf '%s/id_ed25519_%s' "$SSH_DIR" "$1"; }
conffile() { printf '%s/config.d/%s.conf' "$SSH_DIR" "$1"; }

# Add a host without the key-generation chatter. Defaults keep tests short.
add_host() { skm add "$1" "${2:-user@example.com}" ${3:+"$3"} >/dev/null 2>&1; }

fingerprint() { ssh-keygen -lf "$1" 2>/dev/null | awk '{print $2}'; }

identity_file() { awk '$1=="IdentityFile"{print $2}' "$(conffile "$1")"; }

host_line() { awk '$1=="Host"{sub(/^[ \t]*Host[ \t]+/,""); print; exit}' "$(conffile "$1")"; }

file_mode() {
    case $(uname) in
        Darwin) stat -f '%Lp' "$1" ;;
        *)      stat -c '%a'  "$1" ;;
    esac
}

# ---------------------------------------------------------------- keepassxc

# Same lookup the scripts do: on macOS the binary ships inside the app bundle
# and is not on PATH unless it was installed with Homebrew's formula.
KP_APP_BUNDLE=/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli

have_keepassxc() {
    command -v keepassxc-cli >/dev/null 2>&1 || [ -x "$KP_APP_BUNDLE" ]
}

kp_cli() {
    if command -v keepassxc-cli >/dev/null 2>&1; then
        keepassxc-cli "$@"
    else
        "$KP_APP_BUNDLE" "$@"
    fi
}

require_keepassxc() {
    have_keepassxc || skip "keepassxc-cli is not installed"
}

make_vault() { printf '%s\n%s\n' "$DB_PW" "$DB_PW" | kp_cli db-create -p "$DB" >/dev/null; }

vault_attachments() { printf '%s\n' "$DB_PW" | kp_cli show --show-attachments "$DB" "$1" 2>/dev/null; }

# The private key as the vault holds it, written to $1 so its fingerprint can
# be compared with the on-disk copy.
vault_export_key() {
    local name=$1 dest=$2
    printf '%s\n' "$DB_PW" | kp_cli attachment-export "$DB" "SSH Keys/$name" \
        "id_ed25519_$name" "$dest" >/dev/null 2>&1
}

# ------------------------------------------------------------- assertions
#
# These read $status and $output, which bats' `run` sets in the caller.
# shellcheck disable=SC2154

assert_ok() {
    [ "$status" -eq 0 ] && return 0
    printf 'expected success, got exit %s\n--- output ---\n%s\n' "$status" "$output" >&2
    return 1
}

assert_fails() {
    [ "$status" -ne 0 ] && return 0
    printf 'expected failure, got exit 0\n--- output ---\n%s\n' "$output" >&2
    return 1
}

assert_output_has() {
    case $output in
        *"$1"*) return 0 ;;
    esac
    printf 'expected output to contain: %s\n--- output ---\n%s\n' "$1" "$output" >&2
    return 1
}

assert_output_lacks() {
    case $output in
        *"$1"*)
            printf 'expected output NOT to contain: %s\n--- output ---\n%s\n' "$1" "$output" >&2
            return 1 ;;
    esac
    return 0
}

assert_file() {
    [ -f "$1" ] && return 0
    printf 'expected file to exist: %s\n' "$1" >&2
    return 1
}

assert_no_file() {
    [ -e "$1" ] || return 0
    printf 'expected file to be gone: %s\n' "$1" >&2
    return 1
}

assert_mode() {
    local got; got=$(file_mode "$1")
    [ "$got" = "$2" ] && return 0
    printf 'expected mode %s on %s, got %s\n' "$2" "$1" "$got" >&2
    return 1
}

assert_equal() {
    [ "$1" = "$2" ] && return 0
    printf 'expected: %s\n     got: %s\n' "$2" "$1" >&2
    return 1
}
