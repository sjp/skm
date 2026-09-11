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

# A PATH entry of recording stubs: each named command writes its arguments to
# $TRACE_LOG and does nothing else, so a test can see which external commands a
# run reached for. SKM_TRACE_WITNESS names a file a stub also reports on, as
# "witness <path>", when it is still there at the moment the stub ran -- which
# is how a test pins the order of a call against a deletion:
#     trace_setup ssh
#     SKM_TRACE_WITNESS=$(conffile box) PATH="$TRACE_BIN:$PATH" run skm_answer y -- rm box
#     assert_traced "ssh -O exit box"
trace_setup() {   # command...
    TRACE_BIN="$SKM_TMP/trace-bin"
    TRACE_LOG="$SKM_TMP/trace-log"
    mkdir -p "$TRACE_BIN"
    : > "$TRACE_LOG"
    local cmd
    for cmd in "$@"; do
        {
            printf '#!/bin/sh\n'
            printf 'printf "%s %%s\\n" "$*" >> "%s"\n' "$cmd" "$TRACE_LOG"
            # The stub's own text, not this shell's: nothing here is meant to expand.
            # shellcheck disable=SC2016
            printf '[ -n "${SKM_TRACE_WITNESS:-}" ] && [ -e "$SKM_TRACE_WITNESS" ] &&\n'
            # shellcheck disable=SC2016
            printf '    printf "witness %%s\\n" "$SKM_TRACE_WITNESS" >> "%s"\n' "$TRACE_LOG"
            printf 'exit 0\n'
        } > "$TRACE_BIN/$cmd"
        chmod +x "$TRACE_BIN/$cmd"
    done
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

# The config quotes the IdentityFile path, so that a key under a directory with
# a space in its name is still one argument to ssh.
identity_file() {
    awk '$1=="IdentityFile"{ sub(/^[ \t]*IdentityFile[ \t]+/,""); gsub(/^"|"$/,""); print; exit }' \
        "$(conffile "$1")"
}

host_line() { awk '$1=="Host"{sub(/^[ \t]*Host[ \t]+/,""); print; exit}' "$(conffile "$1")"; }

control_path() {
    awk '$1=="ControlPath"{ sub(/^[ \t]*ControlPath[ \t]+/,""); gsub(/^"|"$/,""); print; exit }' \
        "$(conffile "$1")"
}

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

# Whether the database still holds an entry at all, attachments aside.
vault_entry_exists() {
    printf '%s\n' "$DB_PW" | kp_cli show "$DB" "$1" >/dev/null 2>&1
}

# The Password field of an entry: where KeePassXC's agent looks for the
# passphrase that decrypts the key stored alongside it.
vault_password() {
    printf '%s\n' "$DB_PW" | kp_cli show -s "$DB" "$1" 2>/dev/null |
        sed -n 's/^Password: //p'
}

# Give a managed key a passphrase, the way a user who wants one would.
encrypt_key() { ssh-keygen -q -p -P '' -N "$2" -f "$(keyfile "$1")" >/dev/null; }

# Every keepassxc-cli run unlocks the database from scratch, and unlocking is
# the slow part, so the vault commands are also judged by how many runs they
# need. This PATH entry records each subcommand before handing it to the real
# binary:
#     kp_shim_setup
#     PATH="$KP_SHIM:$PATH" skm_answer "$DB_PW" -- export box "$DB"
#     [ "$(kp_calls)" -le 6 ]
kp_shim_setup() {
    KP_SHIM="$SKM_TMP/kp-shim"
    KP_CALLS="$SKM_TMP/kp-calls"
    local real
    if command -v keepassxc-cli >/dev/null 2>&1; then
        real=$(command -v keepassxc-cli)
    else
        real=$KP_APP_BUNDLE
    fi
    mkdir -p "$KP_SHIM"
    cat > "$KP_SHIM/keepassxc-cli" <<SHIM
#!/bin/sh
printf '%s\\n' "\$1" >> "$KP_CALLS"
exec "$real" "\$@"
SHIM
    chmod +x "$KP_SHIM/keepassxc-cli"
    : > "$KP_CALLS"
}

# Calls since the last kp_shim_setup: all of them, or just one subcommand's.
kp_calls()    { wc -l < "$KP_CALLS" | tr -d ' '; }
kp_calls_of() { grep -c "^$1\$" "$KP_CALLS" || true; }

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

assert_traced() {
    grep -qxF -- "$1" "$TRACE_LOG" && return 0
    printf 'expected the run to call: %s\n--- calls ---\n%s\n' "$1" "$(cat "$TRACE_LOG")" >&2
    return 1
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
