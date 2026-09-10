#!/usr/bin/env bats
#
# Commands that need nothing but a sandbox HOME: host creation, the config
# file it writes, and the paths that don't involve a vault.

load helper

setup()    { skm_setup; }
teardown() { skm_teardown; }

# ------------------------------------------------------------------- add

@test "add creates a key, a config fragment and the Include line" {
    run skm add box user@example.com 2222
    assert_ok

    assert_file "$(keyfile box)"
    assert_file "$(keyfile box).pub"
    assert_file "$(conffile box)"

    run cat "$(conffile box)"
    assert_output_has "Host box"
    assert_output_has "HostName example.com"
    assert_output_has "User user"
    assert_output_has "Port 2222"
    assert_output_has "IdentityFile \"$(keyfile box)\""
    assert_output_has "IdentitiesOnly yes"

    run head -1 "$SSH_DIR/config"
    assert_output_has "Include config.d/*.conf"
}

@test "add defaults to port 22" {
    run skm add box user@example.com
    assert_ok
    run grep -c 'Port 22$' "$(conffile box)"
    assert_ok
}

@test "add gives the key, the config and the directories restrictive modes" {
    add_host box
    assert_mode "$(keyfile box)" 600
    assert_mode "$(keyfile box).pub" 600
    assert_mode "$(conffile box)" 600
    assert_mode "$SSH_DIR" 700
    assert_mode "$SSH_DIR/config.d" 700
    assert_mode "$SSH_DIR/config" 600
}

@test "add creates its files private rather than widening them afterwards" {
    umask 022   # a permissive caller must not loosen anything skm writes

    PATH="$NOCHMOD:$PATH" skm add box user@example.com >/dev/null 2>&1

    assert_mode "$(keyfile box)" 600
    assert_mode "$(keyfile box).pub" 600
    assert_mode "$(conffile box)" 600
    assert_mode "$SSH_DIR/config" 600
    assert_mode "$SSH_DIR/config.d" 700
}

@test "add refuses a destination that is not user@host" {
    run skm add box example.com
    assert_fails
    assert_output_has "user@host"
    assert_no_file "$(conffile box)"
}

@test "add refuses a name that is already managed" {
    add_host box
    run skm add box other@example.org
    assert_fails
    assert_output_has "already exists"
}

@test "add refuses a name that would not survive a file path or a Host line" {
    for bad in 'my box' '../x' 'a/b' '.hidden' 'a&b' 'x;y'; do
        run skm add "$bad" user@example.com
        assert_fails
        assert_output_has "invalid host name"
    done
    run ls "$SSH_DIR"
    assert_output_lacks "id_ed25519_"
}

@test "add accepts letters, digits, dots, underscores and hyphens" {
    run skm add web-1.eu_2 user@example.com
    assert_ok
    assert_file "$(keyfile web-1.eu_2)"
    assert_equal "$(host_line web-1.eu_2)" 'web-1.eu_2'
}

@test "add refuses a port that is not a number in range" {
    for bad in 'notaport' '22; echo pwned' 0 65536 -1 '2 2'; do
        run skm add box user@example.com "$bad"
        assert_fails
        assert_output_has "invalid port"
    done
    assert_no_file "$(conffile box)"
}

@test "add quotes the IdentityFile path so a directory with a space still works" {
    export SSH_DIR="$SKM_TMP/my dir/.ssh"
    mkdir -p "$SSH_DIR"
    add_host box

    run cat "$(conffile box)"
    assert_output_has "IdentityFile \"$(keyfile box)\""

    # ssh -G reads the fragment the way ssh itself will: the path must come
    # back whole, not truncated at the space.
    run ssh -F "$(conffile box)" -G box
    assert_ok
    assert_output_has "identityfile $(keyfile box)"
}

@test "add without arguments explains itself instead of writing anything" {
    run skm add
    assert_fails
    assert_output_has "usage: skm add"
    [ ! -d "$SSH_DIR/config.d" ] || [ -z "$(ls -A "$SSH_DIR/config.d")" ]
}

@test "the Include line goes above config that is already there" {
    printf 'Host *\n    ServerAliveInterval 60\n' > "$SSH_DIR/config"
    add_host box

    run head -1 "$SSH_DIR/config"
    assert_output_has "Include config.d/*.conf"

    # first-match-wins means the pre-existing catch-all must survive intact
    run cat "$SSH_DIR/config"
    assert_output_has "Host *"
    assert_output_has "ServerAliveInterval 60"
}

@test "a second add does not add a second Include line" {
    add_host box
    add_host tin
    run grep -c 'Include config.d' "$SSH_DIR/config"
    assert_ok
    assert_equal "$output" 1
}

@test "a managed directory outside ~/.ssh is included by its full path" {
    export SSH_DIR="$SKM_TMP/elsewhere"
    mkdir -p "$SSH_DIR"
    add_host box

    run head -1 "$SSH_DIR/config"
    assert_output_has "Include \"$SSH_DIR/config.d/*.conf\""

    # ssh resolves a relative Include against ~/.ssh whatever directory the
    # config itself sits in, so only the full path reaches the fragments.
    run ssh -F "$SSH_DIR/config" -G box
    assert_ok
    assert_output_has "hostname example.com"
    assert_output_has "identityfile $(keyfile box)"
}

@test "a second add to a relocated directory does not repeat the Include" {
    export SSH_DIR="$SKM_TMP/elsewhere"
    mkdir -p "$SSH_DIR"
    add_host box
    add_host tin

    run grep -c Include "$SSH_DIR/config"
    assert_equal "$output" 1
}

@test "SKM_SSH_DIR wins over SSH_DIR" {
    export SKM_SSH_DIR="$SKM_TMP/namespaced"
    mkdir -p "$SKM_SSH_DIR"
    add_host box

    assert_file "$SKM_SSH_DIR/id_ed25519_box"
    assert_file "$SKM_SSH_DIR/config.d/box.conf"
    assert_no_file "$(conffile box)"
}

# ---------------------------------------------------------- multiplexing

@test "the multiplexing socket lives in the managed directory, named by hash" {
    add_host box
    assert_equal "$(control_path box)" "$SSH_DIR/cm/%C"
    assert_mode "$SSH_DIR/cm" 700
}

@test "a long user and host name still give a short, opaque socket path" {
    add_host long deploy@app-01.prod.eu-west-1.internal.example.com

    run ssh -F "$(conffile long)" -G long
    assert_ok
    local sock
    sock=$(printf '%s\n' "$output" | sed -n 's/^controlpath //p')

    # A Unix socket path is capped at ~104 bytes, and a name built from
    # user@host both grows with them and advertises the target to anyone
    # who can list the directory.
    assert_equal "${sock%/*}" "$SSH_DIR/cm"
    [ "${#sock}" -lt 104 ] || { printf 'socket path too long: %s\n' "$sock" >&2; return 1; }
    case $sock in
        *deploy*|*example.com*)
            printf 'socket name names the target: %s\n' "$sock" >&2; return 1 ;;
    esac
}

# ----------------------------------------------------------------- alias

@test "alias appends patterns to the Host line and leaves HostName alone" {
    add_host box
    run skm alias box example.org '10.0.0.*' '*.internal'
    assert_ok

    assert_equal "$(host_line box)" 'box example.org 10.0.0.* *.internal'
    run grep -c 'HostName example.com' "$(conffile box)"
    assert_equal "$output" 1
}

@test "alias skips patterns the host already matches" {
    add_host box
    skm alias box example.org >/dev/null
    run skm alias box example.org
    assert_ok
    assert_output_has "already matched by"
    assert_equal "$(host_line box)" 'box example.org'
}

@test "alias accumulates across calls" {
    add_host box
    skm alias box one.example.com >/dev/null
    skm alias box two.example.com >/dev/null
    assert_equal "$(host_line box)" 'box one.example.com two.example.com'
}

@test "alias needs a managed host and at least one pattern" {
    add_host box
    run skm alias box
    assert_fails
    assert_output_has "usage: skm alias"

    run skm alias nosuch example.org
    assert_fails
    assert_output_has "no such managed host"
}

@test "alias refuses a pattern outside ssh's pattern alphabet" {
    add_host box
    for bad in 'a&b' 'c|d' 'x y' 'a\\b' 'a#b' '$(id)'; do
        run skm alias box "$bad"
        assert_fails
        assert_output_has "invalid host pattern"
        assert_equal "$(host_line box)" 'box'
    done
}

@test "alias rejects the whole call if any pattern is invalid" {
    add_host box
    run skm alias box good.example.com 'bad&pattern'
    assert_fails
    assert_equal "$(host_line box)" 'box'
}

@test "alias accepts globs and a negated pattern" {
    add_host box
    run skm alias box '*.example.com' '10.0.0.?' '!bad-host'
    assert_ok
    assert_equal "$(host_line box)" 'box *.example.com 10.0.0.? !bad-host'
}

@test "alias leaves no editor backup file behind" {
    add_host box
    skm alias box example.org >/dev/null
    assert_no_file "$(conffile box).bak"
}

# ------------------------------------------------------------ list / show

@test "list shows the name, the target and the key" {
    add_host box user@example.com 2222
    run skm list
    assert_ok
    assert_output_has "box"
    assert_output_has "user@example.com:2222"
    assert_output_has "id_ed25519_box"
}

@test "list omits the port when it is 22 and marks agent-mode hosts" {
    add_host box
    add_host tin
    skm agent tin >/dev/null

    run skm list
    assert_ok
    assert_output_has "user@example.com "
    assert_output_lacks "user@example.com:22"
    assert_output_has "(agent)"
}

@test "show prints the public key" {
    add_host box
    run skm show box
    assert_ok
    assert_output_has "ssh-ed25519 "
    assert_equal "$output" "$(cat "$(keyfile box).pub")"
}

@test "show fails for a host that is not managed" {
    run skm show nosuch
    assert_fails
    assert_output_has "no such managed host"
}

@test "show without a name fails rather than printing another host's key" {
    add_host box
    run skm show
    assert_fails
    assert_output_lacks "ssh-ed25519 "
}

# --------------------------------------------------------- agent / ondisk

@test "agent points IdentityFile at the public key and ondisk puts it back" {
    add_host box
    run skm agent box
    assert_ok
    assert_equal "$(identity_file box)" "$(keyfile box).pub"

    run skm ondisk box
    assert_ok
    assert_equal "$(identity_file box)" "$(keyfile box)"
}

@test "agent leaves the rest of the config fragment untouched" {
    add_host box user@example.com 2222
    skm agent box >/dev/null
    run cat "$(conffile box)"
    assert_output_has "HostName example.com"
    assert_output_has "Port 2222"
    assert_output_has "ControlPersist 10m"
    assert_no_file "$(conffile box).bak"
}

@test "agent keeps the indentation of the IdentityFile line" {
    add_host box
    skm agent box >/dev/null
    run grep -c '^    IdentityFile' "$(conffile box)"
    assert_equal "$output" 1
}

# --------------------------------------------------------------- status

@test "status reports a key that is on disk as OK" {
    add_host box
    run skm status box
    assert_ok
    assert_output_has "private       disk: yes"
    assert_output_has "OK (on disk)"
}

@test "status warns when the config says agent but the key is still on disk" {
    add_host box
    skm agent box >/dev/null
    run skm status box
    assert_ok
    assert_output_has "WARNING"
}

@test "status flags a config pointing at a private key that is gone" {
    add_host box
    rm -f "$(keyfile box)"
    run skm status box
    assert_ok
    assert_output_has "BROKEN"
}

@test "status covers every host when asked for all of them" {
    add_host box
    add_host tin
    run skm status --all
    assert_ok
    assert_output_has "box"
    assert_output_has "tin"
}

@test "status rejects a database path that does not exist" {
    add_host box
    run skm status box "$SKM_TMP/missing.kdbx"
    assert_fails
    assert_output_has "no such database"
}

# ------------------------------------------------------------------- rm

@test "rm deletes the key pair and the config fragment when confirmed" {
    add_host box
    run skm_answer y -- rm box
    assert_ok
    assert_no_file "$(keyfile box)"
    assert_no_file "$(keyfile box).pub"
    assert_no_file "$(conffile box)"
}

@test "rm keeps everything when the answer is no" {
    add_host box
    run skm_answer n -- rm box
    assert_ok
    assert_output_has "aborted"
    assert_file "$(keyfile box)"
    assert_file "$(conffile box)"
}

@test "rm aborts, with a message, when there is nothing on stdin to answer with" {
    add_host box
    run skm rm box
    assert_ok
    assert_output_has "aborted"
    assert_file "$(keyfile box)"
}

# ------------------------------------------------------------- dispatch

@test "no arguments print the command summary" {
    run skm
    assert_output_has "skm add <name>"
    assert_output_has "skm scope <label>"
}

@test "an unrecognised command names it, prints the summary and fails" {
    run skm frobnicate
    assert_fails
    assert_equal "$status" 2
    assert_output_has "unknown command 'frobnicate'"
    assert_output_has "skm add <name>"
}

@test "an unrecognised command keeps the summary off stdout" {
    run bash -c '"$1" "$2" frobnicate 2>/dev/null' _ "$SKM_SHELL" "$SKM_SCRIPT"
    assert_fails
    assert_equal "$output" ""
}

@test "asking for help succeeds" {
    local flag
    for flag in help -h --help; do
        run skm "$flag"
        assert_ok
        assert_output_has "skm add <name>"
    done
}

@test "commands that need a managed host say so instead of crashing" {
    local cmd
    for cmd in show copy agent ondisk rm; do
        run skm "$cmd" nosuch
        assert_fails
        assert_output_has "no such managed host"
    done
}

@test "commands used without a name print their own usage line" {
    local cmd
    for cmd in show copy agent ondisk rm; do
        run skm "$cmd"
        assert_fails
        assert_output_has "usage: skm $cmd <name>"
        assert_output_lacks "unbound variable"
        assert_output_lacks "parameter not set"
    done
}
