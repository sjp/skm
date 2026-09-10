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
    assert_output_has "IdentityFile $(keyfile box)"
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

@test "an unrecognised command prints the command summary" {
    run skm frobnicate
    assert_output_has "skm add <name>"
}

@test "commands that need a managed host say so instead of crashing" {
    local cmd
    for cmd in show copy agent ondisk rm; do
        run skm "$cmd" nosuch
        assert_fails
        assert_output_has "no such managed host"
    done
}
