#!/usr/bin/env bats
#
# Scoped agents: a real ssh-agent per label, holding only the named keys.
# Every test tears its agents down again, so nothing survives the suite.

load helper

setup()    { skm_setup; }
teardown() { skm_teardown; }

sock_for() { printf '%s/agents/%s.sock' "$SSH_DIR" "$1"; }

agent_fingerprints() {
    SSH_AUTH_SOCK=$(sock_for "$1") ssh-add -l 2>/dev/null | awk '{print $2}'
}

@test "scope starts an agent holding exactly the named key" {
    add_host box
    add_host tin

    run skm scope work box
    assert_ok
    assert_output_has "scope 'work' is live"

    assert_equal "$(agent_fingerprints work)" "$(fingerprint "$(keyfile box)")"
}

@test "scope can hold several keys and no others" {
    add_host box
    add_host tin
    add_host can

    run skm scope work box can
    assert_ok

    local loaded; loaded=$(agent_fingerprints work)
    assert_output_has "scope 'work' is live"
    case $loaded in *"$(fingerprint "$(keyfile box)")"*) ;; *) return 1 ;; esac
    case $loaded in *"$(fingerprint "$(keyfile can)")"*) ;; *) return 1 ;; esac
    case $loaded in *"$(fingerprint "$(keyfile tin)")"*) return 1 ;; esac
}

@test "scope keeps its socket private and prints how to mount it" {
    add_host box
    run skm scope work box
    assert_ok

    assert_mode "$SSH_DIR/agents" 700
    assert_mode "$SSH_DIR/agents/work.pid" 600
    assert_output_has "$(sock_for work)"
    assert_output_has '"SSH_AUTH_SOCK": "/ssh-agent"'
}

@test "scopes lists a running scope and what it holds" {
    add_host box
    skm scope work box >/dev/null

    run skm scopes
    assert_ok
    assert_output_has "work"
    assert_output_has "$(fingerprint "$(keyfile box)")"
}

@test "unscope kills the agent and clears the socket" {
    add_host box
    skm scope work box >/dev/null
    local pid; pid=$(cat "$SSH_DIR/agents/work.pid")

    run skm unscope work
    assert_ok
    assert_output_has "killed scope 'work'"

    assert_no_file "$SSH_DIR/agents/work.pid"
    [ ! -S "$(sock_for work)" ]

    run kill -0 "$pid"
    assert_fails
}

@test "scope refuses to replace a scope that is still running" {
    add_host box
    skm scope work box >/dev/null

    run skm scope work box
    assert_fails
    assert_output_has "already running"

    # the original agent is still the one serving the key
    assert_equal "$(agent_fingerprints work)" "$(fingerprint "$(keyfile box)")"
}

@test "scope needs a label and at least one key" {
    add_host box

    run skm scope
    assert_fails
    assert_output_has "usage: skm scope"

    run skm scope work
    assert_fails
    assert_output_has "name at least one key"
}

@test "scope rejects a host that is not managed" {
    run skm scope work nosuch
    assert_fails
    assert_output_has "no such managed host"
}

@test "scope rejects an unknown flag" {
    add_host box
    run skm scope work --wat box
    assert_fails
    assert_output_has "unknown flag"
}

@test "scope refuses a label that would not stay inside the agents directory" {
    add_host box
    for bad in '../escape' 'a/b' 'my label'; do
        run skm scope "$bad" box
        assert_fails
        assert_output_has "invalid scope label"

        run skm unscope "$bad"
        assert_fails
        assert_output_has "invalid scope label"
    done
}

@test "unscope needs a scope that exists" {
    run skm unscope nosuch
    assert_fails
    assert_output_has "no such scope"
}

@test "a vault-only key needs a database to be scoped" {
    add_host box
    rm -f "$(keyfile box)"

    run skm scope work box
    assert_fails
    assert_output_has "pass -d"
}

@test "scope loads a vault-only key without leaving it on disk" {
    require_keepassxc
    make_vault
    add_host box
    local fp; fp=$(fingerprint "$(keyfile box)")
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null
    skm_answer "$DB_PW" y -- drop box "$DB" >/dev/null

    run skm_answer "$DB_PW" -- scope work -d "$DB" box
    assert_ok

    assert_equal "$(agent_fingerprints work)" "$fp"
    assert_no_file "$(keyfile box)"
}
