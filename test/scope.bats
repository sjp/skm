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

# A label that failed should have left nothing an agent could answer on, and
# no pid file for a later run to read a number out of.
assert_no_scope() {
    assert_no_file "$(sock_for "$1")"
    assert_no_file "$SSH_DIR/agents/$1.pid"
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

@test "one unmanaged name stops the scope before any agent is started" {
    add_host box

    run skm scope work box nosuch
    assert_fails
    assert_output_has "no such managed host"

    assert_no_scope work
}

@test "a key the agent will not take takes the half-built scope with it" {
    add_host box
    add_host tin

    refusing_ssh_add
    PATH="$REFUSE_BIN:$PATH" run skm scope work box tin
    assert_fails
    assert_output_has "would not take the key for 'box'"

    assert_no_scope work
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

@test "a key the agent will not take leaves no copy of itself behind" {
    require_keepassxc
    make_vault
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null
    skm_answer "$DB_PW" y -- drop box "$DB" >/dev/null

    refusing_ssh_add
    PATH="$REFUSE_BIN:$PATH" run skm_answer "$DB_PW" -- scope work -d "$DB" box
    assert_fails
    assert_no_extracted_keys
}

@test "a vault that cannot pipe the key still loads it and takes the copy away" {
    require_keepassxc
    make_vault
    add_host box
    local fp; fp=$(fingerprint "$(keyfile box)")
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null
    skm_answer "$DB_PW" y -- drop box "$DB" >/dev/null

    no_stdout_kp
    PATH="$NO_STDOUT_BIN:$PATH" run skm_answer "$DB_PW" -- scope work -d "$DB" box
    assert_ok
    assert_equal "$(agent_fingerprints work)" "$fp"
    assert_no_extracted_keys
}

@test "a key written out for an agent that refuses it does not survive" {
    require_keepassxc
    make_vault
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null
    skm_answer "$DB_PW" y -- drop box "$DB" >/dev/null

    no_stdout_kp
    refusing_ssh_add
    PATH="$REFUSE_BIN:$NO_STDOUT_BIN:$PATH" run skm_answer "$DB_PW" -- scope work -d "$DB" box
    assert_fails
    assert_no_extracted_keys
}

@test "a scoped vault key opens the database the same way every command does" {
    require_keepassxc
    make_vault
    add_host box
    local fp; fp=$(fingerprint "$(keyfile box)")
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null
    skm_answer "$DB_PW" y -- drop box "$DB" >/dev/null

    printf '%s\n' "$DB_PW" > "$SKM_TMP/pw.txt"
    export SKM_KEEPASS_PASSWORD_FILE="$SKM_TMP/pw.txt"

    run skm scope work -d "$DB" box     # nothing on stdin
    assert_ok
    assert_equal "$(agent_fingerprints work)" "$fp"
}

# --------------------------------------------------------------------- rm

@test "a vault key that was never stored takes the scope down with it" {
    require_keepassxc
    make_vault
    add_host box
    add_host tin
    rm -f "$(keyfile tin)"          # vault-only, but nothing ever put it there

    run skm_answer "$DB_PW" -- scope work -d "$DB" box tin
    assert_fails
    assert_output_has "no key attachment for 'tin'"

    assert_no_scope work
    assert_no_extracted_keys
}

@test "a database that will not open stops the scope before any agent starts" {
    require_keepassxc
    make_vault
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null
    skm_answer "$DB_PW" y -- drop box "$DB" >/dev/null

    run skm_answer wrong -- scope work -d "$DB" box
    assert_fails
    assert_output_has "wrong password"

    assert_no_scope work
}

@test "rm names the scoped agents that are still holding the key" {
    add_host box
    skm scope work box >/dev/null

    run skm_answer y -- rm box
    assert_ok
    assert_output_has "still loaded in scoped agent(s): work"
    assert_output_has "skm unscope"
}

@test "rm finds the agents holding a key whose private half is already off disk" {
    add_host box
    skm scope work box >/dev/null
    rm -f "$(keyfile box)"   # as drop leaves it: the public half and the agent

    run skm_answer y -- rm box
    assert_ok
    assert_output_has "still loaded in scoped agent(s): work"
}

@test "rm says nothing about a scope that holds other keys" {
    add_host box
    add_host tin
    skm scope work tin >/dev/null

    run skm_answer y -- rm box
    assert_ok
    assert_output_lacks "still loaded"
}

@test "unscope spares an unrelated process when the pid file is stale" {
    mkdir -p "$SSH_DIR/agents"
    sleep 30 </dev/null >/dev/null 2>&1 &
    local victim=$!
    printf '%s\n' "$victim" > "$SSH_DIR/agents/work.pid"

    run skm unscope work
    assert_ok
    assert_output_has "no longer running"

    # the bystander that inherited the recorded pid is untouched
    kill -0 "$victim"
    kill "$victim" 2>/dev/null || true

    assert_no_file "$SSH_DIR/agents/work.pid"
}

@test "unscope clears up after an agent that died on its own" {
    add_host box
    skm scope work box >/dev/null
    local pid; pid=$(cat "$SSH_DIR/agents/work.pid")
    kill "$pid"
    while kill -0 "$pid" 2>/dev/null; do sleep 0.1; done

    run skm unscope work
    assert_ok
    assert_output_has "no longer running"

    assert_no_file "$SSH_DIR/agents/work.pid"
    [ ! -S "$(sock_for work)" ]
}

@test "scope replaces a scope whose agent has gone" {
    add_host box
    skm scope work box >/dev/null
    local pid; pid=$(cat "$SSH_DIR/agents/work.pid")
    kill "$pid"
    while kill -0 "$pid" 2>/dev/null; do sleep 0.1; done

    run skm scope work box
    assert_ok
    assert_output_has "scope 'work' is live"

    # the pid file names the new agent, not the one that is gone
    local newpid; newpid=$(cat "$SSH_DIR/agents/work.pid")
    [ "$newpid" != "$pid" ]
    kill -0 "$newpid"
}
