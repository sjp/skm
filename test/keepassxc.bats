#!/usr/bin/env bats
#
# The vault half: getting a key into KeePassXC, taking it off disk, and
# getting it back again. Each test builds its own throwaway .kdbx.

load helper

setup() {
    skm_setup
    require_keepassxc
    make_vault
}
teardown() { skm_teardown; }

# ---------------------------------------------------------------- export

@test "export stores the private key, the public key and the agent settings" {
    add_host box
    run skm_answer "$DB_PW" -- export box "$DB"
    assert_ok
    assert_output_has "exported box"

    run vault_attachments "SSH Keys/box"
    assert_output_has "id_ed25519_box"
    assert_output_has "id_ed25519_box.pub"
    assert_output_has "KeeAgent.settings"
}

@test "the stored private key is the key that is on disk" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null

    vault_export_key box "$SKM_TMP/from-vault"
    assert_equal "$(fingerprint "$SKM_TMP/from-vault")" "$(fingerprint "$(keyfile box)")"
}

@test "export refuses to overwrite an entry that is already there" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null

    run skm_answer "$DB_PW" -- export box "$DB"
    assert_fails
    assert_output_has "already in KeePassXC"
    assert_output_has "--force"
}

@test "export --force replaces the stored attachments" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null

    # a different key under the same name: --force must store the new one
    rm -f "$(keyfile box)" "$(keyfile box).pub"
    ssh-keygen -q -t ed25519 -N '' -f "$(keyfile box)" -C replacement

    run skm_answer "$DB_PW" -- export --force box "$DB"
    assert_ok

    vault_export_key box "$SKM_TMP/from-vault"
    assert_equal "$(fingerprint "$SKM_TMP/from-vault")" "$(fingerprint "$(keyfile box)")"
}

@test "export --all stores every managed host" {
    add_host box
    add_host tin
    run skm_answer "$DB_PW" -- export --all "$DB"
    assert_ok

    run vault_attachments "SSH Keys/box"
    assert_output_has "id_ed25519_box"
    run vault_attachments "SSH Keys/tin"
    assert_output_has "id_ed25519_tin"
}

@test "export needs a managed host, an existing database and both arguments" {
    add_host box

    run skm_answer "$DB_PW" -- export nosuch "$DB"
    assert_fails
    assert_output_has "no such managed host"

    run skm_answer "$DB_PW" -- export box "$SKM_TMP/missing.kdbx"
    assert_fails
    assert_output_has "no such database"

    run skm_answer "$DB_PW" -- export box
    assert_fails
    assert_output_has "usage: skm export"
}

@test "export rejects an unknown flag" {
    add_host box
    run skm_answer "$DB_PW" -- export --wat box "$DB"
    assert_fails
    assert_output_has "unknown flag"
}

# ------------------------------------------------------------------ drop

@test "drop deletes the on-disk key once the fingerprints match" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null
    local fp; fp=$(fingerprint "$(keyfile box)")

    run skm_answer "$DB_PW" y -- drop box "$DB"
    assert_ok
    assert_output_has "fingerprints match"

    assert_no_file "$(keyfile box)"
    assert_file "$(keyfile box).pub"
    assert_equal "$(identity_file box)" "$(keyfile box).pub"

    # the vault copy is untouched, so the key is not lost
    vault_export_key box "$SKM_TMP/from-vault"
    assert_equal "$(fingerprint "$SKM_TMP/from-vault")" "$fp"
}

@test "drop keeps the key when the answer is no" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null

    run skm_answer "$DB_PW" n -- drop box "$DB"
    assert_ok
    assert_output_has "aborted"
    assert_file "$(keyfile box)"
    assert_equal "$(identity_file box)" "$(keyfile box)"
}

@test "drop refuses when the key is not in the vault at all" {
    add_host box

    run skm_answer "$DB_PW" y -- drop box "$DB"
    assert_fails
    assert_output_has "not in KeePassXC"
    assert_output_has "refusing to delete"
    assert_file "$(keyfile box)"
}

@test "drop refuses when the vault holds a different key" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null

    rm -f "$(keyfile box)" "$(keyfile box).pub"
    ssh-keygen -q -t ed25519 -N '' -f "$(keyfile box)" -C replacement

    run skm_answer "$DB_PW" y -- drop box "$DB"
    assert_fails
    assert_output_has "fingerprints differ"
    assert_file "$(keyfile box)"
}

@test "drop --force still asks before destroying the only copy" {
    add_host box

    run skm_answer "$DB_PW" n -- drop --force box "$DB"
    assert_ok
    assert_output_has "loses the only copy"
    assert_output_has "aborted"
    assert_file "$(keyfile box)"
}

@test "drop needs a managed host with a key on disk" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null
    skm_answer "$DB_PW" y -- drop box "$DB" >/dev/null

    run skm_answer "$DB_PW" y -- drop box "$DB"
    assert_fails
    assert_output_has "no local private key"
}

# --------------------------------------------------------------- restore

@test "restore brings the key back, byte for byte, and points the config at it" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null
    local fp; fp=$(fingerprint "$(keyfile box)")
    local pub; pub=$(cat "$(keyfile box).pub")
    skm_answer "$DB_PW" y -- drop box "$DB" >/dev/null

    run skm_answer "$DB_PW" -- restore box "$DB"
    assert_ok
    assert_output_has "restored box"

    assert_file "$(keyfile box)"
    assert_equal "$(fingerprint "$(keyfile box)")" "$fp"
    assert_equal "$(cat "$(keyfile box).pub")" "$pub"
    assert_equal "$(identity_file box)" "$(keyfile box)"
}

@test "restore gives the key pair the modes ssh insists on" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null
    skm_answer "$DB_PW" y -- drop box "$DB" >/dev/null
    rm -f "$(keyfile box).pub"

    run skm_answer "$DB_PW" -- restore box "$DB"
    assert_ok
    assert_mode "$(keyfile box)" 600
    assert_mode "$(keyfile box).pub" 644
}

@test "restore refuses to overwrite a key that is already on disk" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null

    run skm_answer "$DB_PW" -- restore box "$DB"
    assert_fails
    assert_output_has "already present"
    assert_output_has "--force"
}

@test "restore fails when the entry holds no key" {
    add_host box
    rm -f "$(keyfile box)"
    run skm_answer "$DB_PW" -- restore box "$DB"
    assert_fails
    assert_output_has "no key attachment"
}

# ---------------------------------------------------------------- status

@test "status reads the vault and confirms the two copies are the same key" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null

    run skm_answer "$DB_PW" -- status box "$DB"
    assert_ok
    assert_output_has "private       disk: yes  vault: yes"
    assert_output_has "public        disk: yes  vault: yes"
    assert_output_has "fingerprint   match"
}

@test "status calls a vault-only key OK once the private key is gone" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null
    skm_answer "$DB_PW" y -- drop box "$DB" >/dev/null

    run skm_answer "$DB_PW" -- status box "$DB"
    assert_ok
    assert_output_has "private       disk: no   vault: yes"
    assert_output_has "OK (vault-only"
}

@test "status flags a vault copy that is a different key" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null

    rm -f "$(keyfile box)" "$(keyfile box).pub"
    ssh-keygen -q -t ed25519 -N '' -f "$(keyfile box)" -C replacement

    run skm_answer "$DB_PW" -- status box "$DB"
    assert_ok
    assert_output_has "fingerprint   MISMATCH"
    assert_output_has "DANGER"
}

@test "status reports a key that is in neither place as lost" {
    add_host box
    skm agent box >/dev/null
    rm -f "$(keyfile box)"

    run skm_answer "$DB_PW" -- status box "$DB"
    assert_ok
    assert_output_has "LOST"
}

# ------------------------------------------------------------- provision

@test "provision chains add, export, agent and drop into one key" {
    # the answers, in order: ssh-keygen's empty passphrase twice, the vault
    # password, "skip" past the agent check, the vault password again, and
    # the confirmation for deleting the on-disk key
    run skm_answer "" "" "$DB_PW" skip "$DB_PW" y -- provision box user@example.com "$DB"
    assert_ok
    assert_output_has "provisioned 'box'"

    # the end state: config and public key on disk, private key in the vault
    assert_file "$(conffile box)"
    assert_file "$(keyfile box).pub"
    assert_no_file "$(keyfile box)"
    assert_equal "$(identity_file box)" "$(keyfile box).pub"

    run vault_attachments "SSH Keys/box"
    assert_output_has "id_ed25519_box"
    assert_output_has "KeeAgent.settings"
}

@test "provision needs a name, a destination and a database that exists" {
    run skm_answer "$DB_PW" -- provision box user@example.com
    assert_fails
    assert_output_has "usage: skm provision"

    run skm_answer "$DB_PW" -- provision box user@example.com "$SKM_TMP/missing.kdbx"
    assert_fails
    assert_output_has "no such database"
    assert_no_file "$(conffile box)"
}
