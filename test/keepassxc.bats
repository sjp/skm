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

@test "export --all steps over a host whose key is already in the vault only" {
    add_host box
    add_host tin
    rm -f "$(keyfile tin)"          # tin's private key lives in the vault now

    run skm_answer "$DB_PW" -- export --all "$DB"
    assert_ok
    assert_output_has "skipping tin (no private key on disk)"
    assert_output_has "exported box"
    assert_output_has "exported 1, skipped 1 (1 with no private key on disk)"

    run vault_attachments "SSH Keys/box"
    assert_output_has "id_ed25519_box"
}

@test "export --all leaves stored entries alone and exports the rest" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null
    add_host tin

    run skm_answer "$DB_PW" -- export --all "$DB"
    assert_ok
    assert_output_has "skipping box (already in KeePassXC"
    assert_output_has "exported tin"
    assert_output_has "exported 1, skipped 1 (1 already in KeePassXC)"

    run vault_attachments "SSH Keys/tin"
    assert_output_has "id_ed25519_tin"
}

@test "export --force --all refreshes every host that still has a key" {
    add_host box
    add_host tin
    skm_answer "$DB_PW" -- export --all "$DB" >/dev/null
    rm -f "$(keyfile tin)"

    # a different key under the same name: --force must reach it even though
    # the host listed before it had nothing to store
    rm -f "$(keyfile box)" "$(keyfile box).pub"
    ssh-keygen -q -t ed25519 -N '' -f "$(keyfile box)" -C replacement

    run skm_answer "$DB_PW" -- export --force --all "$DB"
    assert_ok
    assert_output_has "skipping tin (no private key on disk)"
    assert_output_has "exported 1, skipped 1"

    vault_export_key box "$SKM_TMP/from-vault"
    assert_equal "$(fingerprint "$SKM_TMP/from-vault")" "$(fingerprint "$(keyfile box)")"
}

@test "export --all fails when there is nothing left to export" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null

    run skm_answer "$DB_PW" -- export --all "$DB"
    assert_fails
    assert_output_has "nothing left to export"
    assert_output_has "1 already in KeePassXC"
}

@test "export of a named host still refuses when its key is gone" {
    add_host box
    rm -f "$(keyfile box)"

    run skm_answer "$DB_PW" -- export box "$DB"
    assert_fails
    assert_output_has "no private key on disk"
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

@test "export --all creates the group once, whatever the number of keys" {
    add_host box
    add_host tin
    kp_shim_setup

    PATH="$KP_SHIM:$PATH" skm_answer "$DB_PW" -- export --all "$DB" >/dev/null
    assert_equal "$(kp_calls_of mkdir)" 1
}

@test "export --force rewrites an entry without a removal pass or a second add" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null

    kp_shim_setup
    PATH="$KP_SHIM:$PATH" skm_answer "$DB_PW" -- export --force box "$DB" >/dev/null

    # The attachments are replaced where they stand, and the entry is known to
    # exist before the run starts, so neither costs a database unlock.
    assert_equal "$(kp_calls_of attachment-rm)" 0
    assert_equal "$(kp_calls_of add)" 0

    run vault_attachments "SSH Keys/box"
    assert_output_has "id_ed25519_box"
    assert_output_has "id_ed25519_box.pub"
    assert_output_has "KeeAgent.settings"
}

@test "storing a key costs a bounded number of database unlocks" {
    add_host box
    kp_shim_setup

    PATH="$KP_SHIM:$PATH" skm_answer "$DB_PW" -- export box "$DB" >/dev/null
    # password check, one lookup, the group, the entry, its three attachments
    [ "$(kp_calls)" -le 7 ] || {
        printf 'export box took %s unlocks:\n%s\n' "$(kp_calls)" "$(cat "$KP_CALLS")" >&2
        return 1
    }
}

@test "export stores the key's passphrase in the entry" {
    add_host box
    encrypt_key box 'sekrit pass'

    run skm_answer "$DB_PW" 'sekrit pass' -- export box "$DB"
    assert_ok

    # Without it in the Password field the agent has an undecryptable key.
    assert_equal "$(vault_password "SSH Keys/box")" 'sekrit pass'
}

@test "export refuses a passphrase that does not open the key" {
    add_host box
    encrypt_key box 'sekrit pass'

    run skm_answer "$DB_PW" 'not the passphrase' -- export box "$DB"
    assert_fails
    assert_output_has "passphrase"

    # nothing was stored, so there is no entry claiming to hold the key
    run vault_attachments "SSH Keys/box"
    assert_output_lacks "id_ed25519_box"
}

@test "export asks for no passphrase when the key has none" {
    add_host box

    run skm_answer "$DB_PW" -- export box "$DB"
    assert_ok
    assert_equal "$(vault_password "SSH Keys/box")" ""
}

@test "export --force replaces the password of the key it replaces" {
    add_host box
    encrypt_key box 'sekrit pass'
    skm_answer "$DB_PW" 'sekrit pass' -- export box "$DB" >/dev/null

    # a replacement key with no passphrase: the old one must not be left behind
    rm -f "$(keyfile box)" "$(keyfile box).pub"
    ssh-keygen -q -t ed25519 -N '' -f "$(keyfile box)" -C replacement

    run skm_answer "$DB_PW" -- export --force box "$DB"
    assert_ok
    assert_equal "$(vault_password "SSH Keys/box")" ""
}

@test "export regenerates a missing public half of a passphrased key" {
    add_host box
    encrypt_key box 'sekrit pass'
    rm -f "$(keyfile box).pub"

    run skm_answer "$DB_PW" 'sekrit pass' -- export box "$DB"
    assert_ok

    run vault_attachments "SSH Keys/box"
    assert_output_has "id_ed25519_box.pub"
}

@test "export leaves the rebuilt public key on disk as well as in the vault" {
    add_host box
    local fp; fp=$(fingerprint "$(keyfile box)")
    rm -f "$(keyfile box).pub"

    run skm_answer "$DB_PW" -- export box "$DB"
    assert_ok
    assert_file "$(keyfile box).pub"
    assert_equal "$(fingerprint "$(keyfile box).pub")" "$fp"
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

@test "drop rebuilds a missing public key before deleting the private one" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null
    local fp; fp=$(fingerprint "$(keyfile box)")
    rm -f "$(keyfile box).pub"

    run skm_answer "$DB_PW" y -- drop box "$DB"
    assert_ok
    assert_no_file "$(keyfile box)"
    assert_file "$(keyfile box).pub"
    assert_equal "$(fingerprint "$(keyfile box).pub")" "$fp"
    assert_equal "$(identity_file box)" "$(keyfile box).pub"
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
    assert_mode "$(keyfile box).pub" 600
}

@test "restore writes the key private rather than widening it afterwards" {
    umask 022   # a permissive caller must not loosen anything skm writes
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null
    skm_answer "$DB_PW" y -- drop box "$DB" >/dev/null
    rm -f "$(keyfile box).pub"

    PATH="$NOCHMOD:$PATH" skm_answer "$DB_PW" -- restore box "$DB" >/dev/null

    assert_mode "$(keyfile box)" 600
    assert_mode "$(keyfile box).pub" 600
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

@test "restore --force replaces a key the vault already holds without asking" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null
    local fp; fp=$(fingerprint "$(keyfile box)")

    run skm_answer "$DB_PW" -- restore --force box "$DB"
    assert_ok
    assert_output_lacks "DANGER"
    assert_equal "$(fingerprint "$(keyfile box)")" "$fp"
}

@test "restore --force will not quietly replace a key that is not the vault copy" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null
    # The state `skm rm` followed by `skm add` leaves: same name, different key.
    rm -f "$(keyfile box)" "$(keyfile box).pub"
    ssh-keygen -q -t ed25519 -N '' -C other -f "$(keyfile box)"
    local fp; fp=$(fingerprint "$(keyfile box)")

    run skm_answer "$DB_PW" -- restore --force box "$DB"
    assert_ok
    assert_output_has "fingerprints differ"
    assert_output_has "aborted"
    assert_equal "$(fingerprint "$(keyfile box)")" "$fp"
}

@test "a restore that is called off keeps no copy of the key it pulled out" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null
    rm -f "$(keyfile box)" "$(keyfile box).pub"
    ssh-keygen -q -t ed25519 -N '' -C other -f "$(keyfile box)"

    run skm_answer "$DB_PW" -- restore --force box "$DB"
    assert_ok
    assert_output_has "aborted"
    assert_no_extracted_keys
}

@test "restore --force keeps the displaced key beside the one it restored" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null
    local vault_fp; vault_fp=$(fingerprint "$(keyfile box)")
    rm -f "$(keyfile box)" "$(keyfile box).pub"
    ssh-keygen -q -t ed25519 -N '' -C other -f "$(keyfile box)"
    local local_fp; local_fp=$(fingerprint "$(keyfile box)")

    run skm_answer "$DB_PW" y -- restore --force box "$DB"
    assert_ok
    assert_output_has "kept the displaced key as"
    assert_equal "$(fingerprint "$(keyfile box)")" "$vault_fp"

    local backups=() f
    for f in "$(keyfile box)".bak-*; do
        case $f in *.pub) continue ;; esac
        backups+=("$f")
    done
    assert_equal "${#backups[@]}" 1
    assert_equal "$(fingerprint "${backups[0]}")" "$local_fp"
    assert_file "${backups[0]}.pub"
}

@test "restore refuses an attachment that is not a key and leaves the host alone" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null
    skm_answer "$DB_PW" y -- drop box "$DB" >/dev/null
    printf 'not a key\n' > "$SKM_TMP/junk"
    printf '%s\n' "$DB_PW" | kp_cli attachment-import -f "$DB" "SSH Keys/box" \
        "id_ed25519_box" "$SKM_TMP/junk" >/dev/null

    run skm_answer "$DB_PW" -- restore box "$DB"
    assert_fails
    assert_output_has "not a readable private key"
    assert_no_file "$(keyfile box)"
    assert_equal "$(identity_file box)" "$(keyfile box).pub"
}

# -------------------------------------------------------------------- rm

@test "rm deletes the vault entry when that is asked for as well" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null

    run skm_answer "$DB_PW" y y -- rm box "$DB"
    assert_ok
    assert_output_has "removed entry 'SSH Keys/box'"
    assert_no_file "$(keyfile box)"
    assert_no_file "$(conffile box)"

    run vault_entry_exists "SSH Keys/box"
    assert_fails
}

@test "rm keeps the vault entry when only the local half is wanted gone" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null

    run skm_answer "$DB_PW" y n -- rm box "$DB"
    assert_ok
    assert_output_has "was kept"
    assert_no_file "$(keyfile box)"

    run vault_entry_exists "SSH Keys/box"
    assert_ok
}

@test "rm reports a host the vault does not hold instead of offering to remove it" {
    add_host box

    run skm_answer "$DB_PW" y -- rm box "$DB"
    assert_ok
    assert_output_has "no entry 'SSH Keys/box'"
    assert_output_lacks "also delete"
    assert_no_file "$(keyfile box)"
}

@test "a wrong password stops rm with the host and the entry still there" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null

    run skm_answer wrong -- rm box "$DB"
    assert_fails
    assert_output_has "wrong password"
    assert_file "$(keyfile box)"
    assert_file "$(conffile box)"

    run vault_entry_exists "SSH Keys/box"
    assert_ok
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

@test "provision chains add, export and drop into one key" {
    # the answers, in order: the vault password, ssh-keygen's empty passphrase
    # twice, "skip" past the agent check, and the confirmation for deleting
    # the on-disk key
    run skm_answer "$DB_PW" "" "" skip y -- provision box user@example.com "$DB"
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

@test "provision opens the database once, before it generates anything" {
    kp_shim_setup

    PATH="$KP_SHIM:$PATH" skm_answer "$DB_PW" "" "" skip y \
        -- provision box user@example.com "$DB" >/dev/null
    # One password, proved once: export and drop reuse what provision opened.
    assert_equal "$(kp_calls_of db-info)" 1
}

@test "a provision that cannot open the database leaves nothing on disk" {
    run skm_answer "not the password" -- provision box user@example.com "$DB"
    assert_fails
    assert_output_has "wrong password"
    assert_no_file "$(keyfile box)"
    assert_no_file "$(conffile box)"
}

@test "provision finishes a host whose key never reached the vault" {
    add_host box

    run skm_answer "$DB_PW" skip y -- provision box user@example.com "$DB"
    assert_ok
    assert_output_has "already managed"
    assert_output_has "provisioned 'box'"
    assert_no_file "$(keyfile box)"
    vault_entry_exists "SSH Keys/box"
}

@test "provision on a host that is already provisioned reports it and stops" {
    skm_answer "$DB_PW" "" "" skip y -- provision box user@example.com "$DB" >/dev/null

    run skm_answer "$DB_PW" -- provision box user@example.com "$DB"
    assert_ok
    assert_output_has "already in 'SSH Keys/box' and off disk"
    assert_output_has "provisioned 'box'"
    assert_no_file "$(keyfile box)"
    assert_equal "$(identity_file box)" "$(keyfile box).pub"
}

@test "provision that is told not to delete leaves an on-disk host and says so" {
    run skm_answer "$DB_PW" "" "" skip n -- provision box user@example.com "$DB"
    assert_ok
    assert_output_has "still on disk"
    assert_output_lacks "provisioned 'box'"
    assert_file "$(keyfile box)"
    assert_equal "$(identity_file box)" "$(keyfile box)"

    # and running it again finishes the job
    run skm_answer "$DB_PW" skip y -- provision box user@example.com "$DB"
    assert_ok
    assert_output_has "already stored"
    assert_output_has "provisioned 'box'"
    assert_no_file "$(keyfile box)"
    assert_equal "$(identity_file box)" "$(keyfile box).pub"
}

@test "provision stops when the vault holds a different key under that name" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null

    # a new key under the same name: the stored one is no longer this key
    rm -f "$(keyfile box)" "$(keyfile box).pub"
    ssh-keygen -q -t ed25519 -N '' -f "$(keyfile box)"

    run skm_answer "$DB_PW" skip y -- provision box user@example.com "$DB"
    assert_fails
    assert_output_has "already in KeePassXC under a different key"
    assert_file "$(keyfile box)"
}

@test "provision refuses a managed name that points somewhere else" {
    add_host box user@example.com

    run skm_answer "$DB_PW" -- provision box user@other.example.com "$DB"
    assert_fails
    assert_output_has "points at user@example.com:22"
}

@test "provision warns about a database KeePassXC has open" {
    touch "$DB.lock"
    run skm_answer "$DB_PW" "" "" skip y -- provision box user@example.com "$DB"
    assert_ok
    assert_output_has "looks open in KeePassXC"
    assert_no_file "$(keyfile box)"      # warned about, not stopped by

    # the same file, hidden, is the other spelling of it
    rm -f "$DB.lock"
    touch "$(dirname "$DB")/.$(basename "$DB").lock"
    run skm_answer "$DB_PW" "" "" skip y -- provision tin user@example.com "$DB"
    assert_ok
    assert_output_has "looks open in KeePassXC"
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

# --------------------------------------------------- wrong vault password
#
# A password that doesn't open the database must never be reported as a
# database that doesn't hold the key: that reading is what talks a user into
# deleting their only copy.

@test "a wrong password stops status instead of reporting the key missing" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null

    run skm_answer "not the password" -- status box "$DB"
    assert_fails
    assert_output_has "wrong password"
    assert_output_lacks "vault: no"
    assert_output_lacks "LOST"
}

@test "a wrong password stops drop before it can call the key lost" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null

    run skm_answer "not the password" y -- drop box "$DB"
    assert_fails
    assert_output_has "wrong password"
    assert_output_lacks "DANGER"
    assert_file "$(keyfile box)"
}

@test "a wrong password stops drop --force with the key still on disk" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null

    run skm_answer "not the password" y -- drop --force box "$DB"
    assert_fails
    assert_output_has "wrong password"
    assert_output_lacks "loses the only copy"
    assert_file "$(keyfile box)"
}

@test "a wrong password stops export instead of half-writing an entry" {
    add_host box

    run skm_answer "not the password" -- export box "$DB"
    assert_fails
    assert_output_has "wrong password"
    assert_output_lacks "updating attachments"

    run vault_attachments "SSH Keys/box"
    assert_output_lacks "id_ed25519_box"
}

@test "a wrong password stops restore instead of blaming the entry" {
    add_host box
    skm_answer "$DB_PW" -- export box "$DB" >/dev/null
    skm_answer "$DB_PW" y -- drop box "$DB" >/dev/null

    run skm_answer "not the password" -- restore box "$DB"
    assert_fails
    assert_output_has "wrong password"
    assert_output_lacks "no key attachment"
    assert_no_file "$(keyfile box)"
}

@test "a database that is not a database is reported as such" {
    add_host box
    head -c 512 /dev/urandom > "$SKM_TMP/junk.kdbx"

    run skm_answer "$DB_PW" -- status box "$SKM_TMP/junk.kdbx"
    assert_fails
    assert_output_has "could not open"
    assert_output_lacks "vault: no"
}

# ------------------------------------------- other ways into the database
#
# A database can want a key file as well as its password, or instead of one,
# and a run with nobody at the terminal has to get the password from a file.
# Every one of those has to reach keepassxc-cli or the database stays shut.

# A database that takes a key file as well as a password.
make_keyfile_vault() {
    KEY_FILE="$SKM_TMP/vault.key"
    KEY_DB="$SKM_TMP/keyfile.kdbx"
    head -c 64 /dev/urandom > "$KEY_FILE"
    printf '%s\n%s\n' "$DB_PW" "$DB_PW" \
        | kp_cli db-create -p --set-key-file "$KEY_FILE" "$KEY_DB" >/dev/null
}

@test "a database that also wants a key file opens once the key file is named" {
    add_host box
    make_keyfile_vault

    run skm_answer "$DB_PW" -- export box "$KEY_DB"
    assert_fails
    assert_output_lacks "exported box"

    export SKM_KEEPASS_KEYFILE="$KEY_FILE"
    run skm_answer "$DB_PW" -- export box "$KEY_DB"
    assert_ok
    assert_output_has "exported box"
}

@test "a key file that is not there is named rather than read as a bad password" {
    add_host box
    export SKM_KEEPASS_KEYFILE="$SKM_TMP/missing.key"

    run skm_answer "$DB_PW" -- status box "$DB"
    assert_fails
    assert_output_has "no such KeePassXC key file"
    assert_output_lacks "wrong password"
}

@test "a database with no password of its own needs no answer at the prompt" {
    add_host box
    local kf="$SKM_TMP/only.key" db="$SKM_TMP/nopassword.kdbx"
    head -c 64 /dev/urandom > "$kf"
    kp_cli db-create --set-key-file "$kf" "$db" >/dev/null

    export SKM_KEEPASS_KEYFILE="$kf" SKM_KEEPASS_NO_PASSWORD=1
    run skm export box "$db"      # nothing on stdin at all
    assert_ok
    assert_output_has "exported box"
}

@test "the password can come from a file instead of the prompt" {
    add_host box
    printf '%s\n' "$DB_PW" > "$SKM_TMP/pw.txt"
    export SKM_KEEPASS_PASSWORD_FILE="$SKM_TMP/pw.txt"

    run skm export box "$DB"
    assert_ok
    assert_output_has "exported box"

    run skm status box "$DB"
    assert_ok
    assert_output_has "vault: yes"
}

@test "a wrong password in the file is reported against the file" {
    add_host box
    printf 'not the password\n' > "$SKM_TMP/pw.txt"
    export SKM_KEEPASS_PASSWORD_FILE="$SKM_TMP/pw.txt"

    run skm status box "$DB"
    assert_fails
    assert_output_has "wrong password"
    assert_output_has "pw.txt"
    assert_output_lacks "LOST"
}
