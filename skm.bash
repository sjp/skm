#!/usr/bin/env bash
# skm — a small per-host SSH key manager.
#
# Each host gets:  its own key, its own ~/.ssh/config.d/<name>.conf
# Optionally:      the private key stored in KeePassXC and removed from disk.
#
#   skm add <name> <user@host> [port]   generate key + config entry
#   skm provision <name> <user@host> [port] <db.kdbx>
#                                      add + export + agent + drop, in one go
#   skm alias <name> <pattern>...       let more names/IPs/globs use this key
#   skm list                            show managed hosts
#   skm status [name|--all] [db.kdbx]   show where each key's private/public half lives
#   skm show <name>                     print the public key
#   skm copy <name>                     ssh-copy-id the key to the server
#   skm rm <name>                       delete key + config entry
#   skm export [--force] <name|--all> <db.kdbx>
#                                      import key into KeePassXC as an agent key
#   skm drop [--force] <name> <db.kdbx> remove local key (fingerprint-verified)
#   skm restore [--force] <name> <db.kdbx>
#                                      pull key from KeePassXC back to disk
#   skm agent <name>                    point IdentityFile at the .pub (agent supplies private)
#   skm ondisk <name>                   undo `agent`
#   skm scope <label> [-c] [-t 8h] [-d db.kdbx] <name>...
#                                       start an agent holding ONLY those keys
#   skm scopes                          list scoped agents and what's in them
#   skm unscope <label>                 kill a scoped agent

set -euo pipefail

SSH_DIR="${SSH_DIR:-$HOME/.ssh}"
CONF_DIR="$SSH_DIR/config.d"
CONFIG="$SSH_DIR/config"
SOCK_DIR="$SSH_DIR/agents"
KP_GROUP="${SKM_KEEPASS_GROUP:-SSH Keys}"

die()  { printf 'skm: %s\n' "$*" >&2; exit 1; }
info() { printf '  %s\n' "$*"; }

# ---------------------------------------------------------------- bootstrap

ensure_include() {
    mkdir -p "$CONF_DIR"
    chmod 700 "$SSH_DIR" "$CONF_DIR"
    [[ -f $CONFIG ]] || { : > "$CONFIG"; chmod 600 "$CONFIG"; }

    # Include must sit at the very top: ssh_config is first-match-wins, so a
    # later Include would be shadowed by any earlier catch-all Host block.
    if ! grep -qE '^\s*Include\s+config\.d/' "$CONFIG"; then
        printf 'Include config.d/*.conf\n\n%s' "$(cat "$CONFIG")" > "$CONFIG.tmp"
        mv "$CONFIG.tmp" "$CONFIG"
        chmod 600 "$CONFIG"
        info "added 'Include config.d/*.conf' to $CONFIG"
    fi
}

keyfile()  { printf '%s/id_ed25519_%s' "$SSH_DIR" "$1"; }
conffile() { printf '%s/%s.conf' "$CONF_DIR" "$1"; }

require_host() {
    [[ -f $(conffile "$1") ]] || die "no such managed host: $1  (try: skm list)"
}

# ---------------------------------------------------------------- commands

cmd_add() {
    local name=${1:-} dest=${2:-} port=${3:-22}
    [[ -n $name && -n $dest ]] || die "usage: skm add <name> <user@host> [port]"
    [[ $dest == *@* ]]         || die "destination must be user@host, e.g. git@github.com"

    local user=${dest%@*} host=${dest#*@}
    local key; key=$(keyfile "$name")
    local conf; conf=$(conffile "$name")

    ensure_include
    [[ -e $key  ]] && die "key already exists: $key"
    [[ -e $conf ]] && die "host already managed: $name"

    info "generating key (leave the passphrase empty only if you'll store it in KeePassXC)"
    ssh-keygen -t ed25519 -f "$key" -C "$name@$(hostname -s)-$(date +%Y%m%d)"

    cat > "$conf" <<EOF
# managed by skm
Host $name
    HostName $host
    User $user
    Port $port
    IdentityFile $key
    IdentitiesOnly yes
    # Reuse one authenticated connection for 10 minutes. Repeat 'ssh $name'
    # calls ride the existing master and never re-ask the agent — so a locked
    # KeePassXC vault doesn't interrupt an active session.
    ControlMaster auto
    ControlPath ~/.ssh/cm/%r@%h:%p
    ControlPersist 10m
EOF
    chmod 600 "$conf"
    mkdir -p "$SSH_DIR/cm"; chmod 700 "$SSH_DIR/cm"

    echo
    info "created $conf"
    info "public key:"
    echo
    cat "$key.pub"
    echo
    info "install it with:  skm copy $name"
}

# The ideal end state for a new key: config + public key on disk, private key
# only in KeePassXC. This chains the four manual steps (add, export, agent,
# drop) and, since drop's deletion is irreversible if the agent isn't actually
# serving the key yet, pauses to verify the key is loaded before deleting it.
cmd_provision() {
    local usage="usage: skm provision <name> <user@host> [port] <database.kdbx>"
    local name=${1:-} dest=${2:-} port=22 db=""
    case $# in
        3) db=${3:-} ;;
        4) port=${3:-}; db=${4:-} ;;
        *) die "$usage" ;;
    esac
    [[ -n $name && -n $dest && -n $db ]] || die "$usage"
    [[ -f $db ]] || die "no such database: $db"

    cmd_add    "$name" "$dest" "$port"
    cmd_export "$name" "$db"
    cmd_agent  "$name"

    local key; key=$(keyfile "$name")
    local fp;  fp=$(key_fingerprint "$key")
    [[ -n $fp ]] || die "could not read local key: $key"

    echo
    info "before the on-disk private key can be deleted, KeePassXC must be serving it:"
    info "  1. KeePassXC > Tools > Settings > SSH Agent: enable the agent integration"
    info "  2. re-unlock (or reopen) $db"

    local ans
    while :; do
        echo
        read -rp "press Enter to check the agent (or type 'skip' to continue anyway): " ans || ans=""
        if [[ ${ans,,} == skip ]]; then
            info "skipping agent verification"
            break
        fi
        if ssh-add -l 2>/dev/null | grep -qF "$fp"; then
            info "agent is serving $name ($fp)"
            break
        fi
        info "agent does not list $fp yet -- unlock KeePassXC and try again"
    done

    cmd_drop "$name" "$db"

    echo
    info "provisioned '$name': config + public key on disk, private key in KeePassXC only"
}

# `Host` takes a list of patterns, so extra domains / IPs / globs can share a
# key just by being appended to that line. HostName stays pinned to the
# canonical address, which keeps everything under one known_hosts entry.
cmd_alias() {
    local name=${1:-}; shift 2>/dev/null || true
    [[ -n $name && $# -gt 0 ]] || die "usage: skm alias <name> <pattern> [pattern...]"
    require_host "$name"

    local conf; conf=$(conffile "$name")
    local existing; existing=$(awk '$1=="Host"{sub(/^[ \t]*Host[ \t]+/,""); print; exit}' "$conf")

    local p add=()
    for p in "$@"; do
        [[ " $existing " == *" $p "* ]] || add+=("$p")
    done
    [[ ${#add[@]} -gt 0 ]] || { info "already matched by: Host $existing"; return; }

    sed -i.bak "s|^\([ \t]*Host[ \t]\+\).*|\1$existing ${add[*]}|" "$conf"
    rm -f "$conf.bak"
    info "Host $existing ${add[*]}"
}

cmd_list() {
    [[ -d $CONF_DIR ]] || die "nothing managed yet"
    shopt -s nullglob
    local f name target id agent
    printf '%-14s %-28s %s\n' NAME TARGET KEY
    for f in "$CONF_DIR"/*.conf; do
        name=$(basename "$f" .conf)
        target="$(awk '$1=="User"{u=$2} $1=="HostName"{h=$2} $1=="Port"{p=$2} \
                       END{printf "%s@%s%s", u, h, (p=="22"?"":":" p)}' "$f")"
        id=$(awk '$1=="IdentityFile"{print $2}' "$f")
        agent=""
        [[ $id == *.pub ]] && agent="  (agent)"
        printf '%-14s %-28s %s%s\n' "$name" "$target" "$(basename "$id")" "$agent"
    done
}

# Derive a one-line health verdict from the gathered signals. A fingerprint
# mismatch trumps everything else -- it means the vault copy silently isn't
# the key it claims to be.
status_verdict() {
    local mode=$1 priv_disk=$2 priv_vault=$3 fp_status=$4 agent_state=$5

    if [[ $fp_status == MISMATCH ]]; then
        printf 'DANGER: vault copy is a different key from the on-disk copy'
        return
    fi

    if [[ $mode == ondisk ]]; then
        if [[ $priv_disk == yes ]]; then
            local s="OK (on disk)"
            case $priv_vault in
                yes) s+=", vault backup present" ;;
                no)  s+=", not in vault" ;;
            esac
            printf '%s' "$s"
        else
            local s="BROKEN: IdentityFile points at the private key, but none is on disk"
            [[ $priv_vault == yes ]] && s+=" (in vault -- try: skm restore)"
            printf '%s' "$s"
        fi
        return
    fi

    # agent mode
    if [[ $priv_disk == yes ]]; then
        case $priv_vault in
            yes) printf 'redundant: private key on disk AND in vault (consider: skm drop)' ;;
            no)  printf 'WARNING: agent mode but private key only on disk, not in vault' ;;
            *)   printf 'WARNING: agent mode but private key still on disk (pass a db.kdbx to check the vault)' ;;
        esac
        return
    fi

    case $priv_vault in
        yes)
            case $agent_state in
                serving)       printf 'OK (vault-only, agent serving)' ;;
                'not serving') printf 'OK (vault-only) -- agent NOT serving (unlock KeePassXC)' ;;
                *)             printf 'OK (vault-only, agent status unknown)' ;;
            esac
            ;;
        no)  printf 'LOST: no private key on disk or in vault' ;;
        *)   printf 'OK (assumed vault-only; pass a db.kdbx to verify)' ;;
    esac
}

status_one() {
    local name=$1 db=$2 pw=$3
    local conf; conf=$(conffile "$name")
    local key; key=$(keyfile "$name")
    local pub="$key.pub"

    local target
    target="$(awk '$1=="User"{u=$2} $1=="HostName"{h=$2} $1=="Port"{p=$2} \
                   END{printf "%s@%s%s", u, h, (p=="22"?"":":" p)}' "$conf")"
    local id; id=$(awk '$1=="IdentityFile"{print $2}' "$conf")
    local mode="ondisk"; [[ $id == *.pub ]] && mode="agent"

    local priv_disk="no" pub_disk="no"
    [[ -f $key ]] && priv_disk="yes"
    [[ -f $pub ]] && pub_disk="yes"

    local local_fp=""
    [[ $priv_disk == yes ]] && local_fp=$(key_fingerprint "$key")

    local priv_vault="?" pub_vault="?" vault_fp="" fp_status="n/a (no db)"
    if [[ -n $db ]]; then
        local entry="$KP_GROUP/$name" base; base=$(basename "$key")
        local tmpdir; tmpdir=$(ramtemp)
        if printf '%s\n' "$pw" | keepassxc-cli attachment-export "$db" "$entry" "$base" \
                "$tmpdir/$base" 2>/dev/null; then
            priv_vault="yes"
            vault_fp=$(key_fingerprint "$tmpdir/$base")
        else
            priv_vault="no"
        fi
        if printf '%s\n' "$pw" | keepassxc-cli attachment-export "$db" "$entry" "$base.pub" \
                "$tmpdir/$base.pub" 2>/dev/null; then
            pub_vault="yes"
        else
            pub_vault="no"
        fi
        rm -rf "$tmpdir"

        if [[ -n $local_fp && -n $vault_fp ]]; then
            [[ $local_fp == "$vault_fp" ]] && fp_status="match" || fp_status="MISMATCH"
        elif [[ -n $local_fp || -n $vault_fp ]]; then
            fp_status="n/a (only one copy present)"
        else
            fp_status="n/a"
        fi
    fi

    local fp_for_agent=$local_fp
    [[ -z $fp_for_agent ]] && fp_for_agent=$vault_fp
    local agent_state="unknown"
    if [[ -n $fp_for_agent ]]; then
        if ssh-add -l 2>/dev/null | grep -qF "$fp_for_agent"; then
            agent_state="serving"
        else
            agent_state="not serving"
        fi
    fi

    local verdict
    verdict=$(status_verdict "$mode" "$priv_disk" "$priv_vault" "$fp_status" "$agent_state")

    echo "$name"
    printf '  %-13s %s\n' "target" "$target"
    printf '  %-13s %s%s\n' "IdentityFile" "$(basename "$id")" "$([[ $mode == agent ]] && printf '   (agent)')"
    printf '  %-13s disk: %-4s vault: %s\n' "private" "$priv_disk" "$priv_vault"
    printf '  %-13s disk: %-4s vault: %s\n' "public"  "$pub_disk"  "$pub_vault"
    [[ -n $db ]] && printf '  %-13s %s\n' "fingerprint" "$fp_status"
    printf '  %-13s %s\n' "agent"  "$agent_state"
    printf '  %-13s %s\n' "status" "$verdict"
    echo
}

cmd_status() {
    local a args=() db=""
    for a in "$@"; do
        if [[ $a == *.kdbx ]]; then
            db=$a
        else
            args+=("$a")
        fi
    done
    [[ -z $db || -f $db ]] || die "no such database: $db"

    local what=${args[0]:-}
    local names=()
    if [[ -z $what || $what == --all ]]; then
        [[ -d $CONF_DIR ]] || die "nothing managed yet"
        shopt -s nullglob
        local f
        for f in "$CONF_DIR"/*.conf; do names+=("$(basename "$f" .conf)"); done
        [[ ${#names[@]} -gt 0 ]] || die "nothing managed yet"
    else
        require_host "$what"
        names=("$what")
    fi

    local pw=""
    if [[ -n $db ]]; then
        command -v keepassxc-cli >/dev/null || die "keepassxc-cli not found"
        read -rsp "KeePassXC database password: " pw; echo
    fi

    local n
    for n in "${names[@]}"; do status_one "$n" "$db" "$pw"; done
}

cmd_show() { require_host "$1"; cat "$(keyfile "$1").pub"; }

cmd_copy() {
    require_host "$1"
    ssh-copy-id -i "$(keyfile "$1").pub" "$1"
}

cmd_rm() {
    local name=${1:-}; require_host "$name"
    read -rp "delete key and config for '$name'? [y/N] " ans
    [[ ${ans,,} == y* ]] || { info "aborted"; return; }
    rm -f "$(conffile "$name")" "$(keyfile "$name")" "$(keyfile "$name").pub"
    info "removed $name"
}

# Swap IdentityFile between the private key on disk and the .pub stub.
# With the .pub, ssh asks the agent (KeePassXC) for the matching private key —
# so the private key never has to exist on disk at all.
retarget() {
    local name=$1 to=$2 conf; conf=$(conffile "$name")
    local key; key=$(keyfile "$name")
    case $to in
        agent)  sed -i.bak "s|^\(\s*IdentityFile\s\+\).*|\1$key.pub|" "$conf" ;;
        ondisk) sed -i.bak "s|^\(\s*IdentityFile\s\+\).*|\1$key|"     "$conf" ;;
    esac
    rm -f "$conf.bak"
}

cmd_agent()  { require_host "$1"; retarget "$1" agent
               info "$1 now resolves its key via the ssh-agent"
               info "once verified, you can: shred -u $(keyfile "$1")"; }

cmd_ondisk() { require_host "$1"; retarget "$1" ondisk
               info "$1 now reads $(keyfile "$1") directly"; }

# ---------------------------------------------------------------- keepassxc

# KeePassXC's agent reads two attachments from an entry:
#   - the private key itself
#   - KeeAgent.settings, an XML blob (inherited from the KeePass KeeAgent
#     plugin) that says "yes, this is an SSH key, load it on unlock"
keeagent_xml() {
    cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<EntrySettings>
    <AllowUseOfSshKey>true</AllowUseOfSshKey>
    <AddAtDatabaseOpen>true</AddAtDatabaseOpen>
    <RemoveAtDatabaseClose>true</RemoveAtDatabaseClose>
    <UseConfirmConstraint>false</UseConfirmConstraint>
    <UseLifetimeConstraintWhenAdding>false</UseLifetimeConstraintWhenAdding>
    <LifetimeConstraintDuration>600</LifetimeConstraintDuration>
    <Location>
        <SelectedType>attachment</SelectedType>
        <AttachmentName>$1</AttachmentName>
        <SaveAttachmentToTempFile>false</SaveAttachmentToTempFile>
        <FileName></FileName>
    </Location>
</EntrySettings>
EOF
}

kp_entry_exists() {   # db entry pw  ->  0 if the entry is present
    printf '%s\n' "$3" | keepassxc-cli show "$1" "$2" >/dev/null 2>&1
}

# SHA256 fingerprint only (no comment/bit-count noise), so a match is a real
# match. Works on a private key without its passphrase.
key_fingerprint() {   # file -> "SHA256:..."  (prints nothing on failure)
    ssh-keygen -lf "$1" 2>/dev/null | awk '{print $2}' || true
}

secure_rm() {   # file -> best-effort secure delete
    if command -v shred >/dev/null 2>&1; then
        shred -u "$1" 2>/dev/null || rm -f "$1"
    elif [[ $(uname) == Darwin ]]; then
        rm -P "$1"
    else
        rm -f "$1"
    fi
}

ramtemp() {   # -> path to a fresh 0700 dir, RAM-backed if the platform has one
    local base
    if   [[ -d ${XDG_RUNTIME_DIR:-} ]]; then base=$XDG_RUNTIME_DIR
    elif [[ -d /dev/shm ]];             then base=/dev/shm
    else                                     base=${TMPDIR:-/tmp}
    fi
    local d; d=$(mktemp -d "$base/skm.XXXXXX")
    chmod 700 "$d"
    printf '%s\n' "$d"
}

export_one() {
    local name=$1 db=$2 pw=$3 force=${4:-0}
    local key; key=$(keyfile "$name")
    local entry="$KP_GROUP/$name"
    local base; base=$(basename "$key")
    local pubtmp=""

    [[ -f $key ]] || die "no private key on disk for '$name' (already exported?)"

    local pub="$key.pub"
    if [[ ! -f $pub ]]; then
        pubtmp=$(mktemp)
        ssh-keygen -y -f "$key" > "$pubtmp"
        pub=$pubtmp
    fi

    local kp=(keepassxc-cli)
    # keepassxc-cli reads the database password from stdin, so we hand it the
    # same password for each subcommand rather than prompting five times.
    run_kp() { printf '%s\n' "$pw" | "${kp[@]}" "$@" >/dev/null; }

    run_kp mkdir  "$db" "$KP_GROUP" 2>/dev/null || true
    run_kp add    "$db" "$entry" --url "ssh://$name" 2>/dev/null || \
        info "entry '$entry' exists, updating attachments"

    # attachment-import refuses to clobber an attachment that's already there,
    # so on --force strip the old ones first (no-op if this is a fresh entry).
    if ((force)); then
        run_kp attachment-rm "$db" "$entry" "$base"             2>/dev/null || true
        run_kp attachment-rm "$db" "$entry" "$base.pub"         2>/dev/null || true
        run_kp attachment-rm "$db" "$entry" "KeeAgent.settings" 2>/dev/null || true
    fi

    local tmp; tmp=$(mktemp)
    keeagent_xml "$base" > "$tmp"

    run_kp attachment-import "$db" "$entry" "$base"            "$key"
    run_kp attachment-import "$db" "$entry" "$base.pub"        "$pub"
    run_kp attachment-import "$db" "$entry" "KeeAgent.settings" "$tmp"
    rm -f "$tmp" "$pubtmp"

    info "exported $name -> $entry (private + public key)"
}

cmd_export() {
    command -v keepassxc-cli >/dev/null || die "keepassxc-cli not found"

    local force=0 args=()
    while [[ $# -gt 0 ]]; do
        case $1 in
            -f|--force|--overwrite) force=1; shift ;;
            --all)                  args+=("$1"); shift ;;
            -*)                     die "unknown flag: $1" ;;
            *)                      args+=("$1"); shift ;;
        esac
    done
    local what=${args[0]:-} db=${args[1]:-}
    [[ -n $what && -n $db ]] || die "usage: skm export [--force] <name|--all> <database.kdbx>"
    [[ -f $db ]] || die "no such database: $db"

    local names=()
    if [[ $what == --all ]]; then
        shopt -s nullglob
        for f in "$CONF_DIR"/*.conf; do names+=("$(basename "$f" .conf)"); done
        [[ ${#names[@]} -gt 0 ]] || die "nothing managed to export"
    else
        require_host "$what"; names=("$what")
    fi

    read -rsp "KeePassXC database password: " pw; echo

    if ((! force)); then
        local n existing=()
        for n in "${names[@]}"; do
            kp_entry_exists "$db" "$KP_GROUP/$n" "$pw" && existing+=("$n")
        done
        [[ ${#existing[@]} -eq 0 ]] || \
            die "already in KeePassXC: ${existing[*]}  (re-run with --force to overwrite)"
    fi

    local n
    for n in "${names[@]}"; do export_one "$n" "$db" "$pw" "$force"; done

    echo
    info "next: in KeePassXC, enable Tools > Settings > SSH Agent, then re-unlock the database."
    info "verify with 'ssh-add -l', then run 'skm agent <name>' and delete the on-disk key."
}

# Delete the on-disk private key so it lives only in KeePassXC. Deliberately
# single-key (no --all): this is meant to require real consideration each time.
cmd_drop() {
    command -v keepassxc-cli >/dev/null || die "keepassxc-cli not found"

    local force=0 args=()
    while [[ $# -gt 0 ]]; do
        case $1 in
            -f|--force|--overwrite) force=1; shift ;;
            -*)                     die "unknown flag: $1" ;;
            *)                      args+=("$1"); shift ;;
        esac
    done
    local name=${args[0]:-} db=${args[1]:-}
    [[ -n $name && -n $db ]] || die "usage: skm drop [--force] <name> <database.kdbx>"
    require_host "$name"
    [[ -f $db ]] || die "no such database: $db"

    local key; key=$(keyfile "$name")
    [[ -f $key ]] || die "no local private key for '$name' (already dropped?)"

    local entry="$KP_GROUP/$name" base; base=$(basename "$key")

    read -rsp "KeePassXC database password: " pw; echo

    local have; have=$(key_fingerprint "$key")
    [[ -n $have ]] || die "could not read local key: $key"

    local tmpdir; tmpdir=$(ramtemp)
    local vault_key="$tmpdir/$base" vault_fp=""
    if printf '%s\n' "$pw" | keepassxc-cli attachment-export "$db" "$entry" "$base" "$vault_key" \
            2>/dev/null; then
        vault_fp=$(key_fingerprint "$vault_key")
    fi
    rm -rf "$tmpdir"

    echo
    info "local:  $have"
    info "vault:  ${vault_fp:-(not found in KeePassXC)}"

    if [[ -n $vault_fp && $vault_fp == "$have" ]]; then
        info "fingerprints match -- reversible via 'skm restore $name $db'"
        read -rp "delete local private key for '$name'? [y/N] " ans
        [[ ${ans,,} == y* ]] || { info "aborted"; return; }
    else
        if [[ -z $vault_fp ]]; then
            info "DANGER: '$name' is not in KeePassXC under $entry -- deleting now loses the only copy"
        else
            info "DANGER: fingerprints differ -- the vault copy is NOT this key"
        fi
        ((force)) || die "refusing to delete (re-run with --force if you're sure)"
        read -rp "this cannot be undone -- really delete '$key'? [y/N] " ans
        [[ ${ans,,} == y* ]] || { info "aborted"; return; }
    fi

    secure_rm "$key"
    retarget "$name" agent

    echo
    info "'$name' now resolves its key via the ssh-agent; verify with 'ssh-add -l'"
}

# Inverse of drop: pull the private key back out of KeePassXC onto disk, in
# the layout skm expects, and flip the config back to on-disk.
cmd_restore() {
    command -v keepassxc-cli >/dev/null || die "keepassxc-cli not found"

    local force=0 args=()
    while [[ $# -gt 0 ]]; do
        case $1 in
            -f|--force|--overwrite) force=1; shift ;;
            -*)                     die "unknown flag: $1" ;;
            *)                      args+=("$1"); shift ;;
        esac
    done
    local name=${args[0]:-} db=${args[1]:-}
    [[ -n $name && -n $db ]] || die "usage: skm restore [--force] <name> <database.kdbx>"
    require_host "$name"
    [[ -f $db ]] || die "no such database: $db"

    local key; key=$(keyfile "$name")
    if [[ -f $key ]] && ((! force)); then
        die "local key already present: $key  (re-run with --force to overwrite)"
    fi

    local entry="$KP_GROUP/$name" base; base=$(basename "$key")

    read -rsp "KeePassXC database password: " pw; echo

    printf '%s\n' "$pw" | keepassxc-cli attachment-export "$db" "$entry" "$base" "$key" 2>/dev/null \
        || die "no key attachment for '$name' in $entry"
    chmod 600 "$key"

    if printf '%s\n' "$pw" | keepassxc-cli attachment-export "$db" "$entry" "$base.pub" "$key.pub" \
            2>/dev/null; then
        chmod 644 "$key.pub"
    elif [[ ! -f $key.pub ]]; then
        info "no public key attachment in $entry; regenerating from the private key"
        ssh-keygen -y -f "$key" > "$key.pub"
        chmod 644 "$key.pub"
    fi

    retarget "$name" ondisk

    echo
    info "restored $name -> $key"
    info "fingerprint: $(key_fingerprint "$key")"
    info "$name now reads $key directly"
}

# ---------------------------------------------------------------- scoping

# An agent that holds one key can only ever be asked to sign with that key.
# So instead of forwarding your whole agent into a devcontainer, run a second
# agent containing just the key that container legitimately needs, and mount
# only its socket. Everything else is unreachable — not "denied", but absent.

cmd_scope() {
    local label=${1:-}; shift 2>/dev/null || true
    [[ -n $label ]] || die "usage: skm scope <label> [-c] [-t 8h] [-d db.kdbx] <name>..."

    local confirm=0 ttl="" db="" names=()
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--confirm) confirm=1;      shift ;;
            -t|--ttl)     ttl=${2:?};     shift 2 ;;
            -d|--db)      db=${2:?};      shift 2 ;;
            -*)           die "unknown flag: $1" ;;
            *)            names+=("$1");  shift ;;
        esac
    done
    [[ ${#names[@]} -gt 0 ]] || die "name at least one key to put in the agent"

    mkdir -p "$SOCK_DIR"; chmod 700 "$SOCK_DIR"
    local sock="$SOCK_DIR/$label.sock"

    if [[ -S $sock ]] && SSH_AUTH_SOCK="$sock" ssh-add -l >/dev/null 2>&1; then
        die "scope '$label' is already running (skm unscope $label to replace it)"
    fi
    rm -f "$sock"

    # The agent inherits SSH_ASKPASS/DISPLAY from *this* shell, and it's the
    # agent that renders the -c confirmation dialog. Start it from a graphical
    # session or the prompt will never appear.
    eval "$(ssh-agent -a "$sock")" >/dev/null
    export SSH_AUTH_SOCK="$sock"
    printf '%s\n' "${SSH_AGENT_PID:-}" > "$SOCK_DIR/$label.pid"

    local flags=()
    ((confirm))    && flags+=(-c)
    [[ -n $ttl ]]  && flags+=(-t "$ttl")

    local n key tmp
    for n in "${names[@]}"; do
        require_host "$n"
        key=$(keyfile "$n")

        if [[ -f $key ]]; then
            ssh-add "${flags[@]}" "$key"
        elif [[ -n $db ]]; then
            # Key lives in KeePassXC only. Pull it into memory-backed storage,
            # load it, wipe it. /dev/shm never touches the disk.
            command -v keepassxc-cli >/dev/null || die "keepassxc-cli not found"
            tmp=$(mktemp -d "${XDG_RUNTIME_DIR:-/dev/shm}/skm.XXXXXX" 2>/dev/null) \
                || tmp=$(mktemp -d)
            chmod 700 "$tmp"
            keepassxc-cli attachment-export "$db" "$KP_GROUP/$n" \
                "$(basename "$key")" "$tmp/$n"
            chmod 600 "$tmp/$n"
            ssh-add "${flags[@]}" "$tmp/$n"
            rm -rf "$tmp"
        else
            die "no key on disk for '$n' — pass -d <db.kdbx> to pull it from KeePassXC"
        fi
    done

    echo
    info "scope '$label' is live at $sock"
    SSH_AUTH_SOCK="$sock" ssh-add -l | sed 's/^/    /'
    echo
    info "devcontainer.json:"
    cat <<EOF

    "mounts": [
      "source=$sock,target=/ssh-agent,type=bind"
    ],
    "containerEnv": { "SSH_AUTH_SOCK": "/ssh-agent" }

EOF
    info "inside the container, 'ssh-add -l' should show only the keys above."
}

cmd_scopes() {
    [[ -d $SOCK_DIR ]] || die "no scoped agents"
    shopt -s nullglob
    local s label
    for s in "$SOCK_DIR"/*.sock; do
        label=$(basename "$s" .sock)
        if SSH_AUTH_SOCK="$s" ssh-add -l >/dev/null 2>&1; then
            printf '%s\n' "$label"
            SSH_AUTH_SOCK="$s" ssh-add -l | sed 's/^/    /'
        else
            printf '%s  (dead socket)\n' "$label"
        fi
    done
}

cmd_unscope() {
    local label=${1:-}; [[ -n $label ]] || die "usage: skm unscope <label>"
    local sock="$SOCK_DIR/$label.sock" pidf="$SOCK_DIR/$label.pid"
    [[ -S $sock || -f $pidf ]] || die "no such scope: $label"

    # ssh-agent -k kills the agent named by SSH_AGENT_PID, so we need the pid
    # we recorded at startup — the socket path alone isn't enough.
    if [[ -f $pidf ]]; then
        SSH_AGENT_PID=$(<"$pidf") SSH_AUTH_SOCK="$sock" ssh-agent -k >/dev/null 2>&1 || true
    fi
    rm -f "$sock" "$pidf"
    info "killed scope '$label'"
}

# ---------------------------------------------------------------- dispatch

case "${1:-help}" in
    add)       shift; cmd_add       "$@" ;;
    provision) shift; cmd_provision "$@" ;;
    alias)  shift; cmd_alias  "$@" ;;
    list)   shift; cmd_list   "$@" ;;
    status) shift; cmd_status "$@" ;;
    show)   shift; cmd_show   "$@" ;;
    copy)   shift; cmd_copy   "$@" ;;
    rm)     shift; cmd_rm     "$@" ;;
    export) shift; cmd_export "$@" ;;
    drop)    shift; cmd_drop    "$@" ;;
    restore) shift; cmd_restore "$@" ;;
    agent)  shift; cmd_agent  "$@" ;;
    ondisk) shift; cmd_ondisk "$@" ;;
    scope)   shift; cmd_scope   "$@" ;;
    scopes)  shift; cmd_scopes  "$@" ;;
    unscope) shift; cmd_unscope "$@" ;;
    *)      sed -n '3,26p' "$0" | sed 's/^# \?//' ;;
esac
