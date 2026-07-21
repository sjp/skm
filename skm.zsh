#!/usr/bin/env zsh
# skm — a small per-host SSH key manager.  (zsh port)
#
# Each host gets:  its own key, its own ~/.ssh/config.d/<name>.conf
# Optionally:      the private key stored in KeePassXC and removed from disk.
#
#   skm add <name> <user@host> [port]   generate key + config entry
#   skm provision <name> <user@host> [port] <db.kdbx>
#                                      add + export + agent + drop, in one go
#   skm alias <name> <pattern>...       let more names/IPs/globs use this key
#   skm list                            show managed hosts
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

# Must be POSIX — it has to survive being run by sh/bash in order to complain
# about being run by sh/bash.
[ -n "${ZSH_VERSION:-}" ] || { echo "skm: must be run with zsh (try: zsh skm ...)" >&2; exit 1; }

# emulate -L zsh gives us zsh's native semantics regardless of what the user has
# in ~/.zshrc — notably NO word splitting on unquoted parameters, so "$var" and
# $var behave the same and there is no IFS minefield.
emulate -L zsh
setopt err_exit no_unset pipe_fail

SSH_DIR="${SSH_DIR:-$HOME/.ssh}"
CONF_DIR="$SSH_DIR/config.d"
CONFIG="$SSH_DIR/config"
SOCK_DIR="$SSH_DIR/agents"
KP_GROUP="${SKM_KEEPASS_GROUP:-SSH Keys}"

die()  { print -u2 "skm: $*"; exit 1 }
info() { print "  $*" }

# ---------------------------------------------------------------- bootstrap

ensure_include() {
    mkdir -p "$CONF_DIR"
    chmod 700 "$SSH_DIR" "$CONF_DIR"
    [[ -f $CONFIG ]] || { : > "$CONFIG"; chmod 600 "$CONFIG" }

    # Include must sit at the very top: ssh_config is first-match-wins, so a
    # later Include would be shadowed by any earlier catch-all Host block.
    if ! grep -qE '^[[:space:]]*Include[[:space:]]+config\.d/' "$CONFIG"; then
        print -r -- "Include config.d/*.conf" > "$CONFIG.tmp"
        print >> "$CONFIG.tmp"
        cat "$CONFIG" >> "$CONFIG.tmp"
        mv "$CONFIG.tmp" "$CONFIG"
        chmod 600 "$CONFIG"
        info "added 'Include config.d/*.conf' to $CONFIG"
    fi
}

keyfile()  { print -r -- "$SSH_DIR/id_ed25519_$1" }
conffile() { print -r -- "$CONF_DIR/$1.conf" }

require_host() {
    [[ -f $(conffile "$1") ]] || die "no such managed host: $1  (try: skm list)"
}

# ---------------------------------------------------------------- commands

cmd_add() {
    local name=${1:-} dest=${2:-} port=${3:-22}
    [[ -n $name && -n $dest ]] || die "usage: skm add <name> <user@host> [port]"
    [[ $dest == *@* ]]         || die "destination must be user@host, e.g. git@github.com"

    local user=${dest%@*} host=${dest#*@}
    local key=$(keyfile "$name")
    local conf=$(conffile "$name")

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

    print
    info "created $conf"
    info "public key:"
    print
    cat "$key.pub"
    print
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

    local key=$(keyfile "$name")
    local fp=$(key_fingerprint "$key")
    [[ -n $fp ]] || die "could not read local key: $key"

    print
    info "before the on-disk private key can be deleted, KeePassXC must be serving it:"
    info "  1. KeePassXC > Tools > Settings > SSH Agent: enable the agent integration"
    info "  2. re-unlock (or reopen) $db"

    local ans=""
    while true; do
        print
        read -r "ans?press Enter to check the agent (or type 'skip' to continue anyway): " || ans=""
        if [[ ${(L)ans} == skip ]]; then
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

    print
    info "provisioned '$name': config + public key on disk, private key in KeePassXC only"
}

# `Host` takes a list of patterns, so extra domains / IPs / globs can share a
# key just by being appended to that line. HostName stays pinned to the
# canonical address, which keeps everything under one known_hosts entry.
cmd_alias() {
    local name=${1:-}
    (( $# > 1 )) || die "usage: skm alias <name> <pattern> [pattern...]"
    shift
    require_host "$name"

    local conf=$(conffile "$name")
    local existing=$(awk '$1=="Host"{sub(/^[ \t]*Host[ \t]+/,""); print; exit}' "$conf")

    local p
    local -a add=()
    for p in "$@"; do
        [[ " $existing " == *" $p "* ]] || add+=("$p")
    done
    if (( ${#add} == 0 )); then
        info "already matched by: Host $existing"
        return
    fi

    sed -i.bak "s|^\([ 	]*Host[ 	]\{1,\}\).*|\1$existing ${add[*]}|" "$conf"
    rm -f "$conf.bak"
    info "Host $existing ${add[*]}"
}

cmd_list() {
    [[ -d $CONF_DIR ]] || die "nothing managed yet"
    local f name target id agent
    print -f '%-14s %-28s %s\n' NAME TARGET KEY
    # (N) is zsh's nullglob qualifier: an empty directory yields zero
    # iterations instead of a literal '*.conf'.
    for f in $CONF_DIR/*.conf(N); do
        name=${f:t:r}                       # :t = tail, :r = strip extension
        target=$(awk '$1=="User"{u=$2} $1=="HostName"{h=$2} $1=="Port"{p=$2} \
                      END{printf "%s@%s%s", u, h, (p=="22"?"":":" p)}' "$f")
        id=$(awk '$1=="IdentityFile"{print $2}' "$f")
        agent=""
        [[ $id == *.pub ]] && agent="  (agent)"
        print -f '%-14s %-28s %s%s\n' "$name" "$target" "${id:t}" "$agent"
    done
}

cmd_show() { require_host "$1"; cat "$(keyfile "$1").pub" }

cmd_copy() {
    require_host "$1"
    ssh-copy-id -i "$(keyfile "$1").pub" "$1"
}

cmd_rm() {
    local name=${1:-}
    [[ -n $name ]] || die "usage: skm rm <name>"
    require_host "$name"

    # zsh's read takes the prompt as name?prompt. Do NOT use bash's `read -rp`:
    # in zsh, -p means "read from the coprocess" and silently reads nothing.
    # The `||` matters: under err_exit, an EOF (piped/non-interactive) makes
    # read return non-zero, which would otherwise kill the script mid-way.
    local ans=""
    read -r "ans?delete key and config for '$name'? [y/N] " || ans=""
    case $ans in
        [yY]*) ;;
        *) info "aborted"; return ;;
    esac

    rm -f "$(conffile "$name")" "$(keyfile "$name")" "$(keyfile "$name").pub"
    info "removed $name"
}

# Swap IdentityFile between the private key on disk and the .pub stub.
# With the .pub, ssh asks the agent (KeePassXC) for the matching private key —
# so the private key never has to exist on disk at all.
retarget() {
    local name=$1 to=$2
    local conf=$(conffile "$name")
    local key=$(keyfile "$name")
    case $to in
        agent)  sed -i.bak "s|^\([ 	]*IdentityFile[ 	]\{1,\}\).*|\1$key.pub|" "$conf" ;;
        ondisk) sed -i.bak "s|^\([ 	]*IdentityFile[ 	]\{1,\}\).*|\1$key|"     "$conf" ;;
    esac
    rm -f "$conf.bak"
}

cmd_agent() {
    require_host "$1"
    retarget "$1" agent
    info "$1 now resolves its key via the ssh-agent"
    if (( $+commands[shred] )); then            # zsh: $+commands[x] tests PATH
        info "once verified: shred -u $(keyfile "$1")"
    else
        info "once verified: rm -P $(keyfile "$1")"    # BSD/macOS
    fi
}

cmd_ondisk() {
    require_host "$1"
    retarget "$1" ondisk
    info "$1 now reads $(keyfile "$1") directly"
}

# ---------------------------------------------------------------- keepassxc

# On macOS, keepassxc-cli ships inside the app bundle and isn't on PATH unless
# you installed via Homebrew. Find it either way.
kp_bin() {
    if (( $+commands[keepassxc-cli] )); then
        print -r -- $commands[keepassxc-cli]
    elif [[ -x /Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli ]]; then
        print -r -- /Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli
    else
        die "keepassxc-cli not found (macOS: it lives in KeePassXC.app/Contents/MacOS)"
    fi
}

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

# keepassxc-cli reads the database password from stdin, so we hand it the same
# password for each subcommand rather than prompting five times.
run_kp() {
    print -r -- "$KP_PW" | "$KP_CLI" "$@" >/dev/null
}

kp_entry_exists() {   # db entry  ->  0 if the entry is present
    print -r -- "$KP_PW" | "$KP_CLI" show "$1" "$2" >/dev/null 2>&1
}

# SHA256 fingerprint only (no comment/bit-count noise), so a match is a real
# match. Works on a private key without its passphrase.
key_fingerprint() {   # file -> "SHA256:..."  (prints nothing on failure)
    ssh-keygen -lf "$1" 2>/dev/null | awk '{print $2}' || true
}

secure_rm() {   # file -> best-effort secure delete
    if (( $+commands[shred] )); then
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
    local d=$(mktemp -d "$base/skm.XXXXXX")
    chmod 700 "$d"
    print -r -- "$d"
}

export_one() {
    local name=$1
    local db=$2
    local force=${3:-0}
    local key=$(keyfile "$name")
    local entry="$KP_GROUP/$name"
    local base=${key:t}
    local pub=$key.pub
    local pubtmp=""

    [[ -f $key ]] || die "no private key on disk for '$name' (already exported?)"

    if [[ ! -f $pub ]]; then
        pubtmp=$(mktemp "${TMPDIR:-/tmp}/skm.XXXXXX")
        ssh-keygen -y -f "$key" > "$pubtmp"
        pub=$pubtmp
    fi

    run_kp mkdir "$db" "$KP_GROUP" 2>/dev/null || true
    run_kp add   "$db" "$entry" --url "ssh://$name" 2>/dev/null \
        || info "entry '$entry' exists, updating attachments"

    # attachment-import refuses to clobber an attachment that's already there,
    # so on --force strip the old ones first (no-op if this is a fresh entry).
    if (( force )); then
        run_kp attachment-rm "$db" "$entry" "$base"             2>/dev/null || true
        run_kp attachment-rm "$db" "$entry" "$base.pub"         2>/dev/null || true
        run_kp attachment-rm "$db" "$entry" "KeeAgent.settings" 2>/dev/null || true
    fi

    local tmp=$(mktemp "${TMPDIR:-/tmp}/skm.XXXXXX")   # BSD mktemp needs a template
    keeagent_xml "$base" > "$tmp"

    run_kp attachment-import "$db" "$entry" "$base"             "$key"
    run_kp attachment-import "$db" "$entry" "$base.pub"         "$pub"
    run_kp attachment-import "$db" "$entry" "KeeAgent.settings" "$tmp"
    rm -f "$tmp" "$pubtmp"

    info "exported $name -> $entry (private + public key)"
}

cmd_export() {
    local force=0
    local n
    local -a args=()
    while (( $# > 0 )); do
        case $1 in
            -f|--force|--overwrite) force=1;      shift ;;
            --all)                  args+=("$1"); shift ;;
            -*)                     die "unknown flag: $1" ;;
            *)                      args+=("$1"); shift ;;
        esac
    done
    local what=${args[1]:-} db=${args[2]:-}
    [[ -n $what && -n $db ]] || die "usage: skm export [--force] <name|--all> <database.kdbx>"
    [[ -f $db ]] || die "no such database: $db"

    typeset -g KP_CLI=$(kp_bin)
    typeset -g KP_PW=""

    local -a names=()
    if [[ $what == --all ]]; then
        local f
        for f in $CONF_DIR/*.conf(N); do names+=("${f:t:r}"); done
        (( ${#names} > 0 )) || die "nothing managed to export"
    else
        require_host "$what"
        names=("$what")
    fi

    read -rs "KP_PW?KeePassXC database password: " || die "no password given"
    print   # -s ate the newline

    if (( ! force )); then
        local -a existing=()
        for n in "${names[@]}"; do
            kp_entry_exists "$db" "$KP_GROUP/$n" && existing+=("$n")
        done
        (( ${#existing} == 0 )) || \
            die "already in KeePassXC: ${existing[*]}  (re-run with --force to overwrite)"
    fi

    for n in "${names[@]}"; do export_one "$n" "$db" "$force"; done
    unset KP_PW

    print
    info "next: in KeePassXC, enable Tools > Settings > SSH Agent, then re-unlock the database."
    info "the entry's Password field must hold the key's passphrase, or it can't decrypt it."
    info "verify with 'ssh-add -l', then run 'skm agent <name>' and delete the on-disk key."
}

# Delete the on-disk private key so it lives only in KeePassXC. Deliberately
# single-key (no --all): this is meant to require real consideration each time.
cmd_drop() {
    local kpcli=$(kp_bin)
    local force=0
    local -a args=()
    while (( $# > 0 )); do
        case $1 in
            -f|--force|--overwrite) force=1;      shift ;;
            -*)                     die "unknown flag: $1" ;;
            *)                      args+=("$1"); shift ;;
        esac
    done
    local name=${args[1]:-} db=${args[2]:-}
    [[ -n $name && -n $db ]] || die "usage: skm drop [--force] <name> <database.kdbx>"
    require_host "$name"
    [[ -f $db ]] || die "no such database: $db"

    local key=$(keyfile "$name")
    [[ -f $key ]] || die "no local private key for '$name' (already dropped?)"

    local entry="$KP_GROUP/$name"
    local base=${key:t}

    local pw=""
    read -rs "pw?KeePassXC database password: " || die "no password given"
    print   # -s ate the newline

    local have=$(key_fingerprint "$key")
    [[ -n $have ]] || die "could not read local key: $key"

    local tmpdir=$(ramtemp)
    local vault_key="$tmpdir/$base"
    local vault_fp=""
    if print -r -- "$pw" | "$kpcli" attachment-export "$db" "$entry" "$base" "$vault_key" \
            2>/dev/null; then
        vault_fp=$(key_fingerprint "$vault_key")
    fi
    rm -rf "$tmpdir"

    print
    info "local:  $have"
    info "vault:  ${vault_fp:-(not found in KeePassXC)}"

    local ans=""
    if [[ -n $vault_fp && $vault_fp == $have ]]; then
        info "fingerprints match -- reversible via 'skm restore $name $db'"
        read -r "ans?delete local private key for '$name'? [y/N] " || ans=""
        case $ans in
            [yY]*) ;;
            *) info "aborted"; return ;;
        esac
    else
        if [[ -z $vault_fp ]]; then
            info "DANGER: '$name' is not in KeePassXC under $entry -- deleting now loses the only copy"
        else
            info "DANGER: fingerprints differ -- the vault copy is NOT this key"
        fi
        (( force )) || die "refusing to delete (re-run with --force if you're sure)"
        read -r "ans?this cannot be undone -- really delete '$key'? [y/N] " || ans=""
        case $ans in
            [yY]*) ;;
            *) info "aborted"; return ;;
        esac
    fi

    secure_rm "$key"
    retarget "$name" agent

    print
    info "'$name' now resolves its key via the ssh-agent; verify with 'ssh-add -l'"
}

# Inverse of drop: pull the private key back out of KeePassXC onto disk, in
# the layout skm expects, and flip the config back to on-disk.
cmd_restore() {
    local kpcli=$(kp_bin)
    local force=0
    local -a args=()
    while (( $# > 0 )); do
        case $1 in
            -f|--force|--overwrite) force=1;      shift ;;
            -*)                     die "unknown flag: $1" ;;
            *)                      args+=("$1"); shift ;;
        esac
    done
    local name=${args[1]:-} db=${args[2]:-}
    [[ -n $name && -n $db ]] || die "usage: skm restore [--force] <name> <database.kdbx>"
    require_host "$name"
    [[ -f $db ]] || die "no such database: $db"

    local key=$(keyfile "$name")
    if [[ -f $key ]] && (( ! force )); then
        die "local key already present: $key  (re-run with --force to overwrite)"
    fi

    local entry="$KP_GROUP/$name"
    local base=${key:t}

    local pw=""
    read -rs "pw?KeePassXC database password: " || die "no password given"
    print   # -s ate the newline

    print -r -- "$pw" | "$kpcli" attachment-export "$db" "$entry" "$base" "$key" 2>/dev/null \
        || die "no key attachment for '$name' in $entry"
    chmod 600 "$key"

    if print -r -- "$pw" | "$kpcli" attachment-export "$db" "$entry" "$base.pub" "$key.pub" \
            2>/dev/null; then
        chmod 644 "$key.pub"
    elif [[ ! -f $key.pub ]]; then
        info "no public key attachment in $entry; regenerating from the private key"
        ssh-keygen -y -f "$key" > "$key.pub"
        chmod 644 "$key.pub"
    fi

    retarget "$name" ondisk

    print
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
    local label=${1:-}
    [[ -n $label ]] || die "usage: skm scope <label> [-c] [-t 8h] [-d db.kdbx] <name>..."
    shift

    local confirm=0 ttl="" db=""
    local -a names=()
    while (( $# > 0 )); do
        case $1 in
            -c|--confirm) confirm=1;     shift ;;
            -t|--ttl)     ttl=${2:?};    shift 2 ;;
            -d|--db)      db=${2:?};     shift 2 ;;
            -*)           die "unknown flag: $1" ;;
            *)            names+=("$1"); shift ;;
        esac
    done
    (( ${#names} > 0 )) || die "name at least one key to put in the agent"

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
    print -r -- "${SSH_AGENT_PID:-}" > "$SOCK_DIR/$label.pid"

    # An empty array expands to zero words here — no bash-3.2-style landmine.
    local -a flags=()
    (( confirm ))   && flags+=(-c)
    [[ -n $ttl ]]   && flags+=(-t "$ttl")

    local n key tmp base_dir kpcli
    for n in "${names[@]}"; do
        require_host "$n"
        key=$(keyfile "$n")

        if [[ -f $key ]]; then
            ssh-add "${flags[@]}" "$key"
        elif [[ -n $db ]]; then
            # Key lives in KeePassXC only. Pull it out, load it, wipe it.
            # /dev/shm is RAM-backed so it never hits disk — but it's a Linux
            # thing. macOS has no equivalent, so the copy is briefly on disk
            # there; we unlink it immediately after ssh-add.
            kpcli=$(kp_bin)
            if   [[ -d ${XDG_RUNTIME_DIR:-} ]]; then base_dir=$XDG_RUNTIME_DIR
            elif [[ -d /dev/shm ]];             then base_dir=/dev/shm
            else                                     base_dir=${TMPDIR:-/tmp}
            fi
            tmp=$(mktemp -d "$base_dir/skm.XXXXXX")
            chmod 700 "$tmp"
            "$kpcli" attachment-export "$db" "$KP_GROUP/$n" "${key:t}" "$tmp/$n"
            chmod 600 "$tmp/$n"
            ssh-add "${flags[@]}" "$tmp/$n"
            rm -rf "$tmp"
        else
            die "no key on disk for '$n' — pass -d <db.kdbx> to pull it from KeePassXC"
        fi
    done

    print
    info "scope '$label' is live at $sock"
    SSH_AUTH_SOCK="$sock" ssh-add -l | sed 's/^/    /'
    print
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
    local s label
    for s in $SOCK_DIR/*.sock(N); do
        label=${s:t:r}
        if SSH_AUTH_SOCK="$s" ssh-add -l >/dev/null 2>&1; then
            print -r -- "$label"
            SSH_AUTH_SOCK="$s" ssh-add -l | sed 's/^/    /'
        else
            print -r -- "$label  (dead socket)"
        fi
    done
}

cmd_unscope() {
    local label=${1:-}
    [[ -n $label ]] || die "usage: skm unscope <label>"
    local sock="$SOCK_DIR/$label.sock" pidf="$SOCK_DIR/$label.pid"
    [[ -S $sock || -f $pidf ]] || die "no such scope: $label"

    # ssh-agent -k kills the agent named by SSH_AGENT_PID, so we need the pid
    # we recorded at startup — the socket path alone isn't enough.
    if [[ -f $pidf ]]; then
        SSH_AGENT_PID="$(<$pidf)" SSH_AUTH_SOCK="$sock" ssh-agent -k >/dev/null 2>&1 || true
    fi
    rm -f "$sock" "$pidf"
    info "killed scope '$label'"
}

# ---------------------------------------------------------------- dispatch

case "${1:-help}" in
    add)       shift; cmd_add       "$@" ;;
    provision) shift; cmd_provision "$@" ;;
    alias)   shift; cmd_alias   "$@" ;;
    list)    shift; cmd_list    "$@" ;;
    show)    shift; cmd_show    "$@" ;;
    copy)    shift; cmd_copy    "$@" ;;
    rm)      shift; cmd_rm      "$@" ;;
    export)  shift; cmd_export  "$@" ;;
    drop)    shift; cmd_drop    "$@" ;;
    restore) shift; cmd_restore "$@" ;;
    agent)   shift; cmd_agent   "$@" ;;
    ondisk)  shift; cmd_ondisk  "$@" ;;
    scope)   shift; cmd_scope   "$@" ;;
    scopes)  shift; cmd_scopes  "$@" ;;
    unscope) shift; cmd_unscope "$@" ;;
    *)       sed -n '3,25p' "$0" | sed 's/^# \?//' ;;
esac
