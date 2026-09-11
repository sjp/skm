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
#
# Vault settings, taken from the environment:
#   SKM_KEEPASS_GROUP          group the entries live in (default "SSH Keys")
#   SKM_KEEPASS_KEYFILE        key file the database also needs to unlock
#   SKM_KEEPASS_YUBIKEY        hardware key slot[:serial] the database needs
#   SKM_KEEPASS_NO_PASSWORD    set for a database with no password at all
#   SKM_KEEPASS_PASSWORD_FILE  file whose first line is the database password

set -euo pipefail

# The directory skm manages. SKM_SSH_DIR moves it somewhere else; the older,
# more collision-prone SSH_DIR is still honoured so existing setups keep
# working.
SSH_DIR="${SKM_SSH_DIR:-${SSH_DIR:-$HOME/.ssh}}"
CONF_DIR="$SSH_DIR/config.d"
CONFIG="$SSH_DIR/config"
SOCK_DIR="$SSH_DIR/agents"
KP_GROUP="${SKM_KEEPASS_GROUP:-SSH Keys}"

# A database can be locked with more than a password: a key file, a hardware
# key, or either of those instead of one. keepassxc-cli has to be handed the
# same combination the database was created with, so what unlocks it is
# settled here, in one place, and reaches every vault call from there. A
# password named in a file is read from it rather than asked for, which is
# what lets an unattended run -- a cron health check, say -- open a database.
KP_KEYFILE="${SKM_KEEPASS_KEYFILE:-}"
KP_YUBIKEY="${SKM_KEEPASS_YUBIKEY:-}"
KP_PW_FILE="${SKM_KEEPASS_PASSWORD_FILE:-}"

# Any value but 0 turns it on, so that the spelling the user's other tooling
# uses -- 1, yes, true -- means the same thing here.
if [[ -n ${SKM_KEEPASS_NO_PASSWORD:-} && ${SKM_KEEPASS_NO_PASSWORD:-} != 0 ]]; then
    KP_NO_PW=1
else
    KP_NO_PW=0
fi

# Everything this script writes is a private key, a copy of one, or a config
# fragment naming one. Create all of it unreadable to anyone else from the
# outset: a file made world-readable and tightened a moment later is readable
# by any local user in between. The chmod calls further down cover paths that
# already existed when skm found them.
umask 077

die()  { printf 'skm: %s\n' "$*" >&2; exit 1; }
warn() { printf 'skm: %s\n' "$*" >&2; }
info() { printf '  %s\n' "$*"; }

# ---------------------------------------------------------------- bootstrap

# ssh resolves a relative Include path against ~/.ssh rather than against the
# directory the config file lives in, so only the default layout can use the
# short relative form; anywhere else has to be spelled out in full. The quotes
# hold a path containing spaces together as one argument.
include_arg() {
    if [[ $SSH_DIR == "$HOME/.ssh" ]]; then
        printf 'config.d/*.conf'
    else
        printf '"%s/*.conf"' "$CONF_DIR"
    fi
}

# Every spelling of the fragment glob that reaches the managed directory. ssh
# resolves a relative Include against ~/.ssh, so the short forms only mean that
# directory when it is where skm keeps its files. A glob without the .conf
# suffix picks the fragments up as well, so it counts as already there.
include_spellings() {
    printf '%s/*.conf\n' "$CONF_DIR"
    printf '%s/*\n'      "$CONF_DIR"
    if [[ $SSH_DIR == "$HOME/.ssh" ]]; then
        # Literal strings to compare against, not paths to resolve: this is
        # simply how a hand-written ssh config usually spells the same glob.
        # shellcheck disable=SC2088
        printf '%s\n' 'config.d/*.conf' 'config.d/*' \
                      '~/.ssh/config.d/*.conf' '~/.ssh/config.d/*'
    fi
}

# Where $CONFIG stands on including the fragment directory: a kind, the line the
# Include sits on, and the line and text of the first Host or Match ahead of it.
#
#     absent 0 0
#     top 1 0
#     shadowed 12 3 Host *
#
# The position is worth knowing because ssh keeps the first value it sees for
# each setting: an Include below a catch-all block still reads the fragments,
# but nothing in them can override what that block has already set.
include_state() {
    [[ -f $CONFIG ]] || { printf 'absent 0 0\n'; return; }
    awk -v spellings="$(include_spellings)" '
        BEGIN {
            n = split(spellings, s, "\n")
            for (i = 1; i <= n; i++) want[s[i]] = 1
        }
        # The argument of Include is a list, and any member of it may be quoted.
        function names_dir(args,   tok, i) {
            while (args != "") {
                sub(/^[ \t]+/, "", args)
                if (args == "") break
                if (substr(args, 1, 1) == "\"") {
                    args = substr(args, 2)
                    i = index(args, "\"")
                    tok  = (i ? substr(args, 1, i - 1) : args)
                    args = (i ? substr(args, i + 1)    : "")
                } else {
                    i = match(args, /[ \t]/)
                    tok  = (i ? substr(args, 1, i - 1) : args)
                    args = (i ? substr(args, i)        : "")
                }
                if (tok in want) return 1
            }
            return 0
        }
        {
            line = $0
            sub(/^[ \t]+/, "", line)
            sub(/[ \t]+$/, "", line)
            if (line == "" || line ~ /^#/) next

            # Keywords are case-insensitive and may be joined to their argument
            # by an equals sign rather than by whitespace.
            key = line
            sub(/[ \t=].*$/, "", key)
            key = tolower(key)

            if (key == "host" || key == "match") {
                if (!blocker) { blocker = NR; blocker_line = line }
                next
            }
            if (key != "include") next

            args = line
            sub(/^[^ \t=]+[ \t=]*/, "", args)
            if (!names_dir(args)) next
            found = NR
            exit
        }
        END {
            if (!found)         print "absent 0 0"
            else if (blocker)   printf "shadowed %d %d %s\n", found, blocker, blocker_line
            else                printf "top %d 0\n", found
        }
    ' "$CONFIG"
}

ensure_include() {
    mkdir -p "$CONF_DIR"
    chmod 700 "$SSH_DIR" "$CONF_DIR"
    [[ -f $CONFIG ]] || { : > "$CONFIG"; chmod 600 "$CONFIG"; }

    local kind inc blk text
    read -r kind inc blk text <<< "$(include_state)"

    if [[ $kind == absent ]]; then
        # The new line goes at the very top so the fragments are read before any
        # block that might already have set the same options.
        local arg; arg=$(include_arg)
        printf 'Include %s\n\n' "$arg" > "$CONFIG.tmp"
        cat "$CONFIG" >> "$CONFIG.tmp"
        mv "$CONFIG.tmp" "$CONFIG"
        chmod 600 "$CONFIG"
        info "added 'Include $arg' to $CONFIG"
    elif [[ $kind == shadowed ]]; then
        warn "$CONFIG pulls in $CONF_DIR on line $inc, below '$text' on line $blk"
        warn "ssh keeps the first value it sees for each setting, so what skm writes there may be ignored; move the Include line to the top of the file"
    fi
}

keyfile()  { printf '%s/id_ed25519_%s' "$SSH_DIR" "$1"; }
conffile() { printf '%s/%s.conf' "$CONF_DIR" "$1"; }

# A host name becomes part of a file name, an ssh `Host` pattern, a KeePassXC
# entry name and an XML attachment name, so it is restricted to characters that
# mean the same thing in all four: it must start with a letter or digit and hold
# only letters, digits, '.', '_' and '-'. Excluding '/' and a leading '.' also
# keeps every derived path inside $SSH_DIR.
NAME_RE='^[A-Za-z0-9][A-Za-z0-9._-]*$'

# What ssh itself accepts in a `Host` pattern: host-name characters plus the
# globs '*' and '?' and the leading '!' that negates a pattern. Whitespace is
# excluded because the `Host` line is a list — a pattern containing a space
# would silently become two patterns.
PATTERN_RE='^[A-Za-z0-9._*?!-]+$'

require_name() {
    local name=${1:-} what=${2:-host name}
    [[ $name =~ $NAME_RE ]] || die \
        "invalid $what: '$name'  (letters, digits, '.', '_' and '-', starting with a letter or digit)"
}

require_pattern() {
    local pattern=${1:-}
    [[ $pattern =~ $PATTERN_RE ]] || die \
        "invalid host pattern: '$pattern'  (letters, digits, '.', '_', '-' and the globs '*', '?', '!')"
}

require_port() {
    local port=${1:-}
    { [[ $port =~ ^[1-9][0-9]*$ ]] && (( port <= 65535 )); } || die \
        "invalid port: '$port'  (a number from 1 to 65535)"
}

# Replace the first line of a config fragment whose first word is $2, keeping
# that line's indentation. The replacement travels through the environment
# rather than awk's -v, because -v expands backslash escapes in the value and
# would mangle any path or pattern containing one.
replace_conf_line() {
    local conf=$1 keyword=$2 text=$3
    SKM_KEYWORD=$keyword SKM_TEXT=$text awk '
        !replaced && $1 == ENVIRON["SKM_KEYWORD"] {
            match($0, /^[ \t]*/)
            print substr($0, 1, RLENGTH) ENVIRON["SKM_TEXT"]
            replaced = 1
            next
        }
        { print }
    ' "$conf" > "$conf.new"
    mv "$conf.new" "$conf"
    chmod 600 "$conf"
}

# ssh reads the IdentityFile path as a single quoted argument, so that a key
# under a directory whose name contains a space still resolves; strip the
# quotes back off when reading the path out again.
identity_of() {
    awk '$1 == "IdentityFile" {
             sub(/^[ \t]*IdentityFile[ \t]+/, "")
             gsub(/^"|"$/, "")
             print
             exit
         }' "$1"
}

# Every command that takes a host name goes through here. The second argument
# is the caller's own usage line: a name that is empty means the argument was
# left off the command line, and a usage reminder is more use than a complaint
# about a host called "".
require_host() {
    local name=${1:-} usage=${2:-"usage: skm <command> <name>"}
    [[ -n $name ]] || die "$usage"
    require_name "$name"
    [[ -f $(conffile "$name") ]] || die "no such managed host: $name  (try: skm list)"
}

# ---------------------------------------------------------------- commands

cmd_add() {
    local name=${1:-} dest=${2:-} port=${3:-22}
    [[ -n $name && -n $dest ]] || die "usage: skm add <name> <user@host> [port]"
    [[ $dest == *@* ]]         || die "destination must be user@host, e.g. git@github.com"
    require_name "$name"
    require_port "$port"

    local user=${dest%@*} host=${dest#*@}
    local key; key=$(keyfile "$name")
    local conf; conf=$(conffile "$name")

    ensure_include
    [[ -e $key  ]] && die "key already exists: $key"
    [[ -e $conf ]] && die "host already managed: $name"

    info "generating key -- a passphrase is fine: 'skm export' stores it in the vault entry"
    ssh-keygen -t ed25519 -f "$key" -C "$name@$(hostname -s)-$(date +%Y%m%d)"

    cat > "$conf" <<EOF
# managed by skm
Host $name
    HostName $host
    User $user
    Port $port
    IdentityFile "$key"
    IdentitiesOnly yes
    # Reuse one authenticated connection for 10 minutes. Repeat 'ssh $name'
    # calls ride the existing master and never re-ask the agent — so a locked
    # KeePassXC vault doesn't interrupt an active session.
    ControlMaster auto
    # %C is a fixed-length hash of the connection, so the socket path stays
    # well inside the ~104-byte limit however long the user and host names
    # get, and a directory listing of cm/ gives away neither.
    ControlPath "$SSH_DIR/cm/%C"
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
        require_pattern "$p"
        [[ " $existing " == *" $p "* ]] || add+=("$p")
    done
    [[ ${#add[@]} -gt 0 ]] || { info "already matched by: Host $existing"; return; }

    replace_conf_line "$conf" Host "Host $existing ${add[*]}"
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
        id=$(identity_of "$f")
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

    # A vault that could not be read says nothing about the key. Anything
    # firmer would invite a decision the reading does not support.
    if [[ $priv_vault == error ]]; then
        printf 'UNKNOWN: the vault could not be read'
        return
    fi

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

# Whether the fragments skm writes are reachable at all, and whether anything
# ahead of them in $CONFIG has already had its say. Printed once per run, since
# it describes the file rather than any one host.
include_report() {
    local kind inc blk text
    read -r kind inc blk text <<< "$(include_state)"

    local note=""
    case $kind in
        absent)   note="missing - nothing in $CONF_DIR is read" ;;
        top)      note="line $inc, ahead of any Host or Match block" ;;
        shadowed) note="line $inc, below '$text' on line $blk - settings in $CONF_DIR may be ignored" ;;
    esac

    printf '%s\n' "$CONFIG"
    printf '  %-13s %s\n' "Include" "$note"
    echo
}

status_one() {
    local name=$1 db=$2
    local conf; conf=$(conffile "$name")
    local key; key=$(keyfile "$name")
    local pub="$key.pub"

    local target
    target="$(awk '$1=="User"{u=$2} $1=="HostName"{h=$2} $1=="Port"{p=$2} \
                   END{printf "%s@%s%s", u, h, (p=="22"?"":":" p)}' "$conf")"
    local id; id=$(identity_of "$conf")
    local mode="ondisk"; [[ $id == *.pub ]] && mode="agent"

    local priv_disk="no" pub_disk="no"
    [[ -f $key ]] && priv_disk="yes"
    [[ -f $pub ]] && pub_disk="yes"

    local local_fp=""
    [[ $priv_disk == yes ]] && local_fp=$(key_fingerprint "$key")

    local priv_vault="?" pub_vault="?" vault_fp="" fp_status="n/a (no db)" vault_err=""
    if [[ -n $db ]]; then
        local entry="$KP_GROUP/$name" base; base=$(basename "$key")
        local tmpdir; tmpdir=$(ramtemp)
        local rc=0
        kp_attachment_export "$db" "$entry" "$base" "$tmpdir/$base" || rc=$?
        case $rc in
            0) priv_vault="yes"; vault_fp=$(key_fingerprint "$tmpdir/$base") ;;
            1) priv_vault="no" ;;
            *) priv_vault="error"; vault_err=$KP_ERR ;;
        esac
        rc=0
        kp_attachment_export "$db" "$entry" "$base.pub" "$tmpdir/$base.pub" || rc=$?
        case $rc in
            0) pub_vault="yes" ;;
            1) pub_vault="no" ;;
            *) pub_vault="error"; vault_err=$KP_ERR ;;
        esac
        rm -rf "$tmpdir"

        if [[ $priv_vault == error ]]; then
            fp_status="n/a (vault could not be read)"
        elif [[ -n $local_fp && -n $vault_fp ]]; then
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
    [[ -n $vault_err ]] && printf '  %-13s %s\n' "vault error" "$vault_err"
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

    include_report

    if [[ -n $db ]]; then
        kp_require
        kp_password "$db"
    fi

    local n
    for n in "${names[@]}"; do status_one "$n" "$db"; done
}

cmd_show() {
    local name=${1:-}
    require_host "$name" "usage: skm show <name>"
    cat "$(keyfile "$name").pub"
}

cmd_copy() {
    local name=${1:-}
    require_host "$name" "usage: skm copy <name>"
    ssh-copy-id -i "$(keyfile "$name").pub" "$name"
}

cmd_rm() {
    local name=${1:-}
    require_host "$name" "usage: skm rm <name>"

    # The `||` matters: at EOF (piped or non-interactive input) read returns
    # non-zero, which under `set -e` would otherwise kill the script mid-way
    # with no explanation.
    local ans=""
    read -rp "delete key and config for '$name'? [y/N] " ans || ans=""
    [[ ${ans,,} == y* ]] || { info "aborted"; return; }
    rm -f "$(conffile "$name")" "$(keyfile "$name")" "$(keyfile "$name").pub"
    info "removed $name"
}

# The public key is what agent mode points ssh at, so it has to be on disk for
# the host to work at all. It is also derivable from the private key, so a
# missing one is repaired rather than reported whenever the private half is
# still there; once it is gone, nothing local can rebuild it and the vault is
# the only way back.
ensure_pub() {   # name -> a .pub on disk, or die trying
    local name=$1 key; key=$(keyfile "$name")
    if [[ -f $key.pub ]]; then return 0; fi
    [[ -f $key ]] || die "no public key on disk for '$name', and no private key to rebuild it from -- 'skm restore $name <database.kdbx>' brings both back"

    info "no public key on disk for '$name'; rebuilding $key.pub from the private key"
    key_passphrase "$key"
    write_pub "$key" "$KEY_PASS"
    KEY_PASS=""
}

# Derive the public half of a key and put it on disk. The write lands in a
# temp file first: a half-written .pub left behind by a failure looks exactly
# like a good one to everything that checks for the file.
write_pub() {   # key passphrase
    local key=$1 pass=$2 tmp; tmp=$(mktemp "${TMPDIR:-/tmp}/skm.XXXXXX")
    ssh-keygen -y -P "$pass" -f "$key" > "$tmp" \
        || { rm -f "$tmp"; die "could not derive the public key from $key"; }
    mv "$tmp" "$key.pub"
}

# Swap IdentityFile between the private key on disk and the .pub stub.
# With the .pub, ssh asks the agent (KeePassXC) for the matching private key —
# so the private key never has to exist on disk at all.
retarget() {
    local name=$1 to=$2 conf; conf=$(conffile "$name")
    local key; key=$(keyfile "$name")
    case $to in
        agent)  ensure_pub "$name"
                replace_conf_line "$conf" IdentityFile "IdentityFile \"$key.pub\"" ;;
        ondisk) replace_conf_line "$conf" IdentityFile "IdentityFile \"$key\""     ;;
    esac
}

cmd_agent() {
    local name=${1:-}
    require_host "$name" "usage: skm agent <name>"
    retarget "$name" agent
    info "$name now resolves its key via the ssh-agent"
    info "once verified, you can: shred -u $(keyfile "$name")"
}

cmd_ondisk() {
    local name=${1:-}
    require_host "$name" "usage: skm ondisk <name>"
    retarget "$name" ondisk
    info "$name now reads $(keyfile "$name") directly"
}

# ---------------------------------------------------------------- keepassxc

# The binary and the database password, settled once per run and shared by
# every vault call below. Commands that never open a vault leave both empty.
KP_CLI=""
KP_PW=""

# The passphrase of the key currently being exported, for as long as that
# takes. Empty for a key that has none.
KEY_PASS=""

# The unlock options every keepassxc-cli call carries, built once from the
# settings at the top of the file.
KP_AUTH=()

# What keepassxc-cli last wrote to stderr. Kept so a caller can tell "the
# database says no" from "the database never answered the question".
KP_ERR=""

# On macOS, keepassxc-cli ships inside the app bundle and isn't on PATH unless
# you installed via Homebrew. Find it either way. A failed lookup is reported
# by the exit status and nothing else: this runs inside $( ), where an `exit`
# would end the substitution alone and leave the caller running on an empty
# path.
kp_lookup() {
    if command -v keepassxc-cli >/dev/null 2>&1; then
        command -v keepassxc-cli
    elif [[ -x /Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli ]]; then
        printf '%s\n' /Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli
    else
        return 1
    fi
}

# Settle on the binary before a vault operation starts, so a missing one stops
# the run there instead of turning into a string of unexplained failures --
# and, worse, an empty vault reading that looks like "the key isn't in there".
# Turn the unlock settings into the options keepassxc-cli wants. Every
# subcommand takes the same three, so settling them once here is what puts a
# key-file or hardware-key database within reach of all of them. A key file
# that isn't there is caught now: handed on, it would come back as nothing
# more informative than a rejected password.
kp_auth_opts() {
    KP_AUTH=()
    if [[ -n $KP_KEYFILE ]]; then
        [[ -f $KP_KEYFILE ]] || die "no such KeePassXC key file: $KP_KEYFILE"
        KP_AUTH+=(--key-file "$KP_KEYFILE")
    fi
    if [[ -n $KP_YUBIKEY ]]; then
        KP_AUTH+=(--yubikey "$KP_YUBIKEY")
    fi
    if (( KP_NO_PW )); then
        KP_AUTH+=(--no-password)
    fi
}

kp_require() {
    if [[ -z $KP_CLI ]]; then
        KP_CLI=$(kp_lookup) \
            || die "keepassxc-cli not found (macOS: it lives in KeePassXC.app/Contents/MacOS)"
    fi
    kp_auth_opts
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
# password for each subcommand rather than prompting five times. The rest of
# what unlocks the database goes in right after the subcommand name, where
# every one of them accepts it. Its stderr is kept rather than discarded,
# because "not in the database" and "could not open the database" are the same
# exit status and only the text tells them apart. The prompts it writes there
# even when the answers arrive on stdin are not diagnostics, so both the
# unlock one and the one asking for an entry's own password are dropped.
kp_call() {   # stdin-text subcommand arg...
    local input=$1 sub=$2; shift 2
    local rc=0 err=""
    # bash 3.2, which is what stock macOS ships, reads an empty array as an
    # unset variable under `set -u`; this spelling expands to nothing at all
    # rather than stopping the run when there are no options to pass.
    err=$(printf '%s\n' "$input" | "$KP_CLI" "$sub" ${KP_AUTH[@]+"${KP_AUTH[@]}"} "$@" 2>&1 >/dev/null) || rc=$?
    KP_ERR=$(printf '%s\n' "$err" | sed -e 's/^Enter password to unlock .*: //' \
                                        -e 's/^Enter [a-z ]*password for[^:]*: //' -e '/^$/d')
    return "$rc"
}

run_kp() {   # subcommand arg...
    kp_call "$KP_PW" "$@"
}

# `add -p` and `edit -p` ask for one more secret -- the password to store in
# the entry itself -- and read it from the line after the database password.
run_kp_entry_pw() {   # entry-password subcommand arg...
    local pw=$1; shift
    kp_call "$KP_PW"$'\n'"$pw" "$@"
}

# Stop, quoting keepassxc rather than guessing. Guessing is how an unreadable
# database gets reported as a key that was never stored.
kp_die() {   # context
    die "$1${KP_ERR:+: $KP_ERR}"
}

# Whether the last failure means the thing asked for simply isn't in there.
# Anything else -- a wrong password, an unreadable file, a database that isn't
# one -- leaves the question unanswered and must never read as absence.
kp_absent() {
    [[ $KP_ERR == *'Could not find'* ]]
}

# Ask for the database password and prove it opens the database before any
# command acts on what the database appears to say. An unchecked password is
# indistinguishable from an empty vault, and an empty vault is what makes
# `drop` offer to delete the last copy of a key.
kp_password() {   # db
    local db=$1 tries=1 i

    # A database with no password of its own has nothing to ask for: the key
    # file or the hardware key is the whole credential. It still has to be
    # proved, for the same reason a password does.
    if (( KP_NO_PW )); then
        KP_PW=""
        if run_kp db-info "$db"; then return 0; fi
        kp_die "could not open $db"
    fi

    # A password waiting in a file is the only way a run with nobody watching
    # it can open the database. A wrong one there is worth naming the file
    # over, since there is no one to ask again.
    if [[ -n $KP_PW_FILE ]]; then
        [[ -f $KP_PW_FILE ]] || die "no such KeePassXC password file: $KP_PW_FILE"
        KP_PW=$(head -n 1 "$KP_PW_FILE")
        if run_kp db-info "$db"; then return 0; fi
        KP_PW=""
        if [[ $KP_ERR == *'Invalid credentials'* ]]; then
            die "wrong password for $db (read from $KP_PW_FILE)"
        fi
        kp_die "could not open $db"
    fi
    [[ -t 0 ]] && tries=3   # answers arriving down a pipe get a single attempt

    for (( i = 1; i <= tries; i++ )); do
        read -rsp "KeePassXC database password: " KP_PW || die "no password given"
        echo   # -s ate the newline
        if run_kp db-info "$db"; then
            return 0
        fi
        KP_PW=""
        if [[ $KP_ERR == *'Invalid credentials'* ]]; then
            if ((i < tries)); then
                info "wrong password for $db -- try again"
                continue
            fi
            die "wrong password for $db"
        fi
        kp_die "could not open $db"
    done
}

# The two lookups below answer in three ways, not two:
#   0  the database has it
#   1  the database doesn't have it
#   2  the database could not be read; KP_ERR says why
# Callers must keep 1 and 2 apart: only 1 means the key really isn't stored.
kp_entry_exists() {   # db entry
    if run_kp show "$1" "$2"; then return 0; fi
    if kp_absent; then return 1; fi
    return 2
}

kp_attachment_export() {   # db entry attachment dest
    if run_kp attachment-export "$1" "$2" "$3" "$4"; then return 0; fi
    if kp_absent; then return 1; fi
    return 2
}

# SHA256 fingerprint only (no comment/bit-count noise), so a match is a real
# match. Works on a private key without its passphrase.
key_fingerprint() {   # file -> "SHA256:..."  (prints nothing on failure)
    ssh-keygen -lf "$1" 2>/dev/null | awk '{print $2}' || true
}

# What decrypts a key: nothing at all, or a passphrase only the user knows.
# KeePassXC's agent takes that passphrase from the entry's Password field, so
# an entry holding the wrong one stores a key it can never serve -- and the
# only sign of it is a key quietly missing from the agent, hours later. The
# answer is proved against the key itself before it goes near the vault.
key_passphrase() {   # key -> sets KEY_PASS
    local key=$1 name tries=1 i
    name=$(basename "$key")
    KEY_PASS=""
    if ssh-keygen -y -P "" -f "$key" >/dev/null 2>&1; then return 0; fi

    [[ -t 0 ]] && tries=3   # answers arriving down a pipe get a single attempt
    for (( i = 1; i <= tries; i++ )); do
        read -rsp "passphrase for $name: " KEY_PASS || die "no passphrase given for $name"
        echo   # -s ate the newline
        if ssh-keygen -y -P "$KEY_PASS" -f "$key" >/dev/null 2>&1; then return 0; fi
        KEY_PASS=""
        if ((i < tries)); then
            info "that passphrase does not decrypt $name -- try again"
        fi
    done
    die "wrong passphrase for $name"
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
    local name=$1 db=$2 exists=${3:-0}
    local key; key=$(keyfile "$name")
    local entry="$KP_GROUP/$name"
    local base; base=$(basename "$key")

    [[ -f $key ]] || die "no private key on disk for '$name' (already exported?)"

    local pub="$key.pub"
    # Asked for up front, so that a key whose passphrase nobody can produce is
    # refused outright rather than half-written into the database.
    key_passphrase "$key"

    # The public half goes back to disk, not just into the vault: once the
    # private key is dropped, that file is what ssh is told to offer, and a
    # host whose .pub went missing would otherwise be left unusable with
    # nothing local to rebuild it from.
    if [[ ! -f $pub ]]; then
        info "no public key on disk for '$name'; rebuilding $pub from the private key"
        write_pub "$key" "$KEY_PASS"
    fi

    # Whether the entry is already there was settled by the caller's one
    # lookup, so only a genuinely new entry costs an `add`. Asking `add`
    # itself would answer nothing: it reports a duplicate and an unwritable
    # database with the same "could not create entry".
    #
    # Either way -p writes the key's passphrase into the entry's Password
    # field, which is where KeePassXC looks when it loads the key on unlock.
    # A key with no passphrase empties the field for the same reason: what is
    # left over from a previous key is not the answer for this one.
    if ((exists)); then
        info "entry '$entry' exists, updating attachments"
        run_kp_entry_pw "$KEY_PASS" edit -p "$db" "$entry" \
            || kp_die "could not set the password of '$entry'"
    else
        run_kp_entry_pw "$KEY_PASS" add -p "$db" "$entry" --url "ssh://$name" \
            || kp_die "could not create entry '$entry'"
    fi

    local tmp; tmp=$(mktemp "${TMPDIR:-/tmp}/skm.XXXXXX")   # BSD mktemp needs a template
    keeagent_xml "$base" > "$tmp"

    # -f replaces an attachment that is already stored, which is what updating
    # an existing entry needs; on a fresh entry it makes no difference. Every
    # unlock costs a run of the database's key derivation, so the three
    # imports below are the whole cost of writing a key.
    run_kp attachment-import -f "$db" "$entry" "$base"             "$key" \
        || kp_die "could not store '$base' in '$entry'"
    run_kp attachment-import -f "$db" "$entry" "$base.pub"         "$pub" \
        || kp_die "could not store '$base.pub' in '$entry'"
    run_kp attachment-import -f "$db" "$entry" "KeeAgent.settings" "$tmp" \
        || kp_die "could not store 'KeeAgent.settings' in '$entry'"
    rm -f "$tmp"

    if [[ -n $KEY_PASS ]]; then
        info "exported $name -> $entry (private + public key, passphrase in Password)"
    else
        info "exported $name -> $entry (private + public key)"
    fi
    KEY_PASS=""
}

# The reasons a run stepped over a host, gathered into one phrase for the count
# at the end: "2 already in KeePassXC, 1 with no private key on disk". Empty
# when nothing was skipped.
skip_note() {   # already-stored-count no-key-count
    local note=""
    if (($1 > 0)); then note="$1 already in KeePassXC"; fi
    if (($2 > 0)); then note="${note:+$note, }$2 with no private key on disk"; fi
    printf '%s\n' "$note"
}

cmd_export() {
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

    local all=0 names=()
    if [[ $what == --all ]]; then
        all=1
        shopt -s nullglob
        for f in "$CONF_DIR"/*.conf; do names+=("$(basename "$f" .conf)"); done
        [[ ${#names[@]} -gt 0 ]] || die "nothing managed to export"
    else
        require_host "$what"; names=("$what")
    fi

    kp_require

    # A run over every host is expected to meet hosts that are already dealt
    # with: one whose private key was moved into the database has nothing left
    # on disk to store. Stepping over it, rather than stopping, is what lets
    # the hosts after it have their turn. Asked for by name it stays an error,
    # because then it is the one thing that was asked for.
    local n skipped_nokey=0 skipped_stored=0
    if ((all)); then
        local left=()
        for n in "${names[@]}"; do
            if [[ -f $(keyfile "$n") ]]; then
                left+=("$n")
            else
                info "skipping $n (no private key on disk)"
                ((++skipped_nokey))
            fi
        done
        names=("${left[@]}")
        [[ ${#names[@]} -gt 0 ]] || die "nothing left to export ($(skip_note 0 $skipped_nokey))"
    fi

    kp_password "$db"

    # One lookup per name, before anything is written: it says which entries a
    # plain export would overwrite, and it saves every export the `add` that a
    # name already in the database doesn't need. Over every host, an entry that
    # is already there is left alone unless --force asks for it to be rewritten
    # -- otherwise the second run of --all could never get past the first key
    # the first run stored.
    local rc todo=() stored=()
    for n in "${names[@]}"; do
        rc=0
        kp_entry_exists "$db" "$KP_GROUP/$n" || rc=$?
        case $rc in
            0)  if ((force)); then
                    todo+=("$n"); stored+=(1)
                elif ((all)); then
                    info "skipping $n (already in KeePassXC; --force to overwrite)"
                    ((++skipped_stored))
                else
                    die "already in KeePassXC: $n  (re-run with --force to overwrite)"
                fi ;;
            1)  todo+=("$n"); stored+=(0) ;;
            *)  kp_die "could not read $db" ;;
        esac
    done
    [[ ${#todo[@]} -gt 0 ]] || \
        die "nothing left to export ($(skip_note $skipped_stored $skipped_nokey))"

    # The group holds every exported key, so it is created once for the run
    # rather than once per key. From the second run on "already exists" is the
    # expected answer and the only tolerable failure.
    run_kp mkdir "$db" "$KP_GROUP" || [[ $KP_ERR == *'already exists'* ]] \
        || kp_die "could not create group '$KP_GROUP' in $db"

    local i
    for i in "${!todo[@]}"; do export_one "${todo[i]}" "$db" "${stored[i]}"; done
    KP_PW=""

    # Reached only with at least one key written, so the advice below always
    # has something to be about.
    echo
    if ((all)); then
        local note; note=$(skip_note $skipped_stored $skipped_nokey)
        info "exported ${#todo[@]}, skipped $((skipped_stored + skipped_nokey))${note:+ ($note)}"
    fi
    info "next: in KeePassXC, enable Tools > Settings > SSH Agent, then re-unlock the database."
    info "each entry's Password field holds that key's passphrase, which is what decrypts it."
    info "verify with 'ssh-add -l', then run 'skm agent <name>' and delete the on-disk key."
}

# Delete the on-disk private key so it lives only in KeePassXC. Deliberately
# single-key (no --all): this is meant to require real consideration each time.
cmd_drop() {
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

    kp_require
    kp_password "$db"

    local have; have=$(key_fingerprint "$key")
    [[ -n $have ]] || die "could not read local key: $key"

    local tmpdir; tmpdir=$(ramtemp)
    local vault_key="$tmpdir/$base" vault_fp="" rc=0
    kp_attachment_export "$db" "$entry" "$base" "$vault_key" || rc=$?
    case $rc in
        0) vault_fp=$(key_fingerprint "$vault_key") ;;
        1) ;;   # the key really isn't stored under this entry
        *) rm -rf "$tmpdir"; kp_die "could not read $db" ;;
    esac
    rm -rf "$tmpdir"

    echo
    info "local:  $have"
    info "vault:  ${vault_fp:-(not found in KeePassXC)}"

    local ans=""
    if [[ -n $vault_fp && $vault_fp == "$have" ]]; then
        info "fingerprints match -- reversible via 'skm restore $name $db'"
        read -rp "delete local private key for '$name'? [y/N] " ans || ans=""
        [[ ${ans,,} == y* ]] || { info "aborted"; return; }
    else
        if [[ -z $vault_fp ]]; then
            info "DANGER: '$name' is not in KeePassXC under $entry -- deleting now loses the only copy"
        else
            info "DANGER: fingerprints differ -- the vault copy is NOT this key"
        fi
        ((force)) || die "refusing to delete (re-run with --force if you're sure)"
        read -rp "this cannot be undone -- really delete '$key'? [y/N] " ans || ans=""
        [[ ${ans,,} == y* ]] || { info "aborted"; return; }
    fi

    # Before the private key goes, not after: rebuilding the public half needs
    # it, and agent mode is only usable with that file in place.
    ensure_pub "$name"

    secure_rm "$key"
    retarget "$name" agent

    echo
    info "'$name' now resolves its key via the ssh-agent; verify with 'ssh-add -l'"
}

# Inverse of drop: pull the private key back out of KeePassXC onto disk, in
# the layout skm expects, and flip the config back to on-disk.
cmd_restore() {
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

    kp_require
    kp_password "$db"

    local rc=0
    kp_attachment_export "$db" "$entry" "$base" "$key" || rc=$?
    case $rc in
        0) ;;
        1) die "no key attachment for '$name' in $entry" ;;
        *) kp_die "could not read $db" ;;
    esac
    chmod 600 "$key"

    rc=0
    kp_attachment_export "$db" "$entry" "$base.pub" "$key.pub" || rc=$?
    case $rc in
        0) ;;
        1) info "no public key attachment in $entry"
           ensure_pub "$name" ;;
        *) kp_die "could not read $db" ;;
    esac

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
    require_name "$label" "scope label"

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

    local n key tmp base_dir rc unlocked=0
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
            #
            # The database is opened the once, however many keys come out of
            # it, and by the same route as everywhere else: whatever unlocks
            # it -- key file, hardware key, password -- works here too.
            if ((! unlocked)); then
                kp_require
                kp_password "$db"
                unlocked=1
            fi
            if   [[ -d ${XDG_RUNTIME_DIR:-} ]]; then base_dir=$XDG_RUNTIME_DIR
            elif [[ -d /dev/shm ]];             then base_dir=/dev/shm
            else                                     base_dir=${TMPDIR:-/tmp}
            fi
            tmp=$(mktemp -d "$base_dir/skm.XXXXXX")
            chmod 700 "$tmp"
            rc=0
            kp_attachment_export "$db" "$KP_GROUP/$n" \
                "$(basename "$key")" "$tmp/$n" || rc=$?
            case $rc in
                0) ;;
                1) rm -rf "$tmp"; die "no key attachment for '$n' in $KP_GROUP/$n" ;;
                *) rm -rf "$tmp"; kp_die "could not read $db" ;;
            esac
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
    require_name "$label" "scope label"
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

# The command summary at the top of this file is the help text; printing it
# from there keeps the two from drifting apart.
usage() { sed -n '3,33p' "$0" | sed 's/^# \?//'; }

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
    help|-h|--help) usage ;;
    # A mistyped command must not look like a successful run: scripts that
    # check the exit status would otherwise sail past it.
    *)      printf "skm: unknown command '%s'\n" "$1" >&2; usage >&2; exit 2 ;;
esac
