#!/usr/bin/env zsh
# skm — a small per-host SSH key manager.  (zsh port)
#
# Each host gets:  its own key, its own ~/.ssh/config.d/<name>.conf
# Optionally:      the private key stored in KeePassXC and removed from disk.
#
#   skm add <name> <user@host> [port]   generate key + config entry
#   skm provision <name> <user@host> [port] <db.kdbx>
#                                      add + export + drop, in one go; re-run
#                                      it to finish a run that stopped early
#   skm alias <name> <pattern>...       let more names/IPs/globs use this key
#   skm list                            show managed hosts
#   skm status [name|--all] [db.kdbx]   show where each key's private/public half lives
#   skm show <name>                     print the public key
#   skm copy <name>                     ssh-copy-id the key to the server
#   skm rm <name> [db.kdbx]             delete key + config (+ vault entry)
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

# Must be POSIX — it has to survive being run by sh/bash in order to complain
# about being run by sh/bash.
[ -n "${ZSH_VERSION:-}" ] || { echo "skm: must be run with zsh (try: zsh skm ...)" >&2; exit 1; }

# emulate -L zsh gives us zsh's native semantics regardless of what the user has
# in ~/.zshrc — notably NO word splitting on unquoted parameters, so "$var" and
# $var behave the same and there is no IFS minefield.
emulate -L zsh
setopt err_exit no_unset pipe_fail

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

die()  { print -u2 "skm: $*"; exit 1 }
warn() { print -u2 "skm: $*" }
info() { print "  $*" }

# ---------------------------------------------------------------- bootstrap

# ssh resolves a relative Include path against ~/.ssh rather than against the
# directory the config file lives in, so only the default layout can use the
# short relative form; anywhere else has to be spelled out in full. The quotes
# hold a path containing spaces together as one argument.
include_arg() {
    if [[ $SSH_DIR == "$HOME/.ssh" ]]; then
        print -r -- 'config.d/*.conf'
    else
        print -r -- "\"$CONF_DIR/*.conf\""
    fi
}

# Every spelling of the fragment glob that reaches the managed directory. ssh
# resolves a relative Include against ~/.ssh, so the short forms only mean that
# directory when it is where skm keeps its files. A glob without the .conf
# suffix picks the fragments up as well, so it counts as already there.
include_spellings() {
    print -r -- "$CONF_DIR/*.conf"
    print -r -- "$CONF_DIR/*"
    if [[ $SSH_DIR == "$HOME/.ssh" ]]; then
        print -r -- 'config.d/*.conf'
        print -r -- 'config.d/*'
        # Literal strings to compare against, not paths to resolve: this is
        # simply how a hand-written ssh config usually spells the same glob.
        print -r -- '~/.ssh/config.d/*.conf'
        print -r -- '~/.ssh/config.d/*'
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
    [[ -f $CONFIG ]] || { print -r -- "absent 0 0"; return }
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
    [[ -f $CONFIG ]] || { : > "$CONFIG"; chmod 600 "$CONFIG" }

    local kind inc blk text
    read -r kind inc blk text <<< "$(include_state)"

    if [[ $kind == absent ]]; then
        # The new line goes at the very top so the fragments are read before any
        # block that might already have set the same options.
        local arg=$(include_arg)
        print -r -- "Include $arg" > "$CONFIG.tmp"
        print >> "$CONFIG.tmp"
        cat "$CONFIG" >> "$CONFIG.tmp"
        mv "$CONFIG.tmp" "$CONFIG"
        chmod 600 "$CONFIG"
        info "added 'Include $arg' to $CONFIG"
    elif [[ $kind == shadowed ]]; then
        warn "$CONFIG pulls in $CONF_DIR on line $inc, below '$text' on line $blk"
        warn "ssh keeps the first value it sees for each setting, so what skm writes there may be ignored; move the Include line to the top of the file"
    fi
}

keyfile()  { print -r -- "$SSH_DIR/id_ed25519_$1" }
conffile() { print -r -- "$CONF_DIR/$1.conf" }

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
    { [[ $port =~ '^[1-9][0-9]*$' ]] && (( port <= 65535 )) } || die \
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
    local key=$(keyfile "$name")
    local conf=$(conffile "$name")

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

    print
    info "created $conf"
    info "public key:"
    print
    cat "$key.pub"
    print
    info "install it with:  skm copy $name"
}

# The ideal end state for a new key: config + public key on disk, private key
# only in KeePassXC. This chains the three steps that get there (add, export,
# drop) and, since drop's deletion is irreversible if the agent isn't actually
# serving the key yet, pauses to verify the key is loaded before deleting it.
#
# Every step is skipped when its work is already done, so the way to recover
# from a run that stopped half way -- a mistyped password, a database that
# would not open, a deletion left unconfirmed -- is to run the same command
# again. What is already on disk and in the database decides where it resumes.
cmd_provision() {
    local usage="usage: skm provision <name> <user@host> [port] <database.kdbx>"
    local name=${1:-} dest=${2:-} port=22 db=""
    case $# in
        3) db=${3:-} ;;
        4) port=${3:-}; db=${4:-} ;;
        *) die "$usage" ;;
    esac
    [[ -n $name && -n $dest && -n $db ]] || die "$usage"
    [[ $dest == *@* ]] || die "destination must be user@host, e.g. git@github.com"
    require_name "$name"
    require_port "$port"
    [[ -f $db ]] || die "no such database: $db"

    local key=$(keyfile "$name")
    local conf=$(conffile "$name")
    local entry="$KP_GROUP/$name"

    # The database is opened before a key is generated, because a run that
    # cannot reach the vault has nowhere to put one: a missing keepassxc-cli
    # or a wrong password stops it here, with nothing on disk to explain. It
    # is opened once; the steps below reuse that password rather than asking
    # for it again.
    kp_require
    warn_db_open "$db"
    kp_password "$db"

    local rc=0 stored=0
    kp_entry_exists "$db" "$entry" || rc=$?
    case $rc in
        0) stored=1 ;;
        1) stored=0 ;;
        *) kp_die "could not read $db" ;;
    esac

    if [[ -e $conf ]]; then
        # Resuming means continuing with the host that is already there, so a
        # destination that isn't the one it points at is a different host
        # wearing the same name -- and picking one of the two silently is how
        # a key ends up provisioned for somewhere nobody asked about.
        local have=$(awk '$1=="User"{u=$2} $1=="HostName"{h=$2} $1=="Port"{p=$2} \
                          END{printf "%s@%s:%s", u, h, (p==""?"22":p)}' "$conf")
        [[ $have == "$dest:$port" ]] || \
            die "'$name' is already managed and points at $have, not $dest:$port"
        info "'$name' is already managed; carrying on from there"
    elif [[ -e $key ]]; then
        die "there is already a key at $key but no config for '$name' -- move that key aside, or provision under another name"
    elif (( stored )); then
        die "'$name' is already in KeePassXC under '$entry', with nothing for it on disk -- 'skm restore $name $db' brings it back, or provision under another name"
    else
        cmd_add "$name" "$dest" "$port"
    fi

    local fp=""
    if [[ ! -f $key ]]; then
        # Nothing left to export or delete: the private key is where this
        # command was going to put it. All that can be missing is the config
        # pointing at the public half, which is what ssh needs to ask the
        # agent for the private one.
        info "the private key for '$name' is already in '$entry' and off disk"
        if [[ $(identity_of "$conf") != *.pub ]]; then
            retarget "$name" agent
            info "$name now resolves its key via the ssh-agent"
        fi
        print
        info "provisioned '$name': config + public key on disk, private key in KeePassXC only"
        return
    fi

    fp=$(key_fingerprint "$key")
    [[ -n $fp ]] || die "could not read local key: $key"

    if (( stored )); then
        rc=0
        vault_fingerprint "$db" "$name" || rc=$?
        (( rc <= 1 )) || kp_die "could not read $db"
        if [[ $VAULT_FP == "$fp" ]]; then
            info "'$name' is already stored in '$entry'"
        else
            print
            info "local:  $fp"
            info "vault:  ${VAULT_FP:-(nothing attached to that entry)}"
            die "'$name' is already in KeePassXC under a different key -- 'skm export --force $name $db' replaces it"
        fi
    else
        cmd_export "$name" "$db"
    fi

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

    # drop points the config at the public key itself, once the private key is
    # gone. Declining its confirmation therefore leaves an ordinary on-disk
    # host, which works as it stands -- and saying so is the whole report,
    # since the key this command set out to move is still sitting on disk.
    cmd_drop "$name" "$db"

    print
    if [[ -f $key ]]; then
        info "'$name' is stored in KeePassXC, but its private key is still on disk and the config still reads it from there"
        info "finish with:  skm drop $name $db"
    else
        info "provisioned '$name': config + public key on disk, private key in KeePassXC only"
    fi
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
        require_pattern "$p"
        [[ " $existing " == *" $p "* ]] || add+=("$p")
    done
    if (( ${#add} == 0 )); then
        info "already matched by: Host $existing"
        return
    fi

    replace_conf_line "$conf" Host "Host $existing ${add[*]}"
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
        id=$(identity_of "$f")
        agent=""
        [[ $id == *.pub ]] && agent="  (agent)"
        print -f '%-14s %-28s %s%s\n' "$name" "$target" "${id:t}" "$agent"
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
        print -r -- 'UNKNOWN: the vault could not be read'
        return
    fi

    if [[ $fp_status == MISMATCH ]]; then
        print -r -- 'DANGER: vault copy is a different key from the on-disk copy'
        return
    fi

    if [[ $mode == ondisk ]]; then
        if [[ $priv_disk == yes ]]; then
            local s="OK (on disk)"
            case $priv_vault in
                yes) s+=", vault backup present" ;;
                no)  s+=", not in vault" ;;
            esac
            print -r -- "$s"
        else
            local s="BROKEN: IdentityFile points at the private key, but none is on disk"
            [[ $priv_vault == yes ]] && s+=" (in vault -- try: skm restore)"
            print -r -- "$s"
        fi
        return
    fi

    # agent mode
    if [[ $priv_disk == yes ]]; then
        case $priv_vault in
            yes) print -r -- 'redundant: private key on disk AND in vault (consider: skm drop)' ;;
            no)  print -r -- 'WARNING: agent mode but private key only on disk, not in vault' ;;
            *)   print -r -- 'WARNING: agent mode but private key still on disk (pass a db.kdbx to check the vault)' ;;
        esac
        return
    fi

    case $priv_vault in
        yes)
            case $agent_state in
                serving)       print -r -- 'OK (vault-only, agent serving)' ;;
                'not serving') print -r -- 'OK (vault-only) -- agent NOT serving (unlock KeePassXC)' ;;
                *)             print -r -- 'OK (vault-only, agent status unknown)' ;;
            esac
            ;;
        no)  print -r -- 'LOST: no private key on disk or in vault' ;;
        *)   print -r -- 'OK (assumed vault-only; pass a db.kdbx to verify)' ;;
    esac
}

# Whether the fragments skm writes are reachable at all, and whether anything
# ahead of them in $CONFIG has already had its say. Printed once per run, since
# it describes the file rather than any one host.
include_report() {
    local kind inc blk text
    read -r kind inc blk text <<< "$(include_state)"

    local note
    case $kind in
        absent)   note="missing - nothing in $CONF_DIR is read" ;;
        top)      note="line $inc, ahead of any Host or Match block" ;;
        shadowed) note="line $inc, below '$text' on line $blk - settings in $CONF_DIR may be ignored" ;;
    esac

    print -r -- "$CONFIG"
    print -f '  %-13s %s\n' "Include" "$note"
    print
}

status_one() {
    local name=$1 db=$2
    local conf=$(conffile "$name")
    local key=$(keyfile "$name")
    local pub="$key.pub"

    local target=$(awk '$1=="User"{u=$2} $1=="HostName"{h=$2} $1=="Port"{p=$2} \
                        END{printf "%s@%s%s", u, h, (p=="22"?"":":" p)}' "$conf")
    local id=$(identity_of "$conf")
    local mode="ondisk"; [[ $id == *.pub ]] && mode="agent"

    local priv_disk="no" pub_disk="no"
    [[ -f $key ]] && priv_disk="yes"
    [[ -f $pub ]] && pub_disk="yes"

    local local_fp=""
    [[ $priv_disk == yes ]] && local_fp=$(key_fingerprint "$key")

    local priv_vault="?" pub_vault="?" vault_fp="" fp_status="n/a (no db)" vault_err=""
    if [[ -n $db ]]; then
        local entry="$KP_GROUP/$name" base=${key:t}
        ramtemp; local tmpdir=$SKM_TMPSUB
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
        wipe_tmp "$tmpdir"

        if [[ $priv_vault == error ]]; then
            fp_status="n/a (vault could not be read)"
        elif [[ -n $local_fp && -n $vault_fp ]]; then
            [[ $local_fp == $vault_fp ]] && fp_status="match" || fp_status="MISMATCH"
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

    local verdict=$(status_verdict "$mode" "$priv_disk" "$priv_vault" "$fp_status" "$agent_state")

    print -r -- "$name"
    print -f '  %-13s %s\n' "target" "$target"
    local agent_note=""; [[ $mode == agent ]] && agent_note="   (agent)"
    print -f '  %-13s %s%s\n' "IdentityFile" "${id:t}" "$agent_note"
    print -f '  %-13s disk: %-4s vault: %s\n' "private" "$priv_disk" "$priv_vault"
    print -f '  %-13s disk: %-4s vault: %s\n' "public"  "$pub_disk"  "$pub_vault"
    [[ -n $vault_err ]] && print -f '  %-13s %s\n' "vault error" "$vault_err"
    [[ -n $db ]] && print -f '  %-13s %s\n' "fingerprint" "$fp_status"
    print -f '  %-13s %s\n' "agent"  "$agent_state"
    print -f '  %-13s %s\n' "status" "$verdict"
    print
}

cmd_status() {
    local a db=""
    local -a args=()
    for a in "$@"; do
        if [[ $a == *.kdbx ]]; then
            db=$a
        else
            args+=("$a")
        fi
    done
    [[ -z $db || -f $db ]] || die "no such database: $db"

    local what=${args[1]:-}
    local -a names=()
    if [[ -z $what || $what == --all ]]; then
        [[ -d $CONF_DIR ]] || die "nothing managed yet"
        local f
        for f in $CONF_DIR/*.conf(N); do names+=("${f:t:r}"); done
        (( ${#names} > 0 )) || die "nothing managed yet"
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

# Which running scoped agents are holding a given key. An agent keeps its own
# copy of everything loaded into it, so a key taken off disk stays usable
# through every scope that already has it, for as long as that agent lives.
scopes_holding() {   # fingerprint -> sets SCOPE_HOLDERS
    SCOPE_HOLDERS=()
    local fp=$1 s
    [[ -n $fp && -d $SOCK_DIR ]] || return 0
    for s in $SOCK_DIR/*.sock(N); do
        if SSH_AUTH_SOCK=$s ssh-add -l 2>/dev/null | grep -qF -- "$fp"; then
            SCOPE_HOLDERS+=("${s:t:r}")
        fi
    done
    return 0
}

# Take a host apart: the key, its public half, the config fragment, and -- with
# a database named -- the vault entry as well. Everything the key was reachable
# through is closed on the way out, since a key nobody can delete is only half
# removed: a live multiplexed connection, a scoped agent, an entry that puts the
# key back in the agent at the next unlock.
cmd_rm() {
    local usage="usage: skm rm <name> [database.kdbx]"
    local name=${1:-} db=${2:-}
    require_host "$name" "$usage"
    [[ -z $db || -f $db ]] || die "no such database: $db"

    local key=$(keyfile "$name")
    local entry="$KP_GROUP/$name"

    # The fingerprint is read while the key is still here, because afterwards
    # there is nothing left to tell which agent holds this key rather than some
    # other. In agent mode the private half has already gone and the public one
    # answers the same question.
    local fp=""
    if   [[ -f $key ]];     then fp=$(key_fingerprint "$key")
    elif [[ -f $key.pub ]]; then fp=$(key_fingerprint "$key.pub")
    fi

    # Where the vault stands is worth knowing before the question is asked:
    # with the entry there this is a deletion of the local copy, without it
    # this is the last copy of the key.
    local have_entry=0 rc=0 shown=0
    if [[ -n $db ]]; then
        kp_require
        kp_password "$db"
        kp_entry_exists "$db" "$entry" || rc=$?
        case $rc in
            0) have_entry=1 ;;
            1) ;;
            *) kp_die "could not read $db" ;;
        esac
        print
        shown=1
        if (( have_entry )); then
            info "vault:  '$entry' is in $db"
        else
            info "vault:  no entry '$entry' in $db"
        fi
    fi

    scopes_holding "$fp"
    if (( ${#SCOPE_HOLDERS} > 0 )); then
        print
        shown=1
        info "still loaded in scoped agent(s): ${(j:, :)SCOPE_HOLDERS}"
        info "each keeps serving this key until it is killed: skm unscope <label>"
    fi

    # zsh's read takes the prompt as name?prompt. Do NOT use bash's `read -rp`:
    # in zsh, -p means "read from the coprocess" and silently reads nothing.
    # The `||` matters: under err_exit, an EOF (piped/non-interactive) makes
    # read return non-zero, which would otherwise kill the script mid-way.
    local ans=""
    if (( shown )); then print; fi
    read -r "ans?delete key and config for '$name'? [y/N] " || ans=""
    case $ans in
        [yY]*) ;;
        *) info "aborted"; return ;;
    esac

    # Asked separately, and only when there is something to delete: removing
    # the host's files and removing the stored key are two different decisions,
    # and the second one is the irreversible half.
    local drop_entry=0
    if (( have_entry )); then
        ans=""
        read -r "ans?also delete the KeePassXC entry '$entry'? [y/N] " || ans=""
        case $ans in
            [yY]*) drop_entry=1 ;;
        esac
    fi

    # Closed while the config still names it: ssh derives the socket path from
    # the fragment, so once that is gone it can no longer be asked to shut the
    # master down, and the authenticated connection would stay usable for the
    # rest of its ControlPersist time.
    ssh -O exit "$name" >/dev/null 2>&1 || true

    if (( drop_entry )); then
        # KeePassXC moves a removed entry to the recycle bin if the database
        # has one, so this is recoverable there until the bin is emptied.
        run_kp rm "$db" "$entry" || kp_die "could not remove '$entry' from $db"
        info "removed entry '$entry'"
    fi

    # The private key gets the same treatment it would get from `drop`: there
    # is no sense in overwriting a key when it moves into the vault but not
    # when it is thrown away. Neither the public half nor the config is secret.
    if [[ -f $key ]]; then secure_rm "$key"; fi
    rm -f "$key.pub" "$(conffile "$name")"
    info "removed $name"

    if [[ -n $db ]] && (( have_entry )) && (( ! drop_entry )); then
        info "note: '$entry' was kept; while it is there, unlocking $db loads that key into the agent again"
    elif [[ -z $db ]]; then
        info "note: the KeePassXC entry '$entry', if there is one, was left alone; while it is there, unlocking the database loads that key into the agent again"
        info "to have it removed as well: skm rm $name <database.kdbx>"
    fi
}

# The public key is what agent mode points ssh at, so it has to be on disk for
# the host to work at all. It is also derivable from the private key, so a
# missing one is repaired rather than reported whenever the private half is
# still there; once it is gone, nothing local can rebuild it and the vault is
# the only way back.
ensure_pub() {   # name -> a .pub on disk, or die trying
    local name=$1
    local key=$(keyfile "$name")
    if [[ -f $key.pub ]]; then return 0; fi
    [[ -f $key ]] || die "no public key on disk for '$name', and no private key to rebuild it from -- 'skm restore $name <database.kdbx>' brings both back"

    info "no public key on disk for '$name'; rebuilding $key.pub from the private key"
    key_passphrase "$key"
    write_pub "$key" "$KEY_PASS"
    KEY_PASS=""
}

# Derive the public half of a key and put it on disk. The write lands in a
# temp file first, beside the key rather than off in temporary space: moving
# it into place is then a rename within the one directory, which either
# happened or did not. A half-written .pub looks exactly like a good one to
# everything that checks for the file.
write_pub() {   # key passphrase
    local key=$1 pass=$2
    local tmp=$(mktemp "$key.pub.XXXXXX")
    ssh-keygen -y -P "$pass" -f "$key" > "$tmp" \
        || { rm -f "$tmp"; die "could not derive the public key from $key" }
    mv "$tmp" "$key.pub"
}

# Swap IdentityFile between the private key on disk and the .pub stub.
# With the .pub, ssh asks the agent (KeePassXC) for the matching private key —
# so the private key never has to exist on disk at all.
retarget() {
    local name=$1 to=$2
    local conf=$(conffile "$name")
    local key=$(keyfile "$name")
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
    if (( $+commands[shred] )); then            # zsh: $+commands[x] tests PATH
        info "once verified: shred -u $(keyfile "$name")"
    else
        info "once verified: rm -P $(keyfile "$name")"    # BSD/macOS
    fi
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
# KP_PW_DB names the database the held password was proved against, which is
# what lets a command that opens the same database a second time reuse it
# instead of asking again.
typeset -g KP_CLI=""
typeset -g KP_PW=""
typeset -g KP_PW_DB=""

# The passphrase of the key currently being exported, for as long as that
# takes. Empty for a key that has none.
typeset -g KEY_PASS=""

# The unlock options every keepassxc-cli call carries, built once from the
# settings at the top of the file.
typeset -ga KP_AUTH=()

# What keepassxc-cli last wrote to stderr. Kept so a caller can tell "the
# database says no" from "the database never answered the question".
typeset -g KP_ERR=""

# On macOS, keepassxc-cli ships inside the app bundle and isn't on PATH unless
# you installed via Homebrew. Find it either way. A failed lookup is reported
# by the exit status and nothing else: this runs inside $( ), where an `exit`
# would end the substitution alone and leave the caller running on an empty
# path.
kp_lookup() {
    if (( $+commands[keepassxc-cli] )); then
        print -r -- $commands[keepassxc-cli]
    elif [[ -x /Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli ]]; then
        print -r -- /Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli
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
    err=$(print -r -- "$input" | "$KP_CLI" "$sub" "${KP_AUTH[@]}" "$@" 2>&1 >/dev/null) || rc=$?
    kp_set_err "$err"
    return $rc
}

# What keepassxc-cli wrote to stderr, less the prompts it writes there even
# when the answers arrive on stdin: those are not diagnostics, and a caller
# quoting them back would be quoting its own question.
kp_set_err() {   # stderr-text
    KP_ERR=$(print -r -- "$1" | sed -e 's/^Enter password to unlock .*: //' \
                                    -e 's/^Enter [a-z ]*password for[^:]*: //' -e '/^$/d')
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

# KeePassXC leaves a lock file beside a database it has open. keepassxc-cli
# writes to the database regardless of that file, but the open GUI is holding
# its own copy of the database in memory, and saving that copy writes back
# everything it knew -- which is the database as it was before skm touched it.
# Versions differ over whether the lock file is hidden, so both spellings
# count.
warn_db_open() {   # db
    local db=$1 dir=${db:h} lock
    for lock in "$db.lock" "$dir/.${db:t}.lock"; do
        [[ -e $lock ]] || continue
        warn "$db looks open in KeePassXC ($lock)"
        warn "close or lock it there first, or its next save may put back the database as it was"
        return 0
    done
    return 0
}

# Ask for the database password and prove it opens the database before any
# command acts on what the database appears to say. An unchecked password is
# indistinguishable from an empty vault, and an empty vault is what makes
# `drop` offer to delete the last copy of a key.
kp_password() {   # db
    local db=$1 tries=1 i

    # Whatever opens this database was proved against it already, earlier in
    # the same run. A command chain that opens it twice -- exporting a key and
    # then deleting the on-disk copy -- asks its one question once.
    [[ -n $KP_PW_DB && $KP_PW_DB == $db ]] && return 0

    # A database with no password of its own has nothing to ask for: the key
    # file or the hardware key is the whole credential. It still has to be
    # proved, for the same reason a password does.
    if (( KP_NO_PW )); then
        KP_PW=""
        if run_kp db-info "$db"; then KP_PW_DB=$db; return 0; fi
        kp_die "could not open $db"
    fi

    # A password waiting in a file is the only way a run with nobody watching
    # it can open the database. A wrong one there is worth naming the file
    # over, since there is no one to ask again.
    if [[ -n $KP_PW_FILE ]]; then
        [[ -f $KP_PW_FILE ]] || die "no such KeePassXC password file: $KP_PW_FILE"
        KP_PW=$(head -n 1 "$KP_PW_FILE")
        if run_kp db-info "$db"; then KP_PW_DB=$db; return 0; fi
        KP_PW=""
        if [[ $KP_ERR == *'Invalid credentials'* ]]; then
            die "wrong password for $db (read from $KP_PW_FILE)"
        fi
        kp_die "could not open $db"
    fi
    [[ -t 0 ]] && tries=3   # answers arriving down a pipe get a single attempt

    for (( i = 1; i <= tries; i++ )); do
        read -rs "KP_PW?KeePassXC database password: " || die "no password given"
        print   # -s ate the newline
        if run_kp db-info "$db"; then
            KP_PW_DB=$db
            return 0
        fi
        KP_PW=""
        if [[ $KP_ERR == *'Invalid credentials'* ]]; then
            if (( i < tries )); then
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

# Whether this keepassxc-cli can write an attachment to its standard output.
# One that cannot has to be given a path to write the key to, which means the
# key exists as a file, however briefly. The answer is in --help, so asking
# costs no unlock, and it is asked once.
typeset -g KP_STDOUT=-1
kp_has_stdout() {
    if (( KP_STDOUT < 0 )); then
        local help=$("$KP_CLI" attachment-export --help 2>&1)
        if [[ $help == *--stdout* ]]; then KP_STDOUT=1; else KP_STDOUT=0; fi
    fi
    (( KP_STDOUT ))
}

# Hand a stored key straight to an agent: out of the database, down a pipe,
# into ssh-add, a file at no point. The two ends of the pipe are judged
# separately, because a database that would not open and an agent that turned
# the key down are different failures and only one of them is about the key.
#
#   0  loaded        1  no such attachment
#   2  database unreadable (KP_ERR says why)      3  ssh-add would not take it
kp_add_to_agent() {   # db entry attachment ssh-add-flag...
    setopt local_options no_err_exit
    local db=$1 entry=$2 att=$3; shift 3
    ensure_tmpdir
    local errf=$(mktemp "$SKM_TMPDIR/err.XXXXXX")

    print -r -- "$KP_PW" \
        | "$KP_CLI" attachment-export "${KP_AUTH[@]}" --stdout "$db" "$entry" "$att" 2>"$errf" \
        | ssh-add "$@" -
    local -a st=("${pipestatus[@]}")

    kp_set_err "$(cat "$errf")"
    rm -f "$errf"

    if (( st[2] != 0 )); then
        if kp_absent; then return 1; fi
        return 2
    fi
    (( st[3] == 0 )) || return 3
    return 0
}

# SHA256 fingerprint only (no comment/bit-count noise), so a match is a real
# match. Works on a private key without its passphrase.
key_fingerprint() {   # file -> "SHA256:..."  (prints nothing on failure)
    ssh-keygen -lf "$1" 2>/dev/null | awk '{print $2}' || true
}

# Which key an entry is actually holding, judged from the stored copy rather
# than from anything the entry says about itself. The copy is taken into the
# run's own temporary directory and wiped again before the answer is given.
# The answer lands in a variable because a caller reading it through $( )
# would run this -- and so create the temporary directory -- in a subshell,
# leaving the directory behind when that subshell ends.
#
#   0  VAULT_FP is the fingerprint      1  no key attached to that entry
#   2  the database could not be read; KP_ERR says why
typeset -g VAULT_FP=""
vault_fingerprint() {   # db name -> sets VAULT_FP
    local db=$1 name=$2 rc=0
    local base=$(keyfile "$name"); base=${base:t}
    VAULT_FP=""
    ramtemp
    kp_attachment_export "$db" "$KP_GROUP/$name" "$base" "$SKM_TMPSUB/$base" || rc=$?
    (( rc == 0 )) && VAULT_FP=$(key_fingerprint "$SKM_TMPSUB/$base")
    wipe_tmp "$SKM_TMPSUB"
    return $rc
}

# What decrypts a key: nothing at all, or a passphrase only the user knows.
# KeePassXC's agent takes that passphrase from the entry's Password field, so
# an entry holding the wrong one stores a key it can never serve -- and the
# only sign of it is a key quietly missing from the agent, hours later. The
# answer is proved against the key itself before it goes near the vault.
key_passphrase() {   # key -> sets KEY_PASS
    local key=$1 name=${key:t} tries=1 i
    KEY_PASS=""
    if ssh-keygen -y -P "" -f "$key" >/dev/null 2>&1; then return 0; fi

    [[ -t 0 ]] && tries=3   # answers arriving down a pipe get a single attempt
    for (( i = 1; i <= tries; i++ )); do
        read -rs "KEY_PASS?passphrase for $name: " || die "no passphrase given for $name"
        print   # -s ate the newline
        if ssh-keygen -y -P "$KEY_PASS" -f "$key" >/dev/null 2>&1; then return 0; fi
        KEY_PASS=""
        if (( i < tries )); then
            info "that passphrase does not decrypt $name -- try again"
        fi
    done
    die "wrong passphrase for $name"
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

# Everything this run takes out of the vault -- a private key on its way into
# an agent, a public half on its way back to disk -- is written below one
# directory, made the first time something needs it. Where the platform offers
# memory to write to, that is where it goes: a copy that was never on a medium
# cannot be read off one afterwards. Linux has two such places; macOS has
# none, so there it falls back to ordinary temporary space.
typeset -g SKM_TMPDIR=""
typeset -g SKM_TMP_RAM=0
typeset -g SKM_TMPSUB=""

# The directory is left in $SKM_TMPDIR rather than printed: printed, every
# caller would reach for it through $( ), the assignment would happen in the
# subshell that runs it, and the run itself would end up knowing nothing about
# a directory full of keys.
ensure_tmpdir() {   # -> $SKM_TMPDIR, a 0700 directory made on first use
    [[ -n $SKM_TMPDIR ]] && return 0
    local base
    if   [[ -d ${XDG_RUNTIME_DIR:-} ]]; then base=$XDG_RUNTIME_DIR; SKM_TMP_RAM=1
    elif [[ -d /dev/shm ]];             then base=/dev/shm;         SKM_TMP_RAM=1
    else                                     base=${TMPDIR:-/tmp};  SKM_TMP_RAM=0
    fi
    SKM_TMPDIR=$(mktemp -d "$base/skm.XXXXXX")
    chmod 700 "$SKM_TMPDIR"
}

# Unlinking a file is the whole of deleting it only where the file was never
# on a disk. Anywhere else its bytes stay on the medium until something writes
# over them, so off memory each one goes through the overwriting delete first.
wipe_tmp() {   # dir
    local d=${1:-} f
    [[ -n $d && -d $d ]] || return 0
    if (( ! SKM_TMP_RAM )); then
        for f in "$d"/**/*(.N); do secure_rm "$f"; done
    fi
    rm -rf "$d"
}

# A scope is built in two moves -- start the agent, then fill it -- and until
# the second one finishes there is an agent up holding part of a set of keys.
# The label sits here between the two, so that a run which ends before the
# scope is complete takes that agent down on its way out rather than leaving a
# socket behind that answers with half of what was asked for.
typeset -g SKM_SCOPE_PENDING=""

# An extracted key must not outlive the command that extracted it. Between the
# two there is a passphrase to mistype, a prompt to answer wrongly and a
# Ctrl-C to hit, and each of those ends the run somewhere other than the line
# that cleans up -- so the cleanup hangs on the way out instead, which is the
# one place all of them go through. The database password is dropped here for
# the same reason, and here rather than at the end of each command, because a
# run is free to open the same database again before it is over.
skm_cleanup() {
    wipe_tmp "$SKM_TMPDIR"
    SKM_TMPDIR=""
    KP_PW=""
    KP_PW_DB=""
    if [[ -n $SKM_SCOPE_PENDING ]]; then
        local label=$SKM_SCOPE_PENDING
        SKM_SCOPE_PENDING=""
        kill_scope "$label" >/dev/null 2>&1 || true
        warn "scope '$label' was not completed; its agent has been shut down"
    fi
}
trap 'skm_cleanup' EXIT
trap 'skm_cleanup; exit 130' INT
trap 'skm_cleanup; exit 143' TERM

# Answers in $SKM_TMPSUB for the reason ensure_tmpdir does: read through
# $( ), the directory would be made by a subshell and known only to it.
ramtemp() {   # -> $SKM_TMPSUB, a fresh 0700 dir inside the run's own directory
    ensure_tmpdir
    SKM_TMPSUB=$(mktemp -d "$SKM_TMPDIR/d.XXXXXX")
    chmod 700 "$SKM_TMPSUB"
}

export_one() {
    local name=$1
    local db=$2
    local exists=${3:-0}
    local key=$(keyfile "$name")
    local entry="$KP_GROUP/$name"
    local base=${key:t}
    local pub=$key.pub

    [[ -f $key ]] || die "no private key on disk for '$name' (already exported?)"

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
    if (( exists )); then
        info "entry '$entry' exists, updating attachments"
        run_kp_entry_pw "$KEY_PASS" edit -p "$db" "$entry" \
            || kp_die "could not set the password of '$entry'"
    else
        run_kp_entry_pw "$KEY_PASS" add -p "$db" "$entry" --url "ssh://$name" \
            || kp_die "could not create entry '$entry'"
    fi

    ensure_tmpdir
    local tmp=$(mktemp "$SKM_TMPDIR/keeagent.XXXXXX")   # BSD mktemp needs a template
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
    local -a parts=()
    if (( $1 > 0 )); then parts+=("$1 already in KeePassXC"); fi
    if (( $2 > 0 )); then parts+=("$2 with no private key on disk"); fi
    print -r -- "${(j:, :)parts}"
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

    kp_require

    local all=0
    local -a names=()
    if [[ $what == --all ]]; then
        all=1
        local f
        for f in $CONF_DIR/*.conf(N); do names+=("${f:t:r}"); done
        (( ${#names} > 0 )) || die "nothing managed to export"
    else
        require_host "$what"
        names=("$what")
    fi

    # A run over every host is expected to meet hosts that are already dealt
    # with: one whose private key was moved into the database has nothing left
    # on disk to store. Stepping over it, rather than stopping, is what lets
    # the hosts after it have their turn. Asked for by name it stays an error,
    # because then it is the one thing that was asked for.
    local -i skipped_nokey=0 skipped_stored=0
    if (( all )); then
        local -a left=()
        for n in "${names[@]}"; do
            if [[ -f $(keyfile "$n") ]]; then
                left+=("$n")
            else
                info "skipping $n (no private key on disk)"
                (( ++skipped_nokey ))
            fi
        done
        names=("${left[@]}")
        (( ${#names} > 0 )) || die "nothing left to export ($(skip_note 0 $skipped_nokey))"
    fi

    kp_password "$db"

    # One lookup per name, before anything is written: it says which entries a
    # plain export would overwrite, and it saves every export the `add` that a
    # name already in the database doesn't need. Over every host, an entry that
    # is already there is left alone unless --force asks for it to be rewritten
    # -- otherwise the second run of --all could never get past the first key
    # the first run stored.
    local -a todo=() stored=()
    local rc
    for n in "${names[@]}"; do
        rc=0
        kp_entry_exists "$db" "$KP_GROUP/$n" || rc=$?
        case $rc in
            0)  if (( force )); then
                    todo+=("$n"); stored+=(1)
                elif (( all )); then
                    info "skipping $n (already in KeePassXC; --force to overwrite)"
                    (( ++skipped_stored ))
                else
                    die "already in KeePassXC: $n  (re-run with --force to overwrite)"
                fi ;;
            1)  todo+=("$n"); stored+=(0) ;;
            *)  kp_die "could not read $db" ;;
        esac
    done
    (( ${#todo} > 0 )) || \
        die "nothing left to export ($(skip_note $skipped_stored $skipped_nokey))"

    # The group holds every exported key, so it is created once for the run
    # rather than once per key. From the second run on "already exists" is the
    # expected answer and the only tolerable failure.
    run_kp mkdir "$db" "$KP_GROUP" || [[ $KP_ERR == *'already exists'* ]] \
        || kp_die "could not create group '$KP_GROUP' in $db"

    local i=1
    for n in "${todo[@]}"; do
        export_one "$n" "$db" "${stored[i]}"
        (( ++i ))
    done

    # Reached only with at least one key written, so the advice below always
    # has something to be about.
    print
    if (( all )); then
        local note=$(skip_note $skipped_stored $skipped_nokey)
        local -i skipped=$(( skipped_stored + skipped_nokey ))
        info "exported ${#todo}, skipped $skipped${note:+ ($note)}"
    fi
    info "next: in KeePassXC, enable Tools > Settings > SSH Agent, then re-unlock the database."
    info "each entry's Password field holds that key's passphrase, which is what decrypts it."
    info "verify with 'ssh-add -l', then run 'skm agent <name>' and delete the on-disk key."
}

# Delete the on-disk private key so it lives only in KeePassXC. Deliberately
# single-key (no --all): this is meant to require real consideration each time.
cmd_drop() {
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

    kp_require
    kp_password "$db"

    local have=$(key_fingerprint "$key")
    [[ -n $have ]] || die "could not read local key: $key"

    local rc=0
    vault_fingerprint "$db" "$name" || rc=$?
    (( rc <= 1 )) || kp_die "could not read $db"   # 1 = not stored under this entry
    local vault_fp=$VAULT_FP

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

    # Before the private key goes, not after: rebuilding the public half needs
    # it, and agent mode is only usable with that file in place.
    ensure_pub "$name"

    secure_rm "$key"
    retarget "$name" agent

    print
    info "'$name' now resolves its key via the ssh-agent; verify with 'ssh-add -l'"
}

# Inverse of drop: pull the private key back out of KeePassXC onto disk, in
# the layout skm expects, and flip the config back to on-disk.
cmd_restore() {
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

    kp_require
    kp_password "$db"

    # Both halves come out into a private temp dir first. What an attachment
    # holds is only a key if it parses as one, and something that doesn't must
    # never reach the key's place on disk, nor have the host pointed at it.
    ramtemp; local tmpdir=$SKM_TMPSUB
    local rc=0
    kp_attachment_export "$db" "$entry" "$base" "$tmpdir/$base" || rc=$?
    case $rc in
        0) ;;
        1) wipe_tmp "$tmpdir"; die "no key attachment for '$name' in $entry" ;;
        *) wipe_tmp "$tmpdir"; kp_die "could not read $db" ;;
    esac

    local vault_fp=$(key_fingerprint "$tmpdir/$base")
    if [[ -z $vault_fp ]]; then
        wipe_tmp "$tmpdir"
        die "the key attachment in $entry is not a readable private key -- nothing on disk was changed"
    fi

    local have_pub=0
    rc=0
    kp_attachment_export "$db" "$entry" "$base.pub" "$tmpdir/$base.pub" || rc=$?
    case $rc in
        0) have_pub=1 ;;
        1) info "no public key attachment in $entry" ;;
        *) wipe_tmp "$tmpdir"; kp_die "could not read $db" ;;
    esac

    # A key on disk that isn't the vault copy is a second key, not a stale copy
    # of this one: writing over it would destroy the only copy of it there is.
    # --force alone replaces a key the vault already holds; a different key
    # takes an answer as well, and is kept, dated, beside the restored one.
    if [[ -f $key ]]; then
        local have=$(key_fingerprint "$key")
        if [[ $have != $vault_fp ]]; then
            print
            info "local:  ${have:-(not a readable private key)}"
            info "vault:  $vault_fp"
            if [[ -z $have ]]; then
                info "DANGER: the key on disk cannot be read, so it cannot be shown to be this one"
            else
                info "DANGER: fingerprints differ -- the key on disk is NOT the vault copy"
            fi
            local ans=""
            read -r "ans?replace '$key' with the vault copy? [y/N] " || ans=""
            case $ans in
                [yY]*) ;;
                *) wipe_tmp "$tmpdir"; info "aborted"; return ;;
            esac
            local backup="$key.bak-$(date +%Y%m%dT%H%M%S)"
            mv "$key" "$backup"
            [[ -f $key.pub ]] && mv "$key.pub" "$backup.pub"
            info "kept the displaced key as $backup"
        fi
    fi

    mv "$tmpdir/$base" "$key"
    chmod 600 "$key"
    if (( have_pub )); then
        mv "$tmpdir/$base.pub" "$key.pub"
        chmod 600 "$key.pub"
    fi
    wipe_tmp "$tmpdir"
    (( have_pub )) || ensure_pub "$name"

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

# A scope's agent is shut down by pid: ssh-agent -k signals the process named
# by SSH_AGENT_PID, and the socket path alone cannot ask it to stop. A pid file
# outlives the process it names, though -- after a reboot, or once the agent has
# been killed some other way, that number belongs to whatever the system handed
# it to next -- so nothing is signalled until both the socket and the process
# itself agree that the agent is still there.

# Whether an agent answers on a socket. ssh-add exits 1 when the agent it
# reached is holding no keys and 2 when it could reach no agent at all, so an
# agent that has been emptied still counts as alive.
agent_live() {   # socket
    local sock=$1 rc=0
    [[ -S $sock ]] || return 1
    SSH_AUTH_SOCK=$sock ssh-add -l >/dev/null 2>&1 || rc=$?
    (( rc == 0 || rc == 1 ))
}

# Whether a pid names an ssh-agent process. The comparison drops any leading
# directory, since ps reports the command as a bare name on some platforms and
# as a path on others.
pid_is_agent() {   # pid
    local pid=$1 comm=""
    [[ -n $pid && $pid != *[!0-9]* ]] || return 1
    comm=$(ps -o comm= -p "$pid" 2>/dev/null) || return 1
    [[ ${comm##*/} == ssh-agent ]]
}

# Take a scope down: the agent while it is still there to kill, and the socket
# and pid file either way, so a label that is gone leaves nothing behind for a
# later run to act on.
kill_scope() {   # label -> 0 an agent was killed, 1 only leftovers were removed
    local label=$1
    local sock="$SOCK_DIR/$label.sock" pidf="$SOCK_DIR/$label.pid"
    local pid="" rc=1
    if [[ -f $pidf ]]; then pid=$(<"$pidf"); fi
    if agent_live "$sock" && pid_is_agent "$pid"; then
        if SSH_AGENT_PID=$pid SSH_AUTH_SOCK=$sock ssh-agent -k >/dev/null 2>&1; then
            rc=0
        fi
    fi
    rm -f "$sock" "$pidf"
    return $rc
}


cmd_scope() {
    local label=${1:-}
    [[ -n $label ]] || die "usage: skm scope <label> [-c] [-t 8h] [-d db.kdbx] <name>..."
    require_name "$label" "scope label"
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

    # Everything that can be settled without an agent is settled before there
    # is one. A name that turns out not to be managed, a key that is in
    # neither place it could be, a database that will not open -- each of them
    # ends the run, and ending it here costs nothing, where ending it once the
    # agent is up leaves a live socket holding part of what was asked for.
    local n key vault=0
    for n in "${names[@]}"; do
        require_host "$n"
        key=$(keyfile "$n")
        if [[ ! -f $key ]]; then
            [[ -n $db ]] \
                || die "no key on disk for '$n' — pass -d <db.kdbx> to pull it from KeePassXC"
            vault=1
        fi
    done

    # The database is opened the once, however many keys come out of it, and
    # by the same route as everywhere else: whatever unlocks it -- key file,
    # hardware key, password -- works here too. Asking now also means the
    # password prompt comes before the agent exists rather than after.
    if (( vault )); then
        kp_require
        kp_password "$db"
    fi

    mkdir -p "$SOCK_DIR"; chmod 700 "$SOCK_DIR"
    local sock="$SOCK_DIR/$label.sock"

    if agent_live "$sock"; then
        die "scope '$label' is already running (skm unscope $label to replace it)"
    fi
    # A socket nothing answers on, and the pid file recorded beside it, are both
    # remains of an agent that has gone: clearing the pid file here is what keeps
    # a replaced scope from leaving a number behind that now belongs elsewhere.
    rm -f "$sock" "$SOCK_DIR/$label.pid"

    # The agent inherits SSH_ASKPASS/DISPLAY from *this* shell, and it's the
    # agent that renders the -c confirmation dialog. Start it from a graphical
    # session or the prompt will never appear.
    eval "$(ssh-agent -a "$sock")" >/dev/null
    export SSH_AUTH_SOCK="$sock"
    print -r -- "${SSH_AGENT_PID:-}" > "$SOCK_DIR/$label.pid"

    # From here to the last key loaded, the scope is half-built: a passphrase
    # typed wrongly, an entry that isn't there, a Ctrl-C at the prompt all end
    # the run, and the agent goes with it.
    SKM_SCOPE_PENDING=$label

    # An empty array expands to zero words here — no bash-3.2-style landmine.
    local -a flags=()
    (( confirm ))   && flags+=(-c)
    [[ -n $ttl ]]   && flags+=(-t "$ttl")

    local tmp rc
    for n in "${names[@]}"; do
        key=$(keyfile "$n")

        if [[ -f $key ]]; then
            # Said out loud rather than left to the exit status: a key the
            # agent turns down ends the scope, and the run says which key it
            # was and that nothing was left running.
            ssh-add "${flags[@]}" "$key" || die "ssh-add would not take the key for '$n'"
        else
            # The key lives in KeePassXC only. Where keepassxc-cli can write
            # an attachment to its standard output it goes straight down a
            # pipe into the agent and is never a file at all; where it cannot,
            # it comes out into the run's own directory, which is memory where
            # the platform has any and is wiped however the run ends.
            #
            # Said before the agent asks for anything: a key that arrives down
            # a pipe has no file name for ssh-add to name in its passphrase
            # prompt, and "(stdin)" tells nobody which key is being asked for.
            info "adding '$n' from $db"
            if kp_has_stdout; then
                rc=0
                kp_add_to_agent "$db" "$KP_GROUP/$n" "${key:t}" "${flags[@]}" || rc=$?
                case $rc in
                    0) ;;
                    1) die "no key attachment for '$n' in $KP_GROUP/$n" ;;
                    2) kp_die "could not read $db" ;;
                    *) die "ssh-add would not take the key for '$n'" ;;
                esac
            else
                ramtemp; tmp=$SKM_TMPSUB
                rc=0
                kp_attachment_export "$db" "$KP_GROUP/$n" "${key:t}" "$tmp/$n" || rc=$?
                case $rc in
                    0) ;;
                    1) wipe_tmp "$tmp"; die "no key attachment for '$n' in $KP_GROUP/$n" ;;
                    *) wipe_tmp "$tmp"; kp_die "could not read $db" ;;
                esac
                chmod 600 "$tmp/$n"
                if ! ssh-add "${flags[@]}" "$tmp/$n"; then
                    wipe_tmp "$tmp"
                    die "ssh-add would not take the key for '$n'"
                fi
                wipe_tmp "$tmp"
            fi
        fi
    done

    # Every key asked for is in: the scope is whole, and no longer something
    # the way out has to clear up.
    SKM_SCOPE_PENDING=""

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
    require_name "$label" "scope label"
    local sock="$SOCK_DIR/$label.sock" pidf="$SOCK_DIR/$label.pid"
    [[ -S $sock || -f $pidf ]] || die "no such scope: $label"

    if kill_scope "$label"; then
        info "killed scope '$label'"
    else
        info "scope '$label' was no longer running; removed its leftovers"
    fi
}

# ---------------------------------------------------------------- dispatch

# The command summary at the top of this file is the help text; printing it
# from there keeps the two from drifting apart. $0 inside a zsh function is the
# function's own name, so the script's path has to be captured out here.
SKM_SELF=$0
usage() { sed -n '3,34p' "$SKM_SELF" | sed 's/^# \?//' }

case "${1:-help}" in
    add)       shift; cmd_add       "$@" ;;
    provision) shift; cmd_provision "$@" ;;
    alias)   shift; cmd_alias   "$@" ;;
    list)    shift; cmd_list    "$@" ;;
    status)  shift; cmd_status  "$@" ;;
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
    help|-h|--help) usage ;;
    # A mistyped command must not look like a successful run: scripts that
    # check the exit status would otherwise sail past it.
    *)       print -u2 "skm: unknown command '$1'"; usage >&2; exit 2 ;;
esac
