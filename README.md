# skm

A small per-host SSH key manager, in two dialects of one script.

Instead of one `id_ed25519` offered to every server you ever log in to, skm
gives each host its own key and its own stanza in `~/.ssh/config.d/`. The
private half can then be moved into a KeePassXC database, where KeePassXC
hands it to your ssh-agent when the vault is unlocked and takes it away when
the vault is locked — so the key exists on disk only while you are using it,
or not at all.

```
skm add web deploy@web.example.com   # key + config entry
skm copy web                         # ssh-copy-id it to the server
ssh web                              # the point of the whole exercise
```

## Install

`skm.bash` and `skm.zsh` are the same tool written twice: same commands, same
behaviour, same tests. Install whichever matches the shell you have. Neither
needs the other, and nothing else is installed alongside them.

```sh
install -m 755 skm.zsh  ~/.local/bin/skm     # zsh
install -m 755 skm.bash ~/.local/bin/skm     # bash 4 or newer
```

Make sure `~/.local/bin` is on your `PATH`. Each script names its own
interpreter in its `#!` line, so the installed copy runs under the shell it was
written for whatever shell you call it from.

Needed at runtime: `ssh`, `ssh-keygen`, `ssh-add`, `ssh-agent` and — for the
vault commands only — `keepassxc-cli`. On macOS that binary lives inside
`/Applications/KeePassXC.app`, where skm finds it without help. `shred` is
used when it is there and worked around when it is not, so Linux, macOS and
the BSDs all work.

## What it puts where

| Path | What it is |
|---|---|
| `~/.ssh/config.d/<name>.conf` | one host's stanza: `Host`, `HostName`, `User`, `Port`, `IdentityFile` |
| `~/.ssh/id_ed25519_<name>` | that host's private key, while it is on disk |
| `~/.ssh/id_ed25519_<name>.pub` | the public half, which always stays |
| `~/.ssh/config` | gets an `Include config.d/*.conf` line at the very top |
| `~/.ssh/cm/` | multiplexed connection sockets (`ControlPath`) |
| `~/.ssh/agents/<label>.sock` | the socket of a scoped agent |

`skm` only ever writes its own fragment files; your `~/.ssh/config` is touched
once, to add the `Include` line, and only if nothing already pulls the
directory in. The `Include` has to sit above any `Host` or `Match` block,
because ssh keeps the *first* value it sees for a setting — `skm status` says
where it ended up and complains if a block above it would win.

Each stanza pins `IdentitiesOnly yes`, so exactly one key is offered to that
server rather than every key your agent holds. It also enables connection
multiplexing (`ControlMaster auto`, `ControlPersist 10m`), which keeps repeat
`ssh <name>` calls riding one authenticated connection instead of asking the
agent — and therefore the vault — again.

## The vault

`skm export <name> <db.kdbx>` creates a KeePassXC entry named after the host in
the group `SSH Keys` (`SKM_KEEPASS_GROUP` moves it), with three attachments:
the private key, the public key, and a `KeeAgent.settings` file that tells
KeePassXC to load the key into the agent when the database is unlocked and
drop it when the database closes. If the key has a passphrase, it goes into the
entry's Password field, which is where KeePassXC looks for it on unlock.

Once the key is in the vault and the agent is serving it:

```sh
skm agent web                  # IdentityFile now points at web's .pub
skm drop web ~/vault.kdbx      # delete the private key from disk
```

`drop` compares the copy in the vault against the copy on disk before deleting
anything, so it cannot take away the only copy there is; it refuses rather than
guess. `skm restore` brings a key back to disk, and `skm status` says, for one
host or all of them, which halves exist on disk, which are in the vault,
whether they are the same key, and whether an agent is holding it.

`skm provision <name> <user@host> [port] <db.kdbx>` is `add`, `export` and
`drop` in one command, with a confirmation before the deletion. Every step is
skipped when its work is already done, so a run interrupted by a mistyped
password or a vault that would not open is finished by running the same
command again.

A database locked with more than a password is handled by the settings below:
key file, hardware key, both, or neither.

## Scopes

A normal agent hands every key it holds to anything that can reach its socket.
A scope is a second agent holding only what you name:

```sh
skm scope work -t 8h -d ~/vault.kdbx web db
```

That starts an agent at `~/.ssh/agents/work.sock` carrying those two keys and
nothing else, forgetting them after eight hours; `-c` makes it ask before each
use. Point something at the socket — a devcontainer bind mount, an
`SSH_AUTH_SOCK` in one terminal — and that thing can use those keys and no
others, however many keys your main agent has. `skm scopes` lists the live
ones and what each holds, `skm unscope <label>` ends one.

Keys can come straight out of the vault into a scope, without ever being
written to `~/.ssh`.

## Settings

Taken from the environment:

| Variable | Effect |
|---|---|
| `SKM_SSH_DIR` | the directory skm manages (default `~/.ssh`) |
| `SKM_KEEPASS_GROUP` | group the entries live in (default `SSH Keys`) |
| `SKM_KEEPASS_KEYFILE` | key file the database also needs to unlock |
| `SKM_KEEPASS_YUBIKEY` | hardware key `slot[:serial]` the database needs |
| `SKM_KEEPASS_NO_PASSWORD` | set for a database with no password at all |
| `SKM_KEEPASS_PASSWORD_FILE` | file whose first line is the database password |

`SKM_KEEPASS_PASSWORD_FILE` is what lets an unattended run — a scheduled health
check, say — open a database with no one at the keyboard.

## Worth knowing

- **An agent is a key.** Anything that can reach `$SSH_AUTH_SOCK` can
  authenticate as you, without ever seeing the key itself. That is the reason
  for scopes, and the reason not to use `ForwardAgent` on a host you do not
  control.
- **Dropping a key is not undoing it.** The private key is gone from disk once
  `drop` finishes; the vault holds the only copy. Keep the database backed up
  the way you would keep any other single copy of something irreplaceable.
- **The passphrase and the vault password are different things.** The
  passphrase protects the key file; the vault password protects the database
  that holds it. skm asks for each once per run and never writes either
  anywhere but where it belongs.
- **`skm rm` is a local deletion.** It removes the key and the config, offers
  to remove the vault entry when you name a database, and tells you which
  scoped agents are still holding that key — each of them keeps serving it
  until it is killed.

Run `skm help` for the full command summary, or `skm --version`.

## Tests

```sh
test/run.sh          # both ports
test/run.sh zsh      # one of them
```

The suites need [bats](https://github.com/bats-core/bats-core); the vault ones
also need `keepassxc-cli`, and report themselves as skipped when it is not
installed. `shellcheck` lints the bash port. Every test runs against a
throwaway `HOME`, so nothing in the suite can reach a real `~/.ssh` or a real
database. CI runs the lot on Linux and macOS.

## Licence

MIT — see [LICENSE](LICENSE).
