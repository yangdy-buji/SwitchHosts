# Spider local bridge

Enable SwitchHosts **Preferences → HTTP API**. The browser client uses
`http://127.0.0.1:50761/api/v1/spider` and must come from exactly
`https://spider.yangdy.com`. Other peers, Host headers and origins are rejected,
even if the legacy API is configured to listen beyond loopback.

Click Connect in Spider and approve the native SwitchHosts dialog. Pairing creates
an OS-random 256-bit token in `internal/spider-token` (owner-only permissions on
Unix). It is never logged. Requests use `Authorization: Bearer <token>`.
Deleting that file revokes access; pairing again requires native consent. Keep the
app running. Grant browser local-network access when prompted; do not disable
browser security. SwitchHosts reports HTTP API port conflicts.

The bridge manages one fixed entry, **Spider运行环境**. Environment writes validate
IP addresses, hostnames, the SHA-256 content revision, 256 KiB content size and a
2,000-name limit. Existing active entries with different address sets for the same
name cause rejection. A managed block is replaced inside actual hosts content,
preserving the existing baseline independently of append/overwrite preferences.
System mode removes only that block and managed entry. Repeating a request is
idempotent. Editing/disabling the entry or changing the system file produces an
unapplied status until the environment is applied again.

`internal/spider-transaction.json` stores previous hosts and snapshots of the
manifest, UI state, managed entry and bridge state. The journal is synced before
the privileged write; metadata is synced before removing it. This is recovery
across separate files, not one atomic transaction. If a write fails, rollback
restores the prior state when actual hosts matches a known transaction side.
A pending journal reports unapplied; the next environment request attempts
recovery. If hosts changed independently or the journal is corrupt, writes stop
with an explicit recovery error. Preserve the journal and investigate instead of
manually deleting it. Status and pairing never modify system hosts.

Ordinary UI applies share the native apply lock. Backend aggregation includes a
snapshot stamp; concurrent environment changes reject stale applies. The renderer
passes its selection into the apply command, which persists it before releasing
the lock, then reloads the list. Native environment apply requires no renderer.

Endpoints (API version 1):

- `POST /pair`: native confirmation, returns `{apiVersion, token}`.
- `GET /status`: authenticated `{apiVersion, mode, revision, applied, entryCount, message?}`.
- `PUT /environment`: authenticated `{mode, content, revision}`, returns status.
  Modes: `system`, `prod`, `staging`, `daily`; system requires empty content/revision.
- OPTIONS: exact-origin CORS for GET/POST/PUT and Authorization/Content-Type.

Tests use temporary hosts files and never `/etc/hosts`. A packaged application's
native prompt, OS privilege path and browser local-network permission still need
manual verification on the target machine.
