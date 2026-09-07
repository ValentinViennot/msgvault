---
title: Users and Visible Sources
description: Let several people use one archive, each seeing only the accounts bound to them.
---

One msgvault archive can serve several people. Each person is a **user**;
users have a role (`viewer`, `member`, or `admin`) and a set of **visible
sources** — the accounts whose messages they may read. Administrators see
every source; everyone else sees exactly the sources an administrator bound
to them, and a user with no bound source sees no messages at all.

## What is scoped and what is shared

Visibility applies to everything derived from messages: search in every
mode, Explore, aggregates, message and conversation detail, files by
message, the text views, statistics, document search, visual search, source
status, and the MCP tools. A message from an invisible source is *not found*.

Some parts of the archive are shared between users on purpose, because they
are not partitioned by source:

- the people graph — people, organizations, relationships, and their
  archive-wide activity rollups;
- attachment blobs, which are content-addressed and deduplicated across
  sources (an attachment is reachable by its hash);
- Saved Views, which are definitions, not results — running one applies the
  caller's visibility;
- `POST /api/v1/query`, which stays administrator-only because arbitrary SQL
  cannot be confined.

The text views (`/api/v1/text/*`) filter to one source at a time: a user who
sees several sources passes `source_id`; a user who sees one gets it by
default.

## Where users come from

- **Single sign-on** creates a user on first login (see
  [`[auth.oidc]`](/docs/configuration/#authoidc)); the role follows the
  provider's groups at each login.
- **Named API keys** act as a user when the key names one:

  ```toml
  [[auth.api_keys]]
  name = "reporting"
  key_env = "MSGVAULT_KEY_REPORTING"
  role = "viewer"
  user = "alice@example.com"   # the key sees Alice's sources
  ```

  A non-administrator key without a `user` sees no source.
- **Services acting for a user.** `msgvault mcp --http` authenticates to
  the daemon with its own key and forwards the signed-in person in the
  `X-Msgvault-On-Behalf-Of` header. The daemon honours that header only from
  an admin key configured with `on_behalf_of = true`; the request then runs
  with the named user's role and visibility. Give the sidecar such a key
  instead of `[server].api_key`.

  When the sidecar verified the person itself — an identity-provider access
  token — it also sends `X-Msgvault-On-Behalf-Of-Identity`: the provider
  account (issuer and subject), the display name, and the role it derived
  from the provider's groups. The daemon records that as a sign-in, exactly
  like a browser login: a person it has never seen becomes a user on their
  first MCP call, bound to the provider account a later web sign-in matches,
  and a role the provider changed since is refreshed. A key bound to a `user`
  asserts no identity, because it verified nobody.

  This is a trust boundary. Only a key marked `on_behalf_of` can make the
  daemon create or update a user, and such a key is already an
  administrator, so the assertion grants the sidecar nothing it could not do
  on its own; keep that key out of every other process. The daemon refuses an
  assertion it cannot parse, one without a provider account, or one with an
  unknown role, and it never revives a disabled user. Without the assertion —
  an older sidecar, or a key without `on_behalf_of` — the daemon still
  refuses a person it does not know, and the MCP client shows an
  `acting_user_refused` error asking them to sign in to the Web UI once; that
  first sign-in creates the user.

## Binding sources to users

Administrators bind sources from Settings → Users in the Web UI, from the
CLI, or through the API:

```bash
msgvault user list
msgvault user sources alice@example.com --set 1,3     # source IDs from `msgvault list-accounts`
msgvault user disable alice@example.com
msgvault user enable alice@example.com
```

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/users` | Users with their role, standing, and bound `source_ids` |
| `PUT /api/v1/users/{id}/sources` | Replace the bound sources (`{"source_ids": [1, 3]}`) |
| `PATCH /api/v1/users/{id}` | Disable or re-enable (`{"disabled": true}`) |

A binding change reaches live sessions, keys, and tokens within thirty
seconds; a change made through the API or the Web UI applies immediately. A
disabled user cannot sign in, and keys or tokens acting as that user stop
working.
