// Package pgauthzadm is the embeddable administration library for pgauthz:
// model export and rendering, and the model registry lifecycle (status,
// versions, plan, publish, apply, rollout). It is the shared part of the
// pgauthzctl CLI, extracted so long-running processes (the management
// console's BFF) call the engine in-process instead of spawning a CLI.
//
// Every function takes a DB — satisfied by *pgx.Conn, pgx.Tx and
// *pgxpool.Pool — and maps 1:1 onto the engine's SQL API (docs/API.md). The
// library adds no authorization of its own: callers decide who may call what
// (pgauthzctl: whoever holds the DSN; the console: its own authorization
// store), and the connection role bounds what the engine permits.
package pgauthzadm
