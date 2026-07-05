# Read/write-split example

A tiny Kubernetes Job that demonstrates the primary/replica split the chart sets
up with CloudNativePG: it **writes a tuple to the primary** (`-rw`) and **reads
it back from a replica** (`-ro`), printing how long the change takes to stream
over.

It uses the same dedicated DB roles the pgauthzd writer/reader use — connect as
`pgauthzd_rw` for the write (inherits `authz_writer`) and `authzen_direct` for
the read (inherits `authz_reader`), each least-privileged for its leg.

## Prerequisites

- The chart deployed with **at least one replica** (`database.instances >= 2`;
  the `values-k3d.yaml` default is 2). With a single instance there is no
  replica and `-ro` has no endpoints.
- Default release name `pgauthz` (the Job references `pgauthz-db-rw`,
  `pgauthz-db-ro`, and the `pgauthz-pgauthzd-rw` / `pgauthz-authzen-direct`
  secrets). Adjust the names in `job.yaml` if you installed under a different
  release.

## Run

```bash
kubectl apply -f job.yaml
kubectl logs -f job/pgauthz-rw-split
kubectl delete -f job.yaml      # cleanup
```

## Expected output

```
write conn -> 10.42.0.30 in_recovery=false   (primary)
read conn  -> 10.42.0.48 in_recovery=true    (replica)

[1] replica BEFORE write (expect f):  f
[2] write tuple on the PRIMARY (as authz_writer):  wrote ...
[3] poll the REPLICA until the change streams over:  replica saw it after ~20 ms
[4] cleanup (delete on the primary):  done
```

The poll latency (~tens of ms here) is the async replication lag — the staleness
window a replica read can expose. pgauthz has no consistency tokens, so route
checks that must be read-your-writes-fresh to `-rw` instead.

## What this shows about your app

Split your connection pools the same way: a **write DSN → `-rw`** (primary) and a
**read DSN → `-ro`** (replicas). `write_tuple` / `delete_tuple` and friends go to
the write pool; `check_access` / `list_*` go to the read pool. The engine's
read path is replica-safe (no writes), so it runs unmodified on a hot standby.
