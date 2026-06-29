# Benchmarks

A small multi-suite benchmark framework. Each **suite** benchmarks one
authorization model.

```
bench/
  run.sh            # runner:  ./bench/run.sh [suite ...]   (no args = all suites)
  lib/harness.sql   # shared timing helper + output setup
  suites/
    drive.sql       # Drive-shaped model (nested folders, groups, 50k users)
    github.sql      # GitHub-shaped model (orgs/teams/repos, role hierarchy, nested teams)
    rules.sql       # Rule-combination model (intersection, exclusion, conditions)
```

## Running

```bash
./init.sh              # install the engine first (once)
./bench/run.sh         # run every suite in bench/suites/
./bench/run.sh drive   # run one suite by name
./bench/run.sh drive github   # run several
```

Each suite builds its own store + data and prints a `ms/op` table. See
[`docs/BENCHMARKS.md`](../docs/BENCHMARKS.md) for methodology, environment, and
recorded numbers.

## Adding a suite

Create `bench/suites/<name>.sql`. The runner loads `lib/harness.sql` in the
same session first, so you can use:

- `pg_temp._bench_title('<title>')` — a section header
- `pg_temp._bench('<label>', $$ <sql> $$, <iters>)` — runs `<sql>` `iters`
  times (after warm-up) and prints ms/op

A suite should: reset its own store (`delete_store(..., p_purge_audit => true)`),
build the model + data, run `_bench(...)` scenarios, and tidy up at the end.
Use a store name unique to the suite (e.g. `bench_<name>`). See `suites/drive.sql`
as the template.

Planned suites: the demo's tax-advisor chain.
