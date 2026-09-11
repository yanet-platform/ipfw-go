# Parser and VM performance, 2026-09-11

Five local changes were measured separately and together. The largest gains are
on long comments and VM jumps through unconditional address conditions. Parsing
the mixed ruleset improves only slightly.

## Environment and method

- Go 1.24.1, linux/amd64, Intel Xeon E5-2683 v4 at 2.10 GHz, KVM guest.
- `GOMAXPROCS=1`, CPU affinity fixed to CPU 8. Existing dataplane workers were
  busy on CPUs 1 and 2. This is a shared development host, not dedicated hardware.
- Ten samples per case, `-test.benchtime=200ms -test.benchmem`. Each round rotated
  the variant order and every other round reversed it. Binaries were built before
  measurement, and no other tests or builds were deliberately run during it.
- Identical benchmark implementations within each comparison. Parser state and
  VM construction are outside the timed hot paths. The build benchmark includes
  construction. Benchmark setup checks parse errors and expected VM verdicts.
- Tables below show medians and changes in time per operation from `benchstat`.
  Lower is better. `p=0.000` in tool output means a rounded value below 0.001.
  The benchmark suite geomean is not a workload throughput claim.
- Runtime baseline: `611db25`, with the measurement cases provided by
  `benchmark-fixtures.patch`. The combined runtime candidate applies
  `parser-combined.patch` and `vm-final.patch` to that baseline.

The mixed parser input has 10,000 deterministic synthetic lines, about 0.68 MB.
One operation parses the entire input. VM benchmarks use `xnetip` v0.1.1 network
types. These results do not predict every custom `Network` implementation or
production ruleset.

## Individual experiments

| Change | Benchmark | Before | Changed | Time change |
| --- | --- | ---: | ---: | ---: |
| Direct whitespace loops | Parser any-to-any | 408.2 ns | 394.9 ns | -3.26% |
| Check for `:` before scanning IPv6 bytes | Parser ten networks | 1.430 us | 1.323 us | -7.52% |
| Comment newline via `strings.IndexByte` | Parser 4 KiB comment | 1673.5 ns | 202.5 ns | -87.90% |
| Pass VM targets by pointer | VM no match, 1000 rules | 29.62 us | 26.73 us | -9.73% |
| Precompute positive `any`, on pointer baseline | VM 1000 jumps | 32.08 us | 12.77 us | -60.20% |

The first four comparisons use `parser-base.txt` or `vm-base.txt`. The last
compares `vm-final-pointer.txt` with `vm-any.txt`, so it measures the additional
effect of precomputing `any`. Changes do not add arithmetically.

Whitespace specialization alone is a tradeoff: ten-network parsing gets 2.69%
slower and mixed discard parsing gets 1.18% slower. The final parser combination
improves the ten-network case and leaves mixed discard statistically unchanged.
The compiler already inlines the original scanning helper, so the measurements
do not establish that function-pointer dispatch was the cause of its cost.

The `any` fast path trades slower IPv6 rejection relative to pointers alone for
much faster unconditional matches and jumps. The single-rule IPv6 case rises
from 78.02 ns to 84.14 ns, +7.84%, and the 1024-rule scan slows by 2.79%.
That scan remains 7.87% faster than the original implementation. A workload
consisting almost entirely of IPv6 source misses may prefer pointers alone.

## Final combination against the original runtime

| Benchmark | Before | After | Time change |
| --- | ---: | ---: | ---: |
| Parser mixed, discard state | 8.311 ms | 8.333 ms | no significant difference, p=0.579 |
| Parser mixed, reduce state | 8.718 ms | 8.574 ms | -1.66%, p=0.004 |
| Parser any-to-any | 408.2 ns | 393.8 ns | -3.55% |
| Parser ten networks | 1.430 us | 1.272 us | -11.05% |
| Parser 4 KiB comment | 1673.5 ns | 195.4 ns | -88.32% |
| Parser rule with 4 KiB inline comment | 2176.0 ns | 680.3 ns | -68.74% |
| VM first rule matches | 84.31 ns | 58.84 ns | -30.22% |
| VM 1000 jumps | 40.03 us | 12.77 us | -68.10% |
| VM IPv4 rejection, 1024 rules | 30.20 us | 27.47 us | -9.06% |
| VM IPv6 rejection, 1024 rules | 37.15 us | 34.23 us | -7.87% |
| VM last member of 64-address list | 943.5 ns | 771.4 ns | -18.24% |
| VM traced rejection, 1024 rules | 35.71 us | 33.11 us | -7.30% |
| VM build, large ruleset | 2.588 ms | 2.580 ms | no significant difference, p=0.971 |

Unless shown otherwise, these decreases have p < 0.001. The final parser's
label-only case regresses from 67.80 ns to 68.77 ns, +1.42%, p < 0.001. Small
changes in untouched microbenchmarks suggest sensitivity to binary layout, so
they should not be generalized to an algorithmic improvement or regression.

Packet checks, warmed reduce parsing and single-line parsing report **0 B/op and
0 allocs/op**. Mixed discard parsing reports **1 B/op and 0 allocs/op** in both
versions. Its rounded allocation count does not establish exactly zero bytes
over a benchmark run. The existing zero-allocation tests pass. VM construction
remains at 535 allocations/op. The two `any` flags occupy existing padding,
keeping the internal rule at 64 bytes on this architecture.

The existing `EveryMatcher` case is not a full linear scan of its repeated
ruleset: `skipto tablearg` resolves the repeated label to the last block. The new
source-rejection benchmarks exercise complete scans, and the traced case checks
that exactly 1024 rules were visited before timing a no-op tracer.

## Independent precomputed-any experiment

The standalone `any` change was also measured directly against `611db25`, without
pointer or parser optimizations. Both binaries used `benchmark-fixtures.patch`.
The candidate adds only `vm-any-standalone.patch`, matching the runtime in
`9263e9d`. Ten 200 ms samples alternated baseline and candidate order on CPU 8.

| Benchmark | Before | Standalone any | Time change |
| --- | ---: | ---: | ---: |
| First rule matches | 84.42 ns | 58.92 ns | -30.22%, p < 0.001 |
| 1000 jumps | 40.16 us | 12.74 us | -68.26%, p < 0.001 |
| IPv4 rejection, 1 rule | 69.12 ns | 72.83 ns | +5.36%, p < 0.001 |
| IPv4 rejection, 64 rules | 1.924 us | 2.022 us | +5.09%, p = 0.001 |
| IPv4 rejection, 1024 rules | 30.27 us | 31.01 us | +2.45%, p = 0.001 |
| IPv6 rejection, 1024 rules | 37.17 us | 36.84 us | no significant change, p = 0.052 |

This is a workload tradeoff: unconditional matches and jumps improve, while
IPv4 source rejection slows down in these cases. The independent PR therefore
includes these regressions in its description. Packet checks still report
0 B/op and 0 allocs/op. Building the VM has no significant timing change.

Recalculate this comparison with:

```sh
benchstat vm-any-standalone-base.txt vm-any-standalone.txt
```

## Semantic checks

The Rust whitespace, line/comment, target and VM matching implementations and
their tests were read before editing. LF remains in the scanner's remainder,
CRLF and command-hook input are preserved, and names remain slices of the input.
IPv6 classification still requires both a colon and the same allowed bytes.

VM target pointers refer to the existing arenas. Only one positive `any` skips
the matcher. Negated `any`, empty resolver results, grouped targets, table lookups,
custom network calls and tracing retain their previous behavior. Two explicit
VM cases now cover `not any` on either side.

The measured combined candidate passed `make test` (with the race detector),
`make lint`, and
`Fuzz_Parser_Next` for 30 seconds with four workers (127,357 executions, PASS).
Independent code and comment reviews found no issues.

## Data and reproduction

All `.txt` files are raw Go benchmark output. All `.patch` files apply to the
runtime baseline. `benchmark-fixtures.patch` supplies the complete test and
benchmark fixtures for replaying the experiments. The optimization PRs also
carry their relevant fixtures. `vm-final.patch` contains both VM changes.
Parser changes are independent of the VM patches. Apply the fixture patch and
only the desired runtime patches to a fresh `611db25` worktree, compile it,
then measure the resulting binary.

`vm-base`, `vm-pointer`, and `vm-combined` are the first VM cohort. `vm-pointer`
has only target pointers, while `vm-combined` also has all parser changes.
The final cohort rebuilt its baseline with the two new `not any` test cases:
`vm-final-base` has original runtime code, `vm-final-pointer` has pointers and all
parser changes, and `vm-any` adds precomputed `any`. Each cohort has the same
benchmark bodies. Use the final cohort for combined results.

To recalculate the tables from this directory:

```sh
benchstat parser-base.txt parser-whitespace.txt parser-colon.txt \
    parser-comment.txt parser-combined.txt
benchstat vm-base.txt vm-pointer.txt
benchstat vm-final-base.txt vm-final-pointer.txt vm-any.txt
```

To measure a baseline and candidate again, use two fresh checkouts at `611db25`.
Apply `benchmark-fixtures.patch` to both and the selected runtime patches only
to the candidate. Build each package with `go test -c` from each checkout:

```sh
go test -c -o /tmp/ipfw-parser-VARIANT.test .
go test -c -o /tmp/ipfw-vm-VARIANT.test ./vm
```

Replace `VARIANT` with `before` or `after`. Then alternate the frozen binaries:

```sh
for package in parser vm; do
    : > "$package-before.txt"
    : > "$package-after.txt"
    for round in $(seq 1 10); do
        if [ $((round % 2)) -eq 1 ]; then
            set -- before after
        else
            set -- after before
        fi
        for variant do
            GOMAXPROCS=1 taskset -c 8 "/tmp/ipfw-$package-$variant.test" \
                -test.run='^$' -test.bench='Benchmark_(Parser|VM)' \
                -test.benchtime=200ms -test.benchmem \
                >> "$package-$variant.txt"
        done
    done
    benchstat "$package-before.txt" "$package-after.txt"
done
```

Choose an idle CPU on another host. Keep profiling, builds and correctness tests
outside the timing run. The original binaries, 2-second CPU profiles and the
five-variant measurement driver are also retained locally in
`/extra_vda1/esafronov/ipfw-go-perf-20260911`.

## Further candidates, not yet benchmarked

The parser speculatively reads the first trailing option group before deciding
whether it is a destination port or an option. Avoiding the repeated parse may
help option-heavy inputs, but must preserve error positions, partial state and
hook calls. This needs a separate design and benchmark.

IP version predicates could be folded during VM construction. A correct design
must preserve empty-set and unknown-packet-version behavior. Indexing default
network tables requires more design because `Network` exposes only membership,
and networks may use non-CIDR masks.
