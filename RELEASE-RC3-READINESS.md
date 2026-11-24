# Bypath v3.0.0-rc.3 — release readiness

Status: **READY_FOR_RC3_REVIEW**. This document is a draft for the founder's
review. Nothing has been tagged, published, merged into `main` or activated on
any production host.

Prepared 2026-11-14. Evidence classes: **TESTED** (observed in a run),
**REPORTED** (stated by the external tester, not independently re-run),
**NOT TESTED** (no evidence for this candidate).

## Candidate

| Item | Value |
|---|---|
| Branch | `fix/rc2-ws-alpn-and-select` |
| Commit | `a20c705bef19d663e706a892b584ab6383b5f5b1` |
| Base | `80260b0` (rc.2 tree, `fix/rc2-gateway-prereqs`) |
| Commits since base | 4 (`46a708d`, `88c9c07`, `cd29e0f`, `a20c705`) |
| CI run | `43495398766` — 17 jobs success, Release job skipped by ref gate |
| Verified artifact | `bypath-full-linux-arm64`, 53,084,322 bytes |
| SHA-256 | `f4f99f5dea26bda5a73810cc2a70dd5ca0f9275b9ee129860e4701049d72b394` |
| Build tags | `full with_utls` |
| Version string | `Bypath v0.0.0-ci-yo-fix-a20c705…` (temporary CI tag) |
| amd64 / armv7 | built by the same CI run; not downloaded or hash-verified here |

The branch is not merged into `main` (`eac5360`); `main` and the `v3.0.0-rc.1`
and `v3.0.0-rc.2` tags are unchanged.

## Changes since rc.2

1. **WebSocket ALPN** (`46a708d`) — `ws` links negotiate HTTP/1.1 only, in both
   the sing-box and Xray generators. An advertised `alpn=h2` previously broke
   the WebSocket upgrade and every request ended in EOF.
2. **Select by displayed name** (`46a708d`) — `bypath select` accepts the name
   `bypath list` prints when it identifies exactly one link; an exact raw match
   still wins; ambiguous names are refused with the list index as guidance.
3. **Embedded uTLS** (`46a708d`, `88c9c07`) — full builds and the embed job
   compile sing-box with `with_utls`, so `fp=chrome` links start in-process;
   a regression test fails the build when the tag set drops it.
4. **CI tag argument** (`a20c705`) — multi-word tag sets are passed to
   `go build` as one argument. `cd29e0f` keeps provider details out of the
   test comment.

Diff: 8 files, +304/−31 (`git diff 80260b0..a20c705`).

## Validation evidence

### External native ARM64 acceptance — REPORTED PASS

| Field | Value |
|---|---|
| Result | `RESULT=PASS` |
| Commit | `a20c705…` |
| HTTPS through SOCKS5 | `HTTP_CODE=204` |
| Embedded engine | `EMBEDDED_START=yes` |
| Missing-uTLS error | `UTLS_ERROR=absent` |
| Additional | second subscription provider worked; web panel usable (tester's statement) |

The tester used the reversible acceptance package on DietPi as the ordinary
`dietpi` account. The device was not accessed by the founder; these fields are
the tester's report, archived privately outside this repository.

### Lab and CI — TESTED

- CI run `43495398766` green for all build, test and embed jobs on `a20c705`.
- Emulated ARM64 lab: ALPN reproduction (`h2` → EOF, `http/1.1` → 204), embedded
  engine start with a uTLS fingerprint, amended protocol-policy tests.
- Acceptance-package suite on emulated ARM64 (disposable Debian 12, mocked
  systemd/curl): install, rollback, status, uTLS-error auto-rollback,
  start-failure auto-rollback, preflight stop, execute-bit self-heal — all pass
  from the extracted transfer archive.

### Packaging — TESTED

The first native run needed `chmod +x` on the extracted binary. Root cause: the
packager stored the binary `0644` and marked entries as MS-DOS-created, so
Info-ZIP applied the umask. Corrected archive: binary and scripts stored `0755`
with Unix creator marking; the installer also restores a dropped execute bit
after verifying the SHA-256. Corrected ZIP:
`ff462ec97fae3d70e2335c1013e0650da4fd54c135b747ed213bf2c13c0b074f`
(18,444,268 bytes), binary digest unchanged. Verified by extracting the archive
with Info-ZIP 6.00 on Debian 12 arm64 and running the full acceptance suite from
the extracted copy.

## Tested scope vs untested scope

### Tested on this candidate

| Surface | Evidence |
|---|---|
| SOCKS5 proxy path, native ARM64 | REPORTED 204 through the tester's lab subscription |
| `select` by displayed name | REPORTED (used in acceptance) + CI test |
| Embedded sing-box with uTLS in-process | REPORTED log marker, no fallback |
| WebSocket-over-TLS to a real provider | REPORTED 204 (the failed transport in rc.2) |
| Reversible install/rollback package | TESTED in lab mocks (not exercised on the tester's device) |
| Second provider connectivity | REPORTED only |
| Management panel reachability | REPORTED only; no authentication or TLS review |

### Not tested — do not claim

| Surface | Status |
|---|---|
| **Gateway Mode** — TUN / native-TUN forwarding, LAN client traffic, routing policies | **NOT TESTED** |
| DNS takeover / resolver override under gateway mode | **NOT TESTED** |
| Firewall / proxyguard rules and rollback of those rules | **NOT TESTED** |
| IPv6 gateway egress | **NOT TESTED** (forwarded IPv6 is dropped by design) |
| amd64 and armv7 runtime behaviour | **NOT TESTED** for this candidate |
| Long-run stability, reconnect behaviour, memory use | **NOT TESTED** |
| Panel authentication, TLS and LAN exposure | **NOT TESTED** |

A pass of this candidate is a proxy-mode connectivity correction. It is **not**
evidence that Gateway Mode is ready, and it does not change the rc.2 statement
that gateway paths carry known limitations.

## Known limitations carried forward from rc.2

- IPv6 gateway egress is not validated; forwarded IPv6 is dropped in gateway
  mode.
- Country routing depends on external geo data that is not hash-pinned.
- OpenVPN links require an external sing-box 1.14+ binary.
- The proxy listener has no client authentication.
- arm64 had only emulated validation before this external test; that gap is now
  closed for proxy mode only.

## Open decisions for the founder

1. **Version string.** Decide how rc.3 records the uTLS change. The accepted
   binary carries the temporary CI tag; a release build will differ in the
   version string but not in the source commit.
2. **Release line.** The four commits sit on a branch above `80260b0`, not on
   `main`. Decide the merge/cherry-pick path before tagging.
3. **Rebuild policy.** The accepted ARM64 binary was built by CI from
   `a20c705`. A release build should be produced by the release workflow from
   the tagged commit; it will not be byte-identical to the acceptance binary.
4. **Publication.** Publishing a pre-release and its assets requires explicit
   authorization and working release credentials; neither is in place in this
   session.
5. **Gateway Mode.** If rc.3 is to claim gateway readiness, a separate
   acceptance on real hardware is required; nothing here covers it.

## Not done in this step

No tag, no release, no asset upload, no merge, no push, no change to the
tester's device, no rebuild of the accepted binary. The changes to this
repository for review are the rc.3 `CHANGELOG.md` section and this document,
left uncommitted in the working tree.

## Addendum — 2026-11-14 (split-routing review branch)

Every section above is retained as written; this addendum records later
evidence and separates the classes it mixes. It does not upgrade an earlier
claim, and where an earlier line is now known to be narrower than stated the
correction is called out explicitly. The "left uncommitted in the working tree"
sentence above is superseded: the review freeze commit carries these documents,
and the remediation branch continues from it.

Branch `review/rc3-split-routing-20261114` builds on `a20c705` and adds the
opt-in `routing.country_split` policy plus the runtime gateway wiring that
makes the engine honour it. HEAD and per-commit hashes are recorded in the
private review dossier, outside this repository.

### Correction to the emulated ALPN line

The h2-EOF / http/1.1-204 reproduction and the embedded-engine start were
made in the **emulated** ARM64 lab (QEMU container), not on native hardware.
The CHANGELOG now says so. Native ARM64 evidence in this document is the
external tester's proxy acceptance and beta report, which are separate runs.

### External native ARM64 beta (REPORTED — tester's statement, not re-run)

- Proxy connectivity, web panel access and **Gateway startup** completed with
  11 doctor checks passing.
- Iranian and international IP-check sites returned the **same public IP**,
  which is consistent with every destination being proxied. This branch
  addresses that symptom; it is not proof that it is fixed on the tester's
  device, because no routing, DNS-leak or rollback check was run there.

### Evidence separation from here on

| Evidence class | What it proves | What it does not prove |
|---|---|---|
| Emulated ARM64 ALPN experiment (TESTED, historical) | The WebSocket ALPN defect and its correction in a disposable container | Anything about native hardware, gateway forwarding or routing policy |
| Native ARM64 proxy acceptance at `a20c705` (REPORTED) | SOCKS5 proxy path, embedded engine, uTLS tag set on the tester's Pi | Gateway Mode, LAN forwarding, split routing, rollback on that device |
| Native Gateway startup (REPORTED, later) | The gateway mode process reached its doctor checks | LAN client egress, DNS takeover behaviour, leak protection, policy routing |
| AMD64 split-routing lab on this branch (REPORTED / PARTIAL — see details) | Generated config markers, HTTP 200 responses, an egress-identity comparison for a non-Iranian destination, five configuration snapshots | Per-destination engine log lines, an Iranian-destination egress comparison, a replayable API log; ARM64 runtime, Xray runtime, tester hardware, browser-rendered panel |

### AMD64 split-routing lab details — REPORTED, only partially archived

The isolated AMD64 lab container, binary
`bypath-full-linux-amd64-3.0.0-stripped` sha256 `4f43a68d63f1f96bc3bd05b6773b4081579ae1b29c07804dfb93004b36940bbc`,
sing-box engine, `gateway.enabled: false`, strict DNS, `routing.country_split:
ir`.

What the private archive holds: the generated configuration markers
(`geosite-ir` and `geoip-ir` rule sets), HTTP 200 responses for the requested
sites, an egress-identity comparison whose probe destination is **not** Iranian,
and five configuration snapshots from the disable/rollback sequence.

What it does not hold: the per-destination engine log lines that were reported
as `outbound/direct` for `www.irna.ir` and `outbound/vless[proxy]` for
`example.com`; they come from a prior session transcript and were never
archived. There is also no egress measurement for an Iranian destination. The
DIRECT/PROXY claim is therefore **REPORTED**, not TESTED — and HTTP 200 alone
would not prove it, because a request to the same site through the proxy also
returns 200. The disable/rollback sequence is **PARTIAL** for the same reason:
the snapshots exist, the authenticated API call log does not. Neither public
egress address is reproduced here.

The remediation campaign's integration lab re-measures these claims against the
remediation HEAD and records them in `INTEGRATION-TEST-REPORT.md` and
`VALIDATION-MATRIX.md` in the private remediation dossier (outside this
repository). Those records, not this addendum, are the reference for the new
candidate.

### Still not tested (unchanged or newly identified)

- Xray runtime split path: unit tests only; the lab ran sing-box.
- Browser-rendered panel toggle: the served asset contains the split card and
  the authenticated API path was exercised, but the lab panel had no admin
  session, so no browser interaction was performed.
- ARM64 runtime behaviour of the split policy: not run on hardware in this
  step.
- Geo data: the sing-box rule-set defaults are now pinned to immutable upstream
  commits and each download is validated with sing-box's own reader before it is
  installed, with a provenance sidecar and an operator override for both lists.
  The Xray `.dat` feeds remain unpinned (recorded as a follow-up, not a release
  blocker for the shipped default, which uses sing-box). Every asset is fetched
  over TLS but not by content hash; the provenance sidecar records the hash that
  was accepted. The IR domain list is a published category list, not an
  exhaustive set.
- Race detector: see `VALIDATION-MATRIX.md` for the environment actually used
  and any remaining gap.

## Addendum — 2026-11-15 (RC3 remediation: split DNS, engine gating, assets)

This addendum corrects a claim in the 2026-11-14 text and records the RC3
remediation work. The earlier text stays as written; where it is narrower than
stated, the correction below is the reference.

### Correction: what keeps domestic names resolving

Earlier text implied that the split's `dns-direct` rule sets give domestic names
their direct DNS answer. They do not, for a LAN client. The engine's DNS
section (and its resolve steps) decides connection-time resolution *inside the
engine*; the query a LAN client sends to the gateway is answered by the
gateway's own forwarder (dns2socks, or the built-in forwarder when per-domain
routing is configured), and that forwarder resolved every name through the
tunnel. A domestic name therefore stopped resolving whenever the tunnel was
down, even though the split sent its connection direct.

The remediation adds `gateway.direct_dns`, the operator's trusted resolver for
exactly the names the plan sends `direct`. The forwarder classifies each query
with the same ordered plan the engine evaluates (first match wins); a proxied
name never reaches the direct resolver, a failure returns SERVFAIL for that
name, and the local policy's blanket upstream fallback is suppressed once a
direct resolver is configured. Without `direct_dns`, domestic names still
resolve through the tunnel and the panel now says so, so the outage behaviour is
reported instead of promised.

### Xray and the country split

Xray's DNS module has no per-resolver outbound field: the old `proxyTag` design
was a silent no-op. Generation and apply now refuse `routing.country_split` when
xray is the engine, with a message naming sing-box, and the panel plan marks
both split entries as skipped. The xray DNS section keeps the tunnel resolver
first with `skipFallback` and `disableFallback`, so no proxied name can fall
back to a plaintext local server.

### Plan order

The resolve steps and the DNS section now walk the same ordered list as the
route, so a proxy exception above a DIRECT class keeps its name off the direct
resolver (previously it was resolved in plaintext by `dns-direct`). A DIRECT
default resolves unmatched names domestically. The legacy whitelist path is
included.

### Xray geo databases

`geoip.dat` and `geosite.dat` are now fetched from immutable v2fly release tags
(`202611080027` and `20261115005626`) and must match the SHA-256 published with
that release, under a 128 MiB cap. A mismatch is refused and leaves the
installed asset untouched. This replaces the `releases/latest` download.

### Still not tested after this work

- The `direct_dns` outage behaviour (a LAN client resolving a domestic name
  while the tunnel is down) is unit-tested at the forwarder boundary; the
  end-to-end packet-level check belongs to the Phase 4 acceptance matrix and is
  not claimed here.
- Xray runtime routing beyond configuration generation: the split is refused on
  xray by design, and the remaining xray rules are covered by unit tests and
  config validation in the integration lab.
- The pinned `.dat` downloads are verified against a digest obtained from the
  same GitHub release; they are not verified against a separately published
  signature.

