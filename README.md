# ng911-sip-anomaly

Unsupervised anomaly detection for SIP traffic on an NG911 ESInet.

Reads packet captures, reassembles SIP, aggregates into fixed-width time
windows, and flags windows that do not look like the learned baseline. Built for
hour-rotated captures from a live ESInet, where SIP is a fraction of a percent
of the packets and caller identity must never reach disk.

```
captures ──► port filter ──► SIP reassembly ──► pseudonymise ──► 10s windows
                                                                      │
                                              ┌───────────────────────┤
                                              ▼                       ▼
                                      statistical model        structural rules
                                     (IForest/ECOD/LOF)     (off-mesh, auth storm,
                                              │              silence, domination)
                                              └───────────┬───────────┘
                                                          ▼
                                              flagged windows + reason
```

## Why both a model and rules

The model learns what the baseline looks like and flags departures from it. But
an unsupervised model can only flag what *varies* in training — and some
conditions never occur in a clean baseline at all, so the feature that would
expose them is constant and gets pruned.

A low-rate scan from a host outside the ESInet mesh is the clearest case: it
adds about one message per second to a mesh already doing several, so every
volume feature stays in range. In testing, the model ranked it highly
(ROC AUC 0.92) but never crossed the threshold. It is not a distribution to
estimate — it is traffic from somewhere that should not be sending SIP at all.
Rules assert that directly. Every flagged window records which mechanism caught
it in a `detected_by` column.

## Install

```bash
git clone https://github.com/Kalyan-Adhikari/ng911-sip-anomaly
cd ng911-sip-anomaly
python -m venv .venv
.venv\Scripts\Activate.ps1        # Windows;  source .venv/bin/activate on Unix
pip install -e ".[dev]"
```

Add `.[formats]` if you need pcapng support — the built-in reader handles
classic pcap, which is what `tcpdump` and `dumpcap` write by default.

## Verify it works, with no data

```bash
ng911-sip validate
```

This synthesises an ESInet baseline — an OPTIONS keepalive mesh with occasional
emergency INVITEs to `urn:service:sos` — trains on it, then scores four labelled
attack scenarios:

| Scenario | What it is | Caught by |
|---|---|---|
| `invite_flood` | TDoS: one host drives INVITEs far above mesh rate | model |
| `register_brute` | Credential stuffing, challenged but never completed | model |
| `options_scan` | Low-rate enumeration from an unknown host | rule |
| `keepalive_blackout` | The mesh stops answering | model + rule |

All four are detected at full recall. The command exits non-zero if any is
missed, so it works as a regression test.

## Use it on real captures

```bash
# 1. What SIP is in here?
ng911-sip inspect /captures/2026-08-28 -v

# 2. Build feature windows (caller identity is hashed at parse time)
ng911-sip features /captures/2026-08-28 -o features/baseline.parquet

# 3. Train and calibrate
ng911-sip train features/baseline.parquet -m models --models iforest ecod \
    --target-fpr 0.005

# 4. Score new traffic
ng911-sip features /captures/2026-08-29 -o features/today.parquet
ng911-sip score models/iforest features/today.parquet -o output/scored.parquet
```

To measure accuracy, label a capture you have ground truth for and evaluate:

```bash
ng911-sip features /captures/incident -o features/incident.parquet --label 1
ng911-sip score models/iforest features/incident.parquet -o output/incident.parquet
ng911-sip evaluate output/incident.parquet
```

Add `--per-source` to `features` for one row per (window, source IP). Window
rows answer *is this interval unusual*; source rows answer *which host made it
unusual*.

## Measured behaviour

On 12 GB of production ESInet capture (12 hourly files from a live deployment):

| | |
|---|---|
| Capture volume | 12 GB, 12 files |
| Packets examined | 110,667 SIP-port segments (of ~25M packets) |
| SIP messages parsed | 75,987 |
| Feature windows | 4,239 |
| Read throughput | ~113 MB/s (786 MB file in 7.0 s) |

Fewer than 0.3% of packets touch a SIP port, so the reader decodes only the
fixed-offset Ethernet/IP/TCP fields needed to reject a frame, and copies a
payload only for the ones that survive. On a 786 MB capture that takes a full
pass from 12.7 minutes to 7.0 seconds.

Both halves are needed. Adding a port filter to full Scapy dissection gains
1.1×, because Scapy dissects eagerly and the cost is spent before the port is
readable. Hand-parsing headers without a filter gains 2.6×, because every RTP
payload is still copied and decoded before being discarded. Together: 100× on
an identical packet budget. See
[docs/changes-from-prototype.md](docs/changes-from-prototype.md).

## Privacy

Real NG911 SIP carries caller telephone numbers in `From`/`To`/`Contact` and
caller location on INVITEs with `Geolocation`. The models consume counts and
cardinalities — never identities — so identity is reduced to a keyed HMAC at
parse time, before anything is written.

What is kept in the clear is infrastructure: element IP addresses, hostnames,
`User-Agent` strings, and `urn:service:sos` (a service, not a person). What is
hashed: `From`/`To`/`Contact` user parts, `tel:` numbers whole, Call-IDs, and
any non-service URN that may embed an incident identifier.

The key lives at `~/.ng911_sip/pseudonym.key`, or set `NG911_SIP_PSEUDONYM_KEY`
to share it across hosts. Losing it only means hashes from a later run will not
match an earlier one.

`--no-pseudonymise` exists for synthetic traffic. Do not use it on live ESInet
captures.

`.gitignore` excludes `*.pcap`, `*.parquet`, `models/`, and `*.key` by pattern
rather than directory, so a stray capture anywhere in the tree stays out of
version control.

## Features

Per 10-second window (69 columns; 25 survive collinearity pruning on real data):

- **Volume** — messages, requests, responses, response/request ratio, retransmissions
- **Methods** — one count per SIP method, plus method entropy
- **Responses** — per-class rollups (1xx–6xx) and specific codes (401, 403, 404, 408, 480, 486, 487, 500, 503)
- **Cardinality** — distinct sources, destinations, peer pairs, Call-IDs, From/To users, User-Agents
- **Concentration** — source entropy, top-talker share, busiest source's message and INVITE counts, off-mesh source count and message ratio
- **Size** — mean, max, standard deviation
- **NG911 i3** — emergency (`urn:service:sos`) call count, Geolocation count, SDP count
- **Authentication** — digest challenges, completions, rejections, and unanswered challenges
- **Transport** — TCP share, maximum Via depth
- **Time** — hour and weekday as sine/cosine pairs

### On the authentication counters

A `401` answering a `REGISTER` is the routine digest challenge every
registration receives — not a failed login. Counting those as failures makes
normal registration look like an attack. What matters is the challenge that is
never completed, which is `unanswered_challenge_count`.

Completion is tracked **by Call-ID, not CSeq**: a digest retry reuses the same
Call-ID with an incremented CSeq, so pairing the 401 and the eventual 200 by
sequence number would mark every ordinary registration as unanswered.

## Design notes

**Windows are anchored to absolute epoch time.** Anchoring to each file's first
packet makes hourly-rotated captures restart at window zero with boundaries at
different offsets per file, so no continuous timeline can be built and a dialog
spanning a rotation is counted twice.

**Silent windows are emitted, not dropped.** On a keepalive-driven ESInet the
absence of traffic *is* the anomaly. Gaps are filled only inside an observed
capture span, so the hours between two non-adjacent files are never invented as
silence.

**SIP over TCP is reassembled.** RFC 3261 §7.5 frames SIP over TCP by
Content-Length, not by packet boundary. On the captures this targets SIP runs
predominantly over TCP, and every emergency INVITE — the ones carrying SDP and
Geolocation — exceeds one MTU. Treating one packet as one message loses exactly
the messages that matter most. Streams joined mid-connection resynchronise to
the next valid start line rather than being discarded.

**The threshold is calibrated, not assumed.** `contamination=0.10` makes the
cutoff the 90th percentile of training scores, so 10% of the data defining
"normal" is labelled anomalous regardless of content — 864 alerts a day at
10-second windows. Here the data is split in time, the model fits on the earlier
portion, and the threshold is read off a later held-out portion at an explicit
target FPR. The achieved rate and the implied alerts/day are both reported, and
the rate accounts for rule firings too.

**Collinear features are pruned.** Scaled distances weight every column equally,
so three columns all encoding message volume triple its weight. Anything
correlating above 0.995 with a column already kept is dropped, and the surviving
list is saved with the model.

**Model artifacts are verified before loading.** joblib is pickle-based, and
loading a pickle executes code. Artifacts are build outputs of the machine that
trained them — gitignored, never fetched — and `load` checks a recorded SHA-256
so a truncated or altered file fails loudly instead of being unpickled.

## Development

```bash
pytest                 # 61 tests
ruff check src tests
```

Tests cover TCP segmentation and pipelining, mid-stream resynchronisation,
compact and folded headers, VLAN tags, truncated captures, big-endian files,
absolute-epoch anchoring, gap filling across non-adjacent captures, digest
semantics, source concentration, threshold calibration, collinearity pruning,
and artifact tampering.

## Limitations

- **TLS-encrypted SIP is invisible.** NENA i3 permits SIP over TLS on port 5061;
  if your tap sits downstream of the SBC and sees TLS, this yields nothing. Tap
  pre-encryption, or ingest SBC logs instead.
- **An unsupervised baseline learns whatever it is given.** If the baseline
  contains ongoing scanning, the model learns it as normal. Review the top-scoring
  windows of a fresh baseline before trusting it.
- **The off-mesh rule assumes a stable mesh.** It derives membership from the
  data (sources present in ≥20% of windows). A capture short enough that a
  legitimate element appears rarely will flag that element.
- **No RTP analysis.** Media-plane attacks are out of scope.

## Licence

MIT.
