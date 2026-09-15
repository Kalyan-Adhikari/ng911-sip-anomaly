# Changes from the prototype

This project replaces an earlier SIP anomaly pipeline
(`alextrinhx/sip-anomaly-detection`). That prototype established the shape of
the problem — parse SIP, window it, fit unsupervised models — and this one keeps
that shape. What follows is what changed and why, so the reasoning survives the
rewrite.

The prototype was trained on 17 public Wireshark sample captures as placeholder
data. Several findings below only became visible once real ESInet captures were
available; they are not criticisms of choices made without that data.

## Correctness

### SIP over TCP was not reassembled

The prototype parsed each packet's payload as one complete SIP message. RFC 3261
§7.5 frames SIP over TCP by `Content-Length`, so a message may span segments and
several may share one.

On the production captures this matters more than it sounds. SIP there runs
predominantly over TCP (4,304 of 4,852 messages in one hour), and **every
emergency INVITE exceeded one MTU** — those are precisely the messages carrying
SDP and `Geolocation`. Per-packet parsing loses or corrupts exactly the traffic
the system exists to watch.

Now: per-direction reassembly framed on `Content-Length`, pipelined messages
split correctly, and streams joined mid-connection resynchronise to the next
valid start line instead of being dropped.

### `urn:service:sos` was not recognised

NG911 i3 addresses emergency calls to a service URN (RFC 5031), not `user@host`.
A URI regex matching only `sip:`/`sips:` returns nothing for `urn:service:sos`,
so the field that distinguishes a real emergency call from keepalive traffic was
empty. Service URNs are now parsed and kept verbatim; other URN namespaces
(`urn:emergency:uid:callid:...`) are hashed, since they embed incident
identifiers.

### Windows were anchored per capture file

`(timestamp - capture_start) // window_seconds` restarts at zero in every file
and re-anchors boundaries to that file's first packet. With hourly rotation,
windows from adjacent files cannot be placed on one timeline and a dialog
spanning the rotation is counted twice.

Verified against two halves of one continuous stream: both files produced
`window_number 0..6` with boundaries 60.95 s apart. Windows are now indexed as
`floor(timestamp / window_seconds)` — identical across files and runs.

### Silent windows were dropped

`groupby("window_number")` only yields windows containing messages, so a window
with no traffic produced no row. On a keepalive-driven ESInet that is the
anomaly worth catching. Windows are now emitted with zero counts — but only
inside an observed capture span, so the hours between two non-adjacent files are
not fabricated as silence.

### `auth_failures` counted digest challenges

A `401` answering a `REGISTER` is the challenge every registration receives. The
prototype counted them as failures, so ordinary registration looked like an
attack; its own output showed `auth_failures=1, auth_successes=1` for a single
normal registration.

Now split into `auth_challenge_count`, `auth_completed_count`,
`auth_rejected_count`, and `unanswered_challenge_count`. Completion is tracked
**by Call-ID, not CSeq** — a digest retry reuses the Call-ID with an incremented
CSeq, so pairing by sequence number marks every legitimate registration as
unanswered. This was caught by a test during the rewrite, having been introduced
in the first draft of the replacement.

## Statistics

### The threshold was a tautology

`contamination=0.10` places the cutoff at the 90th percentile of the *training*
scores. Training data is the baseline, which is assumed normal, so exactly 10%
of it is labelled anomalous no matter what it contains. Measured on the
prototype's own data: iforest 11.9%, lof 9.5%, ecod 11.9% — all false positives
by construction, and 864 alerts/day at 10-second windows.

Now: a temporal train/calibration split, with the threshold read off held-out
windows at an explicit target FPR. On 4,239 real windows at `--target-fpr 0.01`
the achieved rate was 1.022% — 88 alerts/day. The reported rate includes rule
firings, so it reflects what an operator actually sees.

The split is temporal rather than random because traffic is autocorrelated;
shuffling would put near-identical adjacent windows on both sides.

### Features were duplicated

Eight pairs correlated above 0.999 on the prototype's data. `total_packets`,
`total_sip_messages`, and `messages_per_second` were mutually perfectly
collinear — volume counted three times — and `register_count` duplicated
`registration_attempts`. Scaled distances weight every column equally, so this
silently tripled the weight of volume.

The duplicates are gone, and anything correlating above 0.995 with a column
already kept is pruned at training time. On real data this takes 69 columns to
25.

### Rare-but-benign methods dominated the score

A single `SUBSCRIBE` or `CANCEL` in one capture made its window a 6.4σ outlier,
so most "anomalies" meant "this capture used a method the others didn't". With a
baseline of thousands of windows from one network rather than 42 from 17
unrelated ones, this resolves on its own.

## Coverage

### The detection path had never run

`score_with_trained_model()` existed but was called from nowhere;
`ATTACK_PCAP_DIR` was defined and unused. The only attack fixture was three
packets (a spoofed INVITE, a 180, an ICMP unreachable), and all three models
scored it as *more normal* than 90% of the baseline.

`ng911-sip validate` now generates synthetic ESInet traffic plus four labelled
attack scenarios, trains, scores, and exits non-zero if any is missed. It needs
no real capture, so the detection path stays exercised.

### Rules complement the model

Validation surfaced a genuine gap: a low-rate `OPTIONS` scan from an unknown
host was ranked highly (ROC AUC 0.92) but never crossed the threshold. It adds
about one message per second to a mesh already doing several, so no volume
feature moves.

The fix is not a better model. The feature that exposes it — traffic from a host
outside the mesh — is constant in a clean baseline, so it is pruned as
non-varying, and even if kept, a tree has no split point to learn from it. Four
structural rules now run alongside the model, and `detected_by` records which
mechanism fired.

### No tests existed

61 now, covering framing, windowing, digest semantics, calibration, pruning, and
artifact tampering.

## Operations

### Throughput

The prototype fully dissected every packet with Scapy, then UTF-8 decoded every
payload before rejecting non-SIP. Measured at ~2,700 pkt/s — about 22 minutes
per GB, so roughly 4.5 hours for a 12 GB day, with the packet DataFrame
accumulated entirely in memory (~1.3 GB per GB of capture).

Fewer than 0.3% of packets touch a SIP port. The reader now decodes only the
fixed-offset headers needed to apply a port filter, and copies a payload only
for frames that pass: on one 786 MB capture (1,634,894 packets), **12.7 minutes
falls to 7.0 seconds — about 109×**, at ~113 MB/s, with only parsed SIP retained.

Neither half of that change is worth much alone. Measured over an identical
60,000-packet budget from the same file:

| Approach | Rate | Speedup |
|---|---|---|
| Scapy dissection + decode every payload (prototype) | 2,149 pkt/s | — |
| Scapy dissection + port filter | 2,448 pkt/s | 1.1× |
| Fixed-offset headers + decode every payload | 5,613 pkt/s | 2.6× |
| Fixed-offset headers + port filter (shipped) | 215,299 pkt/s | 100× |

Filtering on top of Scapy gains almost nothing because Scapy dissects eagerly
when constructing the packet object: by the time the port is readable, the cost
is already paid. Parsing headers by hand without filtering still copies and
UTF-8 decodes every RTP payload before discarding it. Only together do they let
the reject decision be made from roughly twenty bytes of header, leaving the
remaining ~1,400 untouched.

### Caller identity reached disk

`from_header`, `to_header`, `contact`, `request_uri`, `call_id`, and
`user_agent` were written verbatim to `output/sip_messages.csv`. On real
traffic those carry caller telephone numbers, and INVITEs carry location. The
`.gitignore` covered `output/*.csv`, which prevents a commit but not
unencrypted 911 caller data sitting on a lab disk.

Identity is now reduced to a keyed HMAC at parse time, before anything is
written. Infrastructure (element IPs, hostnames, User-Agent, `urn:service:sos`)
stays readable because identifying which element misbehaves is the point.

A `tel:` URI has no `@`, so an early draft of the replacement put the telephone
number in the clear `host` field. A test caught it; `tel:` is now matched
separately and hashed whole.

### Packaging and entry points

- `sip_parser.py` and `inspect_pcaps.py` used non-recursive `iterdir()` on
  `pcaps/`, which had contained zero files at top level since captures were
  reorganised into `baseline/` and `attacks/`. Both exited "No capture files
  found". Replaced by a single `ng911-sip` CLI.
- `requirements.txt` listed 3 of 8 needed packages and pinned neither `pyod` nor
  `scikit-learn`, while committing pickled models built against unpinned
  versions. Dependencies are now declared in `pyproject.toml` with upper bounds.
- Model artifacts are no longer committed. `load` verifies a recorded SHA-256
  before unpickling.
- Partial downloads (`.crdownload`, `.part`) are skipped, and a file that fails
  to parse is recorded and skipped rather than aborting the run.
