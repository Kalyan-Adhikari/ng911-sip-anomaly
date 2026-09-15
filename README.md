# ng911-sip-anomaly

Finds unusual activity in the phone signaling traffic of an NG911 emergency call
network.

## What this does

Emergency call networks use a protocol called SIP to set up, manage, and end 911
calls. This tool reads recorded network traffic, pulls out the SIP messages, and
learns what a normal hour looks like on your network. After that it can review
new traffic and point out the time periods that do not match the normal pattern.

Things it is built to notice:

* A sudden flood of call attempts, which can overwhelm a call center
* Repeated login attempts against your equipment
* A machine that has no business sending SIP suddenly sending it
* Your equipment going quiet when it should be sending regular health checks

It reports a short list of suspicious time windows with a reason attached to
each one. It does not block traffic or change anything on your network. It only
reads recorded capture files.

## Who this is for

Anyone running or researching an NG911 network who has packet captures and wants
an automated second pair of eyes on them. You need to be comfortable on a
command line. You do not need to know machine learning.

## How it works

```
capture files
      |
      v
keep only SIP traffic          (skips the other 99% quickly)
      |
      v
rebuild complete SIP messages  (a message can span several packets)
      |
      v
replace caller phone numbers with codes
      |
      v
group into 10-second blocks and count what happened in each
      |
      v
compare against learned normal  ---> list of suspicious blocks
```

Two things decide whether a block gets reported.

The first is a statistical model. It learns the shape of ordinary traffic from
your own captures and reports blocks that look different. This catches floods,
login storms, and outages.

The second is a short list of fixed rules. Some problems never appear in clean
training data, so a model has nothing to learn them from. The clearest example is
a slow scan from an unfamiliar machine. It adds barely any traffic, so every
count stays in its normal range, but the machine sending it does not belong on
the network at all. A rule can state that directly. During testing the model
ranked such a scan highly but never quite flagged it, while the rule caught it
every time.

Each reported block says which of the two found it, in a column called
`detected_by`.

## Requirements

* Python 3.10 or newer
* Packet captures in `.pcap` format, which is what `tcpdump` and Wireshark write
  by default
* Enough disk space for the captures themselves. The tool needs very little on
  top of that.

Tested on Linux and Windows. Nothing in it is platform specific.

## Install

```bash
git clone https://github.com/Kalyan-Adhikari/ng911-sip-anomaly.git
cd ng911-sip-anomaly
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

On Windows, replace the activate line with `.venv\Scripts\Activate.ps1`.

If your captures are `.pcapng` rather than `.pcap`, install the optional reader
as well:

```bash
pip install -e ".[formats]"
```

## Check that it works

Run this first. It builds its own practice traffic, so you do not need any
capture files.

```bash
ng911-sip validate
```

It creates a stretch of ordinary-looking emergency network traffic, learns from
it, then tries four known attacks against what it learned:

| Test | What it simulates |
|---|---|
| `invite_flood` | A flood of call attempts from one machine |
| `register_brute` | Repeated login attempts |
| `options_scan` | A quiet scan from an unfamiliar machine |
| `keepalive_blackout` | Equipment stops responding |

The last line should read `all scenarios detected`. If it does, your install is
working. The command fails with an error code if any test is missed, so it also
works as a check after upgrades.

## Using it on real captures

Point the tool at a folder. It reads every capture inside, including
subfolders, and skips partial downloads and other files.

### Step 1: See what is in your captures

```bash
ng911-sip inspect /path/to/captures -v
```

This prints how many SIP messages were found, which message types appeared, and
how much of the traffic was emergency calls. Run this first to confirm the tool
is seeing your SIP traffic. If it reports zero messages, see Troubleshooting.

### Step 2: Turn captures into a summary table

```bash
ng911-sip features /path/to/captures -o features/baseline.parquet
```

This writes one row per 10-second block, with about 70 columns counting what
happened in that block. Phone numbers are already replaced with codes at this
point.

### Step 3: Learn what normal looks like

```bash
ng911-sip train features/baseline.parquet -m models --target-fpr 0.005
```

Use captures from a period you believe was ordinary. The tool splits them by
time, learns from the earlier part, and uses the later part to set its alerting
level.

`--target-fpr 0.005` means "aim to flag about 0.5% of normal traffic." Lower
numbers mean fewer alerts and a higher chance of missing something. The command
prints how many alerts per day that setting works out to, so you can adjust
before deploying.

### Step 4: Review new traffic

```bash
ng911-sip features /path/to/new-captures -o features/today.parquet
ng911-sip score models/iforest features/today.parquet -o output/today.parquet
```

This prints the most suspicious blocks and writes the full results to a file.

Use captures the model has not seen. Scoring the same traffic you trained on
only proves the software runs.

## Reading the results

The output file has one row per 10-second block. The useful columns:

| Column | Meaning |
|---|---|
| `window_start_utc` | When the block began |
| `is_anomaly` | 1 if flagged, 0 if not |
| `detected_by` | What flagged it |
| `anomaly_score` | Higher means more unusual |
| `total_messages` | How many SIP messages were in the block |

Values you may see in `detected_by`:

| Value | What it means |
|---|---|
| `model` | Statistically different from your normal traffic |
| `offmesh_traffic` | A machine that is not a regular part of your network sent SIP |
| `auth_storm` | Many login attempts in one block, none succeeding |
| `mesh_silent` | No SIP at all during a period that should have had some |
| `single_source_domination` | One machine sent nearly all the traffic in a busy block |

A flag means "worth a look," not "confirmed attack." Some perfectly normal
events will be flagged, especially real emergency calls on a network that is
otherwise mostly automated health checks.

To find out which machine caused a flagged block, rebuild the features with
`--per-source`. That gives one row per machine per block instead of one row per
block.

## Privacy

Real 911 traffic contains caller phone numbers, and call setup messages can
contain caller location. This tool does not need any of that to do its job, so
it removes it early.

Phone numbers, caller IDs, and call identifiers are replaced with scrambled
codes as soon as a message is read, before anything is saved to disk. The codes
are consistent, so you can still count how many different callers there were, but
they cannot be turned back into phone numbers.

Equipment addresses, hostnames, and software names are kept readable, because
knowing which piece of equipment is misbehaving is the whole point.

The scrambling key is created automatically the first time you run the tool and
stored at `~/.ng911_sip/pseudonym.key`. Back it up. If you lose it, codes from
future runs will not match codes from past runs. To use the same key across
several machines, set the `NG911_SIP_PSEUDONYM_KEY` environment variable to the
same value on each.

There is a `--no-pseudonymise` option. It is for testing with fake traffic. Do
not use it on real emergency call data.

The included `.gitignore` blocks captures, results, models, and keys from being
committed by accident.

## Configuration

Most runs need no options. These are the ones that matter.

| Option | Default | When to change it |
|---|---|---|
| `--ports` | `5060,5061,5062` | Your network uses a different SIP port |
| `--window-seconds` | `10` | You want coarser or finer time blocks |
| `--target-fpr` | `0.01` | You are getting too many or too few alerts |
| `--per-source` | off | You want results broken down by machine |
| `--models` | `iforest ecod` | You want to compare different detection methods |

The port setting deserves attention. The tool ignores traffic on other ports as
its main speed trick, so if your SIP runs somewhere unusual and you do not set
this, it will find nothing and report no problems.

## Troubleshooting

**"No SIP messages found"**

Almost always the port. Check what port your SIP actually uses and pass it with
`--ports`. Encrypted SIP, usually on port 5061, cannot be read by this tool at
all; see Limitations.

**Flags far more than expected on new traffic**

Your traffic has changed since you trained. Retrain on more recent captures.

**Flags nothing, ever**

Confirm `ng911-sip inspect` still finds SIP messages. A tool that reports
nothing because it stopped seeing traffic looks the same as a quiet network.

**Out of memory**

Process fewer captures at a time and combine the results. Memory use scales with
the number of SIP messages, not the size of the captures.

## What gets counted

Each 10-second block records roughly 70 numbers, including:

* How many messages, split by request and response
* Counts for each SIP message type
* Counts for each response code
* How many different machines, callers, and calls appeared
* Whether one machine dominated the block
* Message sizes
* Emergency-specific items: calls to the emergency service address, messages
  carrying location, messages with media descriptions
* Login attempts, successes, and attempts that were never completed
* Time of day and day of week

Columns that measure nearly the same thing are dropped automatically before
training, so no single quantity gets counted twice.

### A note on login counts

A "401" response to a login is not a failure. It is a normal challenge that
every login receives before the real attempt. Counting those as failures makes
routine activity look like an attack. This tool counts them separately and only
treats a login as suspicious when the challenge is never completed.

## Design notes

These are the choices that most affect accuracy.

**Time blocks use clock time, not file position.** Captures are usually split
into hourly files. Numbering blocks from the start of each file makes the blocks
from different files impossible to line up, and a call spanning the split gets
counted twice. Blocks here are tied to actual clock time, so they line up across
any number of files.

**Quiet periods are recorded, not skipped.** On a network where equipment sends
regular health checks, silence is the problem worth catching. Empty blocks are
written out with zero counts. Gaps are only filled inside periods a capture
actually covers, so a missing hour between two files is never mistaken for
silence.

**Messages are rebuilt before being read.** A SIP message can be split across
several packets, and several can share one packet. Reading each packet on its own
miscounts both cases. In testing against a real network, rebuilding messages
correctly interpreted 8 of 8 emergency calls where per-packet reading managed 6.

**The alert level is measured, not assumed.** A common shortcut is to tell the
software "assume 10% of traffic is bad." That guarantees 10% of your normal
traffic gets flagged no matter what it contains, which works out to hundreds of
alerts a day. Here the software holds back part of your data, measures where the
cutoff actually falls, and reports the real rate before you deploy.

**Saved models are checked before loading.** Model files are Python pickles,
which execute code when loaded. They are treated as local build output, never
committed or downloaded, and the tool verifies a checksum before opening one.

## Performance

Measured on a 786 MB capture containing 1.6 million packets:

| | |
|---|---|
| Time for a full pass | 7 seconds |
| Reading speed | about 113 MB per second |

On that network fewer than 1 in 200 packets was SIP. The tool reads a few dozen
bytes from each packet to decide whether to care, then skips the rest. Reading
every packet in full took 12.7 minutes on the same file.

## Limitations

**Encrypted SIP cannot be read.** If your SIP runs over TLS, usually port 5061,
this tool sees nothing useful. You would need to capture before encryption, at
the session border controller, or use its logs instead.

**It only looks at SIP.** Attacks on supporting services such as DNS, scanning
activity, and media-stream attacks are all invisible to it. It is one layer, not
a complete monitoring system.

**It learns from whatever you give it.** If your training captures already
contain an ongoing attack, it learns that as normal. Review the highest-scoring
blocks of a fresh baseline before trusting it.

**It needs a reasonably steady network.** The unfamiliar-machine rule works out
which machines are regulars by seeing which appear consistently. Very short
captures, or networks where equipment comes and goes, will produce false alarms.

**Audio is not examined.** Only call signaling.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src tests
```

63 tests cover message rebuilding, time block alignment, login counting, alert
level calibration, and file tampering.

For a detailed account of what changed from the earlier prototype and why, see
[docs/design-notes.md](docs/design-notes.md).

## License

MIT. See [LICENSE](LICENSE).
