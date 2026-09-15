# Design notes

Why this tool is built the way it is. Most of these choices came out of testing
an earlier prototype against real NG911 traffic and finding where it went wrong.
The numbers below are measured, not estimated.

## Reading captures

### Only look closely at SIP

On the production network we tested against, fewer than 1 packet in 200 was SIP.
The rest was monitoring traffic, container networking, DNS, and web traffic.

A straightforward approach reads each packet fully and then checks whether it was
SIP. That means doing all the work for 99.5% of packets you are going to throw
away. On a 786 MB file it took 12.7 minutes.

Instead the reader looks at about 54 bytes from each packet, just enough to see
which port it came from, and skips the rest unless the port matters. Same file:
7 seconds.

Both halves are needed. We measured each separately on the same data:

| Approach | Speed |
|---|---|
| Full packet decoding, check port afterwards | 2,149 packets/sec |
| Full packet decoding, check port first | 2,448 packets/sec |
| Minimal decoding, no port check | 5,613 packets/sec |
| Minimal decoding, check port first | 215,299 packets/sec |

Checking the port on its own barely helps, because the expensive part is decoding
the packet, and that already happened. Minimal decoding on its own helps a little,
because the payload still gets copied and examined. Together they are 100 times
faster, because a packet can be rejected after reading a few dozen bytes.

The tradeoff: SIP on an unusual port is invisible unless you set `--ports`.

### Rebuild messages before reading them

SIP over TCP does not line up with packet boundaries. One message can span
several packets, and several messages can share one packet. The standard says to
use the `Content-Length` header to find where each message ends, which is what
this tool does.

Measured on the same capture both ways:

| | One packet at a time | Rebuilt properly |
|---|---|---|
| Messages found | 4,850 | 4,852 |
| Payloads that failed to parse | 7 | 0 |
| Emergency calls found | 8 | 8 |
| Emergency calls read correctly | 6 | 8 |

The message count barely changes because that capture used a large snapshot
length and the network card was combining packets, so most large messages arrived
whole. The difference shows up in reading message contents: two of eight
emergency calls were genuinely split, and reading packet by packet saw only the
first half.

How much this matters depends entirely on where you capture. A smaller snapshot
length or a different tap point would widen the gap. Rebuilding is correct either
way.

The reader also recovers if a capture starts in the middle of a conversation. It
skips forward to the next message start instead of discarding the connection.

## Understanding NG911 specifically

### Emergency calls are addressed to a service, not a person

Ordinary SIP addresses look like `sip:someone@somewhere.com`. NG911 addresses
emergency calls to `urn:service:sos` instead, which names a service rather than a
person. Code written for ordinary SIP does not recognise this and comes up empty
on the one field that separates a real emergency call from routine equipment
chatter.

This tool recognises service addresses and keeps them readable. Other kinds of
special addresses can contain incident identifiers, so those get scrambled.

### Call details are bundled, not sent plainly

NG911 rarely sends media descriptions on their own. It bundles them together with
caller location and extra data in a single multipart body. Checking only the
top-level content type reports "no media description" on exactly the emergency
calls that carry one. We saw this on all 8 emergency calls in our sample.

The tool now looks inside multipart bodies, and separately records whether a
message carried location data.

### A login challenge is not a login failure

When equipment tries to register, it always gets rejected the first time with a
"401" response. That is the system asking for credentials, not refusing them. The
equipment then tries again with credentials and succeeds.

Counting those first rejections as failures makes completely routine activity
look like an attack. This tool counts challenges, successes, and rejections
separately, and only treats a login as suspicious if the challenge is never
completed.

One detail matters here: the retry reuses the same call identifier but increments
a sequence number. Matching the rejection to the eventual success by sequence
number never works, so every normal login would look unanswered. They have to be
matched by call identifier.

## Time blocks

### Use clock time, not position in the file

Captures are usually saved in hourly files. If you number time blocks from the
first packet of each file, the blocks restart at zero every hour and begin at a
different point in each file. Blocks from two files cannot be lined up, and a
call that crosses the hour boundary gets counted twice.

We confirmed this by splitting one continuous stream into two files: both
produced blocks numbered 0 through 6, starting about a minute apart.

Blocks here are tied to actual clock time, so they line up across any number of
files and across separate runs.

### Record quiet periods

A simple grouping only produces a block if something happened in it. On a network
where equipment sends health checks every few seconds, a block with nothing in it
is the problem you most want to know about.

The tool writes out empty blocks with zero counts. It only does this inside
periods a capture actually covers, so a missing hour between two files is not
mistaken for silence.

### Measure who is talking, not just how much

Adding up everything in a block hides a single machine flooding traffic among
normal activity, which is the shape a denial-of-service attack takes. Each block
also records how concentrated the traffic was and how much the busiest machine
sent.

## Deciding what to flag

### Measure the alert rate instead of assuming one

A common shortcut is to tell the software "assume 10% of this is bad." The
software then flags the worst 10% of whatever you gave it. Since you trained on
traffic you believe is normal, all of those are false alarms, and at 10-second
blocks that works out to about 864 alerts a day.

This tool splits your data by time, learns from the earlier part, and uses the
later part to find where the cutoff actually falls for a rate you choose. On
4,239 blocks of real traffic, asking for 1% produced a measured 1.02%, or about
88 alerts a day.

The split is by time rather than random, because traffic minutes apart looks very
similar. Shuffling would put nearly identical blocks on both sides and make the
result look better than it is.

### Drop columns that measure the same thing

The prototype had three columns that all recorded traffic volume and two that
both counted registrations. Since every column carries equal weight, volume
counted three times.

Anything that tracks an existing column too closely is dropped automatically
before training. On real data this took 69 columns down to 25.

### Use rules for things a model cannot learn

A model can only flag what varies in its training data. Some problems never occur
in clean data, so the column that would reveal them never changes and gets
dropped as useless.

A slow scan from an unfamiliar machine is the clearest case. It adds about one
message a second to a network already doing several, so no count moves out of
range. In testing the model ranked it highly but never flagged it.

Four fixed rules run alongside the model for cases like this. Each flagged block
records which mechanism found it.

## Privacy

Real 911 traffic contains caller phone numbers in several headers, and call setup
messages can contain caller location.

None of it is needed. The detection works on counts and totals, never identities.
So identities are replaced with scrambled codes as soon as a message is read,
before anything reaches disk. Equipment addresses and software names stay
readable, because identifying which equipment is misbehaving is the point.

One case worth noting: a `tel:` address has no separator between user and host,
so code written for ordinary addresses puts the whole phone number in the field
meant for the hostname, in plain text. A test caught this during development.
Phone-only addresses are now handled separately and scrambled whole.

## Model files

Trained models are saved with joblib, which uses Python pickles. Loading a pickle
runs code, so these files are treated as something you build locally, never
something you download or commit. The tool records a checksum when saving and
verifies it before loading, so an altered or truncated file fails with a clear
error instead of being opened.

## Testing

The prototype had no tests, and its scoring function was never called from
anywhere, so the detection half had never actually run. Its only attack sample
was three packets, which every model rated as more normal than the baseline.

There are now 63 tests, and `ng911-sip validate` builds its own practice traffic,
trains on it, and runs four attacks against it. It fails with an error code if
any attack is missed, so the detection path cannot quietly stop working.
