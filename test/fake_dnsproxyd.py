#!/usr/bin/env python3
"""Fake dnsproxyd speaking the getaddrinfo command, for testing libnss_netd.

Answer shapes follow AOSP's DnsProxyListener: "%.3d" result code
(DnsProxyQueryResult = 222) then per address BE32 flags/family/socktype/
protocol/addrlen + raw sockaddr + BE32 canonname_len + canonname, then BE32 0.
Flags and socktype follow the hints; protocol is filled in by netd. Only the
first record carries a canonical name - later records send the BE32 0 that says
there is none, which is what netd does.
Errors go through SocketClient::sendBinaryMsg instead: a "%.3d" code
(DnsProxyOperationFailed = 401), a BE32 payload length, then the payload -
here an int32 in bionic's EAI_* numbering, which is what a real netd sends
because it is built against bionic's netdb.h. A wrong token count is answered
the way FrameworkListener does it, with the text "501 <message>\\0".

The gethostbyaddr command answers from a small PTR table with netd's hostent
framing: length-prefixed h_name, aliases ended by a zero length, BE32
h_addrtype and h_length, then 16-byte address chunks ended by a zero length.
Its failure reply is 401 with a zero-length payload, because
GetHostByAddrHandler has no EAI code to send.

Some names and PTR addresses answer badly on purpose, so the suite can check
that bad replies are rejected or bounded. These include malformed replies, a
reply dribbled out in small pieces (CHUNKED), a reply that never ends (FLOOD),
a daemon that accepts and says nothing (STALLED, longer than the module's five
second timeout), and a reply spread over more than that timeout in pieces
small enough that no single read times out (TRICKLE).
"""
import os
import socket
import stat
import struct
import sys
import threading
import time

AF_INET, AF_INET6 = socket.AF_INET, socket.AF_INET6
SOCK_DGRAM, SOCK_STREAM = socket.SOCK_DGRAM, socket.SOCK_STREAM
IPPROTO_UDP, IPPROTO_TCP = socket.IPPROTO_UDP, socket.IPPROTO_TCP

# bionic's EAI_* values (libc/include/netdb.h): positive, and not glibc's.
EAI_ADDRFAMILY, EAI_AGAIN, EAI_BADFLAGS, EAI_FAIL, EAI_FAMILY = 1, 2, 3, 4, 5
EAI_MEMORY, EAI_NODATA, EAI_NONAME, EAI_SERVICE, EAI_SOCKTYPE = 6, 7, 8, 9, 10
EAI_SYSTEM, EAI_BADHINTS, EAI_PROTOCOL, EAI_OVERFLOW = 11, 12, 13, 14

# name -> addresses per family, canonical name, and whether to answer twice
# per address (a daemon that ignores the requested socktype, to test dedup).
ZONE = {
    "a.test": {"A": ["192.0.2.1", "192.0.2.2"], "AAAA": ["2001:db8::1"], "canon": "a.test"},
    "alias.test": {"A": ["192.0.2.1", "192.0.2.2"], "canon": "a.test"},
    "v6.test": {"AAAA": ["2001:db8::6"], "canon": "v6.test"},
    "canon.test": {"A": ["192.0.2.11"], "canon": "real.test"},
    "dup.test": {"A": ["192.0.2.9"], "AAAA": ["2001:db8::9"], "canon": "dup.test", "dup": True},
    "dribble.test": {"A": ["192.0.2.7"], "canon": "dribble.test"},
    "trickle.test": {"A": ["192.0.2.8"], "canon": "trickle.test"},
    "noname.test": {},  # rv 0, no records -> NODATA
    # no canonical name at all: every record carries the BE32 0 that says so
    "zerocanon.test": {"A": ["192.0.2.20"], "canon": ""},
    # 30 addresses: on 64-bit, more than glibc's 1024-byte scratch buffer can
    # hold as gaih_addrtuple (40 bytes each), so glibc has to grow it and ask
    # again. On 32-bit the tuples are smaller and already fit.
    "many.test": {"A": ["192.0.2.%d" % (i + 1) for i in range(30)],
                  "canon": "many.test"},
    # 40 addresses: over MAX_ADDRS, so the rest is dropped - a documented
    # limit nothing else in the suite reaches.
    "many40.test": {"A": ["192.0.2.%d" % (i + 1) for i in range(40)],
                    "canon": "many40.test"},
}
EAI_ERRORS = {"nx.test": EAI_NONAME, "again.test": EAI_AGAIN,
              "fail.test": EAI_FAIL, "memory.test": EAI_MEMORY,
              "nodata.test": EAI_NODATA, "broken.test": EAI_SYSTEM,
              "addr.test": EAI_ADDRFAMILY, "service.test": EAI_SERVICE}
# Reverse lookups: address string -> (h_name, aliases). netd packs every
# reply address into 16 bytes, even when h_length says 4.
PTR = {
    "192.0.2.1": ("ptr.test", ["alias.ptr.test", "second.ptr.test"]),
    # 40 aliases: over MAX_ALIASES, so the rest is dropped.
    "192.0.2.2": ("manyalias.test", ["alias%d.test" % i for i in range(40)]),
    "2001:db8::1": ("ptr6.test", []),
}
# One address whose reply is cut off inside the canonical name.
PTR_MALFORMED = "192.0.2.250"
# Names with this suffix are answered whatever they contain: a name the
# module should have rejected is then resolved instead of failing, which is
# how the rejection rules below become observable.
ACCEPTED = ".accept.test"
CHUNKED = ("dribble.test",)
FLOOD = ("flood.test",)
STALLED = ("hang.test",)
TRICKLE = ("trickle.test",)


def be32(v):
    return struct.pack("!i", v)


def sa4(ip):
    return struct.pack("<H", AF_INET) + struct.pack("!H", 0) + socket.inet_aton(ip) + b"\x00" * 8


def sa6(ip, scope=0):
    return (
        struct.pack("<H", AF_INET6)
        + struct.pack("!H", 0)
        + struct.pack("!I", 0)
        + socket.inet_pton(AF_INET6, ip)
        + struct.pack("@I", scope)
    )


def record(family, raw, canon, flags=2, socktype=SOCK_STREAM, proto=IPPROTO_TCP):
    """One addrinfo record, as sendaddrinfo() writes it.

    flags/socktype/protocol echo the hints the caller sent (AI_CANONNAME,
    SOCK_STREAM, and the protocol netd fills in for it); canon is the
    canonical name for this record, or "" for the BE32 0 netd sends when
    there is none.
    """
    out = be32(1) + be32(flags) + be32(family)
    out += be32(socktype) + be32(proto)
    c = canon.encode() + b"\x00" if canon else b""
    return out + be32(len(raw)) + raw + be32(len(c)) + c


def len_data(data):
    return be32(len(data)) + data


def hostent(name, aliases, addrtype, addrs):
    """One hostent reply, as sendhostent() writes it."""
    h_length = 16 if addrtype == AF_INET6 else 4
    out = len_data(name.encode() + b"\x00")
    for alias in aliases:
        out += len_data(alias.encode() + b"\x00")
    out += be32(0)
    out += be32(addrtype) + be32(h_length)
    for raw in addrs:
        out += be32(16) + raw + b"\x00" * (16 - len(raw))
    out += be32(0)
    return out


def answer(name, af):
    if name in EAI_ERRORS:
        # sendBinaryMsg(401, &rv, 4): code, BE32 payload length, native int32.
        return b"401\x00" + be32(4) + struct.pack("@i", EAI_ERRORS[name])
    if name == "badcmd.test":
        # FrameworkListener answers a bad command with text, not a frame.
        return b"501 bad command \x1b[31mwith an escape\x00"
    if name == "garbage.test":
        # a result code that is neither 222 nor 401
        return b"xyz\x00" + be32(0)
    if name == "badresult.test":
        # Numeric parsing sees 222, but the fourth byte is not a NUL.
        return b"222x" + be32(0)
    if name == "wrongerror.test":
        # A four-byte EAI payload belongs only to the 401 error frame.
        return b"501\x00" + be32(4) + struct.pack("@i", EAI_NONAME)
    if name == "longerr.test":
        # a failure frame whose payload length lies (100, not the 4 that
        # sendBinaryMsg(401, &rv, sizeof(rv)) always sends): the first four
        # bytes of a payload like this are not an EAI code the module may act
        # on, so it has to give up on the reply, not answer from it
        return (b"401\x00" + be32(100) + struct.pack("@i", EAI_NONAME)
                + b"x" * 96)
    if name == "nulcode.test":
        # four digits and no NUL: a client that parses this as a C string
        # runs off the end of its four byte buffer
        return b"2222" + be32(0)
    if name == "badaddr.test":
        # addrlen claims 4096 bytes, the sockaddr that follows is 16
        return (b"222\x00" + be32(1) + be32(0) + be32(AF_INET) + be32(SOCK_STREAM)
                + be32(IPPROTO_TCP) + be32(4096) + sa4("192.0.2.1") + be32(0))
    if name == "negaddr.test":
        # addrlen = -1: not "this record has no address", but a record that
        # cannot be read - bionic stops parsing here
        return (b"222\x00" + be32(1) + be32(2) + be32(AF_INET) + be32(SOCK_STREAM)
                + be32(IPPROTO_TCP) + be32(-1) + be32(0) + be32(0))
    if name == "negcanon.test":
        # namelen = -1 on an otherwise valid record
        raw = sa4("192.0.2.22")
        return (b"222\x00" + be32(1) + be32(2) + be32(AF_INET) + be32(SOCK_STREAM)
                + be32(IPPROTO_TCP) + be32(len(raw)) + raw + be32(-1) + be32(0))
    if name == "unterminatedcanon.test":
        # A valid address with a canonical name whose declared length omits
        # the NUL that netd always sends.
        raw = sa4("192.0.2.23")
        return (b"222\x00" + be32(1) + be32(2) + be32(AF_INET) + be32(SOCK_STREAM)
                + be32(IPPROTO_TCP) + be32(len(raw)) + raw + be32(4) + b"evil"
                + be32(0))
    if name == "truncated.test":
        # "222" then a record cut off before the canonname length
        return (b"222\x00" + be32(1) + be32(0) + be32(AF_INET) + be32(SOCK_STREAM)
                + be32(IPPROTO_TCP) + be32(len(sa4("192.0.2.1"))) + sa4("192.0.2.1"))
    if name == "bigcanon.test":
        # a canonical name no buffer of MAX_CANONNAME bytes can hold
        return b"222\x00" + record(AF_INET, sa4("192.0.2.21"), "x" * 600) + be32(0)
    if name.endswith(ACCEPTED) or name.endswith(ACCEPTED + "."):
        # Anything the module lets through gets an answer, so a name it was
        # supposed to reject is visibly resolved instead of quietly failing.
        return b"222\x00" + record(AF_INET, sa4("192.0.2.77"), name) + be32(0)
    entry = ZONE.get(name, {})
    out = b"222\x00"
    first = True
    for label, family, mk in (("A", AF_INET, sa4), ("AAAA", AF_INET6, sa6)):
        if af not in (0, family):
            continue
        for ip in entry.get(label, []):
            # netd fills in ai_canonname on the first result only. Later
            # records carry the BE32 0 that says so.
            canon = entry.get("canon", "") if first else ""
            first = False
            if entry.get("dup"):
                # a daemon that answers once per socket type, as netd does
                # when the caller leaves ai_socktype unset
                out += record(family, mk(ip), canon, socktype=SOCK_DGRAM,
                              proto=IPPROTO_UDP)
            out += record(family, mk(ip), canon)
    return out + be32(0)


def serve_gethostbyaddr(conn, parts):
    if len(parts) != 5:
        conn.sendall(b"501 GetHostByAddrCmd::runCommand: invalid number of arguments\x00")
        return
    addrstr = parts[1]
    try:
        af = int(parts[3])
    except ValueError:
        conn.sendall(b"501 bad family\x00")
        return
    if af not in (AF_INET, AF_INET6):
        conn.sendall(b"501 bad family\x00")
        return
    if addrstr == PTR_MALFORMED:
        # A reply cut off inside the canonical name.
        conn.sendall(b"222\x00" + be32(8) + b"ab")
        return
    if addrstr == "192.0.2.249":
        # Only MAX_RECORDS ends a record stream that never ends.
        head = len_data(b"flood.ptr\x00") + be32(0)
        conn.sendall(b"222\x00" + head + be32(AF_INET) + be32(4))
        blob = be32(16) + socket.inet_aton("192.0.2.1") + b"\x00" * 12
        while True:
            conn.sendall(blob)
    if addrstr == "192.0.2.248":
        # A success reply with an empty address list.
        conn.sendall(b"222\x00" + hostent("nodata.ptr.test", [], AF_INET, []))
        return
    if addrstr == "192.0.2.251":
        # h_addrtype is not a family the module can use.
        out = hostent("badtype.test", [], socket.AF_UNIX, [b"\x00" * 4])
        conn.sendall(b"222\x00" + out)
        return
    if addrstr == "192.0.2.252":
        # An address chunk over the 16-byte cap.
        out = len_data(b"oversized.test\x00") + be32(0)
        out += be32(AF_INET) + be32(4)
        out += be32(32) + b"\x00" * 32
        conn.sendall(b"222\x00" + out + be32(0))
        return
    if addrstr == "192.0.2.253":
        # An alias whose declared length omits the NUL netd always sends.
        conn.sendall(b"222\x00" + len_data(b"badalias.test\x00")
                     + be32(4) + b"evil")
        return
    if addrstr == "192.0.2.254":
        # 401 with a payload netd never sends for this command.
        conn.sendall(b"401\x00" + be32(4) + b"abcd")
        return
    if addrstr == "192.0.2.255":
        # 40 addresses: over MAX_ADDRS, so the rest is dropped.
        addrs = [socket.inet_aton("192.0.2.%d" % (i + 1)) for i in range(40)]
        conn.sendall(b"222\x00" + hostent("manyaddr.test", [], AF_INET, addrs))
        return
    entry = PTR.get(addrstr)
    if entry is None:
        # GetHostByAddrHandler has no EAI code to send: 401 with no payload.
        conn.sendall(b"401\x00" + be32(0))
        return
    name, aliases = entry
    raw = socket.inet_pton(af, addrstr)
    conn.sendall(b"222\x00" + hostent(name, aliases, af, [raw]))


def serve(conn):
    try:
        cmd = b""
        while not cmd.endswith(b"\x00"):
            chunk = conn.recv(4096)
            if not chunk:
                break
            cmd += chunk
        if not cmd:
            return
        parts = cmd.rstrip(b"\x00").decode().split(" ")
        if parts[0] == "gethostbyaddr":
            serve_gethostbyaddr(conn, parts)
            return
        # DnsProxyListener wants exactly 8 tokens and answers a mismatch as
        # text rather than with the binary framing.
        if len(parts) != 8:
            conn.sendall(b"501 GetAddrInfoCmd::runCommand: invalid number of arguments\x00")
            return
        if parts[0] != "getaddrinfo":
            return
        name = parts[1]
        try:
            af = int(parts[4])
        except ValueError:
            conn.sendall(b"501 bad family\x00")
            return
        if af not in (AF_INET, AF_INET6):  # -1 means "no hints", like bionic sends
            af = 0
        if name in STALLED:
            time.sleep(6)  # longer than the module's NETD_TIMEOUT
        if name in FLOOD:
            # a valid record stream that never ends: the module has to give
            # up on its own, a receive timeout never fires while data flows
            blob = record(AF_INET, sa4("192.0.2.1"), "flood.test")
            conn.sendall(b"222\x00" + blob)
            while True:
                conn.sendall(blob)
        payload = answer(name, af)
        if name in TRICKLE:
            # A byte every 1.5 s: no single read waits longer than the
            # module's five second receive timeout, but the whole reply takes
            # far longer than it. Only a deadline ends this lookup.
            for i, byte in enumerate(payload):
                conn.sendall(bytes([byte]))
                if i < 7:
                    time.sleep(1.5)
        elif name in CHUNKED:
            for i in range(0, len(payload), 7):
                conn.sendall(payload[i:i + 7])
                time.sleep(0.001)
        else:
            conn.sendall(payload)
    except OSError:
        pass  # client gave up (timeout) or closed early
    finally:
        conn.close()


def main():
    path = sys.argv[1]
    try:
        if not stat.S_ISSOCK(os.lstat(path).st_mode):
            raise SystemExit(f"{path} exists and is not a socket")
        os.unlink(path)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(16)
    print("fake dnsproxyd (getaddrinfo) on", path, flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
