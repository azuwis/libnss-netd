#!/usr/bin/env python3
"""Probe the dnsproxyd "getaddrinfo" command - the one bionic itself uses.

Request (text, NUL-terminated, one write):
    getaddrinfo <name|^> <service|^> <ai_flags> <ai_family> <ai_socktype> <ai_protocol> <netid>
Reply:
    4 bytes "%.3d" result code (DnsProxyQueryResult = 222), then per address
    BE32 flags, family, socktype, protocol, addrlen, raw sockaddr,
    BE32 canonname_len, canonname; a final BE32 0 ends the list.
    A failure is sent with SocketClient::sendBinaryMsg instead: 4 bytes
    "401" + NUL (DnsProxyOperationFailed), a BE32 payload length, then the
    payload - a native int32 EAI code in bionic's numbering, which is
    positive (2 EAI_AGAIN, 7 EAI_NODATA, 8 EAI_NONAME, 11 EAI_SYSTEM) and
    unlike glibc's.

A bare IPv4 or IPv6 address probes netd's gethostbyaddr command instead:

Request (text, NUL-terminated, one write):
    gethostbyaddr <address> <addrlen> <af> <netid>
Reply:
    4 bytes "%.3d" result code (DnsProxyQueryResult = 222), then a hostent:
    BE32 name length + name, aliases ended by a BE32 0, BE32 h_addrtype,
    BE32 h_length, then 16-byte address chunks ended by a BE32 0. A failure
    is "401" + NUL (DnsProxyOperationFailed) with a BE32 payload length of 0.

DNSPROXYD overrides the socket path (default /dev/socket/dnsproxyd).

Usage: gai-probe.py [name [service [ai_family [ai_socktype]]]]
       gai-probe.py <address>
"""
import os
import socket
import struct
import sys

SOCK = os.environ.get("DNSPROXYD", "/dev/socket/dnsproxyd")
RESULT_CODE = 222
# Stop where the module stops, so the output stays bounded.
MAX_RECORDS = 256
# bionic's EAI_* values, from bionic's libc/include/netdb.h.
EAI_NAMES = {
    1: "EAI_ADDRFAMILY", 2: "EAI_AGAIN", 3: "EAI_BADFLAGS", 4: "EAI_FAIL",
    5: "EAI_FAMILY", 6: "EAI_MEMORY", 7: "EAI_NODATA", 8: "EAI_NONAME",
    9: "EAI_SERVICE", 10: "EAI_SOCKTYPE", 11: "EAI_SYSTEM",
    12: "EAI_BADHINTS", 13: "EAI_PROTOCOL", 14: "EAI_OVERFLOW",
}


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("dnsproxyd closed early")
        buf += chunk
    return buf


def recv_rest(sock, limit=4096):
    """Everything until the daemon closes, for text (FrameworkListener) frames."""
    buf = b""
    while len(buf) < limit:
        chunk = sock.recv(limit - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def be32(buf):
    return struct.unpack("!i", buf)[0]


def parse_ip(address):
    """The (family, packed) of an IP literal, or None."""
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            return family, socket.inet_pton(family, address)
        except OSError:
            pass
    return None


def probe_reverse(address, family, packed):
    """Probe one gethostbyaddr reply. Returns the exit status."""
    cmd = f"gethostbyaddr {address} {len(packed)} {family} 0".encode() + b"\x00"

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect(SOCK)
    except OSError as e:
        # Lookups usually fail here because the process cannot reach netd.
        print(f"dnsproxyd {SOCK}: not reachable ({e})")
        print("(is this process in an app UID with the INTERNET permission?)")
        return 2
    print(f"# dnsproxyd {SOCK}: gethostbyaddr {address}")
    try:
        s.sendall(cmd)
        s.shutdown(socket.SHUT_WR)
        code = recv_exact(s, 4)
        digits = code.rstrip(b"\x00")
        if not digits.isdigit():
            # FrameworkListener answers a bad command with text, not a frame.
            text = (code + recv_rest(s)).rstrip(b"\x00").decode(errors="replace")
            print("error: " + repr(text))
            return 1
        if int(digits) != RESULT_CODE:
            n = be32(recv_exact(s, 4))  # sendBinaryMsg: BE32 payload length
            if n:
                print(f"error: {code!r} (DnsProxyOperationFailed), "
                      f"payload length {n}")
            else:
                # GetHostByAddrHandler has no EAI code: NXDOMAIN, a timeout,
                # and a refused query all look like this.
                print(f"error: {code!r} (DnsProxyOperationFailed), no payload")
            return 1

        def chunk():
            n = be32(recv_exact(s, 4))
            if n < 0 or n > 1024:
                raise ValueError(f"bogus chunk length {n}")
            return recv_exact(s, n) if n else b""

        name = chunk().rstrip(b"\x00").decode(errors="replace")
        aliases = []
        while True:
            alias = chunk()
            if not alias:
                break
            aliases.append(alias.rstrip(b"\x00").decode(errors="replace"))
            if len(aliases) >= MAX_RECORDS:
                raise ValueError(f"over the {MAX_RECORDS} record limit")
        addrtype = be32(recv_exact(s, 4))
        addrlen = be32(recv_exact(s, 4))
        addrs = []
        while True:
            raw = chunk()
            if not raw:
                break
            addrs.append(raw)
            if len(addrs) >= MAX_RECORDS:
                raise ValueError(f"over the {MAX_RECORDS} record limit")

        print(f"h_name={name!r} addrtype={addrtype} h_length={addrlen}")
        for alias in aliases:
            print(f"alias={alias!r}")
        for raw in addrs:
            try:
                text = socket.inet_ntop(addrtype, raw[:addrlen])
            except (OSError, ValueError):
                text = raw.hex()
            print(f"addr={text}")
        print(f"{len(addrs)} address(es) for {address}")
        return 0 if addrs else 1
    except EOFError as e:
        print(f"error: {e}")
        return 1
    except OSError as e:
        # Report the failure instead of raising.
        print(f"error: dnsproxyd did not answer ({e})")
        return 1
    except ValueError as e:
        print(f"error: {e}")
        return 1
    finally:
        s.close()


def main():
    if len(sys.argv) == 2:
        parsed = parse_ip(sys.argv[1])
        if parsed is not None:
            return probe_reverse(sys.argv[1], *parsed)
    name = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    service = sys.argv[2] if len(sys.argv) > 2 else "^"  # ^ means NULL
    family = sys.argv[3] if len(sys.argv) > 3 else "0"   # 0 AF_UNSPEC, 2, 10
    socktype = sys.argv[4] if len(sys.argv) > 4 else "1"  # 1 SOCK_STREAM
    # The hints the module sends: AI_CANONNAME, AF_UNSPEC, SOCK_STREAM, and
    # netid 0 = the calling UID's default network. bionic sends -1 for all
    # four when its caller passed hints == NULL.
    cmd = f"getaddrinfo {name} {service} 2 {family} {socktype} 0 0".encode() + b"\x00"

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect(SOCK)
    except OSError as e:
        # Lookups usually fail here because the process cannot reach netd.
        print(f"dnsproxyd {SOCK}: not reachable ({e})")
        print("(is this process in an app UID with the INTERNET permission?)")
        return 2
    print(f"# dnsproxyd {SOCK}: getaddrinfo {name} {service}")
    try:
        s.sendall(cmd)
        s.shutdown(socket.SHUT_WR)
        code = recv_exact(s, 4)
        digits = code.rstrip(b"\x00")
        if not digits.isdigit():
            # FrameworkListener answers a bad command with text, not a frame.
            text = (code + recv_rest(s)).rstrip(b"\x00").decode(errors="replace")
            print("error: " + repr(text))
            return 1
        if int(digits) != RESULT_CODE:
            n = be32(recv_exact(s, 4))  # sendBinaryMsg: BE32 payload length
            if n < 0 or n > 4096:
                print(f"error: {code!r}, bogus payload length {n}")
                return 1
            payload = recv_exact(s, n)
            if len(payload) >= 4:
                rv = struct.unpack("@i", payload[:4])[0]
                print(f"error: {code!r} (DnsProxyOperationFailed), "
                      f"EAI {rv} {EAI_NAMES.get(rv, 'unknown')}")
            else:
                print(f"error: {code!r}, {n}-byte payload {payload!r}")
            return 1
        records = 0
        while True:
            if be32(recv_exact(s, 4)) == 0:
                break
            flags = be32(recv_exact(s, 4))
            family = be32(recv_exact(s, 4))
            socktype = be32(recv_exact(s, 4))
            proto = be32(recv_exact(s, 4))
            addrlen = be32(recv_exact(s, 4))
            if addrlen < 0 or addrlen > 128:  # sizeof(struct sockaddr_storage)
                print(f"error: bogus addrlen {addrlen}")
                return 1
            raw = recv_exact(s, addrlen) if addrlen else b""
            namelen = be32(recv_exact(s, 4))
            if namelen < 0 or namelen > 1024:
                print(f"error: bogus canonname length {namelen}")
                return 1
            canon = recv_exact(s, namelen).rstrip(b"\x00").decode() if namelen else ""
            af = struct.unpack("<H", raw[0:2])[0] if len(raw) >= 2 else 0
            port = struct.unpack("!H", raw[2:4])[0] if len(raw) >= 4 else 0
            if af == socket.AF_INET and len(raw) >= 8:
                addr = socket.inet_ntop(socket.AF_INET, raw[4:8])
            elif af == socket.AF_INET6 and len(raw) >= 24:
                addr = socket.inet_ntop(socket.AF_INET6, raw[8:24])
            else:
                addr = raw.hex()
            records += 1
            if records > MAX_RECORDS:
                print(f"error: over the {MAX_RECORDS} record limit; giving up "
                      "where the module does")
                return 1
            print(
                f"family={family} socktype={socktype} proto={proto} af={af} "
                f"addr={addr} port={port} canon={canon!r} flags={flags}"
            )
        print(f"{records} address record(s) for {name}")
        return 0 if records else 1
    except EOFError as e:
        print(f"error: {e}")
        return 1
    except OSError as e:
        # Report the failure instead of raising.
        print(f"error: dnsproxyd did not answer ({e})")
        return 1
    finally:
        s.close()


if __name__ == "__main__":
    sys.exit(main())
