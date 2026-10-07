#!/usr/bin/env python3
"""Test libnss_netd.so.2 through glibc's own NSS plumbing.

    make check              run everything
    FAST=1 make check       skip the tests that wait out a real timeout

test/fake_dnsproxyd.py stands in for Android's netd (the same getaddrinfo
command) and test/libnss_fakedns.c for the "dns" service, so the suite is
hermetic: no Android device, no working resolver, no change to the host's
resolver configuration. Every case runs in a fresh worker process (this file
with --worker) because glibc finds NSS modules on the loader path the
interpreter was started with; workers call glibc through ctypes, and the ABI
tests call the module's entry points directly.

Covered, one line per area:

  answers    getaddrinfo()/gethostbyname*() results: A/AAAA, the legacy
             hostent path, canonical names, dedup, the address cap, glibc
             buffer growth, AI_V4MAPPED
  statuses   netd's EAI_* to nss_status mapping and the hosts service-list
             semantics ([NOTFOUND=return], [TRYAGAIN=return], ...)
  loading    a missing daemon or module, service order, NETDNS_SOCKET
  replies    malformed frames, lying lengths, endless/dribbled/trickled
             replies
  names      the 254-byte limit and the characters bionic refuses
  reverse    gethostbyaddr() through netd's hostent reply
  abi        the gethostbyname4_r buffer contract: ERANGE, alignment, padding
  probe      tools/gai-probe.py against the same replies
  deadlines  a daemon that accepts the command and says nothing
"""

import atexit
import collections
import ctypes
import errno
import os
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from ctypes import (POINTER, byref, c_char_p, c_int, c_size_t, c_uint32,
                    c_void_p)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SELF = os.path.abspath(__file__)
# make check builds a test copy with the NETDNS_SOCKET override. The installed
# module has no runtime socket override.
TESTDIR = os.path.join(ROOT, "test")
MODULE = os.path.join(TESTDIR, "libnss_netd.so.2")
FAKEDNS_C = os.path.join(ROOT, "test", "libnss_fakedns.c")
FAKE_DNSPROXYD = os.path.join(ROOT, "test", "fake_dnsproxyd.py")
PROBE = os.path.join(ROOT, "tools", "gai-probe.py")

# The service list the module is tested with, and the one that makes TRYAGAIN
# observable: on the default list TRYAGAIN and UNAVAIL both continue to the
# next service, so only a list that stops on the status tells them apart.
DEFAULT_HOSTS = "files netd [NOTFOUND=return] fakedns"
TRYAGAIN_HOSTS = "files netd [TRYAGAIN=return] fakedns"
# Must match ACCEPTED in fake_dnsproxyd.py: names with this suffix are
# answered whatever they contain, so a name the module should have rejected
# is visibly resolved instead of quietly failing.
ACCEPT_SUFFIX = ".accept.test"

# A 254-byte absolute name (the DNS limit) and one byte more.
LABEL63, LABEL49 = "a" * 63, "b" * 49
VALID_FQDN = "%s.%s.%s.%s%s." % (LABEL63, LABEL63, LABEL63, LABEL49,
                                 ACCEPT_SUFFIX)
LONG_NAME = "%s.%s.%s.%s%s." % (LABEL63, LABEL63, LABEL63, LABEL49 + "b",
                                ACCEPT_SUFFIX)

# glibc's EAI_* codes, spelled out because the module translates bionic's
# numbering into these and the suite asserts the translation.
EAI_NONAME = getattr(socket, "EAI_NONAME", -2)
EAI_AGAIN = getattr(socket, "EAI_AGAIN", -3)
EAI_NODATA = getattr(socket, "EAI_NODATA", -5)
EAI_SYSTEM = getattr(socket, "EAI_SYSTEM", -11)

WORKER_TIMEOUT = 30
WORK = None
SOCK = None
_daemon = None

# ------------------------------------------------------------- ABI structures


class AddrInfo(ctypes.Structure):
    pass


AddrInfo._fields_ = [
    ("ai_flags", c_int), ("ai_family", c_int), ("ai_socktype", c_int),
    ("ai_protocol", c_int), ("ai_addrlen", c_uint32),  # socklen_t
    ("ai_addr", c_void_p), ("ai_canonname", c_char_p),
    ("ai_next", POINTER(AddrInfo)),
]


class HostEnt(ctypes.Structure):
    pass


HostEnt._fields_ = [
    ("h_name", c_char_p), ("h_aliases", POINTER(c_char_p)),
    ("h_addrtype", c_int), ("h_length", c_int),
    ("h_addr_list", POINTER(c_void_p)),
]


class AddrTuple(ctypes.Structure):
    """glibc's struct gaih_addrtuple, the buffer layout gethostbyname4_r
    fills in."""


AddrTuple._fields_ = [
    ("next", POINTER(AddrTuple)), ("name", c_char_p), ("family", c_int),
    ("addr", c_uint32 * 4), ("scopeid", c_uint32),
]


NSS_STATUS_TRYAGAIN = -2
NSS_STATUS_UNAVAIL = -1
NSS_STATUS_NOTFOUND = 0
NSS_STATUS_SUCCESS = 1
NSS_STATUS_NAMES = {NSS_STATUS_SUCCESS: "SUCCESS",
                    NSS_STATUS_NOTFOUND: "NOTFOUND",
                    NSS_STATUS_UNAVAIL: "UNAVAIL",
                    NSS_STATUS_TRYAGAIN: "TRYAGAIN"}
H_ERRNO_NAMES = {1: "HOST_NOT_FOUND", 2: "TRY_AGAIN", 3: "NO_RECOVERY",
                 4: "NO_DATA"}


def status_name(value):
    return NSS_STATUS_NAMES.get(value, str(value))


def errno_name(value):
    return errno.errorcode.get(value, str(value))


def herror_name(value):
    return H_ERRNO_NAMES.get(value, str(value))


def say(text):
    print(text, flush=True)


_libc = None


def libc():
    """glibc itself, as the NSS client a real program would be."""
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(None)
        _libc.__nss_configure_lookup.argtypes = [c_char_p, c_char_p]
        _libc.__nss_configure_lookup.restype = c_int
        _libc.getaddrinfo.argtypes = [c_char_p, c_char_p, POINTER(AddrInfo),
                                      POINTER(POINTER(AddrInfo))]
        _libc.getaddrinfo.restype = c_int
        _libc.freeaddrinfo.argtypes = [POINTER(AddrInfo)]
        _libc.gai_strerror.argtypes = [c_int]
        _libc.gai_strerror.restype = c_char_p
        _libc.gethostbyname.argtypes = [c_char_p]
        _libc.gethostbyname.restype = POINTER(HostEnt)
        _libc.gethostbyname2.argtypes = [c_char_p, c_int]
        _libc.gethostbyname2.restype = POINTER(HostEnt)
        _libc.gethostbyaddr.argtypes = [c_char_p, c_int, c_int]
        _libc.gethostbyaddr.restype = POINTER(HostEnt)
        _libc.hstrerror.argtypes = [c_int]
        _libc.hstrerror.restype = c_char_p
        _libc.__h_errno_location.restype = POINTER(c_int)
    return _libc


def open_entry_point():
    """dlopen the module and return its gethostbyname4_r entry point."""
    lib = ctypes.CDLL(MODULE)
    fn = lib._nss_netd_gethostbyname4_r
    fn.restype = c_int
    fn.argtypes = [c_char_p, POINTER(POINTER(AddrTuple)), c_void_p, c_size_t,
                   POINTER(c_int), POINTER(c_int), c_void_p]
    return lib, fn


def addrtuple_lines(pat):
    """One line per tuple: the address itself and whether it is the last."""
    lines = []
    while pat:
        tuple_ = pat.contents
        size = 4 if tuple_.family == socket.AF_INET else 16
        addr = socket.inet_ntop(tuple_.family, bytes(tuple_.addr)[:size])
        lines.append("tuple family=%d addr=%s next=%s"
                     % (tuple_.family, addr, "yes" if tuple_.next else "no"))
        pat = tuple_.next
    return lines


def sockaddr_address(family, raw):
    """The (address, port) in a raw sockaddr: the port is big-endian at
    offset 2, the address follows the 4-byte IPv4 or 8-byte IPv6 header."""
    port = int.from_bytes(raw[2:4], "big")
    if family == socket.AF_INET:
        return socket.inet_ntop(family, raw[4:8]), port
    return socket.inet_ntop(family, raw[8:24]), port


def worker_addrinfo(name, service, family, flags):
    """One glibc getaddrinfo() call with SOCK_STREAM hints."""
    hints = AddrInfo(ai_family=family, ai_socktype=socket.SOCK_STREAM,
                     ai_flags=flags)
    res = POINTER(AddrInfo)()
    rc = libc().getaddrinfo(name.encode(), service.encode() if service else None,
                            byref(hints), byref(res))
    if rc != 0:
        say("GAIERROR %d %s" % (rc, libc().gai_strerror(rc).decode()))
        return 1
    try:
        while res:
            ai = res.contents
            raw = ctypes.string_at(ai.ai_addr, ai.ai_addrlen)
            addr, port = sockaddr_address(ai.ai_family, raw)
            say("family=%d socktype=%d addr=%s port=%d"
                % (ai.ai_family, ai.ai_socktype, addr, port))
            res = ai.ai_next
    finally:
        libc().freeaddrinfo(res)
    return 0


def worker_hostent(name, af):
    """One glibc gethostbyname*() call: the legacy hostent path."""
    if af == socket.AF_UNSPEC:
        host = libc().gethostbyname(name.encode())
    else:
        host = libc().gethostbyname2(name.encode(), af)
    if not host:
        herr = libc().__h_errno_location().contents.value
        say("HOSTERROR %d %s" % (herr, libc().hstrerror(herr).decode()))
        return 1
    ent = host.contents
    say("h_name=%s h_addrtype=%d h_length=%d"
        % (ent.h_name.decode(), ent.h_addrtype, ent.h_length))
    i = 0
    while ent.h_addr_list[i]:
        raw = ctypes.string_at(ent.h_addr_list[i], ent.h_length)
        say("addr=%s" % socket.inet_ntop(ent.h_addrtype, raw))
        i += 1
    return 0


def worker_reverse(ip):
    """One glibc gethostbyaddr() call through the module."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    packed = socket.inet_pton(family, ip)
    host = libc().gethostbyaddr(packed, len(packed), family)
    if not host:
        herr = libc().__h_errno_location().contents.value
        say("HOSTERROR %d %s" % (herr, herror_name(herr)))
        return 1
    ent = host.contents
    say("h_name=%s h_addrtype=%d h_length=%d"
        % (ent.h_name.decode(), ent.h_addrtype, ent.h_length))
    if ent.h_aliases:
        j = 0
        while ent.h_aliases[j]:
            say("alias=%s" % ent.h_aliases[j].decode())
            j += 1
    i = 0
    while ent.h_addr_list[i]:
        raw = ctypes.string_at(ent.h_addr_list[i], ent.h_length)
        say("addr=%s" % socket.inet_ntop(ent.h_addrtype, raw))
        i += 1
    return 0


def worker_reverse_status(ip):
    """Call the module's reverse entry point directly to see its status."""
    lib = ctypes.CDLL(MODULE)
    fn = lib._nss_netd_gethostbyaddr2_r
    fn.restype = c_int
    fn.argtypes = [c_void_p, c_uint32, c_int, POINTER(HostEnt), c_void_p,
                   c_size_t, POINTER(c_int), POINTER(c_int), c_void_p]
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    raw = socket.inet_pton(family, ip)
    packed = ctypes.create_string_buffer(raw, 16)
    host, buf = HostEnt(), ctypes.create_string_buffer(1024)
    err, herr = c_int(0), c_int(0)
    status = fn(ctypes.addressof(packed), len(raw), family, byref(host),
                ctypes.addressof(buf), 1024, byref(err), byref(herr), None)
    say("status=%s errno=%s h_errno=%s"
        % (status_name(status), errno_name(err.value), herror_name(herr.value)))
    tiny = ctypes.create_string_buffer(8)
    status = fn(ctypes.addressof(packed), len(raw), family, byref(host),
                ctypes.addressof(tiny), 8, byref(err), byref(herr), None)
    say("tiny status=%s errno=%s"
        % (status_name(status), errno_name(err.value)))
    return 0


def worker_name_rule(name):
    """Call the entry point directly to see the exact NSS status, errno and
    h_errno for a name the module has to refuse before it talks to netd."""
    _lib, fn = open_entry_point()
    pat, err, herr = POINTER(AddrTuple)(), c_int(0), c_int(0)
    buf = ctypes.create_string_buffer(1024)
    status = fn(name.encode(), byref(pat), ctypes.addressof(buf), 1024,
                byref(err), byref(herr), None)
    say("status=%s errno=%s h_errno=%s"
        % (status_name(status), errno_name(err.value), herror_name(herr.value)))
    return 0


def worker_erange(name):
    """A tiny buffer has to come back as TRYAGAIN/ERANGE, and what a big one
    fills in is the answer: one tuple per address, v4 first."""
    _lib, fn = open_entry_point()
    pat, err = POINTER(AddrTuple)(), c_int(0)
    herr = c_int(0)
    tiny = ctypes.create_string_buffer(8)
    status = fn(name.encode(), byref(pat), ctypes.addressof(tiny), 8,
                byref(err), byref(herr), None)
    say("tiny status=%s errno=%s" % (status_name(status), errno_name(err.value)))
    if status != NSS_STATUS_TRYAGAIN or err.value != errno.ERANGE:
        say("FAIL tiny buffer: want TRYAGAIN/ERANGE")
        return 1
    big = ctypes.create_string_buffer(4096)
    status = fn(name.encode(), byref(pat), ctypes.addressof(big), 4096,
                byref(err), byref(herr), None)
    say("big status=%s" % status_name(status))
    if status != NSS_STATUS_SUCCESS:
        return 1
    for line in addrtuple_lines(pat):
        say(line)
    return 0


def worker_misaligned(name):
    """The caller's buffer may start anywhere, so the module has to align
    the tuples inside it - and the size it asks glibc to grow to has to count
    the padding that costs."""
    _lib, fn = open_entry_point()
    raw = ctypes.create_string_buffer(4096)
    buf, buflen = ctypes.addressof(raw) + 1, 4095  # one byte off, deliberately
    pat, err, herr = POINTER(AddrTuple)(), c_int(0), c_int(0)
    status = fn(name.encode(), byref(pat), buf, buflen, byref(err), byref(herr),
                None)
    if status != NSS_STATUS_SUCCESS:
        say("FAIL unaligned buffer: status=%s" % status_name(status))
        return 1
    align = ctypes.alignment(AddrTuple)
    say("misaligned pat_align=%d" % (ctypes.cast(pat, c_void_p).value % align))
    tuples, t = 0, pat
    while t:
        tuples += 1
        t = t.contents.next
    namelen = len(pat.contents.name) + 1
    needed = (-buf) % align + tuples * ctypes.sizeof(AddrTuple) + namelen
    say("needed=%d tuples=%d" % (needed, tuples))
    for line in addrtuple_lines(pat):
        say(line)
    status = fn(name.encode(), byref(pat), buf, needed, byref(err), byref(herr),
                None)
    if status != NSS_STATUS_SUCCESS:
        say("FAIL exact size: %d bytes, status=%s" % (needed, status_name(status)))
        return 1
    status = fn(name.encode(), byref(pat), buf, needed - 1, byref(err),
                byref(herr), None)
    say("short status=%s errno=%s" % (status_name(status), errno_name(err.value)))
    if status != NSS_STATUS_TRYAGAIN or err.value != errno.ERANGE:
        return 1
    return 0


def worker_main(argv):
    mode, name = argv[0], argv[1]
    service = argv[2] if len(argv) > 2 else "-"
    hosts = os.environ.get("NSS_HOSTS")
    if hosts is not None:
        if libc().__nss_configure_lookup(b"hosts", hosts.encode()) != 0:
            say("BAD-SERVICE-LIST %s" % hosts)
            return 2
    service = None if service == "-" else service
    if mode == "addrinfo":
        return worker_addrinfo(name, service, socket.AF_UNSPEC, 0)
    if mode == "v4mapped":
        return worker_addrinfo(name, service, socket.AF_INET6, socket.AI_V4MAPPED)
    if mode == "hostent":
        return worker_hostent(name, socket.AF_UNSPEC)
    if mode == "hostent6":
        return worker_hostent(name, socket.AF_INET6)
    if mode == "reverse":
        return worker_reverse(name)
    if mode == "reverse-status":
        return worker_reverse_status(name)
    if mode == "name-rule":
        return worker_name_rule(name)
    if mode == "erange":
        return worker_erange(name)
    if mode == "misaligned":
        return worker_misaligned(name)
    say("unknown mode %s" % mode)
    return 2


# --------------------------------------------------------------- test driver

Addr = collections.namedtuple("Addr", "family socktype addr port")
ADDR_RE = re.compile(r"^family=(-?\d+) socktype=(-?\d+) addr=(.*) port=(\d+)$")
GAI_RE = re.compile(r"^GAIERROR (-?\d+)")
HOST_RE = re.compile(r"^h_name=(.*) h_addrtype=(-?\d+) h_length=(-?\d+)$",
                     re.M)


def A(addr):
    return Addr(int(socket.AF_INET), int(socket.SOCK_STREAM), addr, 0)


def A6(addr):
    return Addr(int(socket.AF_INET6), int(socket.SOCK_STREAM), addr, 0)


def MAPPED(addr):
    return Addr(int(socket.AF_INET6), int(socket.SOCK_STREAM),
                "::ffff:" + addr, 0)


FALLBACK = [A("203.0.113.53")]


def parse_addrs(text):
    addrs = []
    for line in text.splitlines():
        match = ADDR_RE.match(line)
        if match:
            addrs.append(Addr(int(match[1]), int(match[2]), match[3],
                              int(match[4])))
    return addrs


def tuple_lines(text):
    return [line for line in text.splitlines() if line.startswith("tuple ")]


def slow(test):
    """Mark a test that waits out a real timeout: FAST=1 skips it."""
    return unittest.skipIf(os.environ.get("FAST") == "1",
                           "FAST=1 skips tests that wait out a timeout")(test)


def _socket_ready(path):
    try:
        return stat.S_ISSOCK(os.stat(path).st_mode)
    except OSError:
        return False


def _cleanup():
    global _daemon, WORK
    if _daemon is not None:
        _daemon.terminate()
        try:
            _daemon.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _daemon.kill()
            _daemon.wait()
        if _daemon.stdout is not None:
            _daemon.stdout.close()
        _daemon = None
    if WORK is not None:
        shutil.rmtree(WORK, ignore_errors=True)
        WORK = None


def setUpModule():
    """Build the fake dns service and start the fake netd daemon."""
    global WORK, SOCK, _daemon
    if not os.path.isfile(MODULE):
        raise RuntimeError("run make check first (it builds the test module)")
    cc = shlex.split(os.environ.get("CC", "cc"))
    if not shutil.which(cc[0]):
        raise RuntimeError("no C compiler found ($CC=%s); install one or set CC="
                           % os.environ.get("CC", "cc"))
    WORK = tempfile.mkdtemp(prefix="libnss-netd-test.")
    atexit.register(_cleanup)
    cmd = cc + ["-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-o",
                os.path.join(WORK, "libnss_fakedns.so.2"), FAKEDNS_C]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError("cannot build the fake dns service ($CC=%s):\n%s%s"
                           % (" ".join(cc), proc.stdout, proc.stderr))
    SOCK = os.path.join(WORK, "dnsproxyd")
    _daemon = subprocess.Popen([sys.executable, FAKE_DNSPROXYD, SOCK],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not _socket_ready(SOCK):
        if _daemon.poll() is not None:
            raise RuntimeError("the fake dnsproxyd exited: %s"
                               % (_daemon.stdout.read() if _daemon.stdout else ""))
        time.sleep(0.05)
    if not _socket_ready(SOCK):
        raise RuntimeError("the fake dnsproxyd never created %s" % SOCK)


def tearDownModule():
    _cleanup()


class NetdTestCase(unittest.TestCase):
    """Run one lookup in a fresh process and assert on what it printed."""

    maxDiff = None

    def run_worker(self, *args, hosts=None, netd_socket=None, library_path=None,
                   cwd=None, timeout=WORKER_TIMEOUT):
        env = dict(os.environ)
        if library_path is None:
            # Keep the test modules ahead of the interpreter's search path.
            paths = [TESTDIR, ROOT, WORK]
            if env.get("LD_LIBRARY_PATH"):
                paths.append(env["LD_LIBRARY_PATH"])
            library_path = os.pathsep.join(paths)
        env["LD_LIBRARY_PATH"] = library_path
        # A preloaded libnss_netd.so.2 (for example /etc/ld-nix.so.preload on
        # Nix-on-Droid) wins the SONAME lookup before LD_LIBRARY_PATH. Preload
        # the test module so NSS resolves "netd" to this copy. LD_PRELOAD is
        # loaded before /etc/ld.so.preload, so appending still beats a module
        # from the preload file while keeping any existing preload first: an
        # instrumented module must not be loaded before the sanitizer runtime.
        if os.path.exists(MODULE) and TESTDIR in library_path.split(os.pathsep):
            preload = [MODULE]
            if env.get("LD_PRELOAD"):
                preload.insert(0, env["LD_PRELOAD"])
            env["LD_PRELOAD"] = os.pathsep.join(preload)
        env["NETDNS_SOCKET"] = SOCK if netd_socket is None else netd_socket
        env["NSS_HOSTS"] = DEFAULT_HOSTS if hosts is None else hosts
        cmd = [sys.executable, SELF, "--worker", *args]
        try:
            return subprocess.run(cmd, env=env, cwd=cwd, capture_output=True,
                                  text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            self.fail("%s did not finish within %ss: %s"
                      % (" ".join(cmd), timeout, exc))

    @staticmethod
    def output(proc):
        return proc.stdout + proc.stderr

    def assert_addrs(self, name, expected, mode="addrinfo", **kwargs):
        """One lookup; the answered addresses must be exactly expected.

        Order is not asserted: glibc sorts a getaddrinfo() result by the
        host's own address configuration. The module's own tuple order is
        checked by AbiTest, where nothing sorts it.
        """
        proc = self.run_worker(mode, name, "-", **kwargs)
        text = self.output(proc)
        self.assertEqual(proc.returncode, 0, text)
        self.assertCountEqual(list(expected), parse_addrs(proc.stdout), text)

    def assert_fallback(self, name, **kwargs):
        """The module must decline, so the fake dns service answers."""
        self.assert_addrs(name, FALLBACK, **kwargs)

    def assert_gai_error(self, name, code, mode="addrinfo", **kwargs):
        proc = self.run_worker(mode, name, "-", **kwargs)
        text = self.output(proc)
        self.assertEqual(proc.returncode, 1, text)
        self.assertEqual([], parse_addrs(proc.stdout), text)
        match = GAI_RE.search(proc.stdout)
        self.assertIsNotNone(match, text)
        self.assertEqual(code, int(match[1]), text)

    def hostent(self, name, mode="hostent", **kwargs):
        proc = self.run_worker(mode, name, "-", **kwargs)
        text = self.output(proc)
        self.assertEqual(proc.returncode, 0, text)
        match = HOST_RE.search(proc.stdout)
        self.assertIsNotNone(match, text)
        addrs = [line[len("addr="):] for line in proc.stdout.splitlines()
                 if line.startswith("addr=")]
        return (match[1], int(match[2]), int(match[3])), addrs

    def abi(self, mode, name):
        proc = self.run_worker(mode, name, "-")
        self.assertEqual(proc.returncode, 0, self.output(proc))
        return proc

    def probe(self, *args, timeout=WORKER_TIMEOUT):
        cmd = [sys.executable, PROBE, *args]
        try:
            return subprocess.run(cmd, env=dict(os.environ, DNSPROXYD=SOCK),
                                  capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            self.fail("%s did not finish within %ss: %s"
                      % (" ".join(cmd), timeout, exc))


class AnswersTest(NetdTestCase):
    """Successful lookups through glibc's NSS plumbing."""

    # name, mode, expected addresses, what the row proves
    ADDR_CASES = [
        ("a.test", "addrinfo",
         [A("192.0.2.1"), A("192.0.2.2"), A6("2001:db8::1")],
         "A and AAAA records"),
        ("dup.test", "addrinfo", [A("192.0.2.9"), A6("2001:db8::9")],
         "an address repeated per socktype is collapsed"),
        ("many.test", "addrinfo", [A("192.0.2.%d" % i) for i in range(1, 31)],
         "30 tuples; they exceed glibc's scratch buffer on 64-bit"),
        ("many40.test", "addrinfo", [A("192.0.2.%d" % i) for i in range(1, 33)],
         "over MAX_ADDRS the rest is dropped"),
        ("canon.test", "v4mapped", [MAPPED("192.0.2.11")],
         "AI_V4MAPPED maps netd's A record"),
        ("v6.test", "v4mapped", [A6("2001:db8::6")],
         "AI_V4MAPPED keeps a native AAAA"),
    ]
    # name, mode, (h_name, h_addrtype, h_length), addresses, what the row proves
    HOSTENT_CASES = [
        ("a.test", "hostent", ("a.test", socket.AF_INET, 4),
         ["192.0.2.1", "192.0.2.2"], "the legacy gethostbyname path"),
        ("v6.test", "hostent6", ("v6.test", socket.AF_INET6, 16),
         ["2001:db8::6"], "gethostbyname2 for an AAAA-only name"),
        ("canon.test", "hostent", ("real.test", socket.AF_INET, 4),
         ["192.0.2.11"], "netd's canonical name"),
        ("alias.test", "hostent", ("a.test", socket.AF_INET, 4),
         ["192.0.2.1", "192.0.2.2"], "an alias's canonical name"),
        ("zerocanon.test", "hostent", ("zerocanon.test", socket.AF_INET, 4),
         ["192.0.2.20"], "no canonical name: the query name"),
    ]

    def test_address_answers(self):
        for name, mode, expected, why in self.ADDR_CASES:
            with self.subTest(name=name, why=why):
                self.assert_addrs(name, expected, mode=mode)

    def test_hostent_answers(self):
        for name, mode, header, addrs, why in self.HOSTENT_CASES:
            with self.subTest(name=name, why=why):
                self.assertEqual((header, addrs), self.hostent(name, mode=mode))


class StatusTest(NetdTestCase):
    """What the module answers decides whether the chain stops or goes on.

    The default list ends in [NOTFOUND=return], so a NOTFOUND from netd is
    final while everything else reaches the fake dns service.
    """

    FINAL = [
        ("nx.test", EAI_NONAME, "netd EAI_NONAME -> HOST_NOT_FOUND"),
        ("noname.test", EAI_NODATA, "an empty success reply -> NO_DATA"),
        ("nodata.test", EAI_NODATA, "netd EAI_NODATA -> NO_DATA"),
        ("addr.test", EAI_NODATA, "netd EAI_ADDRFAMILY -> NO_DATA"),
        ("service.test", EAI_NONAME, "netd EAI_SERVICE -> HOST_NOT_FOUND"),
    ]

    def test_final_answers(self):
        for name, code, why in self.FINAL:
            with self.subTest(name=name, why=why):
                self.assert_gai_error(name, code)

    def test_transient_errors_reach_the_next_service(self):
        for name in ("again.test", "fail.test", "memory.test", "broken.test"):
            with self.subTest(name=name):
                self.assert_fallback(name)

    def test_tryagain_is_not_unavail(self):
        # TRYAGAIN and UNAVAIL both continue the chain by default, so make
        # TRYAGAIN final. Only the right status keeps the caller's error.
        for name in ("again.test", "fail.test", "memory.test"):
            with self.subTest(name=name):
                self.assert_gai_error(name, EAI_AGAIN, hosts=TRYAGAIN_HOSTS)

    def test_notfound_continues_without_a_return_action(self):
        self.assert_fallback("blocked.test", hosts="files netd fakedns")

    def test_unavail_is_not_tryagain(self):
        self.assert_gai_error("blocked.test", EAI_SYSTEM,
                              netd_socket=os.path.join(WORK, "nope"),
                              hosts="files netd [UNAVAIL=return] fakedns")


class LoadingTest(NetdTestCase):
    """A missing daemon or module, service order, and NETDNS_SOCKET."""

    def test_missing_daemon_falls_through(self):
        self.assert_fallback("blocked.test",
                             netd_socket=os.path.join(WORK, "nope"))

    def test_missing_module_falls_through(self):
        # A globally preloaded libnss_netd.so.2 exports its symbols; a copy
        # loaded by these tests does not.
        if getattr(ctypes.CDLL(None), "_nss_netd_gethostbyname4_r",
                   None) is not None:
            self.skipTest("libnss_netd.so.2 is preloaded, so it cannot be "
                          "made missing")
        only_fallback = os.path.join(WORK, "only-fallback")
        os.makedirs(only_fallback, exist_ok=True)
        shutil.copy(os.path.join(WORK, "libnss_fakedns.so.2"), only_fallback)
        self.assert_fallback("blocked.test", library_path=only_fallback)

    def test_service_order_is_respected(self):
        self.assert_fallback("blocked.test", hosts="fakedns files netd")

    def test_relative_socket_override_is_ignored(self):
        # From a directory where "dnsproxyd" is a live relative path: only an
        # absolute path names a socket the module may use.
        self.assert_fallback("a.test", netd_socket="dnsproxyd", cwd=WORK)

    def test_socket_path_over_sun_path_falls_through(self):
        self.assert_fallback("a.test", netd_socket=os.path.join(WORK, "x" * 120))


class HostileReplyTest(NetdTestCase):
    """Replies the module must refuse, or bound, instead of answering from."""

    BROKEN = [
        ("garbage.test", "a result code that is neither 222 nor 401"),
        ("badresult.test", "222 with a fourth byte that is not NUL"),
        ("wrongerror.test", "a four-byte EAI payload off the 401 frame"),
        ("longerr.test", "a 401 frame whose payload length lies"),
        ("nulcode.test", "four digits and no NUL"),
        ("badaddr.test", "addrlen past sockaddr_storage"),
        ("negaddr.test", "a negative addrlen"),
        ("negcanon.test", "a negative canonname length"),
        ("unterminatedcanon.test", "a canonical name without its NUL"),
        ("truncated.test", "a record cut off before the canonname length"),
        ("bigcanon.test", "a canonical name over MAX_CANONNAME"),
    ]

    def test_broken_replies_fall_through(self):
        for name, why in self.BROKEN:
            with self.subTest(name=name, why=why):
                self.assert_fallback(name)

    def test_endless_record_stream_is_capped(self):
        # The record cap, not the deadline, has to end this quickly.
        start = time.monotonic()
        self.assert_fallback("flood.test", timeout=20)
        self.assertLessEqual(time.monotonic() - start, 3)

    def test_reply_dribbled_in_pieces(self):
        self.assert_addrs("dribble.test", [A("192.0.2.7")])

    @slow
    def test_reply_trickled_past_the_deadline(self):
        # Every single read stays under the socket timeout while the reply as
        # a whole does not: only the deadline can end this lookup.
        start = time.monotonic()
        self.assert_fallback("trickle.test", timeout=20)
        self.assertLessEqual(time.monotonic() - start, 10)


class NameRulesTest(NetdTestCase):
    """Names are rejected locally, where bionic would reject them too."""

    def test_254_byte_absolute_name_resolves(self):
        self.assert_addrs(VALID_FQDN, [A("192.0.2.77")])

    def test_name_over_254_bytes_is_rejected(self):
        self.assert_gai_error(LONG_NAME, EAI_NODATA)

    def test_rejected_characters(self):
        # The fake daemon answers any ".accept.test" name, so a rule that
        # loses a character turns a rejection into a resolution.
        for prefix in ("bad name", "tab\ttest", "lf\ntest", "cr\rtest",
                       "caret^test", "sq'test", 'dq"test'):
            with self.subTest(name=prefix):
                self.assert_gai_error(prefix + ACCEPT_SUFFIX, EAI_NODATA)

    def test_empty_name_is_rejected_locally(self):
        # The direct call shows the exact status, errno and h_errno. glibc
        # only surfaces the resulting GAI error. No daemon is listening, so
        # a module that talked to netd anyway would answer UNAVAIL instead.
        proc = self.run_worker("name-rule", "", "-",
                               netd_socket=os.path.join(WORK, "nope"))
        self.assertEqual(proc.returncode, 0, self.output(proc))
        self.assertIn("status=NOTFOUND errno=ENOENT h_errno=NO_DATA",
                      proc.stdout)

    def test_empty_name_is_rejected_before_netd(self):
        # glibc hands empty names to NSS, so this goes through the whole
        # chain. The netd socket is missing: a module that did not refuse
        # locally would answer UNAVAIL and let fakedns resolve the name.
        self.assert_gai_error("", EAI_NODATA,
                              netd_socket=os.path.join(WORK, "nope"))


class ReverseLookupTest(NetdTestCase):
    """gethostbyaddr() through netd's gethostbyaddr command."""

    def test_ipv4(self):
        proc = self.run_worker("reverse", "192.0.2.1", "-")
        text = self.output(proc)
        self.assertEqual(proc.returncode, 0, text)
        self.assertIn("h_name=ptr.test h_addrtype=2 h_length=4", text)
        self.assertIn("addr=192.0.2.1", text)
        self.assertIn("alias=alias.ptr.test", text)
        self.assertIn("alias=second.ptr.test", text)

    def test_ipv6(self):
        proc = self.run_worker("reverse", "2001:db8::1", "-")
        text = self.output(proc)
        self.assertEqual(proc.returncode, 0, text)
        self.assertIn("h_name=ptr6.test h_addrtype=10 h_length=16", text)
        self.assertIn("addr=2001:db8::1", text)

    def test_not_found(self):
        proc = self.run_worker("reverse", "192.0.2.99", "-")
        text = self.output(proc)
        self.assertEqual(proc.returncode, 1, text)
        self.assertIn("HOSTERROR 1 HOST_NOT_FOUND", text)

    def test_aliases_are_capped(self):
        proc = self.run_worker("reverse", "192.0.2.2", "-")
        text = self.output(proc)
        self.assertEqual(proc.returncode, 0, text)
        aliases = [line for line in text.splitlines()
                   if line.startswith("alias=")]
        self.assertEqual(32, len(aliases))
        self.assertIn("alias=alias31.test", text)
        self.assertNotIn("alias=alias32.test", text)

    def test_malformed_reply_is_unavail(self):
        proc = self.run_worker("reverse-status", "192.0.2.250", "-")
        text = self.output(proc)
        self.assertEqual(proc.returncode, 0, text)
        self.assertIn("status=UNAVAIL errno=EAGAIN h_errno=-1", text)

    def test_broken_replies_are_unavail(self):
        # Bad addrtype, an oversized address chunk, an alias without its NUL,
        # and a 401 whose length says a payload follows.
        for ip in ("192.0.2.251", "192.0.2.252", "192.0.2.253",
                   "192.0.2.254"):
            with self.subTest(ip=ip):
                proc = self.run_worker("reverse-status", ip, "-")
                text = self.output(proc)
                self.assertEqual(proc.returncode, 0, text)
                self.assertIn("status=UNAVAIL errno=EAGAIN h_errno=-1", text)

    def test_small_buffer_is_retried(self):
        proc = self.run_worker("reverse-status", "192.0.2.1", "-")
        text = self.output(proc)
        self.assertEqual(proc.returncode, 0, text)
        self.assertIn("tiny status=TRYAGAIN errno=ERANGE", text)

    def test_empty_success_is_no_data(self):
        proc = self.run_worker("reverse-status", "192.0.2.248", "-")
        text = self.output(proc)
        self.assertEqual(proc.returncode, 0, text)
        self.assertIn("status=NOTFOUND errno=ENOENT h_errno=NO_DATA", text)

    def test_empty_success_reaches_glibc_as_no_data(self):
        proc = self.run_worker("reverse", "192.0.2.248", "-")
        text = self.output(proc)
        self.assertEqual(proc.returncode, 1, text)
        self.assertIn("HOSTERROR 4 NO_DATA", text)

    def test_addresses_are_capped(self):
        proc = self.run_worker("reverse", "192.0.2.255", "-")
        text = self.output(proc)
        self.assertEqual(proc.returncode, 0, text)
        addrs = [line for line in text.splitlines()
                 if line.startswith("addr=")]
        self.assertEqual(32, len(addrs))
        self.assertIn("addr=192.0.2.32", addrs)
        self.assertNotIn("addr=192.0.2.33", addrs)

    def test_endless_address_stream_is_capped(self):
        # The record cap, not the deadline, has to end this quickly.
        start = time.monotonic()
        proc = self.run_worker("reverse", "192.0.2.249", "-", timeout=20)
        text = self.output(proc)
        self.assertEqual(proc.returncode, 1, text)
        self.assertLessEqual(time.monotonic() - start, 3)


class AbiTest(NetdTestCase):
    """The gethostbyname4_r entry point, called directly."""

    def test_small_buffer_is_retried_and_tuples_come_v4_first(self):
        proc = self.abi("erange", "a.test")
        self.assertIn("tiny status=TRYAGAIN errno=ERANGE", proc.stdout)
        self.assertIn("big status=SUCCESS", proc.stdout)
        self.assertEqual(["tuple family=2 addr=192.0.2.1 next=yes",
                          "tuple family=2 addr=192.0.2.2 next=yes",
                          "tuple family=10 addr=2001:db8::1 next=no"],
                         tuple_lines(proc.stdout))

    def test_misaligned_buffer(self):
        proc = self.abi("misaligned", "a.test")
        self.assertIn("misaligned pat_align=0", proc.stdout)
        match = re.search(r"^needed=(\d+) tuples=(\d+)$", proc.stdout, re.M)
        self.assertIsNotNone(match, self.output(proc))
        needed, tuples = int(match[1]), int(match[2])
        self.assertEqual(3, tuples)
        # The size the module asks glibc to grow to has to include the
        # padding it inserts: the worker verified that exactly this many
        # bytes succeed and that one byte less does not.
        padding = needed - tuples * ctypes.sizeof(AddrTuple) - len("a.test") - 1
        self.assertGreaterEqual(padding, 0)
        self.assertLess(padding, ctypes.alignment(AddrTuple))
        self.assertIn("short status=TRYAGAIN errno=ERANGE", proc.stdout)
        self.assertEqual(["tuple family=2 addr=192.0.2.1 next=yes",
                          "tuple family=2 addr=192.0.2.2 next=yes",
                          "tuple family=10 addr=2001:db8::1 next=no"],
                         tuple_lines(proc.stdout))


class ProbeTest(NetdTestCase):
    """tools/gai-probe.py has to survive the replies the module survives."""

    def test_reports_addresses(self):
        proc = self.probe("a.test")
        text = self.output(proc)
        self.assertEqual(proc.returncode, 0, text)
        self.assertIn("addr=192.0.2.1", text)
        self.assertIn("addr=2001:db8::1", text)
        self.assertIn("canon='a.test'", text)
        self.assertIn("3 address record(s) for a.test", text)

    def test_reports_an_eai_error(self):
        proc = self.probe("nx.test")
        text = self.output(proc)
        self.assertEqual(proc.returncode, 1, text)
        self.assertIn("EAI 8 EAI_NONAME", text)

    def test_escapes_text_errors(self):
        proc = self.probe("badcmd.test")
        text = self.output(proc)
        self.assertEqual(proc.returncode, 1, text)
        self.assertIn(r"'501 bad command \x1b[31mwith an escape'", text)
        self.assertNotIn("\x1b[31m", text)

    def test_reverse_reports_a_hostent(self):
        proc = self.probe("192.0.2.1")
        text = self.output(proc)
        self.assertEqual(proc.returncode, 0, text)
        self.assertIn("h_name='ptr.test' addrtype=2 h_length=4", text)
        self.assertIn("alias='alias.ptr.test'", text)
        self.assertIn("addr=192.0.2.1", text)

    def test_reverse_reports_ipv6(self):
        proc = self.probe("2001:db8::1")
        text = self.output(proc)
        self.assertEqual(proc.returncode, 0, text)
        self.assertIn("h_name='ptr6.test' addrtype=10 h_length=16", text)
        self.assertIn("addr=2001:db8::1", text)

    def test_reverse_reports_a_failure(self):
        proc = self.probe("192.0.2.99")
        text = self.output(proc)
        self.assertEqual(proc.returncode, 1, text)
        self.assertIn("DnsProxyOperationFailed", text)
        self.assertIn("no payload", text)

    def test_non_address_still_uses_getaddrinfo(self):
        proc = self.probe("999.1.2.3")
        text = self.output(proc)
        self.assertIn("getaddrinfo 999.1.2.3", text)

    def test_bounds_an_endless_stream(self):
        proc = self.probe("flood.test", timeout=20)
        text = self.output(proc)
        self.assertEqual(proc.returncode, 1, text)
        self.assertIn("record limit", text)
        # Bounded by the record cap (256 records plus the header and the
        # error), not by how long the daemon felt like talking.
        self.assertLessEqual(len(text.splitlines()), 300, text)

    @slow
    def test_reports_a_stalled_daemon(self):
        proc = self.probe("hang.test", timeout=20)
        text = self.output(proc)
        self.assertNotEqual(proc.returncode, 0, text)
        self.assertIn("did not answer", text)


class DeadlineTest(NetdTestCase):
    """A daemon that accepts the command and then says nothing."""

    @slow
    def test_lookup_is_bounded_by_the_deadline(self):
        start = time.monotonic()
        self.assert_fallback("hang.test", timeout=20)
        elapsed = time.monotonic() - start
        self.assertGreaterEqual(elapsed, 4)
        self.assertLessEqual(elapsed, 15)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        sys.exit(worker_main(sys.argv[2:]))
    unittest.main(verbosity=2)
