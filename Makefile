# libnss_netd.so.2 - resolve host names through Android's netd resolver.
CC ?= cc
# -D_FORTIFY_SOURCE (in HARDEN) needs optimization to do anything, and says so
# with a #warning when it has none: keep -O in CFLAGS if you override it.
CFLAGS ?= -O2 -Wall -Wextra
# The installed module has a compile-time socket path and no runtime override.
# The test build adds the NETDNS_SOCKET override the suite needs. SOCKET must
# be absolute, or a privileged process could be redirected through its cwd.
SOCKET ?= /dev/socket/dnsproxyd
ifneq ($(SOCKET),$(filter /%,$(SOCKET)))
$(error SOCKET must be an absolute path)
endif
SOCKET_FLAGS = -DNETDNS_SOCKET_PATH='"$(SOCKET)"'
# The suite points NETDNS_SOCKET at its fake daemon, but one case lets a
# relative override fall through to the compile-time path. Test with one
# that cannot exist, or on Android that case would reach the real dnsproxyd.
TEST_SOCKET ?= /nonexistent/libnss-netd-test/dnsproxyd
ifneq ($(TEST_SOCKET),$(filter /%,$(TEST_SOCKET)))
$(error TEST_SOCKET must be an absolute path)
endif
TEST_SOCKET_FLAGS = -DNETDNS_SOCKET_PATH='"$(TEST_SOCKET)"'
# An NSS module can load into any process using glibc NSS host lookup and
# parses what another process sends it. glibc opens it by the
# libnss_netd.so.2 filename, so keep the SONAME the same. Otherwise the
# loader can register one file under two names.
# Overriding HARDEN= removes the hardening along with it.
HARDEN ?= -fstack-protector-strong -fstack-clash-protection -D_FORTIFY_SOURCE=2
# -z defs: a module dlopen()ed into arbitrary programs must not leave symbols
# for the host process to resolve.
LDSO = -Wl,-soname,$(MODULE) -Wl,-z,relro,-z,now -Wl,-z,defs
PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib

MODULE = libnss_netd.so.2
TEST_MODULE = test/$(MODULE)

all: $(MODULE)

$(MODULE): libnss_netd.c
	$(CC) -shared -fPIC $(CPPFLAGS) $(SOCKET_FLAGS) $(CFLAGS) $(HARDEN) \
		$(LDSO) -o $@ $<

$(TEST_MODULE): libnss_netd.c
	$(CC) -shared -fPIC $(CPPFLAGS) $(TEST_SOCKET_FLAGS) \
		-DNETDNS_ALLOW_SOCKET_OVERRIDE $(CFLAGS) $(HARDEN) $(LDSO) \
		-o $@ $<

check: $(TEST_MODULE)
	python3 test/test_libnss_netd.py

install: $(MODULE)
	install -Dm644 $(MODULE) $(DESTDIR)$(LIBDIR)/$(MODULE)

uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/$(MODULE)

clean:
	rm -f $(MODULE) $(TEST_MODULE)

.PHONY: all check install uninstall clean
