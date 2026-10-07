# libnss-netd

`libnss-netd` is a glibc NSS module for host name lookups on Android. It sends
glibc's requests to Android's resolver through `/dev/socket/dnsproxyd`, so a
glibc program can use the same network, VPN, Private DNS, search domains, and
DNS64 settings as Android apps.

This is mainly for glibc environments running under Termux, such as
proot-distro, Nix-on-Droid, or a chroot. Termux packages built against bionic
already use Android's resolver.

## Requirements

- Android 6.0 or newer: the parser expects the `dnsproxyd` reply format used
  by those releases.
- A glibc environment with a C compiler and development headers. The module
  uses `clock_gettime()` from glibc 2.17 or newer. Test builds also use
  `secure_getenv()`.
- Access to `/dev/socket/dnsproxyd` and permission to use the network. For an
  app such as Termux, that normally means the `INTERNET` permission. A working
  glibc install alone is not enough.

## Build and install

```sh
make
make check                 # Python unittest suite, no Android device needed
sudo make install          # installs libnss_netd.so.2 to /usr/local/lib
echo /usr/local/lib | sudo tee /etc/ld.so.conf.d/libnss-netd.conf
sudo ldconfig
```

`PREFIX`, `LIBDIR`, and `DESTDIR` can be passed to `make install` if the
default path does not suit the target glibc environment. Run the install and
`ldconfig` commands *inside that environment*. If the shell is already root,
omit `sudo`.

`SOCKET` changes the compile-time path of `/dev/socket/dnsproxyd`. It must be
absolute. The installed module has no runtime override. Only the test build
honors the `NETDNS_SOCKET` environment variable, which the suite uses for its
fake daemon.

Then set the `hosts` entry in its `/etc/nsswitch.conf`:

```text
hosts: files netd
```

With this setting, `/etc/hosts` is checked first. Other forward and reverse
lookups go to netd. If the socket or module is unavailable, there is no DNS
fallback.

If you want glibc's usual `dns` service as a fallback, use:

```text
hosts: files netd [NOTFOUND=return] dns
```

Here, successful answers and negative answers from netd are final. A temporary
error, an unavailable socket, or a reply the module cannot parse continues to
`dns`, which reads `/etc/resolv.conf`. Netd may also return a temporary or
system error when it refuses a query. In that case the fallback can resolve a
name that Android refused. Use `hosts: files netd` if netd's decision must be
final.

### Nix-on-Droid

nixpkgs' glibc does not use the system `/etc/ld.so.cache`, so installing the
module in `/usr/local/lib` and running `ldconfig` may not make it loadable.
Put the directory containing `libnss_netd.so.2` on the loader path instead:

```sh
export LD_LIBRARY_PATH="/path/to/libnss-netd${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
```

Use a directory that other users cannot write to. The loader ignores
`LD_LIBRARY_PATH` for setuid and setgid programs. Those need the module in a
path their glibc loader already searches.

Nix's `preloadNSS()` overrides the hosts database inside its own process,
bypassing `/etc/nsswitch.conf`. Preload both files into nixpkgs' glibc preload
file, `/etc/ld-nix.so.preload`:

```text
/path/to/libnss-netd/nss-hosts-shim.so
/path/to/libnss-netd/libnss_netd.so.2
```

Set `NSS_HOSTS_SHIM_DEBUG=1` to log ignored overrides.

## Check on a device

After installation, try normal glibc lookups:

```sh
getent ahosts example.com   # forward
getent hosts 192.0.2.1      # reverse
```

To check the Android side separately, run:

```sh
python3 tools/gai-probe.py example.com   # getaddrinfo
python3 tools/gai-probe.py 192.0.2.1     # gethostbyaddr
```

The probe speaks the same commands over `dnsproxyd` without loading the NSS
module. If it cannot connect, check the socket path and the process's Android
UID and `INTERNET` permission. If the probe returns addresses but `getent`
does not, check the module's loader path and the `hosts` entry in
`/etc/nsswitch.conf`.

`make check` runs the unittest suite in `test/test_libnss_netd.py`. It needs
python3 and a C compiler (set `CC` to pick one). `nix-shell --run 'make check'`
provides both on Nix. Tests that wait out real five-second timeouts dominate a
full run. `FAST=1 make check` skips them while iterating. The suite uses a fake
daemon and a fake `dns` NSS service, so it does not change the host's resolver
configuration.

## Behavior and limits

The module implements glibc's `gethostbyname4_r`, `gethostbyname*_r`,
`gethostbyaddr2_r`, and `gethostbyaddr_r` NSS entry points. It asks netd for
the caller's default network (netid 0). Forward lookups use `AI_CANONNAME` and
`SOCK_STREAM`. IPv4 and IPv6 addresses are returned, repeated addresses are
removed, and netd's canonical name is used when available. Reverse lookups use
netd's `gethostbyaddr` command. Up to 32 aliases from its reply are returned.
The module has no cache.

Netd attributes the query to the connecting process's credentials
(`SO_PEERCRED`), as bionic does. A setuid program in a chroot resolves as its
elevated UID. Under proot, setuid is emulated, so the app UID is used.

Netd's `EAI_NONAME`, `EAI_NODATA`, and related negative answers become NSS
`NOTFOUND`. `EAI_AGAIN`, `EAI_FAIL`, and `EAI_MEMORY` become `TRYAGAIN`.
Connection failures, unknown errors, and malformed replies become `UNAVAIL`.
A failed reverse lookup carries no error code from netd, so every negative
reverse reply becomes `NOTFOUND`. A successful reply with no addresses is
`NOTFOUND` with `NO_DATA`, and an unreadable one is `UNAVAIL`. The `hosts`
line above decides which of these are final.

The module limits how much it reads from netd:

- Reads share a five-second deadline starting before the connection. Separate
  five-second socket timeouts bound a blocked connect or send, so a lookup can
  take longer than five seconds in those cases.
- At most 32 addresses from each IP family are returned. Further addresses
  are dropped.
- At most 32 aliases from a reverse reply are returned. Further aliases are
  dropped.
- Replies with more than 256 records or a canonical name longer than 256
  bytes are rejected, allowing the next NSS service to try if configured.
- Empty names, names over 254 bytes, and names containing spaces, tabs,
  newlines, carriage returns, `^`, or quotes are rejected locally.

Programs that bypass glibc NSS and query DNS themselves, including `dig` and
some Go binaries, do not use this module.

## License

Apache-2.0. See [LICENSE](LICENSE).
