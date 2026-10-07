/*
 * nss-hosts-shim.so - keep Nix's hosts lookups from bypassing
 * /etc/nsswitch.conf.
 *
 * Nix's preloadNSS() calls __nss_configure_lookup("hosts", "files dns") as a
 * sandbox workaround. That makes the Nix process ignore /etc/nsswitch.conf
 * for hosts lookups, so NSS services such as netd never run. This object is
 * preloaded and turns that one service list into a no-op. Other calls are
 * forwarded to glibc unchanged.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*configure_lookup_fn) (const char *, const char *);

int
__nss_configure_lookup (const char *database, const char *configuration)
{
  static configure_lookup_fn real;

  if (database != NULL && configuration != NULL
      && strcmp (database, "hosts") == 0
      && strcmp (configuration, "files dns") == 0)
    {
      if (getenv ("NSS_HOSTS_SHIM_DEBUG") != NULL)
        dprintf (2, "nss-hosts-shim: ignored the hosts=files dns override\n");
      return 0;
    }

  if (real == NULL)
    real = (configure_lookup_fn) dlsym (RTLD_NEXT, "__nss_configure_lookup");
  if (real != NULL)
    return real (database, configuration);

  errno = ENOSYS;
  return -1;
}
