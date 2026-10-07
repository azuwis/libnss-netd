/* libnss_fakedns.so.2 - a deterministic stand-in for the "dns" service, so the
 * fallback path can be tested without a working resolver. */
#define _GNU_SOURCE
#include <errno.h>
#include <netdb.h>
#include <nss.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define FAKE_ADDR 0xcb007135 /* 203.0.113.53 */

enum nss_status
_nss_fakedns_gethostbyname4_r(const char *name, struct gaih_addrtuple **pat,
                              char *buffer, size_t buflen, int *errnop,
                              int *herrnop, int32_t *ttlp)
{
    (void)herrnop;
    size_t namelen = strlen(name) + 1;
    struct gaih_addrtuple *t = (struct gaih_addrtuple *)buffer;
    char *copy = buffer + sizeof(*t);

    if (buflen < sizeof(*t) + namelen) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }
    memset(t, 0, sizeof(*t));
    memcpy(copy, name, namelen);
    t->name = copy;
    t->family = AF_INET;
    t->addr[0] = htonl(FAKE_ADDR);
    t->next = NULL;
    *pat = t;
    if (ttlp)
        *ttlp = 0;
    return NSS_STATUS_SUCCESS;
}
