/* NSS hosts lookup through Android's netd resolver. See README for setup,
 * nsswitch.conf choices and fallback behavior. */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <nss.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define NETDNS_DEFAULT_SOCKET "/dev/socket/dnsproxyd"
#ifndef NETDNS_SOCKET_PATH
#define NETDNS_SOCKET_PATH NETDNS_DEFAULT_SOCKET
#endif
/* Read deadline, measured from before connect. Socket timeouts also bound
   connect and send; they do not make the entire exchange strictly five
   seconds. A per-read timeout alone would reset on a trickling reply. */
#define NETD_TIMEOUT 5
#define MAX_ADDRS 32 /* per family, the rest is dropped, see README */
/* Stop after this many records. A longer stream is a broken reply. netd
   sends one record per address, so even 64 dual-stack addresses stay far
   below it. */
#define MAX_RECORDS 256
#define MAX_SOCKADDR ((int32_t)sizeof(struct sockaddr_storage))
#define MAX_CANONNAME 256
/* Reverse replies keep at most this many aliases. The rest are dropped. */
#define MAX_ALIASES 32

/* netd sends bionic's positive EAI values, not glibc's EAI_* constants. */
#define BIONIC_EAI_ADDRFAMILY 1
#define BIONIC_EAI_AGAIN 2
#define BIONIC_EAI_FAIL 4
#define BIONIC_EAI_MEMORY 6
#define BIONIC_EAI_NODATA 7
#define BIONIC_EAI_NONAME 8
#define BIONIC_EAI_SERVICE 9

/* Response codes SocketClient sends as three digits and a NUL. */
#define DNS_PROXY_QUERY_RESULT 222
#define DNS_PROXY_OPERATION_FAILED 401

/* ---------------------------------------------------------------- protocol */

/* Milliseconds left, never negative. */
static int
deadline_left(const struct timespec *deadline)
{
    struct timespec now;
    long long ms;

    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
        return 0; /* no clock, no bound: treat the deadline as expired */
    ms = (long long)(deadline->tv_sec - now.tv_sec) * 1000
         + (deadline->tv_nsec - now.tv_nsec) / 1000000;
    if (ms <= 0)
        return 0;
    return (ms > INT_MAX) ? INT_MAX : (int)ms;
}

/* Set *deadline to now + NETD_TIMEOUT, or fail so the caller gives up
   instead of waiting without a bound. */
static int
start_deadline(struct timespec *deadline)
{
    if (clock_gettime(CLOCK_MONOTONIC, deadline) < 0)
        return -1;
    deadline->tv_sec += NETD_TIMEOUT;
    return 0;
}

static int
wait_readable(int fd, const struct timespec *deadline)
{
    struct pollfd pfd = { .fd = fd, .events = POLLIN };

    for (;;) {
        int left = deadline_left(deadline);
        int n;

        if (left == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        n = poll(&pfd, 1, left);
        if (n > 0)
            return 0;
        if (n == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (errno != EINTR)
            return -1;
        /* EINTR only means a handler ran. Recompute the remaining time and
           keep waiting. */
    }
}

static int
read_full(int fd, void *buf, size_t len, const struct timespec *deadline)
{
    unsigned char *p = buf;

    while (len > 0) {
        ssize_t n;

        if (wait_readable(fd, deadline) < 0)
            return -1;
        n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            errno = EPIPE;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

/* Reply framing fields are big-endian. The sockaddr is copied in its usual
   in-memory layout, and the EAI payload is a native int32_t. */
static int
read_be32(int fd, int32_t *out, const struct timespec *deadline)
{
    unsigned char b[4];

    if (read_full(fd, b, sizeof(b), deadline) < 0)
        return -1;
    *out = (int32_t)((uint32_t)b[0] << 24 | (uint32_t)b[1] << 16
                     | (uint32_t)b[2] << 8 | b[3]);
    return 0;
}

/* Read one BE32 length and that many bytes into buf (capacity cap). */
static int
read_chunk(int fd, void *buf, size_t cap, int32_t *size,
           const struct timespec *deadline)
{
    int32_t n;

    if (read_be32(fd, &n, deadline) < 0)
        return -1;
    if (n < 0 || (size_t)n > cap)
        return -1;
    if (n > 0 && read_full(fd, buf, (size_t)n, deadline) < 0)
        return -1;
    *size = n;
    return 0;
}

/* Read the 4-byte response code, or -1 when it is not a three-digit code
   followed by a NUL (for instance the text of a 501 reply). */
static int
read_netd_code(int fd, const struct timespec *deadline)
{
    unsigned char code[4];

    if (read_full(fd, code, sizeof(code), deadline) < 0)
        return -1;
    if (code[0] < '0' || code[0] > '9' || code[1] < '0' || code[1] > '9'
        || code[2] < '0' || code[2] > '9' || code[3] != '\0')
        return -1;
    return (code[0] - '0') * 100 + (code[1] - '0') * 10 + (code[2] - '0');
}

struct addresses {
    struct in_addr v4[MAX_ADDRS];
    struct {
        struct in6_addr addr;
        uint32_t scope;
    } v6[MAX_ADDRS];
    char canon[MAX_CANONNAME];
    int n4, n6;
};

/* One gethostbyaddr reply: netd's hostent framing. */
struct hostent_reply {
    char name[MAX_CANONNAME];
    char aliases[MAX_ALIASES][MAX_CANONNAME];
    int naliases;
    int addrtype;
    int addrlen;
    unsigned char addrs[MAX_ADDRS][16];
    int naddrs;
};

enum netd_answer {
    NETD_ANSWER_OK = 0,
    NETD_ANSWER_NOT_FOUND, /* 401: netd reports the lookup failed */
    NETD_ANSWER_NO_DATA,   /* 222 with no addresses in it */
    NETD_ANSWER_ERROR,     /* unreadable or unexpected reply */
};

/* The module asks for one socktype, so netd normally returns one record per
   address. DNS answers can still repeat an address, so filter duplicates. */
static void
add_v4(struct addresses *a, const struct in_addr *addr)
{
    int i;

    for (i = 0; i < a->n4; i++)
        if (memcmp(&a->v4[i], addr, sizeof(*addr)) == 0)
            return;
    if (a->n4 < MAX_ADDRS)
        a->v4[a->n4++] = *addr;
}

static void
add_v6(struct addresses *a, const struct in6_addr *addr, uint32_t scope)
{
    int i;

    for (i = 0; i < a->n6; i++)
        if (a->v6[i].scope == scope
            && memcmp(&a->v6[i].addr, addr, sizeof(*addr)) == 0)
            return;
    if (a->n6 < MAX_ADDRS) {
        a->v6[a->n6].addr = *addr;
        a->v6[a->n6].scope = scope;
        a->n6++;
    }
}

static void
collect(const unsigned char *raw, size_t addrlen, struct addresses *out)
{
    struct sockaddr_storage ss;
    sa_family_t family;

    /* The caller already checked addrlen against MAX_SOCKADDR. */
    if (addrlen < sizeof(family))
        return;
    memset(&ss, 0, sizeof(ss));
    memcpy(&ss, raw, addrlen);
    memcpy(&family, &ss, sizeof(family)); /* the sockaddr is native-endian */

    if (family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *sa = (const struct sockaddr_in *)&ss;

        add_v4(out, &sa->sin_addr);
    } else if (family == AF_INET6
               && addrlen >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *sa = (const struct sockaddr_in6 *)&ss;

        add_v6(out, &sa->sin6_addr, sa->sin6_scope_id);
    }
}

/* The socket to use. Only the test build honors the environment override,
   and secure_getenv ignores it after a privileged exec. A relative
   compile-time path would resolve against each caller's cwd, so it falls
   back to the default; make rejects such a SOCKET before compiling. */
static const char *
netd_socket_path(void)
{
#ifdef NETDNS_ALLOW_SOCKET_OVERRIDE
    const char *path = secure_getenv("NETDNS_SOCKET");

    if (path != NULL && path[0] == '/')
        return path;
#endif
    if (NETDNS_SOCKET_PATH[0] != '/')
        return NETDNS_DEFAULT_SOCKET;
    return NETDNS_SOCKET_PATH;
}

/* Connect to netd and send one NUL-terminated command. Linux bounds a unix
   connect that waits on a full listener queue by SO_SNDTIMEO. Both socket
   timeouts also backstop reads after poll wakes. If a sandbox refuses
   them, the module gives up rather than wait without a bound.
   FrameworkListener expects the whole command in one read, so it goes out
   in one call with MSG_NOSIGNAL. */
static int
netd_send(const char *cmd, size_t len)
{
    struct sockaddr_un sa = { .sun_family = AF_UNIX };
    struct timeval tv = { NETD_TIMEOUT, 0 };
    const char *path = netd_socket_path();
    size_t pathlen;
    int fd, saved;

    pathlen = strlen(path);
    if (pathlen >= sizeof(sa.sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0
        || setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
        goto fail;
    memcpy(sa.sun_path, path, pathlen);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        goto fail;
    if (send(fd, cmd, len, MSG_NOSIGNAL) != (ssize_t)len)
        goto fail;
    return fd;

fail:
    saved = errno;
    close(fd);
    errno = saved;
    return -1;
}

/* Ask netd into out, which the caller must have zeroed. Returns 0 for a
   complete success reply, even one with no addresses. On failure, *eai is a
   bionic EAI_* value only when a valid error frame was received; otherwise
   it remains 0, which lookup() maps to UNAVAIL. */
static int
netd_getaddrinfo(const char *name, int af, struct addresses *out, int *eai)
{
    struct timespec deadline;
    unsigned char sockaddr_raw[MAX_SOCKADDR];
    char cmd[1024], canonname[MAX_CANONNAME];
    int fd, n, saved, records = 0, ret = -1;

    *eai = 0;
    /* A fully qualified DNS name can occupy 254 bytes with its trailing dot.
       Bionic also rejects the characters that disrupt the command format. */
    if (strlen(name) == 0 || strlen(name) > 254
        || strpbrk(name, " \t\n\r^'\"") != NULL) {
        *eai = BIONIC_EAI_NODATA;
        errno = EINVAL;
        return -1;
    }

    /* AI_CANONNAME is always requested. It costs one string in the reply, and
       only the caller decides whether the name is used. */
    n = snprintf(cmd, sizeof(cmd), "getaddrinfo %s ^ %d %d %d %d 0", name,
                 AI_CANONNAME, af, SOCK_STREAM, 0);
    if (n < 0 || (size_t)n + 1 > sizeof(cmd)) {
        errno = EMSGSIZE;
        return -1;
    }

    /* The read deadline starts before connect. netd_send's socket timeouts
       separately bound a blocked connect or send. */
    if (start_deadline(&deadline) < 0)
        return -1;
    fd = netd_send(cmd, (size_t)n + 1);
    if (fd < 0)
        return -1;

    switch (read_netd_code(fd, &deadline)) {
    case DNS_PROXY_OPERATION_FAILED: {
        /* sendBinaryMsg() writes a BE32 payload length and then the payload,
           which here is a native int32 EAI code in bionic's numbering. bionic
           throws it away; keeping the value makes the nss_status mapping
           exact. Only this code with a four-byte payload is trusted as an EAI
           reply. */
        int32_t len, rv;

        if (read_chunk(fd, &rv, sizeof(rv), &len, &deadline) == 0
            && len == (int32_t)sizeof(rv))
            *eai = rv;
        goto out;
    }
    case DNS_PROXY_QUERY_RESULT:
        break;
    default:
        goto out; /* not a frame this module understands */
    }

    for (;;) {
        int32_t have_more, addrlen, namelen;

        if (read_be32(fd, &have_more, &deadline) < 0)
            goto out;
        if (have_more == 0) {
            ret = 0;
            goto out;
        }
        if (records++ >= MAX_RECORDS)
            goto out;
        /* Skip flags, family, socktype and protocol. The sockaddr has its
           own family, and NSS only needs the address. */
        if (read_full(fd, sockaddr_raw, 4 * sizeof(int32_t), &deadline) < 0
            || read_be32(fd, &addrlen, &deadline) < 0)
            goto out;
        /* A length outside these bounds does not mean "no address" or "no
           name". The reply cannot be read, and answering from it would turn
           a broken frame into a final NOTFOUND. bionic stops parsing at the
           same point. */
        if (addrlen < 0 || addrlen > MAX_SOCKADDR)
            goto out;
        if (addrlen > 0
            && read_full(fd, sockaddr_raw, (size_t)addrlen, &deadline) < 0)
            goto out;
        if (read_be32(fd, &namelen, &deadline) < 0)
            goto out;
        if (namelen < 0 || namelen > MAX_CANONNAME)
            goto out;
        if (namelen > 0) {
            if (read_full(fd, canonname, (size_t)namelen, &deadline) < 0)
                goto out;
            if (canonname[namelen - 1] != '\0')
                goto out; /* netd sends the terminator as part of the name */
            if (out->canon[0] == '\0' && canonname[0] != '\0')
                memcpy(out->canon, canonname, strlen(canonname) + 1);
        }
        if (addrlen > 0)
            collect(sockaddr_raw, (size_t)addrlen, out);
    }

out:
    saved = errno;
    close(fd);
    errno = saved;
    return ret;
}

/* Ask netd for a PTR record with its gethostbyaddr command. netd sends no
   EAI code in the negative reply, so a nonexistent name, a timeout, and a
   refused query all look the same. */
static enum netd_answer
netd_gethostbyaddr(const void *addr, socklen_t len, int af,
                   struct hostent_reply *out)
{
    struct timespec deadline;
    char addrstr[INET6_ADDRSTRLEN];
    char cmd[256], alias[MAX_CANONNAME], raw[16];
    int fd, n, saved, records = 0;
    int32_t size;
    enum netd_answer ret = NETD_ANSWER_ERROR;

    memset(out, 0, sizeof(*out));
    if (!((af == AF_INET && len == sizeof(struct in_addr))
          || (af == AF_INET6 && len == sizeof(struct in6_addr)))) {
        errno = EAFNOSUPPORT;
        return NETD_ANSWER_ERROR;
    }
    if (inet_ntop(af, addr, addrstr, sizeof(addrstr)) == NULL)
        return NETD_ANSWER_ERROR;
    n = snprintf(cmd, sizeof(cmd), "gethostbyaddr %s %d %d 0", addrstr,
                 (int)len, af);
    if (n < 0 || (size_t)n + 1 > sizeof(cmd)) {
        errno = EMSGSIZE;
        return NETD_ANSWER_ERROR;
    }

    if (start_deadline(&deadline) < 0)
        return NETD_ANSWER_ERROR;
    fd = netd_send(cmd, (size_t)n + 1);
    if (fd < 0)
        return NETD_ANSWER_ERROR;

    switch (read_netd_code(fd, &deadline)) {
    case DNS_PROXY_OPERATION_FAILED:
        /* GetHostByAddrHandler sends the failure with a zero-length payload
           instead of an EAI code. */
        if (read_be32(fd, &size, &deadline) == 0 && size == 0)
            ret = NETD_ANSWER_NOT_FOUND;
        goto out;
    case DNS_PROXY_QUERY_RESULT:
        break;
    default:
        goto out;
    }

    if (read_chunk(fd, out->name, sizeof(out->name), &size, &deadline) < 0)
        goto out;
    if (size > 0 && out->name[size - 1] != '\0')
        goto out;

    for (;;) {
        if (read_chunk(fd, alias, sizeof(alias), &size, &deadline) < 0)
            goto out;
        if (size == 0)
            break;
        if (++records > MAX_RECORDS || alias[size - 1] != '\0')
            goto out;
        if (out->naliases < MAX_ALIASES) {
            memcpy(out->aliases[out->naliases], alias, (size_t)size);
            out->naliases++;
        }
    }

    if (read_be32(fd, &out->addrtype, &deadline) < 0)
        goto out;
    if (read_be32(fd, &out->addrlen, &deadline) < 0)
        goto out;
    /* Only the pair has to be consistent. A v4-mapped IPv6 query comes back
       from netd as a plain AF_INET hostent, as in bionic, so this must not
       require addrtype == af. */
    if (!((out->addrtype == AF_INET && out->addrlen == 4)
          || (out->addrtype == AF_INET6 && out->addrlen == 16)))
        goto out;

    for (;;) {
        if (read_chunk(fd, raw, sizeof(raw), &size, &deadline) < 0)
            goto out;
        if (size == 0)
            break;
        if (++records > MAX_RECORDS)
            goto out;
        /* netd sends 16 bytes per address even for IPv4, where only
           h_length of them are the address. */
        if (size < out->addrlen)
            goto out;
        if (out->naddrs < MAX_ADDRS) {
            memcpy(out->addrs[out->naddrs], raw, (size_t)out->addrlen);
            out->naddrs++;
        }
    }
    if (out->naddrs == 0) {
        ret = NETD_ANSWER_NO_DATA;
        goto out;
    }
    ret = NETD_ANSWER_OK;

out:
    saved = errno;
    close(fd);
    errno = saved;
    return ret;
}

/* -------------------------------------------------------------- NSS glue */

/* Resolve for family AF_*, mapping netd's answer onto nss_status. */
static enum nss_status
lookup(const char *name, int af, struct addresses *addrs, int *errnop,
       int *herrnop)
{
    int eai;

    memset(addrs, 0, sizeof(*addrs));
    if (netd_getaddrinfo(name, af, addrs, &eai) < 0) {
        /* 0 means no valid EAI reply was read. */
        switch (eai) {
        case BIONIC_EAI_AGAIN:
        case BIONIC_EAI_FAIL: /* netd can use EAI_FAIL for a blocked UID. */
        case BIONIC_EAI_MEMORY: /* the per-UID query limit on newer netd */
            *errnop = EAGAIN;
            *herrnop = TRY_AGAIN;
            return NSS_STATUS_TRYAGAIN;
        case BIONIC_EAI_ADDRFAMILY:
        case BIONIC_EAI_NODATA:
            /* No address was returned for the requested family. */
            *errnop = ENOENT;
            *herrnop = NO_DATA;
            return NSS_STATUS_NOTFOUND;
        case BIONIC_EAI_NONAME:
        case BIONIC_EAI_SERVICE:
            *errnop = ENOENT;
            *herrnop = HOST_NOT_FOUND;
            return NSS_STATUS_NOTFOUND;
        default:
            /* The daemon is missing or the reply is unusable, so let the next
               service handle the name. */
            *errnop = EAGAIN;
            *herrnop = NETDB_INTERNAL;
            return NSS_STATUS_UNAVAIL;
        }
    }
    if (addrs->n4 == 0 && addrs->n6 == 0) {
        *errnop = ENOENT;
        *herrnop = NO_DATA;
        return NSS_STATUS_NOTFOUND;
    }
    return NSS_STATUS_SUCCESS;
}

/* Bump allocator over the caller's buffer. */
static void *
alloc_from(char **p, char *end, size_t size, size_t align)
{
    uintptr_t a = ((uintptr_t)*p + align - 1) & ~(uintptr_t)(align - 1);

    if (a + size > (uintptr_t)end)
        return NULL;
    *p = (char *)(a + size);
    return (void *)a;
}

static void
addr_bytes(int family, const struct addresses *addrs, size_t i, void *dst)
{
    if (family == AF_INET)
        memcpy(dst, &addrs->v4[i], sizeof(struct in_addr));
    else
        memcpy(dst, &addrs->v6[i].addr, sizeof(struct in6_addr));
}

/* getaddrinfo's path: one tuple per address, all inside the caller's buffer. */
enum nss_status
_nss_netd_gethostbyname4_r(const char *name, struct gaih_addrtuple **pat,
                           char *buffer, size_t buflen, int *errnop,
                           int *herrnop, int32_t *ttlp)
{
    struct addresses addrs;
    struct gaih_addrtuple *tuples;
    enum nss_status status;
    size_t namelen, needed, i, n, pad;
    const char *hostname;
    char *namebuf;

    status = lookup(name, AF_UNSPEC, &addrs, errnop, herrnop);
    if (status != NSS_STATUS_SUCCESS)
        return status;

    n = (size_t)addrs.n4 + (size_t)addrs.n6;
    hostname = (addrs.canon[0] != '\0') ? addrs.canon : name;
    namelen = strlen(hostname) + 1;
    /* The caller's buffer may not be aligned for the tuples, so reserve the
       padding inside it; glibc's own nss_files aligns the same way. */
    pad = (size_t)(-(uintptr_t)buffer % _Alignof(struct gaih_addrtuple));
    needed = pad + n * sizeof(*tuples) + namelen;
    if (buflen < needed) {
        *errnop = ERANGE;
        *herrnop = NETDB_INTERNAL;
        return NSS_STATUS_TRYAGAIN;
    }

    /* The pad above makes this aligned. The void * step tells -Wcast-align,
       which cannot see the alignment through the arithmetic. */
    tuples = (struct gaih_addrtuple *)(void *)(buffer + pad);
    namebuf = buffer + pad + n * sizeof(*tuples);
    memcpy(namebuf, hostname, namelen);
    for (i = 0; i < n; i++) {
        int fam = (i < (size_t)addrs.n4) ? AF_INET : AF_INET6;
        size_t idx = (fam == AF_INET) ? i : i - (size_t)addrs.n4;

        tuples[i].next = (i + 1 < n) ? &tuples[i + 1] : NULL;
        tuples[i].name = namebuf;
        tuples[i].family = fam;
        memset(tuples[i].addr, 0, sizeof(tuples[i].addr));
        addr_bytes(fam, &addrs, idx, tuples[i].addr);
        tuples[i].scopeid = (fam == AF_INET6) ? addrs.v6[idx].scope : 0;
    }
    *pat = tuples;
    if (ttlp != NULL)
        *ttlp = 0;
    return NSS_STATUS_SUCCESS;
}

/* gethostbyname*() path: a struct hostent with name, alias and address
   vectors, all inside the caller's buffer. */
static enum nss_status
hostent_answer(const char *name, int af, struct hostent *host, char *buffer,
               size_t buflen, int *errnop, int *herrnop, int32_t *ttlp,
               char **canonp)
{
    struct addresses addrs;
    enum nss_status status;
    size_t i, n, namelen, alen;
    const char *hostname;
    char *p = buffer, *end = buffer + buflen, *data;
    char **aliases, **addr_list;
    int family;

    status = lookup(name, af, &addrs, errnop, herrnop);
    if (status != NSS_STATUS_SUCCESS)
        return status;

    if (af == AF_INET6)
        family = AF_INET6;
    else if (af == AF_INET || addrs.n4 > 0)
        family = AF_INET;
    else
        family = AF_INET6;
    n = (family == AF_INET) ? (size_t)addrs.n4 : (size_t)addrs.n6;
    if (n == 0) {
        *herrnop = NO_DATA;
        return NSS_STATUS_NOTFOUND;
    }
    alen = (family == AF_INET) ? sizeof(struct in_addr)
                               : sizeof(struct in6_addr);
    hostname = (addrs.canon[0] != '\0') ? addrs.canon : name;
    namelen = strlen(hostname) + 1;

    host->h_name = alloc_from(&p, end, namelen, 1);
    aliases = alloc_from(&p, end, sizeof(char *), sizeof(char *));
    addr_list = alloc_from(&p, end, (n + 1) * sizeof(char *), sizeof(char *));
    data = alloc_from(&p, end, n * alen, sizeof(uint32_t));
    if (host->h_name == NULL || aliases == NULL || addr_list == NULL
        || data == NULL) {
        *errnop = ERANGE;
        *herrnop = NETDB_INTERNAL;
        return NSS_STATUS_TRYAGAIN;
    }
    memcpy(host->h_name, hostname, namelen);
    aliases[0] = NULL;
    for (i = 0; i < n; i++) {
        addr_bytes(family, &addrs, i, data + i * alen);
        addr_list[i] = data + i * alen;
    }
    addr_list[n] = NULL;

    host->h_aliases = aliases;
    host->h_addrtype = family;
    host->h_length = (int)alen;
    host->h_addr_list = addr_list;
    if (ttlp != NULL)
        *ttlp = 0;
    if (canonp != NULL)
        *canonp = host->h_name;
    return NSS_STATUS_SUCCESS;
}

/* The reverse path: netd's hostent, aliases included. */
static enum nss_status
hostent_reply_answer(const struct hostent_reply *rep, struct hostent *host,
                     char *buffer, size_t buflen, int *errnop, int *herrnop,
                     int32_t *ttlp)
{
    size_t i, n = (size_t)rep->naddrs, na = (size_t)rep->naliases;
    size_t alen = (size_t)rep->addrlen;
    size_t namelen = strlen(rep->name) + 1;
    char *p = buffer, *end = buffer + buflen, *data, *alias;
    char **aliases, **addr_list;

    host->h_name = alloc_from(&p, end, namelen, 1);
    aliases = alloc_from(&p, end, (na + 1) * sizeof(char *), sizeof(char *));
    addr_list = alloc_from(&p, end, (n + 1) * sizeof(char *), sizeof(char *));
    data = alloc_from(&p, end, n * alen, sizeof(uint32_t));
    if (host->h_name == NULL || aliases == NULL || addr_list == NULL
        || data == NULL) {
        *errnop = ERANGE;
        *herrnop = NETDB_INTERNAL;
        return NSS_STATUS_TRYAGAIN;
    }
    memcpy(host->h_name, rep->name, namelen);
    for (i = 0; i < na; i++) {
        size_t len = strlen(rep->aliases[i]) + 1;

        alias = alloc_from(&p, end, len, 1);
        if (alias == NULL) {
            *errnop = ERANGE;
            *herrnop = NETDB_INTERNAL;
            return NSS_STATUS_TRYAGAIN;
        }
        memcpy(alias, rep->aliases[i], len);
        aliases[i] = alias;
    }
    aliases[na] = NULL;
    for (i = 0; i < n; i++) {
        memcpy(data + i * alen, rep->addrs[i], alen);
        addr_list[i] = data + i * alen;
    }
    addr_list[n] = NULL;

    host->h_aliases = aliases;
    host->h_addrtype = rep->addrtype;
    host->h_length = (int)alen;
    host->h_addr_list = addr_list;
    if (ttlp != NULL)
        *ttlp = 0;
    return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_netd_gethostbyname3_r(const char *name, int af, struct hostent *host,
                           char *buffer, size_t buflen, int *errnop,
                           int *herrnop, int32_t *ttlp, char **canonp)
{
    return hostent_answer(name, af, host, buffer, buflen, errnop, herrnop, ttlp,
                          canonp);
}

enum nss_status
_nss_netd_gethostbyname2_r(const char *name, int af, struct hostent *host,
                           char *buffer, size_t buflen, int *errnop,
                           int *herrnop)
{
    return hostent_answer(name, af, host, buffer, buflen, errnop, herrnop, NULL,
                          NULL);
}

enum nss_status
_nss_netd_gethostbyname_r(const char *name, struct hostent *host, char *buffer,
                          size_t buflen, int *errnop, int *herrnop)
{
    return hostent_answer(name, AF_INET, host, buffer, buflen, errnop, herrnop,
                          NULL, NULL);
}

/* Reverse lookups through netd. Every failure reply is the same, so they
   all become NOTFOUND, as in bionic's own proxy client; a malformed reply
   stays UNAVAIL so the next service can try. */
static enum nss_status
gethostbyaddr_answer(const void *addr, socklen_t len, int af,
                     struct hostent *host, char *buffer, size_t buflen,
                     int *errnop, int *herrnop, int32_t *ttlp)
{
    struct hostent_reply rep;
    enum netd_answer ret = netd_gethostbyaddr(addr, len, af, &rep);

    switch (ret) {
    case NETD_ANSWER_OK:
        return hostent_reply_answer(&rep, host, buffer, buflen, errnop,
                                    herrnop, ttlp);
    case NETD_ANSWER_NOT_FOUND:
        *errnop = ENOENT;
        *herrnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    case NETD_ANSWER_NO_DATA:
        *errnop = ENOENT;
        *herrnop = NO_DATA;
        return NSS_STATUS_NOTFOUND;
    default:
        *errnop = EAGAIN;
        *herrnop = NETDB_INTERNAL;
        return NSS_STATUS_UNAVAIL;
    }
}

enum nss_status
_nss_netd_gethostbyaddr2_r(const void *addr, socklen_t len, int af,
                           struct hostent *host, char *buffer, size_t buflen,
                           int *errnop, int *herrnop, int32_t *ttlp)
{
    return gethostbyaddr_answer(addr, len, af, host, buffer, buflen, errnop,
                                herrnop, ttlp);
}

enum nss_status
_nss_netd_gethostbyaddr_r(const void *addr, socklen_t len, int af,
                          struct hostent *host, char *buffer, size_t buflen,
                          int *errnop, int *herrnop)
{
    return gethostbyaddr_answer(addr, len, af, host, buffer, buflen, errnop,
                                herrnop, NULL);
}
