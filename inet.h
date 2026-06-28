/* IPv4/IPv6 address helpers, cf. the inet.[ch] wrapper in uftpd/SMCRoute */
#ifndef MINI_SNMPD_INET_H_
#define MINI_SNMPD_INET_H_

#include "config.h"
#include <netinet/in.h>
#include <sys/socket.h>

#ifdef CONFIG_ENABLE_IPV6
#define INET_ADDRSTR_LEN INET6_ADDRSTRLEN
#else
#define INET_ADDRSTR_LEN INET_ADDRSTRLEN
#endif

/*
 * Wrapper for an IPv4 or IPv6 socket address.  Everything is kept in a
 * sockaddr_storage and the family is inspected through the helpers below,
 * so the rest of mini-snmpd does not need to special-case AF_INET vs
 * AF_INET6.
 */
typedef struct sockaddr_storage inet_addr_t;

/* Family of @ss, AF_INET or AF_INET6 */
sa_family_t inet_family(const inet_addr_t *ss);

/* Length of the concrete sockaddr in @ss, for bind()/sendto() */
socklen_t   inet_len(const inet_addr_t *ss);

/* Port in host byte order, regardless of family */
in_port_t   inet_port(const inet_addr_t *ss);

/* Set the port (host byte order) in the correct family-specific field */
void        inet_set_port(inet_addr_t *ss, in_port_t port);

/* Initialize @ss to the wildcard address of @family with @port */
void        inet_anyaddr(sa_family_t family, in_port_t port, inet_addr_t *ss);

/* Presentation string of the address in @ss, e.g. for logging */
const char *inet_ntop2(const inet_addr_t *ss, char *buf, size_t len);

/*
 * Parse a numeric address with optional port into @ss, defaulting to
 * @defport: "1.2.3.4", "1.2.3.4:162", "[::1]", or "[::1]:162".  Returns
 * 0 on success, -1 on a malformed or unsupported address.
 */
int inet_pton2(const char *str, in_port_t defport, inet_addr_t *ss);

#endif /* MINI_SNMPD_INET_H_ */
