/* IPv4/IPv6 address helpers, cf. the inet.[ch] wrapper in uftpd/SMCRoute */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "inet.h"

sa_family_t inet_family(const inet_addr_t *ss)
{
	return ss->ss_family;
}

socklen_t inet_len(const inet_addr_t *ss)
{
#ifdef CONFIG_ENABLE_IPV6
	if (ss->ss_family == AF_INET6)
		return sizeof(struct sockaddr_in6);
#else
	(void)ss;
#endif
	return sizeof(struct sockaddr_in);
}

in_port_t inet_port(const inet_addr_t *ss)
{
#ifdef CONFIG_ENABLE_IPV6
	if (ss->ss_family == AF_INET6)
		return ntohs(((const struct sockaddr_in6 *)ss)->sin6_port);
#endif
	return ntohs(((const struct sockaddr_in *)ss)->sin_port);
}

void inet_set_port(inet_addr_t *ss, in_port_t port)
{
#ifdef CONFIG_ENABLE_IPV6
	if (ss->ss_family == AF_INET6) {
		((struct sockaddr_in6 *)ss)->sin6_port = htons(port);
		return;
	}
#endif
	((struct sockaddr_in *)ss)->sin_port = htons(port);
}

void inet_anyaddr(sa_family_t family, in_port_t port, inet_addr_t *ss)
{
	memset(ss, 0, sizeof(*ss));
	ss->ss_family = family;

#ifdef CONFIG_ENABLE_IPV6
	if (family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

		sin6->sin6_addr = in6addr_any;
		sin6->sin6_port = htons(port);
		return;
	}
#endif
	((struct sockaddr_in *)ss)->sin_addr.s_addr = htonl(INADDR_ANY);
	((struct sockaddr_in *)ss)->sin_port        = htons(port);
}

const char *inet_ntop2(const inet_addr_t *ss, char *buf, size_t len)
{
	buf[0] = 0;

#ifdef CONFIG_ENABLE_IPV6
	if (ss->ss_family == AF_INET6)
		return inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)ss)->sin6_addr, buf, len);
#endif
	return inet_ntop(AF_INET, &((const struct sockaddr_in *)ss)->sin_addr, buf, len);
}

int inet_pton2(const char *str, in_port_t defport, inet_addr_t *ss)
{
	char buf[INET6_ADDRSTRLEN + 8];
	char *host = buf, *port = NULL, *p;
	sa_family_t family = AF_INET;
	in_port_t portnum = defport;

	if (!str || !*str)
		return -1;
	snprintf(buf, sizeof(buf), "%s", str);

	if (buf[0] == '[') {			/* [v6] or [v6]:port */
		host = buf + 1;
		p = strchr(host, ']');
		if (!p)
			return -1;
		*p++ = 0;
		if (*p == ':')
			port = p + 1;
		family = AF_INET6;
	} else {
		p = strchr(buf, ':');
		if (p && !strchr(p + 1, ':')) {	/* single colon: v4:port */
			*p = 0;
			port = p + 1;
		} else if (p) {			/* several colons: bare v6 */
			family = AF_INET6;
		}
	}

	if (port && *port)
		portnum = (in_port_t)atoi(port);

	memset(ss, 0, sizeof(*ss));
	ss->ss_family = family;

#ifdef CONFIG_ENABLE_IPV6
	if (family == AF_INET6) {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;

		if (inet_pton(AF_INET6, host, &s6->sin6_addr) != 1)
			return -1;
		s6->sin6_port = htons(portnum);
		return 0;
	}
#else
	if (family == AF_INET6)
		return -1;		/* no IPv6 support compiled in */
#endif

	if (inet_pton(AF_INET, host, &((struct sockaddr_in *)ss)->sin_addr) != 1)
		return -1;
	((struct sockaddr_in *)ss)->sin_port = htons(portnum);

	return 0;
}
