#include <array>
#include <cerrno>
#include <string>
#include <variant>
#include <vector>
#include "config.hpp"
#include "client.hpp"

extern "C" {
#include <string.h>
#include <netdb.h>
#include <nss.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
}

#include <iostream>

static ZtnsdClient *client = nullptr;

static bool ensure_connect() {
	if (client) {
		return true;
	}

	auto newclient = ztnsd_client();
	if (!std::holds_alternative<ZtnsdClient>(newclient)) {
		return false;
	}
	client = new ZtnsdClient(std::get<ZtnsdClient>(newclient));
	return true;
}

struct BufData {
	char *dummy;
	char name[255];
	struct in6_addr addr;
	char *addrp;
};

#define EXC __attribute__((visibility("default"))) extern "C"

EXC enum nss_status _nss_zerotier_gethostbyname2_r(const char *name, int af, struct hostent *result, char *buffer, size_t buflen, int *errnop,
                                                  int *h_errnop) {
	*errnop = ENOENT;
	*h_errnop = NO_RECOVERY;

	if (!ensure_connect()) {
		return NSS_STATUS_UNAVAIL;
	}

	Msg req;
	req.typ = AddrByName;
	req.nettyp = af == AF_INET ? V4 : V6;
	strncpy(&req.param[0], name, sizeof(req.param));
	auto respx = client->request(req);
	if (!std::holds_alternative<Msg>(respx)) {
		return NSS_STATUS_UNAVAIL;
	}
	auto resp = std::get<Msg>(respx);

	if (resp.typ == NotFound || resp.typ == Unsupported) {
		return NSS_STATUS_NOTFOUND;
	}

	result->h_addrtype = resp.nettyp == V4 ? AF_INET : AF_INET6;

	BufData *bd = reinterpret_cast<BufData*>(buffer);
	result->h_aliases = &bd->dummy;

	strncpy(&bd->name[0], name, sizeof(bd->name));
	result->h_name = &bd->name[0];

	if (inet_pton(result->h_addrtype, &resp.param[0], &bd->addr) != 1) {
		return NSS_STATUS_NOTFOUND;
	}
	bd->addrp = reinterpret_cast<char*>(&bd->addr);
	result->h_addr_list = reinterpret_cast<char**>(&bd->addrp);

	*errnop = 0;
	return NSS_STATUS_SUCCESS;
}

#ifdef HAS_BSD_NSS
EXC int _nss_zerotier_gethostbyname2_r_BSD(void *retval, void *mdata __unused, va_list ap) {
	const char *name = va_arg(ap, char *);
	int af = va_arg(ap, int);
	struct hostent *hp = va_arg(ap, struct hostent*);
	char *buf = va_arg(ap, char*);
	size_t buflen = va_arg(ap, size_t);
	int ret_errno = va_arg(ap, int);
	int *h_errnop = va_arg(ap, int*);
	struct hostent **resultp = reinterpret_cast<struct hostent**>(retval);

	*resultp = NULL;
	if (hp == NULL)
		return (NS_UNAVAIL);

	int status;
	status = _nss_zerotier_gethostbyname2_r(name, af, hp, buf, buflen,
			&ret_errno, h_errnop);
	status = __nss_compat_result(status, *h_errnop);
	if (status == NS_SUCCESS) {
		*resultp = hp;
	}
	return status;
}

static ns_mtab methods[] = {
	{NSDB_HOSTS, "gethostbyname2_r", _nss_zerotier_gethostbyname2_r_BSD, nullptr},
};

EXC ns_mtab *nss_module_register(const char *name, unsigned int *size, nss_module_unregister_fn *unregister) {
	*size = sizeof(methods) / sizeof(methods[0]);
	*unregister = NULL;
	return (methods);
}
#endif
