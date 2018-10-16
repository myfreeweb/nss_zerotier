#pragma once
/* NOTE: do not use exceptions here, it's used in the nss plugin */
#include <variant>
#include "config.hpp"
#include "shared.hpp"

extern "C" {
#include <string.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
}

class ZtnsdClient {
 public:
	int fd;

	ZtnsdClient(int fdesc) : fd(fdesc){};

	std::variant<Msg, int> request(const Msg req) {
		int res = -1;
		if ((res = send(fd, &req, sizeof(req), 0)) != sizeof(req)) {
			return res;
		}
		struct pollfd pfd = { fd, POLLIN, 0 };
		if (poll(&pfd, 1, 2000) < 1) {
			return -1;
		}
		Msg resp;
		if ((res = recv(fd, &resp, sizeof(resp), 0)) != sizeof(resp)) {
			return res;
		}
		return resp;
	};
};

static std::variant<ZtnsdClient, const char*> ztnsd_client() {
	int fd;
	struct sockaddr_un addr;
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
	if ((fd = socket(AF_UNIX, SOCK_SEQPACKET, 0)) < 0) {
		return "Could not socket";
	}
	if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
		return "Could not connect";
	}
	return ZtnsdClient(fd);
}
