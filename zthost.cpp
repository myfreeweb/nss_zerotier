#include <array>
#include <cstring>
#include <iostream>
#include <variant>
#include "client.hpp"
#include "shared.hpp"

int main(int argc, char *argv[]) {
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " [hostname]" << std::endl;
		return 0;
	}
	auto client = std::get<ZtnsdClient>(ztnsd_client());
	Msg req;
	req.typ = AddrByName;
	req.nettyp = V6;
	strncpy(&req.param[0], argv[1], sizeof(req.param));
	auto resp = client.request(req);
	std::cout << std::string(&std::get<Msg>(resp).param[0]) << std::endl;
}
