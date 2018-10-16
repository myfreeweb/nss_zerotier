#include <rapidjson/document.h>
#include <rapidjson/filereadstream.h>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <exception>
#include <iostream>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <variant>
#include <vector>
#include "config.hpp"
#include "shared.hpp"

extern "C" {
#include <curl/curl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
}

using std::vector, std::array, std::string, std::runtime_error, std::thread, std::shared_mutex;

size_t curl_write_string(void *ptr, size_t size, size_t nmemb, string *data) {
	data->append(static_cast<char *>(ptr), size * nmemb);
	return size * nmemb;
}

class CurlReq {
	CURL *curl = nullptr;
	struct curl_slist *hdrs = nullptr;
	string resp;

 public:
	CurlReq(const char *url) {
		curl = curl_easy_init();
		if (!curl) {
			throw runtime_error("Could not create curl");
		}
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
		curl_easy_setopt(curl, CURLOPT_USERAGENT, "nss_zerotier");
		curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
		curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_string);
	}

	void add_header(const char *hdr) { hdrs = curl_slist_append(hdrs, hdr); }

	long perform() {
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
		CURLcode res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			throw runtime_error("curl perform error " + std::to_string(res));
		}
		long rcode;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &rcode);
		return rcode;
	}

	string response() { return resp; }

	~CurlReq() {
		if (curl) {
			curl_easy_cleanup(curl);
		}
		if (hdrs) {
			curl_slist_free_all(hdrs);
		}
	}
};

struct ZNetwork {
	const string controller;
	const string token;
	const string id;
	const string tld;
};

vector<ZNetwork> read_networks(const char *fpath) {
	FILE *fp = fopen(fpath, "rb");
	char readBuffer[8192];
	rapidjson::FileReadStream is(fp, readBuffer, sizeof(readBuffer));
	rapidjson::Document d;
	if (d.ParseStream(is).HasParseError()) {
		throw runtime_error("JSON parse error at offset " + std::to_string(d.GetErrorOffset()));
	}
	vector<ZNetwork> result;
	for (auto &ent : d.GetArray()) {
		result.push_back({
		    ent["controller"].GetString(),
		    ent["token"].GetString(),
		    ent["network"].GetString(),
		    ent["tld"].GetString(),
		});
	}
	return result;
}

string display_ipv6_addr(const array<uint8_t, 16> &bytes) {
	std::ostringstream result;
	result << std::hex;
	for (size_t i = 0; i < 16; i += 2) {
		result << (bytes[i] << 8 | bytes[i + 1]);
		if (i != 14) {
			result << ':';
		}
	}
	return result.str();
}

struct ZMember {
	const uint64_t network_id;
	const uint64_t node_id;
	const string name;
	const string tld;

	array<uint8_t, 16> make_6plane_addr() {
		uint64_t net_id = network_id ^ (network_id >> 32);
#define U8(x) static_cast<uint8_t>(x)
		return {
		    0xfc,
		    U8(net_id >> 24),
		    U8(net_id >> 16),
		    U8(net_id >> 8),
		    U8(net_id),
		    U8(node_id >> 32),
		    U8(node_id >> 24),
		    U8(node_id >> 16),
		    U8(node_id >> 8),
		    U8(node_id),
		    0x00,
		    0x00,
		    0x00,
		    0x00,
		    0x00,
		    0x01,
		};
	}
};

void get_network_members(const ZNetwork &net, vector<ZMember> &members) {
	string url = net.controller + "/api/network/" + net.id + "/member";
	string auth = "Authorization: Bearer " + net.token;
	CurlReq req(url.c_str());
	req.add_header(auth.c_str());
	long rcode = req.perform();
	if (rcode != 200) {
		throw runtime_error("Server returned code " + std::to_string(rcode));
	}
	rapidjson::Document d;
	if (d.Parse(req.response().c_str()).HasParseError()) {
		throw runtime_error("JSON parse error at offset " + std::to_string(d.GetErrorOffset()));
	}
	for (auto &ent : d.GetArray()) {
		members.push_back({
		    std::stoull(ent["networkId"].GetString(), 0, 16),
		    std::stoull(ent["nodeId"].GetString(), 0, 16),
		    ent["name"].GetString(),
		    net.tld,
		});
	}
}

vector<ZNetwork> allnets;
shared_mutex rwlock;
vector<ZMember> allmembers;

void refresh_loop() {
	size_t alloc_len = 2;
	while (true) {
		vector<ZMember> members;
		members.reserve(alloc_len);
		for (auto &net : allnets) {
			try {
				get_network_members(net, members);
			} catch (std::exception e) {
				std::cerr << e.what() << std::endl;
			}
		}
#if 0
		for (auto &m : members) {
			auto adr = m.make_6plane_addr();
			std::cout << m.name << ' ' << display_ipv6_addr(adr) << std::endl;
		}
#endif
		alloc_len = members.size();
		{
			std::unique_lock<shared_mutex> lock(rwlock);
			std::swap(allmembers, members);
		}
		std::this_thread::sleep_for(std::chrono::seconds(10));
	}
}

vector<string> split_domain_parts(const string d) {
	std::istringstream ss{d};
	string tmp;
	vector<string> result;
	while (std::getline(ss, tmp, '.')) {
		result.push_back(tmp);
	}
	return result;
}

bool is_same_domain(const vector<string> &dparts, const ZMember &m) {
	if (dparts.size() == 0) {
		return false;
	}
	if (dparts.size() == 1) {
		return m.name == dparts[0] && m.tld == "";
	}
	return m.name == dparts[dparts.size() - 2] && m.tld == dparts[dparts.size() - 1];
}

void client_loop(int client) {
	while (true) {
		Msg req;
		if (recv(client, &req, sizeof(req), 0) != sizeof(req)) {
			break;
		}
		string param(&req.param[0], strnlen(&req.param[0], sizeof(req.param)));
		std::shared_lock<shared_mutex> lock(rwlock);
		switch (req.typ) {
			case AddrByName: {
				auto domain_parts = split_domain_parts(param);
				for (auto &m : allmembers) {
					auto adr = m.make_6plane_addr();
					if (is_same_domain(domain_parts, m)) {
						Msg resp;
						resp.typ = Result;
						resp.nettyp = V6;
						strcpy(&resp.param[0], display_ipv6_addr(adr).c_str());
						send(client, &resp, sizeof(resp), 0);
						break;
					}
				}
				Msg resp = {NotFound, V6, {0}};
				send(client, &resp, sizeof(resp), 0);
			} break;
			case NameByAddr:  // TODO needs ip addr parsing
			default: {
				Msg resp = {Unsupported, V6, {0}};
				send(client, &resp, sizeof(resp), 0);
			} break;
		}
	}
}

int main() {
	allnets = read_networks((string(CONFIG_PATH_PREFIX) + "/networks.json").c_str());
	thread refresher(refresh_loop);
	refresher.detach();
	int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (sock < 0) {
		std::cerr << "Could not socket" << std::endl;
		return -1;
	}
	struct sockaddr_un addr;
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
	unlink(SOCKET_PATH);
	if (bind(sock, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
		std::cerr << "Could not bind to " << SOCKET_PATH << std::endl;
		return -1;
	}
	if (listen(sock, 5) < 0) {
		std::cerr << "Could not listen" << std::endl;
		return -1;
	}
	while (true) {
		int client = accept(sock, nullptr, nullptr);
		if (client < 0) {
			std::cerr << "Could not accept" << std::endl;
			std::this_thread::sleep_for(std::chrono::seconds(1));
			continue;
		}
		thread reqhandler(client_loop, client);
		reqhandler.detach();
	}
}
