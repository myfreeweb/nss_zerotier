#pragma once
#include <array>

enum MsgType {
	AddrByName,
	NameByAddr,
	Result,
	NotFound,
	Unsupported,
};

enum NetType {
	V4,
	V6,
};

struct Msg {
	MsgType typ;
	NetType nettyp;
	std::array<char, 256 - sizeof(MsgType) - sizeof(NetType)> param;
};

static_assert(sizeof(Msg) == 256);
