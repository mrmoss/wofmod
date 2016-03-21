#ifndef PROBE_HPP
#define PROBE_HPP

#include <string>
#include <vector>

struct wof_t
{
	std::string proto;
	std::string l_ip;
	std::string l_mask;
	std::string l_port;
	std::string dir;
	std::string f_ip;
	std::string f_mask;
	std::string f_port;
	std::string action;
	bool V6;
};

typedef std::vector<wof_t> wof_list_t;

void wof_probe_line(std::string line,wof_list_t& wofs);

std::string wof_probe(wof_list_t wofs,const bool highports=false);

#endif