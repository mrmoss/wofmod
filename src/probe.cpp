#include "probe.hpp"

#include "parser_util.hpp"
#include <map>
#include <sstream>
#include <stdexcept>
#include "string_util.hpp"

void wof_probe_line(std::string line,wof_list_t& wofs)
{
	line=split(strip(line),"#")[0];

	if(line.size()>0)
	{
		wof_t wof;
		bool was_any=false;
		wof.proto=parse_proto(line);
		bool l_v6=false;
		wof.l_ip=parse_ip(line,was_any,l_v6,"after proto");
		wof.l_mask=parse_subnet_mask(line,was_any,l_v6);
		wof.l_port=parse_port(line);
		wof.dir=parse_dir(line,"after local address");
		bool f_v6=false;
		wof.f_ip=parse_ip(line,was_any,f_v6,"after direction");
		if(l_v6!=f_v6)
			throw std::runtime_error("Local \""+wof.l_ip+
				"\" and foreign \""+wof.f_ip+
				"\" addresses must be of the same version.");
		wof.f_mask=parse_subnet_mask(line,was_any,f_v6);
		wof.f_port=parse_port(line);
		wof.V6=(l_v6||f_v6);
		line=strip(line);
		if(line.size()>0)
			throw std::runtime_error("Unknown string \""+line+"\".");
		wofs.push_back(wof);
	}
}

typedef std::map<unsigned int,size_t> count_t;

std::string wof_probe(wof_list_t wofs)
{
	count_t i_ports;
	count_t o_ports;

	for(size_t ii=0;ii<wofs.size();++ii)
	{
		if(wofs[ii].dir=="<>"||wofs[ii].dir==">")
			++o_ports[to_int(wofs[ii].f_port)];
		if(wofs[ii].dir=="<>"||wofs[ii].dir=="<")
			++i_ports[to_int(wofs[ii].l_port)];
	}

	std::ostringstream ostr;
	ostr<<"Out Ports\n";
	for(count_t::iterator it=o_ports.begin();it!=o_ports.end();++it)
		if(it->first>0&&it->first<65536&&it->second>0)
			ostr<<it->first<<" "<<it->second<<std::endl;
	ostr<<"\nIn Ports\n";
	for(count_t::iterator it=i_ports.begin();it!=i_ports.end();++it)
		if(it->first>0&&it->first<65536&&it->second>0)
			ostr<<it->first<<" "<<it->second<<std::endl;

	return ostr.str();
}