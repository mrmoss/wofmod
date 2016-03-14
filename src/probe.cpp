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

struct node_t
{
	unsigned int port;
	std::string proto;
};

bool operator<(const node_t& lhs,const node_t& rhs)
{
	return lhs.port<rhs.port;
}

typedef std::map<node_t,size_t> count_t;

std::string wof_probe(wof_list_t wofs)
{
	count_t i_ports;
	count_t o_ports;

	for(size_t ii=0;ii<wofs.size();++ii)
	{
		if(wofs[ii].dir=="<>"||wofs[ii].dir==">")
		{
			node_t node;
			node.port=to_int(wofs[ii].f_port);
			node.proto=wofs[ii].proto;
			++o_ports[node];
		}
		if(wofs[ii].dir=="<>"||wofs[ii].dir=="<")
		{
			node_t node;
			node.port=to_int(wofs[ii].l_port);
			node.proto=wofs[ii].proto;
			++i_ports[node];
		}
	}

	std::ostringstream ostr;
	ostr<<"#Defaults\ndefault <> deny\n\n";
	ostr<<"#Out Ports\n";
	for(count_t::iterator it=o_ports.begin();it!=o_ports.end();++it)
		if(it->first.port>0&&it->first.port<65536&&it->second>0)
			ostr<<it->first.proto<<" any>any:"<<it->first.port<<" pass\n";
	ostr<<"\n";
	ostr<<"#In Ports\n";
	for(count_t::iterator it=i_ports.begin();it!=i_ports.end();++it)
		if(it->first.port>0&&it->first.port<65536&&it->second>0)
			ostr<<it->first.proto<<" any:"<<it->first.port<<"<any pass\n";

	return ostr.str();
}