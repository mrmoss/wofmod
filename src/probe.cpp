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

class node_t
{
	public:
		unsigned int port;
		std::string proto;

		node_t(unsigned int port,const std::string& proto):
			port(port),proto(proto)
		{}
};

bool operator<(const node_t& lhs,const node_t& rhs)
{
	return lhs.port<rhs.port;
}

typedef std::map<node_t,size_t> count_t;

std::string wof_probe(wof_list_t wofs,const bool highports)
{
	count_t i_ports;
	count_t o_ports;

	for(size_t ii=0;ii<wofs.size();++ii)
	{
		if((wofs[ii].dir=="<>"||wofs[ii].dir==">")&&wofs[ii].f_port!="0"&&(to_int(wofs[ii].f_port)<1024||highports))
			++o_ports[node_t(to_int(wofs[ii].f_port),wofs[ii].proto)];
		if((wofs[ii].dir=="<>"||wofs[ii].dir=="<")&&wofs[ii].l_port!="0"&&(to_int(wofs[ii].l_port)<1024||highports))
			++i_ports[node_t(to_int(wofs[ii].l_port),wofs[ii].proto)];
	}

	for(count_t::iterator it=o_ports.begin();it!=o_ports.end();++it)
	{
		if(it->first.proto=="tcp")
		{
			if(it->first.port==80&&o_ports.count(node_t(443,"tcp"))<=0)
				o_ports[node_t(443,"tcp")]=it->second;
			if(it->first.port==443&&o_ports.count(node_t(80,"tcp"))<=0)
				o_ports[node_t(80,"tcp")]=it->second;
		}
	}

	std::ostringstream ostr;
	ostr<<"#Defaults\ndefault <> deny\n\n";

	ostr<<"#Out Ports\n";
	for(count_t::iterator it=o_ports.begin();it!=o_ports.end();++it)
		ostr<<it->first.proto<<" any>any:"<<it->first.port<<" pass\n";
	ostr<<"\n";

	ostr<<"#In Ports\n";
	for(count_t::iterator it=i_ports.begin();it!=i_ports.end();++it)
		ostr<<it->first.proto<<" any:"<<it->first.port<<"<any pass\n";
	ostr<<"\n";

	ostr<<"#Assumed Services (Change/Uncomment)\n";
	ostr<<"#udp any:68<>any:67 pass         #DHCP Client\n";
	ostr<<"#udp any>any:53     pass         #DNS  Client\n";
	ostr<<"#udp any<>any:123   pass         #NTP  Client\n";

	return ostr.str();
}
