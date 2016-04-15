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
		std::string dir;
		std::string addr;

		node_t(unsigned int port,const std::string& proto,const std::string& dir="",const std::string& addr="any"):
			port(port),proto(proto),dir(dir),addr(addr)
		{}
};

bool operator<(const node_t& lhs,const node_t& rhs)
{
	return (lhs.port<rhs.port);
}

bool operator==(const node_t& lhs,const node_t& rhs)
{
	return (lhs.port==rhs.port&&lhs.proto==rhs.proto&&
		(lhs.dir==rhs.dir||lhs.dir=="<>"||rhs.dir=="<>")&&
		(lhs.addr==rhs.addr||lhs.addr=="any"||rhs.addr=="any"));
}

node_t reverse(node_t node)
{
	if(node.dir==">")
		node.dir="<";
	else if(node.dir=="<")
		node.dir=">";
	return node;
}

typedef std::map<node_t,size_t> count_t;

void remove_duplicates(count_t& counts,const std::vector<node_t> dups)
{
	for(count_t::iterator it=counts.begin();it!=counts.end();)
	{
		bool deleted=false;
		for(size_t ii=0;ii<dups.size();++ii)
		{
			if(it->first==dups[ii])
			{
				counts.erase(it++);
				deleted=true;
				break;
			}
		}
		if(!deleted)
			++it;
	}
}

std::string wof_probe(wof_list_t wofs,const bool highports)
{
	count_t i_ports;
	count_t o_ports;
	for(size_t ii=0;ii<wofs.size();++ii)
	{
		if((wofs[ii].dir=="<>"||wofs[ii].dir==">")&&wofs[ii].f_port!="0"&&(to_int(wofs[ii].f_port)<10000||highports))
		{
			std::string addr(wofs[ii].f_ip+"/"+wofs[ii].f_mask);
			if(wofs[ii].f_mask=="32"&&!wofs[ii].V6)
				addr=wofs[ii].f_ip;
			if(wofs[ii].f_mask=="128"&&wofs[ii].V6)
				addr=wofs[ii].f_ip;
			if(wofs[ii].f_ip=="0.0.0.0"||wofs[ii].f_ip=="::"||wofs[ii].f_port=="80"||wofs[ii].f_port=="443")
				addr="any";
			++o_ports[node_t(to_int(wofs[ii].f_port),wofs[ii].proto,">",addr)];
		}
		if((wofs[ii].dir=="<>"||wofs[ii].dir=="<")&&wofs[ii].l_port!="0"&&(to_int(wofs[ii].l_port)<10000||highports))
			++i_ports[node_t(to_int(wofs[ii].l_port),wofs[ii].proto,"<")];
	}
	//https://support.microsoft.com/en-us/kb/832017#4
	//nodes are arranged for a client, call reverse on server checks.
	bool ad_server=false;
	bool ad_client=false;
	std::vector<node_t> ad_ports;
		ad_ports.push_back(node_t(88,"any",">"));
		ad_ports.push_back(node_t(389,"any",">"));
		ad_ports.push_back(node_t(464,"any",">"));
		ad_ports.push_back(node_t(636,"any",">"));
		ad_ports.push_back(node_t(2535,"udp",">"));
		ad_ports.push_back(node_t(3268,"tcp",">"));
		ad_ports.push_back(node_t(3269,"tcp",">"));
		ad_ports.push_back(node_t(9389,"tcp",">"));
	std::vector<node_t> ad_ports_additional;
		ad_ports_additional.push_back(node_t(25,"tcp",">"));
		ad_ports_additional.push_back(node_t(53,"udp",">"));
		ad_ports_additional.push_back(node_t(67,"udp",">"));
		ad_ports_additional.push_back(node_t(123,"udp",">"));
		ad_ports_additional.push_back(node_t(445,"tcp","<"));
		ad_ports_additional.push_back(node_t(135,"tcp","<"));
		ad_ports_additional.push_back(node_t(137,"udp","<"));
		ad_ports_additional.push_back(node_t(138,"udp","<"));
		ad_ports_additional.push_back(node_t(139,"tcp","<"));
	std::vector<node_t> ad_devil_ports;
		ad_devil_ports.push_back(node_t(445,"tcp","<"));
		ad_devil_ports.push_back(node_t(135,"tcp","<"));
		ad_devil_ports.push_back(node_t(137,"udp","<"));
		ad_devil_ports.push_back(node_t(138,"udp","<"));
		ad_devil_ports.push_back(node_t(139,"tcp","<"));
	for(count_t::iterator it=i_ports.begin();it!=i_ports.end();++it)
	{
		for(size_t ii=0;ii<ad_ports.size();++ii)
			if(it->first==reverse(ad_ports[ii]))
			{
				ad_server=true;
				break;
			}
		if(ad_server)
			break;
	}
	for(count_t::iterator it=o_ports.begin();it!=o_ports.end();++it)
	{
		for(size_t ii=0;ii<ad_ports.size();++ii)
			if(it->first==ad_ports[ii])
			{
				ad_client=true;
				break;
			}
		if(ad_client)
			break;
	}
	if(ad_server)
	{
		remove_duplicates(i_ports,ad_ports);
		remove_duplicates(i_ports,ad_ports_additional);
	}
	if(ad_client)
	{
		remove_duplicates(o_ports,ad_ports);
		remove_duplicates(o_ports,ad_ports_additional);
	}
	if(!ad_server&&!ad_client)
	{
		for(count_t::iterator it=i_ports.begin();it!=i_ports.end();)
		{
			bool deleted=false;
			for(size_t ii=0;ii<ad_devil_ports.size();++ii)
			{
				if(it->first==ad_devil_ports[ii]||it->first==reverse(ad_devil_ports[ii]))
				{
					i_ports.erase(it++);
					deleted=true;
					break;
				}
			}
			if(!deleted)
				++it;
		}
		for(count_t::iterator it=o_ports.begin();it!=o_ports.end();)
		{
			bool deleted=false;
			for(size_t ii=0;ii<ad_devil_ports.size();++ii)
			{
				if(it->first==ad_devil_ports[ii]||it->first==reverse(ad_devil_ports[ii]))
				{
					o_ports.erase(it++);
					deleted=true;
					break;
				}
			}
			if(!deleted)
				++it;
		}
	}
	for(count_t::iterator it=o_ports.begin();it!=o_ports.end();++it)
	{
		if(o_ports.count(node_t(80,"tcp"))>0&&o_ports.count(node_t(443,"tcp")))
			break;
		if(it->first.proto=="tcp")
		{
			if(it->first.port==80&&o_ports.count(node_t(443,"tcp"))<=0)
				o_ports[node_t(443,"tcp")]=it->second;
			if(it->first.port==443&&o_ports.count(node_t(80,"tcp"))<=0)
				o_ports[node_t(80,"tcp")]=it->second;
		}
	}
	std::ostringstream ostr;
	ostr<<"#Defaults\n";
	ostr<<"default <> deny\n\n";
	if(o_ports.size()>0)
	{
		ostr<<"#Out Ports\n";
		for(count_t::iterator it=o_ports.begin();it!=o_ports.end();++it)
			ostr<<it->first.proto<<" any>"<<it->first.addr<<":"<<it->first.port<<" pass\n";
		ostr<<"\n";
	}
	if(i_ports.size()>0)
	{
		ostr<<"#In Ports\n";
		for(count_t::iterator it=i_ports.begin();it!=i_ports.end();++it)
			ostr<<it->first.proto<<" "<<it->first.addr<<":"<<it->first.port<<"<any pass\n";
		ostr<<"\n";
	}
	if(ad_server)
	{
		ostr<<"#AD Server\n";
		ostr<<"#Note, you probably want to change remote address to client ip range.\n";
		for(size_t ii=0;ii<ad_ports.size();++ii)
			ostr<<ad_ports[ii].proto<<" any:"<<ad_ports[ii].port<<"<any pass\n";
		ostr<<"tcp any:25<any\n";
		ostr<<"udp any:53<any\n";
		ostr<<"udp any:67<>any:68\n";
		ostr<<"udp any:123<>any:123\n";
		ostr<<"\n";
	}
	if(ad_client)
	{
		ostr<<"#AD Client\n";
		ostr<<"#Note, you probably want to change remote address to server ip.\n";
		for(size_t ii=0;ii<ad_ports.size();++ii)
			ostr<<ad_ports[ii].proto<<" any>any:"<<ad_ports[ii].port<<" pass\n";
		ostr<<"tcp any>any:25\n";
		ostr<<"udp any>any:53\n";
		ostr<<"udp any:68<>any:67\n";
		ostr<<"udp any:123<>any:123\n";
		ostr<<"\n";
	}
	ostr<<"#Common Services (Change/Uncomment)\n";
	ostr<<"#udp any:68<>any:67   pass #DHCP Client\n";
	ostr<<"#udp any>any:53       pass #DNS  Client\n";
	ostr<<"#udp any:123<>any:123 pass #NTP  Client\n";
	return ostr.str();
}
