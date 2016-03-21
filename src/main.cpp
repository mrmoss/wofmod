#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include "probe.hpp"

void show_help()
{
	std::cerr<<"  Usage: ./wofprobe [-h][FILE]"<<std::endl;
	std::cerr<<"  -h          Apply high ports >=1024."<<std::endl;
	std::cerr<<"  If no wofstat file is provided, wofstats will be read from stdin."<<std::endl;
}

int main(int argc,char* argv[])
{
	std::cerr<<"Walls of Fire - Massages wofstat output into wof firewall rules."<<std::endl;
	std::istream* istr=&std::cin;
	std::ifstream fstr;
	bool highports=false;
	int lineno=0;
	try
	{
		if(argc>1)
		{
			for(int ii=1;ii<argc;++ii)
			{
				std::string option(argv[ii]);

				if(ii+1==argc&&option.substr(0,1)!="-")
				{
					fstr.open(argv[ii]);
					if(!fstr)
						throw std::runtime_error("Could not open file \""+std::string(argv[1])+"\".");
					istr=&fstr;
				}
				else
				{
					std::string option(argv[ii]);
					if(option=="-h")
						highports=true;
					else
						throw std::runtime_error("Unknown cli option \""+option+"\".");
				}
			}
		}
		wof_list_t wofs;
		std::string temp;
		while(true)
		{
			if(getline(*istr,temp))
			{
				wof_probe_line(temp,wofs);
				++lineno;
			}
			else
			{
				break;
			}
		}
		fstr.close();
		std::string output(wof_probe(wofs,highports));
		if(output.size()==0)
		{
			lineno=-1;
			throw std::runtime_error("No wofstats found.");
		}
		std::cout<<output<<std::flush;
	}
	catch(std::exception& error)
	{
		if(lineno>=0)
			std::cerr<<"Error line "<<lineno+1<<" - "<<error.what()<<std::endl;
		else
			std::cerr<<"Error - "<<error.what()<<std::endl;
		show_help();
		return 1;
	}
	catch(...)
	{
		if(lineno>=0)
			std::cerr<<"Error line "<<lineno+1<<" - Unknown exception."<<std::endl;
		else
			std::cerr<<"Error - Unknown exception."<<std::endl;
		show_help();
		return 1;
	}

	return 0;
}
