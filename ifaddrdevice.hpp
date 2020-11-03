#pragma once
class ifaddrdevice
{
public:
		typedef std::vector<ifaddrdevice> ifaddrdevice_array;
		virtual ~ifaddrdevice(){}

		static ifaddrdevice_array make()
		{

			struct sockaddr_in host_name;
			socklen_t host_len = sizeof(host_name);
			char myip[20] = {0, };

			{
				tnsocket sock(AF_INET, SOCK_DGRAM, 0);
				TN_ASSERT(sock.connect("8.8.8.8", 53) == tnsocket::sock_condition::ok);
				TN_ASSERT(!getsockname(sock.fd(), (struct sockaddr *)&host_name, &host_len));
				TN_ASSERT(inet_ntop(AF_INET, &host_name.sin_addr, myip, sizeof(myip)) != nullptr)
			}

			std::string default_local(myip);

			ifaddrdevice_array _s;

			struct ifaddrs *_ifaddrs = nullptr;
			TN_ASSERT(getifaddrs(&_ifaddrs) == 0);

			for(struct ifaddrs *addr = _ifaddrs;
					addr != nullptr;
					addr = addr->ifa_next)
			{
				ifaddrdevice _dev(addr, default_local);
				if(!_dev)
				{
					continue;
				}

				_s.push_back(_dev);
			}
			freeifaddrs(_ifaddrs);
			return _s;
		}
		friend std::ostream& operator<<(std::ostream& os, const ifaddrdevice& o);
		const std::string &name()const{return _name;}
		const std::string &address()const {return _addr;}
		bool is_defaultlocal() const {return _defaultlocal;}
private:
	ifaddrdevice(struct ifaddrs *from, const std::string &defaultlocal) :
		_defaultlocal(false)
	{
		if(from->ifa_addr->sa_family != AF_INET)
		{
			return;

		}
		get_devname(from, defaultlocal);
		get_addr(from, defaultlocal);
		get_addr_name(from, defaultlocal);
		get_netmask(from, defaultlocal);
		get_defaultlocal(from, defaultlocal);
		if(is_defaultlocal())
		{
			get_bcast(from, defaultlocal);
		}
	}
	void get_devname(struct ifaddrs *from, const std::string &defaultlocal)
	{
		_name = std::string(from->ifa_name);

	}
	void get_addr(struct ifaddrs *from, const std::string &defaultlocal)
	{
		char addrinfo[100] = {0, };
		TN_ASSERT(!getnameinfo(from->ifa_addr,
				sizeof(struct sockaddr_in),
				addrinfo,
				100,
				nullptr,
				0,
				NI_NUMERICHOST));
		_addr = std::string(addrinfo);
	}
	void get_addr_name(struct ifaddrs *from, const std::string &defaultlocal)
	{
		char addrinfoname[100] = {0, };
		TN_ASSERT(!getnameinfo(from->ifa_addr,
				sizeof(struct sockaddr_in),
				addrinfoname,
				100,
				nullptr,
				0,
				0));
		_addrname = std::string(addrinfoname);
	}
	void get_netmask(struct ifaddrs *from, const std::string &defaultlocal)
	{
		char netmask[100] = {0, };
		TN_ASSERT(!getnameinfo(from->ifa_netmask,
				sizeof(struct sockaddr_in),
				netmask,
				100,
				nullptr,
				0,
				NI_NUMERICHOST));
		_netmask = std::string(netmask);
	}
	void get_defaultlocal(struct ifaddrs *from, const std::string &defaultlocal)
	{
		_defaultlocal = _addr == defaultlocal;
	}

	void get_bcast(struct ifaddrs *from, const std::string &defaultlocal)
	{
		char bcast[100] = {0, };
		int sock;
		struct ifreq ifr;
		struct sockaddr_in *sin = nullptr;

		sock = socket(AF_INET, SOCK_STREAM, 0);
		TN_ASSERT(sock >= 0);

		strcpy(ifr.ifr_name, _name.c_str());

		TN_ASSERT(ioctl(sock, SIOCGIFBRDADDR, &ifr)>= 0)

		sin = (struct sockaddr_in*)&ifr.ifr_addr;

		strcpy(bcast, inet_ntoa(sin->sin_addr));

		close(sock);
		_bcastaddr = std::string(bcast);
	}
	 operator bool ()
		{
			 return !_name.empty() &&
					 !_addr.empty() &&
					 !_addrname.empty() &&
					 !_netmask.empty();
		}

	bool _defaultlocal;
	std::string _name;
	std::string _addr;
	std::string _addrname;
	std::string _netmask;
	std::string _bcastaddr;
};
std::ostream& operator<<(std::ostream& os, const ifaddrdevice& o)
{
	 os << "<ifaddrdevice info>" << std::endl;
    os << "device = " << o._name << std::endl;
    os << "address = " << o._addr << std::endl;
    os << "address name = " << o._addrname << std::endl;
    os << "netmask = " << o._netmask << std::endl;
    os << "bcast = " << o._bcastaddr << std::endl;
    os << "default local ip = " << o._defaultlocal << std::endl;
    return os;
}
