#pragma once
class pcap final
{
public:
	using packetfunctor = std::function<void (struct timeval, unsigned char const *const , unsigned )>;
private:

	class capturethread
	{
		friend class pcap;
		bool operator ==(const std::string &ifdev)
		{
			return _ifdev == ifdev;
		}
		packetfunctor _pktfunctor;
		pcap_t *_pcap_t;
		std::thread *_th;
		std::string _ifdev;
		capturethread(const std::string &ifdev,
				packetfunctor &&pf,
				int snapsize = sizeof(unsigned short),
				int mode = 1) : _pktfunctor(std::move(pf)),
						_pcap_t(pcap_open_live(ifdev.c_str(), snapsize, mode, 0, nullptr)),
						_th(nullptr),
						_ifdev(ifdev)

		{
			TN_ASSERT(_pcap_t);
		}
		~capturethread()
		{
			pcap_breakloop(_pcap_t);
			_th->join();
			delete _th;
			pcap_close(_pcap_t);
			_th = nullptr;
			_pcap_t = nullptr;
		}

		void cap(const struct pcap_pkthdr * hdr, const u_char *d)
		{
			_pktfunctor(hdr->ts, (unsigned char const *const)d, hdr->len);
		}
		static void cap(u_char *a, const struct pcap_pkthdr * hdr, const u_char *d)
		{
			((capturethread *)a)->cap(hdr, d);
		}
		void start()
		{
			_th = new std::thread([&]()->void{
					pcap_loop(_pcap_t, 0, capturethread::cap, (u_char *)this);
			});
		}
	};

	using _pcap_if = struct pcap_if;

	_pcap_if *_pcap_interface;

	template <typename functor>
	const _pcap_if *match_scan_if(functor &&f) const
	{
		_pcap_if *if_device = _pcap_interface;
		while(if_device)
		{
			if(f(if_device))
			{
				return if_device;
			}
			if_device = if_device->next;
		}
		return nullptr;
	}
	template <typename gfunctor>
	typename std::result_of<gfunctor(const _pcap_if *)>::type
	match_name_scanf_if_get(const std::string &ifname,
			gfunctor &&gf) const
	{
		return gf(match_scan_if([&ifname](const _pcap_if *i) -> bool {
			return ifname == i->name;
		}));
	}

public:
	using addresses = std::tuple<std::string, /* address */
			std::string, /* netmask for that address */
			std::string, /* broadcast address for that address */
			std::string /* P2P destination address for that address */
	>;

	std::list<capturethread *> _captureth;

	pcap() : _pcap_interface(nullptr)
	{

		char err[PCAP_ERRBUF_SIZE] = {0, };
		TN_ASSERT(pcap_findalldevs(&_pcap_interface, err) >= 0);
	}
	~pcap()
	{
		std::vector<std::string> devices = interface_name();
		for(auto &it : devices)
		{
			stop_capture(it);
		}
		pcap_freealldevs(_pcap_interface);
		_pcap_interface = nullptr;
	}
	const std::string & getip(const addresses &addrs) const 			{ return std::get<0>(addrs); }
	const std::string & getnetmask(const addresses &addrs) const 	{ return std::get<1>(addrs); }
	const std::string & getbroadcast(const addresses &addrs) const { return std::get<2>(addrs); }
	const std::string & getdst(const addresses &addrs) const 			{ return std::get<3>(addrs); }

	bool has_interface_name(const std::string &expectif) const
	{
		return match_scan_if([&expectif](_pcap_if *e)->bool{
			return expectif == e->name;
		}) != nullptr;
	}

	std::vector<std::string> interface_name() const
	{
		std::vector<std::string> names;
		match_scan_if([&names](const _pcap_if *i)->bool{
			names.push_back(i->name);
			return false;
		});
		return names;
	}
	std::string interface_description(const std::string &expectif) const
	{
		return match_name_scanf_if_get(expectif,
				[](const _pcap_if *i)->std::string{
			return i ? std::string(i->description) : std::string();
		});
	}
	std::vector<addresses>interface_address(const std::string &expectif)
	{
		return match_name_scanf_if_get(expectif,
						[&expectif](const _pcap_if *i)->std::vector<addresses>{
			std::vector <addresses> vec;
			struct pcap_addr *_addrs = i ? i->addresses : nullptr;
			while(_addrs)
			{
				vec.push_back(std::make_tuple(
						_addrs->addr ? std::string(inet_ntoa(((struct sockaddr_in *)_addrs->addr)->sin_addr)) : std::string(),
						_addrs->netmask ? std::string(inet_ntoa(((struct sockaddr_in *)_addrs->netmask)->sin_addr)) : std::string(),
						_addrs->broadaddr ? std::string(inet_ntoa(((struct sockaddr_in *)_addrs->broadaddr)->sin_addr)) : std::string(),
						_addrs->dstaddr ? std::string(inet_ntoa(((struct sockaddr_in *)_addrs->dstaddr)->sin_addr)) : std::string()));
				_addrs = _addrs->next;
			}
			return vec;
		});
	}

	bool interface_loopback(const std::string &expectif) const
	{
		return match_name_scanf_if_get(expectif,
				[](const _pcap_if *i)->bool{
			return i ? i->flags & PCAP_IF_LOOPBACK : false;
		});
	}
	bool interface_up(const std::string &expectif) const
	{
		return match_name_scanf_if_get(expectif,
				[](const _pcap_if *i)->bool{
			return i ? i->flags & PCAP_IF_UP : false;
		});
	}
	bool interface_running(const std::string &expectif) const
	{
		return match_name_scanf_if_get(expectif,
				[](const _pcap_if *i)->bool{
			return i ? i->flags & PCAP_IF_RUNNING : false;
		});
	}
	bool interface_wireless(const std::string &expectif) const
	{
		return match_name_scanf_if_get(expectif,
				[](const _pcap_if *i)->bool{
			return i ? i->flags & PCAP_IF_WIRELESS : false;
		});
	}
	bool interface_connectionstatus(const std::string &expectif) const
	{
		return match_name_scanf_if_get(expectif,
				[](const _pcap_if *i)->bool{
			return i ? i->flags & PCAP_IF_CONNECTION_STATUS : false;
		});
	}
	bool interface_statusunknown(const std::string &expectif) const
	{
		return match_name_scanf_if_get(expectif,
				[](const _pcap_if *i)->bool{
			return i ? i->flags & PCAP_IF_CONNECTION_STATUS_UNKNOWN : false;
		});
	}
	bool interface_statusconnected(const std::string &expectif) const
	{
		return match_name_scanf_if_get(expectif,
				[](const _pcap_if *i)->bool{
			return i ? i->flags & PCAP_IF_CONNECTION_STATUS_CONNECTED : false;
		});
	}

	bool interface_statusdisconnected(const std::string &expectif) const
	{
		return match_name_scanf_if_get(expectif,
				[](const _pcap_if *i)->bool{
			return i ? i->flags & PCAP_IF_CONNECTION_STATUS_DISCONNECTED : false;
		});

	}
	bool interface_statusnotapplicable(const std::string &expectif) const
	{
		return match_name_scanf_if_get(expectif,
				[](const _pcap_if *i)->bool{
			return i ? i->flags & PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE : false;
		});
	}

	unsigned number_of_interface_devices() const
	{
		unsigned num = 0;
		match_scan_if([&num](_pcap_if *e)->bool{num++;return false;});
		return num;
	}


	int do_capture(const std::string &ifdev,
			packetfunctor &&df,
			int snapsize = sizeof(unsigned short),
			int mode = 1)
	{
		if(!match_scan_if([&](const _pcap_if *i)->bool{
			return ifdev == i->name;
		}))
		{
			return -1;
		}
		_captureth.push_back(new capturethread(ifdev,
				std::move(df),
				snapsize,
				mode));
		_captureth.back()->start();
		return 1;
	}
	void stop_capture(const std::string &ifdev)
	{
		std::list<capturethread *>::iterator it;
		it = _captureth.begin();
		while(it != _captureth.end())
		{
			if((*it)->operator ==(ifdev))
			{
				capturethread *d = *it;
				_captureth.erase(it);
				delete d;
			}
		}
	}
};
