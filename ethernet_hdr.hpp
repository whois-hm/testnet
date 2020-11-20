#pragma once
class ethernet_hdr
{
protected:
	unsigned char const *const _pkt;
	unsigned _len;
	struct ether_header *_ether_hdr;
	struct iphdr *_ip_hdr;

	virtual void print(const std::string &what)
	{
		printf("%s", what.c_str());
	}
	void dump_pkt()
	{
		for(int i = 1; i <= _len; i++)
		{
			char b[10] = {0,};
			snprintf(b, 8, "%02x ", _pkt[i-1]);
			print(b);
			if(i % 16 == 0)
			{
				print("\n");
			}
		}
	}

	void dec_layer_datalink()
	{
		char src_mac_buffer [256] = {0,};
		char dst_mac_buffer [256] = {0,};
		uint16_t host = 0;
		char const *ethernet_type = nullptr;
		bool supported = false;
		struct _ethtype_map
		{
			u_int16_t t;
			char const *s;
			bool b;
		}ethtype_map[] =
		{
				{ETHERTYPE_PUP, 		"Xeror PUP", false},
				{ETHERTYPE_SPRITE, 	"Sprite", false},
				{ETHERTYPE_IP, 		"IP", true},
				{ETHERTYPE_ARP, 		"Address resolution", true},
				{ETHERTYPE_REVARP, 	"Reverse ARP", false},
				{ETHERTYPE_AT, 		"AppleTalk protocol", false},
				{ETHERTYPE_AARP, 	"AppleTalk ARP", false},
				{ETHERTYPE_VLAN, 	"IEEE 802.1Q VLAN tagging", false},
				{ETHERTYPE_IPX, 		"IPX", false},
				{ETHERTYPE_IPV6, 	"IP protocol version 6", false},
				{ETHERTYPE_LOOPBACK,"used to test interfaces", false},
		};

		_ether_hdr = (struct ether_header *)_pkt;
		snprintf(src_mac_buffer, 250, "%02x:%02x:%02x:%02x:%02x:%02x",
				_ether_hdr->ether_shost[0],
				_ether_hdr->ether_shost[1],
				_ether_hdr->ether_shost[2],
				_ether_hdr->ether_shost[3],
				_ether_hdr->ether_shost[4],
				_ether_hdr->ether_shost[5]);
		snprintf(dst_mac_buffer, 250, "%02x:%02x:%02x:%02x:%02x:%02x",
				_ether_hdr->ether_dhost[0],
				_ether_hdr->ether_dhost[1],
				_ether_hdr->ether_dhost[2],
				_ether_hdr->ether_dhost[3],
				_ether_hdr->ether_dhost[4],
				_ether_hdr->ether_dhost[5]);

		host = ntohs(_ether_hdr->ether_type);
		for(int i = 0; i < sizeof(ethtype_map) / sizeof(ethtype_map[0]); i++)
		{
			if(host == ethtype_map[i].t)
			{
				ethernet_type = ethtype_map[i].s;
				supported = ethtype_map[i].b;
				break;
			}
		}
		print(std::string("- DataLink Layer -\n"));
		if(!supported)
		{
			print("Sorry Can't parsing this DataLink Layer Data\n");
			dump_pkt();
			return;
		}
		print(std::string("Source Mac Address = ") + src_mac_buffer + std::string("\n"));
		print(std::string("Destination Mac Address = ") + dst_mac_buffer + std::string("\n"));
		print(std::string("Ethernet Type = ") + ethernet_type + std::string("\n"));
		dec_layer_network();
	}
	void dec_layer_network_type_icmp()
	{

	}
	void dec_layer_network_type_ip()
	{
		struct _ipproto_map
		{
			unsigned t;
			char const *s;
			bool b;
		}ipproto_map[] =
		{
				{IPPROTO_IP ,	   " Dummy protocol for TCP.  ", false},
				{IPPROTO_HOPOPTS,   " IPv6 Hop-by-Hop options.  ", false},
				{IPPROTO_ICMP,	   " Internet Control Message Protocol.  ", true},
				{IPPROTO_IGMP,	   " Internet Group Management Protocol. ", false},
				{IPPROTO_IPIP,	   " IPIP tunnels (older KA9Q tunnels use 94).  ", false},
				{IPPROTO_TCP ,	   " Transmission Control Protocol.  ", true},
				{IPPROTO_EGP ,	   " Exterior Gateway Protocol.  ", false},
				{IPPROTO_PUP ,	   " PUP protocol.  ", false},
				{IPPROTO_UDP ,	   " User Datagram Protocol.  ", true},
				{IPPROTO_IDP ,	   " XNS IDP protocol.  ", false},
				{IPPROTO_TP ,	   " SO Transport Protocol Class 4.  ", false},
				{IPPROTO_DCCP ,	   " Datagram Congestion Control Protocol.  ", false},
				{IPPROTO_IPV6 ,     " IPv6 header.  ", false},
				{IPPROTO_ROUTING ,  " IPv6 routing header.  ", false},
				{IPPROTO_FRAGMENT , " IPv6 fragmentation header.  ", false},
				{IPPROTO_RSVP ,	   " Reservation Protocol.  ", false},
				{IPPROTO_GRE,	   " General Routing Encapsulation.  ", false},
				{IPPROTO_ESP,      " encapsulating security payload.  ", false},
				{IPPROTO_AH ,       " authentication header.  ", false},
				{IPPROTO_ICMPV6,   " ICMPv6.  ", false},
				{IPPROTO_NONE,     " IPv6 no next header.  ", false},
				{IPPROTO_DSTOPTS ,  " IPv6 destination options.  ", false},
				{IPPROTO_MTP ,	   " Multicast Transport Protocol.  ", false},
				{IPPROTO_ENCAP,	   " Encapsulation Header.  ", false},
				{IPPROTO_PIM ,	   " Protocol Independent Multicast.  ", false},
				{IPPROTO_COMP,	   " Compression Header Protocol.  ", false},
				{IPPROTO_SCTP ,	   " Stream Control Transmission Protocol.  ", false},
				{IPPROTO_UDPLITE , " UDP-Lite protocol.  ", false},
				{IPPROTO_RAW,	   " Raw IP packets.  ", false}
		};

		char const *proto = nullptr;
		bool supported = false;
		_ip_hdr = (struct iphdr *)(_pkt + sizeof(struct ether_header));

		for(int i = 0; i < sizeof(ipproto_map) / sizeof(ipproto_map[0]); i++)
		{
			if(_ip_hdr->protocol == ipproto_map[i].t)
			{
				proto = ipproto_map[i].s;
				supported = ipproto_map[i].b;
				break;
			}
		}
		if(!supported)
		{
			print("Sorry Can't parsing this Network Layer Data\n");
			dump_pkt();
			return;
		}

		print(std::string("IP Version = ") + std::to_string(_ip_hdr->version) + std::string("\n"));
		print(std::string("Header Length = ") + std::to_string(_ip_hdr->ihl << 2) + std::string("Bytes") + std::string("\n"));
		print(std::string("Type of Service = ") + std::to_string(ntohs(_ip_hdr->tos)) + std::string("\n"));
		print(std::string("Total Length = ") + std::to_string(ntohs(_ip_hdr->tot_len)) + std::string("Bytes") + std::string("\n"));
		print(std::string("ID = ") + std::to_string(ntohs(_ip_hdr->id)) + std::string("\n"));
		print(std::string("Fragment offset = ") + std::to_string(ntohs(_ip_hdr->frag_off)) + std::string("\n"));
		print(std::string("TTL = ") + std::to_string(_ip_hdr->ttl) + std::string("sec") + std::string("\n"));
		print(std::string("Checksum = ") + std::to_string(_ip_hdr->check) + std::string("\n"));
		struct in_addr a;
		a.s_addr = _ip_hdr->saddr;
		print(std::string("Source IP = ") + std::string(inet_ntoa(a)) + std::string("\n"));
		a.s_addr = _ip_hdr->daddr;
		print(std::string("Destination IP = ") + std::string(inet_ntoa(a)) + std::string("\n"));
		print(std::string("Protocol = ") + std::string(proto) + std::string("\n"));


		if(_ip_hdr->protocol == IPPROTO_UDP ||
				_ip_hdr->protocol == IPPROTO_TCP)
		{
			dec_layer_transport();
		}
		else if(_ip_hdr->protocol == IPPROTO_ICMP)
		{
			dec_layer_network_type_icmp();
		}

	}
	void dec_layer_network()
	{
		print(std::string("- Network Layer -\n"));
		if(ntohs(_ether_hdr->ether_type) == ETHERTYPE_IP)
		{
			dec_layer_network_type_ip();
		}
		else
		{
			print("Sorry Can't parsing this Network Layer Data\n");
			dump_pkt();
			return;
		}

	}
	void dec_layer_transport()
	{

	}
public:
	ethernet_hdr(unsigned char const *const packet, unsigned len) :
		_pkt(packet), _len(len), _ether_hdr(nullptr),_ip_hdr(nullptr) { }
	virtual ~ethernet_hdr(){}
	std::pair<unsigned char *, unsigned> copy()
	{
		unsigned char *newdump = new unsigned char[_len];
		memcpy(newdump, _pkt, _len);
		return std::make_pair(newdump, _len);
	}
	void decode()
	{
		dec_layer_datalink();
	}

};
