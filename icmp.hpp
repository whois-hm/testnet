#pragma once
class neticmp
/*internet control message protocol
 * -------------------------------------------------------------------
 * | type(8bits)		|	code(8bits) | 	checksum(16bits)	|
 * -------------------------------------------------------------------
 * |					rest of the header						|
 * -------------------------------------------------------------------
 * |					data section								|
 * -------------------------------------------------------------------
 * 		type	             						code
 *     0(echo reply)
 *     3(destination unreachable)			   0(net unreachable)
 *                                         1(host unreacahble)
 *                                         2(protocol unreachable)
 *                                         3(port unreachable)
 *                                         4(fragmentation required, and df set)
 *                                         5(source route failed)
 *                                         6(destication network unknown)
 *                                         7(destination host unknown)
 *                                         8(source host lsolated)
 *                                         9(network administratively prohibited)
 *                                         10(host administratively prohibited)
 *                                         11(network unreachable for tos)
 *                                         12(host unreachable for tos)
 *                                         13(communication administratively prohibited)
 *
 *       4(source quench)
 *       5(redirect)                       0(redirect datagram for the network)
 *                                         1(redirect datagram for the host)
 *                                         2(redirect datagram for the tos & network)
 *                                         3(redirect datagram for the tos & host)
 *
 *
 *       8(echo)
 *       9(router advertisement)
 *       10(router selection)
 *       11(time exceeded)						0(ttl exceeded)
 *       											1(fragment reassembly time exceeded)
 *
 *       12(parameter problem)				0(pointer problem)
 *                                         1(missing a required operand)
 *                                         2(bad length)
 *
 *
 *       13(timestamp)
 *       14(timestamp reply)
 *       15(information request)
 *       16(informaion reply)
 *       17(address mask request)
 *       18(address mask reply)
 *       30(traceroute)
 * */
{
public:
	struct tc
	{
		int _type, _code;
		tc(int type, int code) : _type(type), _code(code){}
		~tc(){}
		virtual operator bool() const = 0;
	};
	struct echo_reply : public tc
	{
		std::chrono::nanoseconds _nsec;
		echo_reply(int type, int code, std::chrono::nanoseconds &&nsec) : tc(type, code), _nsec(nsec){}
		virtual operator bool() const
		{

			return echo_reply::match(_type, _code);
		}
		static bool match(int type, int code)
		{
			return type == ICMP_ECHOREPLY &&
					code == ICMP_ECHOREPLY;
		}
		friend std::ostream& operator<<(std::ostream& os, const neticmp::echo_reply& o);
	};
	struct timestamp_reply : public tc
	{
		std::chrono::milliseconds _sender_stime;
		std::chrono::milliseconds _sender_rtime;
		std::chrono::milliseconds _receiver_stime;
		std::chrono::milliseconds _receiver_rtime;
		timestamp_reply(int type, int code) : tc(type, code), _sender_stime(-1),_sender_rtime(-1),_receiver_stime(-1),_receiver_rtime(-1){}
		std::chrono::milliseconds sedingtime()const {return _receiver_rtime - _sender_stime;}
		std::chrono::milliseconds receivingtime() const {return _sender_rtime - _receiver_stime;}
		std::chrono::milliseconds rtt()const {return sedingtime() + receivingtime();}
		virtual operator bool() const
		{
			return timestamp_reply::match(_type, _code);
		}
		static bool match(int type, int code)
		{
			return type == ICMP_TIMESTAMPREPLY &&
					code == ICMP_ECHOREPLY;
		}
		friend std::ostream& operator<<(std::ostream& os, const neticmp::timestamp_reply& o);
	};
private:
	unsigned short checksum(unsigned short *p,
			unsigned n)
	{
	    register u_short answer;
	    register long sum = 0;
	    u_short odd_byte = 0;

	    while( n > 1 )
	    {
	        sum += *p++;
	        n -= 2;

	    }/* WHILE */

	    /* mop up an odd byte, if necessary */
	    if( n == 1 )
	    {
	        *( u_char* )( &odd_byte ) = *( u_char* )p;
	        sum += odd_byte;
	    }/* IF */

	    sum = ( sum >> 16 ) + ( sum & 0xffff );    /* add hi 16 to low 16 */
	    sum += ( sum >> 16 );                    /* add carry */
	    answer = ~sum;                            /* ones-complement, truncate*/

	    return ( answer );
	}

	int flow(const std::string targetip, int timeout, struct icmp pack, struct icmp &rpack)
	{
		int flow_res = -1;
		unsigned char iphdr_icmp_buffer[
										sizeof(struct iphdr) +
										60 +
										sizeof(struct icmp) + 100] = {0, };
		do
		{
			tnsocket sock(AF_INET, SOCK_RAW, IPPROTO_ICMP);
			sock.make_nonblock();

			/*put icmp packet*/
			if(!sock.sr_condition_ok(sock.sendto((void *)&pack,
					sizeof(struct icmp),
					MSG_DONTWAIT | MSG_NOSIGNAL,
					targetip,
					0)))
			{
				break;
			}

			/*recv ip*/
			if(sock.sr_readbyte(sock.recvfrom(iphdr_icmp_buffer,
					sizeof(iphdr_icmp_buffer),
					MSG_NOSIGNAL,
					targetip,
				    0,
					timeout,
					[&](unsigned char *, unsigned)->bool{return true;})) <= 0)
			{
				break;
			}

			/*complete all reading*/
			if(((struct iphdr *)iphdr_icmp_buffer)->protocol != IPPROTO_ICMP)
			{
				break;
			}
			rpack = *(struct icmp *) (iphdr_icmp_buffer + (((struct iphdr *)iphdr_icmp_buffer)->ihl * 4));
			flow_res = 0;
		}while(0);
		return flow_res;
	}
public:
	neticmp(){}
	virtual ~neticmp(){}
	neticmp::timestamp_reply timestamp(const std::string &targetip,
			int timeout = 0)
	{
		timestamp_reply tr(3, 0);
		struct icmp icmp_pack;
		struct icmp icmp_rpack;
		memset(&icmp_pack, 0, sizeof(struct icmp));
		memset(&icmp_rpack, 0, sizeof(struct icmp));
		do
		{

			{
				auto _now = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
				auto _ms = std::chrono::time_point_cast<std::chrono::milliseconds>(_now);
				tr._sender_stime = _ms.time_since_epoch();
			}

			/*set icmp*/
			icmp_pack.icmp_type = ICMP_TIMESTAMP;
			icmp_pack.icmp_code = 0;
			icmp_pack.icmp_hun.ih_idseq.icd_id = getpid();
			icmp_pack.icmp_hun.ih_idseq.icd_seq = 10;
			icmp_pack.icmp_dun.id_ts.its_otime = tr._sender_stime.count();
			icmp_pack.icmp_cksum = checksum((unsigned short *)&icmp_pack, sizeof(struct icmp));

			if(flow(targetip, timeout, icmp_pack, icmp_rpack))
			{
				break;
			}

			if(!neticmp::timestamp_reply::match(icmp_rpack.icmp_type, icmp_rpack.icmp_code) ||
					icmp_rpack.icmp_hun.ih_idseq.icd_id != getpid() ||
					icmp_rpack.icmp_hun.ih_idseq.icd_seq != 10)
			{
				break;
			}
			{
				auto _now = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
				auto _ms = std::chrono::time_point_cast<std::chrono::milliseconds>(_now);
				tr._sender_rtime = _ms.time_since_epoch();
			}
			tr._receiver_rtime = std::chrono::milliseconds(icmp_rpack.icmp_dun.id_ts.its_rtime);
			tr._receiver_stime = std::chrono::milliseconds(icmp_rpack.icmp_dun.id_ts.its_ttime);
			tr._type = icmp_rpack.icmp_type;
			tr._code = icmp_rpack.icmp_code;
			return tr;
		}while(0);
		return tr;/*net un reachable*/;
	}

	neticmp::echo_reply echo(const std::string &targetip,
			int timeout = 0)
	{
		std::chrono::system_clock::time_point start_rtt;
		std::chrono::system_clock::time_point end_rtt;
		struct icmp icmp_pack;
		struct icmp icmp_rpack;
		memset(&icmp_pack, 0, sizeof(struct icmp));
		memset(&icmp_rpack, 0, sizeof(struct icmp));

		do
		{
			icmp_pack.icmp_type = ICMP_ECHO;
			icmp_pack.icmp_code = 0;
			icmp_pack.icmp_hun.ih_idseq.icd_id = getpid();
			icmp_pack.icmp_hun.ih_idseq.icd_seq = 10;
			icmp_pack.icmp_cksum = checksum((unsigned short *)&icmp_pack, sizeof(struct icmp));

			start_rtt = std::chrono::system_clock::now();
			if(flow(targetip, timeout, icmp_pack, icmp_rpack))
			{
				break;
			}
			if(!neticmp::echo_reply::match(icmp_rpack.icmp_type, icmp_rpack.icmp_code) ||
					icmp_rpack.icmp_hun.ih_idseq.icd_id != getpid() ||
					icmp_rpack.icmp_hun.ih_idseq.icd_seq != 10)
			{
				break;
			}
			end_rtt = std::chrono::system_clock::now();
			return neticmp::echo_reply(icmp_rpack.icmp_type,
					icmp_rpack.icmp_code,
					end_rtt - start_rtt);
		}while(0);

		return neticmp::echo_reply(3,
				0,
				std::chrono::nanoseconds(-1));/*net un reachable*/;
	}
};


std::ostream& operator<<(std::ostream& os, const neticmp::echo_reply& o)
{
	os << "<echo reply>" << std::endl;
	os << "type = " << o._type << std::endl;
	os << "code = " << o._code << std::endl;
	os << "nsec = " << o._nsec.count() << std::endl;
	os << "res = " << o.operator bool() << std::endl;
   return os;
}
std::ostream& operator<<(std::ostream& os, const neticmp::timestamp_reply& o)
{
	os << "<timestamp reply>" << std::endl;
	os << "type = " << o._type << std::endl;
	os << "code = " << o._code << std::endl;
	os << "sender sending time = "<< o._sender_stime.count() << std::endl;
	os << "sender receiving time = "<< o._sender_rtime.count() << std::endl;
	os << "receiver sending time = "<< o._receiver_stime.count() << std::endl;
	os << "receiver receiving time = "<< o._receiver_rtime.count() << std::endl;
	os << "sending time = " << o.sedingtime().count() << std::endl;
	os << "receiving time = " << o.receivingtime().count() << std::endl;
	os << "rtt = " << o.rtt().count() << std::endl;
	os << "res = " << o.operator bool() << std::endl;

    return os;
}
