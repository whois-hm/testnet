#pragma once

class netftpclient
{
public:
	class dtp/*data transfer process*/
	{
		friend class netftpclient;
	public:
		typedef std::pair<unsigned char *, unsigned> data;

	private:
		tnsocket _tsock;
		flowtime _ft;
		bool _bcon;
		dtp(const std::string &ip, int port, int atime) :
			_tsock(AF_INET, SOCK_STREAM, 0),
			_ft(atime),
			_bcon(_tsock.connect(ip,
					port,
					_ft.remaintime()) == tnsocket::ok) { }
		bool can_get()
		{

			return _bcon &&
					_ft.flow();
		}
		bool can_put()
		{
			return can_get();/*same.*/
		}
		int put(const std::string &path)
		{
			int fd = open(path.c_str(), O_RDONLY);
			unsigned fd_size = 0;
			unsigned fd_up_size = 0;
			if(fd < 0)
			{
				return -1;
			}
			fd_size = lseek(fd, 0, SEEK_END);

			lseek(fd, 0, SEEK_SET);

			while(can_put())
			{
				unsigned char tbuf[1024] = {0, };
				unsigned fd_readbyte = read(fd, tbuf, 1024);
				if(fd_readbyte <= 0)
				{
					break;
				}
				tnsocket::sr res = _tsock.send(tbuf, fd_readbyte, 0, _ft.remaintime());
				if(!_tsock.sr_condition_ok(res))
				{
					break;
				}
				fd_up_size += _tsock.sr_writebyte(res);
				printf("ftp > dtp put [%d/%d]\r", fd_up_size, fd_size);
			}
			close(fd);
			return fd_size <= fd_up_size ? 1 : -1;
		}
		data get(unsigned size)
		{
			tnsocket::sr res;
			unsigned char *_get = nullptr;
			if(can_get() &&
					size > 0)
			{
				_get = new unsigned char[size];
				res = _tsock.recv(_get,
							size,
							0,
							_ft.remaintime(),
							[&](unsigned char *p, unsigned l)->bool{
							printf("ftp > dtp get [%d/%d]\r", l, size);
							return false;
						});

				if(_tsock.sr_condition_ok(res))
				{
					return std::make_pair(_get, size);
				}

				delete [] _get;
				_get = nullptr;
			}
			return std::make_pair(nullptr, 0);
		}
		data get()
		{
			unsigned char *_get = nullptr;
			unsigned _g_len = 0;
			unsigned p_g_len = 0;
			while(can_get())
			{
				unsigned char buffer[1024] = {0, };
				tnsocket::sr res = _tsock.recv(buffer,
										sizeof(buffer),
										0,
										_ft.remaintime(),
										[&](unsigned char *p, unsigned l)->bool{
										return true;
									});
				if(!_tsock.sr_condition_can(res))
				{
					/*we return the max byte util timeout or shutdowned..*/
					break;
				}

				p_g_len = _g_len;
				_g_len += _tsock.sr_readbyte(res);
				printf("ftp > dtp get [%d]\r", _g_len);

				if(p_g_len <= 0)
				{
					_get = new unsigned char[_g_len];
					memcpy(_get, buffer, _g_len);
					continue;
				}

				data dump[p_g_len];
				memcpy(dump,
						_get,
						p_g_len);
				delete [] _get;
				_get = new unsigned char[_g_len];
				memcpy(_get,
						dump,
						p_g_len);
				memcpy(_get + p_g_len,
						buffer,
						_g_len - p_g_len);
			}
			return std::make_pair(_get, _g_len);
		}

	};
private:
	std::string _serverip;
	int _port;
	tnsocket _pi_sock;

	typedef  std::tuple <bool, int, std::string, std::string > reply;
	int reply_code(const reply &r)
	{
		return std::get<1>(r);
	}
	bool reply_suc(const reply &r)
	{
		return std::get<0>(r);
	}
	std::string reply_cm(const reply &r)
	{
		return std::get<2>(r);
	}
	std::string reply_proto(const reply &r)
	{
		return std::get<3>(r);
	}
	bool can_parse(char *proto = nullptr, unsigned len = 0)
	{
		return (proto &&
				len > 3 &&
				proto[len - 1] == '\n' &&
				proto[len - 2] == '\r');
	}
	reply parse(char *proto = nullptr, unsigned len = 0)
	{
		reply res(false, -1, "unknown", "unknown");
		char recvproto[len + 1] = {0, };

		char *pcode = nullptr;
		char *pcm = nullptr;
		if(can_parse(proto, len))
		{
			memcpy(recvproto, proto, len);
			recvproto[len - 1] = 0;
			recvproto[len - 2] = 0;
			pcode = recvproto;
			for(unsigned i = 0; i < len; i++)
			{
				if(recvproto[i] == ' ')
				{
					recvproto[i] = 0;
					pcm = recvproto + (i + 1);
					break;
				}
			}
		}
		if(pcode) 						std::get<1>(res) = std::stoi(pcode);
		if(pcm) 							std::get<2>(res) = pcm;
		if(std::get<1>(res) != -1) 	std::get<0>(res) = true;
		if(std::get<0>(res)) 			std::get<3>(res) = std::string(proto);

		return res;
	}
	bool request(const std::string &request, int rqtime)
	{
		bool res = _pi_sock.sr_condition_ok(_pi_sock.send((void *)request.c_str(),
				request.size(),
				0,
				rqtime));
		if(res) 	printf("(ok) ftp request -> %s", request.c_str());
		else		printf("(fail) ftp request -> %s", request.c_str());

		return  res;
	}
	reply response(int rptime)
	{
		tnsocket::sock_srbyte buffer[1024] = {0, };

		tnsocket::sr res = _pi_sock.recv(buffer,
				sizeof(buffer),
				0,
				rptime,
				[&](unsigned char *p, unsigned l)->bool{
				return can_parse((char *)p,l);
			});
		if(_pi_sock.sr_condition_ok(res))
		{
			reply r = parse((char *)buffer,
					_pi_sock.sr_readbyte(res));
			if(reply_suc(r)) 	printf("(ok) ftp response -> %s", reply_proto(r).c_str());
			else 					printf("(fail) ftp response\n");


			return r;
		}
		return parse();
	}
	reply reqeust_reply(const std::string &requestcmd, int time)
	{
		do
		{
			flowtime ft(time);
			if(!requestcmd.empty())
			{
				if(!request(requestcmd, ft.remaintime()))
				{
					break;
				}
				if(!ft.flow())
				{
					break;
				}
			}
			return response(ft.remaintime());
		}while(0);
		/*break case reqeust ok but response process is timeout*/
		printf("(next to timeout fail) ftp request -> %s", requestcmd.c_str());
		return parse();
	}
	int enter_mode_pasv(std::string &addr, int &port, int timeout = -1 )
	{
		char *find;
		int a,b,c,d;
		int pa,pb;
		char ipaddr[256] = {0, };

		std::string proto = "PASV " + std::string("\r\n");
		reply re = reqeust_reply(proto, timeout);
		if(reply_code(re) != 227)
		{
			return -1;
		}
		find = strrchr((char *)reply_cm(re).c_str(), '(');
		sscanf(find, "(%d,%d,%d,%d,%d,%d)", &a, &b, &c, &d, &pa, &pb);
		sprintf(ipaddr, "%d.%d.%d.%d", a, b, c, d);
		port = pa * 256 + pb;
		addr = ipaddr;
		return 1;
	}
public:
	netftpclient() = delete;
	netftpclient(const std::string &serverip,
			unsigned port = 21) : _serverip(serverip),
					_port(port),
					_pi_sock(AF_INET, SOCK_STREAM, 0){}
	virtual ~netftpclient(){}
	unsigned get_dtplen(const netftpclient::dtp::data &d)
	{
		return d.second;
	}
	unsigned char *get_dtpdata(const netftpclient::dtp::data &d)
	{
		return d.first;
	}
	void dtpclear(netftpclient::dtp::data &d)
	{
		if(d.second > 0)
		{
			delete d.first;
		}
	}
	int pi_connet(int timeout = -1)
	{
		printf("ftp connection try.. %s (%d)\n", _serverip.c_str(), _port);
		do
		{
			flowtime ft(timeout);

			if(_pi_sock.connect(_serverip,
							_port,
							ft.remaintime())
					!=tnsocket::sock_condition::ok)
			{
				break;
			}
			if(!ft.flow())
			{
				break;
			}
			if(reply_code(response(ft.remaintime())) != 220)
			{
				break;
			}
			printf("ftp connection to %s (%d)\n", _serverip.c_str(), _port);
			return 1;
		}while(0);
		printf("ftp connection fail.. %s (%d)\n", _serverip.c_str(), _port);
		return -1;
	}
	int login(const std::string &id, const std::string &pwd, int timeout = -1)
	{
		do
		{
			flowtime ft(timeout);

			std::string proto = "USER "+ id + "\r\n";
			if(reply_code(reqeust_reply(proto, ft.remaintime())) != 331)
			{
				break;
			}
			if(!ft.flow())
			{
				break;
			}
			std::string repwd = "PASS " + pwd + "\r\n";
			if(reply_code(reqeust_reply(repwd, ft.remaintime())) != 230)
			{
				break;
			}
			return 1;
		}while(0);
		return -1;
	}
	int logout(int timeout = -1)
	{
		//todo close stream all

		std::string proto = "QUIT " + std::string("\r\n");
		if(reply_code(reqeust_reply(proto, timeout)) != 221)
		{
			return -1;
		}
		return 1;
	}
	std::string pwd(int timeout = -1)
	{

		do
		{
			std::string proto = "PWD " + std::string("\r\n");
			reply r = reqeust_reply(proto, timeout);

			if(reply_code(r) != 257)
			{
				break;
			}

			std::string path = reply_cm(r);
			if(path.size() <= 3 ||
							path.front() != '"')
			{
				break;
			}
			size_t nextq = path.find('"', 1);
			if(nextq == std::string::npos)
			{
				break;
			}
			return path.substr(1, nextq - 1);
		}while(0);
		return "";
	}
	netftpclient::dtp::data ls(const std::string &path, int timeout = -1)
	{
		netftpclient::dtp::data dlist(nullptr, 0);

		do
		{
			flowtime ft(timeout);
			std::string ip;
			int port;

			if(path.empty() ||
					enter_mode_pasv(ip, port, ft.remaintime()) <  0 ||
					!ft.flow())
			{
				break;
			}

			netftpclient::dtp dtpcon(ip, port, ft.remaintime());
			if(!dtpcon.can_get())
			{
				break;
			}
			std::string reuser = "NLST " + path + std::string("\r\n");
			if(reply_code(reqeust_reply(reuser, ft.remaintime())) != 150)
			{
				break;
			}
			if(!ft.flow())
			{
				break;
			}
			dlist = dtpcon.get();
			if(reply_code(response(ft.remaintime())) != 226)
			{
				if(dlist.second > 0)
				{
					delete [] dlist.first;
					dlist.second = 0;
				}
			}
		}while(0);

		return dlist;
	}
	netftpclient::dtp::data ls_al(const std::string &path, int timeout = -1)
	{
		netftpclient::dtp::data dlist(nullptr, 0);

		do
		{
			flowtime ft(timeout);
			std::string ip;
			int port;

			if(path.empty() ||
					enter_mode_pasv(ip, port, ft.remaintime()) <  0 ||
					!ft.flow())
			{
				break;
			}

			netftpclient::dtp dtpcon(ip, port, ft.remaintime());
			if(!dtpcon.can_get())
			{
				break;
			}
			std::string reuser = "LIST " + path + std::string("\r\n");
			if(reply_code(reqeust_reply(reuser, ft.remaintime())) != 150)
			{
				break;
			}
			if(!ft.flow())
			{
				break;
			}
			dlist = dtpcon.get();
			if(reply_code(response(ft.remaintime())) != 226)
			{
				if(dlist.second > 0)
				{
					delete [] dlist.first;
					dlist.second = 0;
				}
			}
		}while(0);

		return dlist;
	}
	int upload(const std::string &localpath,
			const std::string &targetpath,
			const std::string &file,
			int timeout = -1)
	{
		netftpclient::dtp::data ddata(nullptr, 0);
		int upres = -1;
		do
		{
			flowtime ft(timeout);

			std::string ip;
			int port;
			std::string fullpath = localpath + "/" + file;

			if(access(fullpath.c_str(), 0))
			{
				break;
			}

			if(enter_mode_pasv(ip, port, ft.remaintime()) <  0 ||
					!ft.flow())
			{
				break;
			}
			{
				netftpclient::dtp dtpcon(ip, port, ft.remaintime());
				if(!dtpcon.can_put())
				{
					break;
				}
				std::string reuser = "STOR " + targetpath + "/" + file + std::string("\r\n");
				reply r = reqeust_reply(reuser, ft.remaintime());
				if(reply_code(r) != 150)
				{
					break;
				}
				if(!ft.flow())
				{
					break;
				}
				upres = dtpcon.put(fullpath);
			}

			if(reply_code(response(ft.remaintime())) != 226)
			{
				upres = -1;
			}
			return upres;
		}while(0);
		return -1;
	}
	netftpclient::dtp::data download(const std::string &path,
			int timeout = -1)
	{
		unsigned size = 0;
		netftpclient::dtp::data ddata(nullptr, 0);
		do
		{
			flowtime ft(timeout);
			std::string ip;
			int port;

			if(path.empty() ||
					enter_mode_pasv(ip, port, ft.remaintime()) <  0 ||
					!ft.flow())
			{
				break;
			}
			netftpclient::dtp dtpcon(ip, port, ft.remaintime());
			if(!dtpcon.can_get())
			{
				break;
			}
			std::string reuser = "RETR " + path + std::string("\r\n");
			reply r = reqeust_reply(reuser, ft.remaintime());
			if(reply_code(r) != 150)
			{
				break;
			}
			if(!ft.flow())
			{
				break;
			}
			const char *find = strchr(reply_cm(r).c_str(), '(');
			if(find &&
					strlen(find) > 2 &&
					(sscanf(find + 1, "%d", &size) == 1))
			{
				ddata = dtpcon.get(size);
			}else ddata = dtpcon.get();
			if(reply_code(response(ft.remaintime())) != 226)
			{
				if(ddata.second > 0)
				{
					delete [] ddata.first;
					ddata.second = 0;
				}
			}
		}while(0);

		return ddata;
	}
	int  cd(const std::string &path,
			int timeout = -1)
	{
		std::string proto = "CWD " + path + std::string("\r\n");
		if(reply_code(reqeust_reply(proto, timeout)) != 250)
		{
			return -1;
		}
		return 1;
	}
	int rmdir(const std::string &path,
			int timeout = -1)
	{
		std::string proto = "MKD " + path + std::string("\r\n");
		if(reply_code(reqeust_reply(proto, timeout)) != 250)
		{
			return -1;
		}
		return 1;
	}
	int mkdir(const std::string &path,
			int timeout = -1)
	{
		std::string proto = "RMD " + path + std::string("\r\n");
		if(reply_code(reqeust_reply(proto, timeout)) != 250)
		{
			return -1;
		}
		return 1;
	}
	int rm(const std::string &path,
			int timeout = -1)
	{
		std::string proto = "DELE " + path + std::string("\r\n");
		if(reply_code(reqeust_reply(proto, timeout)) != 250)
		{
			return -1;
		}
		return 1;
	}
	int system(int timeout = -1)
	{
		std::string proto = "SYST " + std::string("\r\n");
		if(reply_code(reqeust_reply(proto, timeout)) != 215)
		{
			return -1;
		}
		return 1;
	}
	int mv(const std::string &pathfrom, const std::string &pathto, int timeout = -1)
	{
		flowtime ft(timeout);
		do
		{
			std::string proto_fr = "RNFR " + pathfrom + std::string("\r\n");
			if(reply_code(reqeust_reply(proto_fr, timeout)) != 350)
			{
				break;
			}
			if(!ft.flow())
			{
				break;
			}
			std::string proto_to = "RNTO " + pathto + std::string("\r\n");
			if(reply_code(reqeust_reply(proto_to, timeout)) != 250)
			{
				break;
			}
			return 1;
		}while(0);
		return -1;
	}

};
