#pragma once

class tnsocket
{
public:
	typedef unsigned sock_srbyte;
	enum sock_condition
	{
		ok,
		shutdown,
		timeout,
		connection_refuse,
		error
	};

	typedef std::function<bool(unsigned char *, unsigned)> sr_break_status;

	typedef std::pair<sock_srbyte,/*value for socket reading or sending byte*/
			enum sock_condition/*value for condition*/
	> sr;
	unsigned sr_readbyte(const sr &srres) 						const { return srres.first; }
	unsigned sr_writebyte(const sr &srres) 						const { return srres.first; }
	enum sock_condition sr_condition(const sr &srres) 			const { return srres.second; }
	bool sr_condition_ok(const sr &srres) 						const { return sr_condition(srres) == tnsocket::sock_condition::ok; }
	bool sr_condition_shutdown(const sr &srres) 				const { return sr_condition(srres) == tnsocket::sock_condition::shutdown; }
	bool sr_condition_error(const sr &srres) 					const { return sr_condition(srres) == tnsocket::sock_condition::error; }
	bool sr_condition_timeout(const sr &srres) 					const { return sr_condition(srres) == tnsocket::sock_condition::timeout; }
	bool sr_condition_connection_refuse(const sr &srres) 	const { return sr_condition(srres) == tnsocket::sock_condition::connection_refuse; }
	bool sr_condition_can(const sr &srres) 						const { return !sr_condition_shutdown(srres) &&
																								!sr_condition_error(srres) &&
																								!sr_condition_connection_refuse(srres);}

private:


	tnsocket::sr makesr_syscall(int srcall)
	{
		sock_srbyte sbyte = 0;
		enum sock_condition con = tnsocket::sock_condition::error;
		if(srcall > 0)
		{
			sbyte = (sock_srbyte)srcall;
			con = tnsocket::sock_condition::ok;
		}
		else if(srcall == 0)
		{
			sbyte = 0;
			con = tnsocket::sock_condition::shutdown;
		}
		else
		{
			sbyte = 0;
			con = tnsocket::sock_condition::error;
		}
		return std::make_pair(sbyte, con);
	}

	enum sock_condition wait_for(int rw/*wait signal for reading if set 1
		other set 0 wait signal for writing
		other set -1 wait signal both rw*/,
		int timeout)
	{
		if(rw >= 1) rw = 1;
		if (rw <= -1) rw = -1;

		bool rflag = rw == 1 || rw < 0;
		bool wflag = rw == 0 || rw < 0;
		bool eflag = true;
		fds _wait(fds::_element(_fd, /*using _fds's block mode*/
						rflag,
						wflag,
						eflag));
		fds::fds_search_res res = _wait(timeout);
		if(_wait.timeout(res))
		{
			return tnsocket::sock_condition::timeout;
		}
		if(_wait.error(res))
		{
			return tnsocket::sock_condition::error;
		}
		fds::_element resp= _wait.get(res,
				fds::_element(_fd,
						true,
						true,
						true));
		if(!resp || resp.except())
		{
			return tnsocket::sock_condition::error;
		}
		if(rflag && resp.read())
		{
			return tnsocket::sock_condition::ok;
		}
		if(wflag && resp.write())
		{
			return tnsocket::sock_condition::ok;
		}
		return tnsocket::sock_condition::error;
	}
	template <typename functor>
	tnsocket::sr sr_any(functor &&f,
			sr_break_status &f_status,
			void *p,
			unsigned l,
			int fl,
			struct sockaddr_in in,
			int timeout,
			int waitdir)
	{
		sock_srbyte total = 0;
		tnsocket::sock_condition con = tnsocket::sock_condition::error;
		bool iscurrentblock = !fds::_element(_fd).is_nonblocking();
		make_nonblock();
		flowtime ft(timeout);

		do
		{
			tnsocket::sr srres;

			con = wait_for(waitdir, ft.remaintime());
			if(con == tnsocket::sock_condition::error)
			{
				total = 0;
				break;
			}
			if(con == tnsocket::sock_condition::timeout)
			{
				break;
			}
			srres = f((void*)(((unsigned char *)p) + total),
					l - total,
					fl,
					in);

			if(!sr_condition_can(srres))
			{
				total = 0;
				con = sr_condition(srres);
				break;
			}

			total += sr_readbyte(srres);
			con = tnsocket::sock_condition::timeout;

			if(f_status)
			{
				if(f_status(((unsigned char *)p), total))
				{
					con = tnsocket::sock_condition::ok;
					break;
				}
			}

			if(total >= (sock_srbyte)l)
			{
				con = tnsocket::sock_condition::ok;
				break;
			}

		}while(ft.flow());
		if(iscurrentblock)
		{
			make_block();
		}
		return std::make_pair( total,
				con);
	}
protected:
	int _domain;
	int _type;
	int _protocol;
	int _fd;
	struct sockaddr_in fill_sockaddr_in(const std::string &ip,
			int domain,
			unsigned short port)
	{
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(struct sockaddr_in));

		if(!ip.empty())
		{
			addr.sin_addr.s_addr = inet_addr(ip.c_str());
		}
		else
		{
			addr.sin_addr.s_addr = htonl(INADDR_ANY);
		}
		addr.sin_family = domain;
		addr.sin_port = htons(port);
		return addr;
	}
public:
	tnsocket (const tnsocket &s) = delete;
	tnsocket operator = (const tnsocket &s) = delete;
	tnsocket (tnsocket &&rhs)
	{
		_fd = rhs._fd;
		_domain = rhs._domain;
		_type = rhs._type;
		_protocol = rhs._protocol;
		rhs._fd = -1;
	}
	tnsocket operator = (tnsocket &&s)
	{
		return std::move(s);
	}

	tnsocket() :
	_domain(-1),
	_type(-1),
	_protocol(-1),
	 _fd(-1){}
	tnsocket(int fd) : _fd(fd)
	{
		TN_ASSERT(valid());
		{
			socklen_t len = sizeof(_domain);
			TN_ASSERT(!getsockopt(_fd, SOL_SOCKET, SO_DOMAIN, &_domain, &len));
		}
		{
			socklen_t len = sizeof(_type);
			TN_ASSERT(!getsockopt(_fd, SOL_SOCKET, SO_TYPE, &_type, &len));
		}
		{
			socklen_t len = sizeof(_protocol);
			TN_ASSERT(!getsockopt(_fd, SOL_SOCKET, SO_PROTOCOL, &_protocol, &len));
		}
	}
	tnsocket(int domain,
			int type,
			int protocol) :
				_domain(domain),
				_type(type),
				_protocol(protocol),
				_fd (socket(_domain, _type, _protocol))
	{
		TN_ASSERT(valid());
	}
	bool isaccepted()
	{
		int t = -1;
		if(valid())
		{
			socklen_t len = sizeof(t);
			TN_ASSERT(!getsockopt(_fd, SOL_SOCKET, SO_ACCEPTCONN, &t, &len));
			t = 1;
		}

		return t == 1;
	}
	std::string accepted_get_ip()
	{
		struct sockaddr_in clientaddr;
		bzero(&clientaddr, sizeof(clientaddr));
		socklen_t client_len = sizeof(clientaddr);
		if(isaccepted() &&
				!getpeername(_fd, (struct sockaddr *)&clientaddr, &client_len))
		{
			return std::string (inet_ntoa(clientaddr.sin_addr));
		}
		return std::string();
	}
	int accepted_get_port()
	{
		struct sockaddr_in clientaddr;
		bzero(&clientaddr, sizeof(clientaddr));
		socklen_t client_len = sizeof(clientaddr);
		if(isaccepted() &&
				!getpeername(_fd, (struct sockaddr *)&clientaddr, &client_len))
		{
			return ntohs(clientaddr.sin_port);
		}
		return -1;
	}
	virtual ~tnsocket()
	{
		set_invalid();
	}
	const int &fd()
	{
		return _fd;
	}
	bool valid() const {return _fd != -1;}
	operator bool() const
	{
		return valid();
	}
	void set_invalid()
	{
		if(valid())
		{
			close(_fd);
			_fd = -1;
		}
	}
	void make_nonblock()
	{
		fds::_element(_fd).
				make_nonblocking();
	}
	void make_block()
	{
		fds::_element(_fd).
				make_blocking();
	}

	tnsocket::sr send(void *p,
			unsigned l,
			int f,
			int timeout = 0,
			sr_break_status f_status = nullptr)
	{
		struct sockaddr_in in;
		return sr_any([&](void *p,
				unsigned l,
				int fl,
				struct sockaddr_in in)->tnsocket::sr{
			return makesr_syscall(::send(_fd,
							p,
							l,
							f));
		}, f_status, p, l, f, in, timeout, 0);
	}
	tnsocket::sr recv(void *p,
			unsigned l,
			int f,
			int timeout = 0,
			sr_break_status f_status = nullptr)
	{
		struct sockaddr_in in;
		return sr_any([&](void *p,
				unsigned l,
				int fl,
				struct sockaddr_in in)->tnsocket::sr{
			return makesr_syscall(::recv(_fd,
					p,
					l,
					f));
		}, f_status, p, l, f, in, timeout, 1);
	}
	tnsocket::sr sendto(void *p,
			unsigned l,
			int f,
			const std::string &toip,
			unsigned short toport,
			int timeout = 0,
			sr_break_status f_status = nullptr)
	{
		struct sockaddr_in to_server =
				fill_sockaddr_in(toip, _domain, toport);

		return sr_any([&](void *p,
				unsigned l,
				int fl,
				struct sockaddr_in in)->tnsocket::sr{
			return makesr_syscall(::sendto(_fd,
							p,
							l,
							f,
							(struct sockaddr *)&to_server,
							sizeof(to_server)));
		}, f_status, p, l, f, to_server, timeout, 0);
	}
	tnsocket::sr recvfrom(void *p,
			unsigned l,
			int f,
			const std::string &toip,
			unsigned short toport,
			int timeout = 0,
			sr_break_status f_status = nullptr)
	{
		struct sockaddr_in to_server =
				fill_sockaddr_in(toip, _domain, toport);

		return sr_any([&](void *p,
				unsigned l,
				int fl,
				struct sockaddr_in in)->tnsocket::sr{
			unsigned len = sizeof(in);
			return makesr_syscall(::recvfrom(_fd,
							p,
							l,
							f,
							(struct sockaddr *)&to_server,
							&len));
		}, f_status, p, l, f, to_server, timeout, 1);
	}


	tnsocket::sock_condition connect(const std::string &toip,
			unsigned short toport,
			int timeout = -1)
	{
		#define break_con(n) {conres = n; break;}
		bool iscurrentblock = !fds::_element(_fd).is_nonblocking();
		tnsocket::sock_condition conres = tnsocket::sock_condition::error;
		struct sockaddr_in to_server = fill_sockaddr_in(toip, _domain, toport);
		socklen_t getopt_len = 0;
		int getopt_len_error = 0;


		make_nonblock();

		do
		{
			if(::connect(_fd,
					(struct sockaddr *)&to_server,
					sizeof(struct sockaddr_in)) >= 0)
			{
				break_con(tnsocket::sock_condition::ok);
			}
			if(errno != EINPROGRESS)
			{
				break_con(tnsocket::sock_condition::error);
			}
			tnsocket::sock_condition con = wait_for(0, timeout);
			if( con != tnsocket::sock_condition::ok)
			{
				break_con(con);
			}
			getopt_len = sizeof(getopt_len_error);
			if(getsockopt(_fd,
					SOL_SOCKET,
					SO_ERROR,
					(void *)&getopt_len_error,
					&getopt_len) < 0)
			{
				if(getopt_len_error == ECONNREFUSED)
				{
					break_con(tnsocket::sock_condition::connection_refuse);
				}
				if(getopt_len_error == ETIMEDOUT)
				{
					break_con(tnsocket::sock_condition::timeout);
				}
				break_con(tnsocket::sock_condition::error);
			}
			/*now connected*/
			break_con(tnsocket::sock_condition::ok);
		}while(0);
		if(iscurrentblock)
		{
			make_block();
		}
		return conres;
	}
	bool listen_setup(const std::string ip, unsigned short port)
	{
		struct sockaddr_in addr = fill_sockaddr_in(ip, _domain, port);

		if(bind(_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		{
			return false;
		}
		if(listen(_fd, 5) < 0)
		{
			return false;
		}
		make_nonblock();
		return true;
	}
	tnsocket accept()
	{
		struct sockaddr_in client_addr;
	   unsigned client_addr_size = sizeof( client_addr);

	   int client = ::accept(_fd,
			   (struct sockaddr*)&client_addr,
			   &client_addr_size);

	   if(client < 0)
	   {
		   return tnsocket();
	   }

		return tnsocket(client);
	}

};
