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
	int _domain;
	int _type;
	int _protocol;
	int _fd;

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

	struct sockaddr_in fill_sockaddr_in(const std::string &ip,
			int domain,
			unsigned short port)
	{
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(struct sockaddr_in));

		addr.sin_addr.s_addr = inet_addr(ip.c_str());
		addr.sin_family = domain;
		addr.sin_port = htons(port);
		return addr;
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
public:
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
	virtual ~tnsocket()
	{
		set_invalid();
	}
	const int &fd()
	{
		return _fd;
	}
	bool valid() const {return _fd != -1;}
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
};
