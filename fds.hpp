#pragma once
class fds
{
public:
	class _element
	{
		friend class fds;
		int _fd;
		bool _r, _w, _e;
		friend std::ostream& operator<<(std::ostream& os, const fds::_element& o);
	public:
		_element() : _fd(-1),
				_r(false),
				_w(false),
				_e(false){}
		_element(int fd) : _fd(fd),
				_r(false),
				_w(false),
				_e(false){}
		_element(int fd,
				bool r,
				bool w,
				bool e) : _fd(fd),
				_r(r),
				_w(w),
				_e(e){}
		_element(int fd,
				bool make_it_non_blocking,
				bool r,
				bool w,
				bool e) : _fd(fd),
				_r(r),
				_w(w),
				_e(e)
		{
			if(make_it_non_blocking)
				make_nonblocking();
			else
				make_blocking();
		}
		operator bool() const
		{
			return _fd != -1;
		}
		bool read() const {return _r;}
		bool write() const {return _w;}
		bool except() const {return _e;}

		void make_blocking()
		{
			TN_ASSERT(*this);
			int opt = 0;
			opt = fcntl(_fd, F_GETFL);
			TN_ASSERT(opt >= 0);
			if(!is_nonblocking())
			{
				return;
			}
			opt &= ~O_NONBLOCK;
			TN_ASSERT(fcntl(_fd, F_SETFL, opt) >= 0);
		}
		void make_nonblocking()
		{
			TN_ASSERT(*this);
			int opt = 0;
			opt = fcntl(_fd, F_GETFL);
			TN_ASSERT(opt >= 0);
			if(is_nonblocking())
			{
				return;
			}
			opt = (O_NONBLOCK | O_RDWR | opt);
			TN_ASSERT(fcntl(_fd, F_SETFL, opt) >= 0);
		}
		bool is_nonblocking() const
		{
			return (fcntl(_fd, F_GETFL) &
					O_NONBLOCK) > 0;
		}
	};

	fds(){}
	fds(std::vector<fds::_element> &el_vec) :
		_el_vec(el_vec){}
	template<typename... Args>
	fds(Args... es){ pute(es...); }
	virtual ~fds(){}
	void operator << (fds::_element &&e)
	{
		TN_ASSERT(e);

		for(auto &it : _el_vec)
		{
			if(it._fd == e._fd)
			{
				return;
			}
		}
		_el_vec.push_back(std::move(e));
	}
	void operator >> (fds::_element &&e)
	{
		TN_ASSERT(e);
		for(auto &it : _el_vec)
		{
			if(it._fd == e._fd)
			{
				_el_vec.erase(std::remove_if(_el_vec.begin(), _el_vec.end(),
						[&](const fds::_element &in)->bool
							{
								return in._fd == e._fd;
							}
						)
				);
				break;
			}
		}
	}
	fds::_element &operator[](fds::_element &&e)
	{
		TN_ASSERT(e);

		for(auto &it : _el_vec)
		{
			if(it._fd == e._fd)
			{
				return it;
			}
		}
		return e;
	}


	typedef std::pair<int,
			std::vector<fds::_element>> fds_search_res;

	bool has(fds_search_res &r)
	{
		return !timeout(r) &&
				!error(r);
	}
	bool timeout(fds_search_res &r)
	{
		return r.first == 0;
	}
	bool error(fds_search_res &r)
	{
		return r.first < 0;
	}

	fds::_element get(fds_search_res &r, fds::_element &&e)
	{
		if(has(r))
		{
			for(auto &it : r.second)
			{
				if(it._fd == e._fd)
				{
					return fds::_element(it._fd,
							it._r && e._r,
							it._w && e._w,
							it._e && e._e);
				}
			}
		}
		return fds::_element();
	}
	fds_search_res operator()(int timeout)
	{
		std::vector<fds::_element> res_el;
		struct timeval tv;
		fd_set readfds;
		fd_set writefds;
		fd_set exceptfds;
		int maxfd = -1;

		tv.tv_sec = 0;
		tv.tv_usec = 0;
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		FD_ZERO(&exceptfds);

		for(auto &it : _el_vec)
		{
			if(it._r) FD_SET(it._fd, &readfds);
			if(it._w) FD_SET(it._fd, &writefds);
			if(it._e) FD_SET(it._fd, &exceptfds);
			maxfd = std::max(it._fd, maxfd);
		}
		if(maxfd < 0)
		{
			return std::make_pair(-1, res_el);
		}
		struct timeval *tm = NULL;
		if(timeout >= 0)
		{
			tv.tv_sec = timeout / 1000;
			tv.tv_usec = (timeout % 1000) * 1000;
			tm = &tv;
		}

		 int res = select(maxfd + 1,
				&readfds,
				&writefds,
				&exceptfds,
				tm);
		 if(res <= 0)
		 {
			 return std::make_pair(res, res_el);
		 }

		for(auto &it : _el_vec)
		{
			fds::_element e;
			if(FD_ISSET(it._fd, &readfds)) {e._fd = it._fd; e._r = true;}
			if(FD_ISSET(it._fd, &writefds)) {e._fd = it._fd;e._w = true;}
			if(FD_ISSET(it._fd, &exceptfds)) {e._fd = it._fd;e._e = true;}
			if(e)
			{
				res_el.push_back(e);
			}
		}
		return std::make_pair(res, res_el);
	}
private:
	template <typename T, typename... Types>
	void pute(T &e, Types&... es)/*for 'fds(Args... es)'*/
	{

		(*this).operator <<(std::move(e));
		//fds::operator << (std::move(e));
		pute(es...);
	}
	void pute()const{}/*for 'void put(T &e, Types&... es)'*/
	std::vector<fds::_element> _el_vec;
	friend std::ostream& operator<<(std::ostream& os, const fds& o);
};

std::ostream& operator<<(std::ostream& os, const fds& o)
{
	os << "<fds wait for list count = "<< o._el_vec.size() << ">" << std::endl;
	for(auto &it : o._el_vec)
	{
		os << it << std::endl;
	}
    return os;
}
std::ostream& operator<<(std::ostream& os, const fds::_element& o)
{
	os << "<fds element>" << std::endl;
	os << "descriptor = " << o._fd << std::endl;
	os << "read set = " << o._r << std::endl;
	os << "write set = " << o._w << std::endl;
	os << "except set = " << o._e << std::endl;
	os << "nonblock mode = " << o.is_nonblocking() << std::endl;
   return os;
}
