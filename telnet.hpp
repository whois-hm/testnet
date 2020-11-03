#pragma once
class nettelnet
{
	typedef enum
	{
		feed_x,
		feed_o,
		feed_max
	}feed;
	typedef enum
	{
		lineparse_unkown,
		lineparse_start,
		lineparse_ing,
		lineparse_comp,
		lineparse_max

	}lineparse;
	tnsocket _sock;
	std::string _srvip;
	unsigned short _srvport;
	telnet_t *_telnet;
	std::thread *_th;
	lineparse _line;
	int _recv_buffer_cursor;
	unsigned _recv_buffer_size;
	char *_recv_buffer;
	std::string _message_prefix;
	std::list<std::string> _messagefilters;
	void receiving()
	{
		char buffer[1024] = {0, };
		while(1)
		{
			tnsocket::sr res;
			res = _sock.recv(buffer, 1024, 0, -1,
					[&](unsigned char *p, unsigned l)->bool{
					return true;
			});
			if(!_sock.sr_condition_can(res))
			{
				break;
			}
			telnet_recv(_telnet,
					buffer,
					_sock.sr_readbyte(res));
		}
	}
	static void evthandler(telnet_t *telnet, telnet_event_t *ev,
			void *user_data)
	{
		((nettelnet *)user_data)->evthandler(telnet, ev);
	}
	static void send(const char *buffer, size_t size, void *userdata)
	{
		((nettelnet *)userdata)->send(buffer, size);
	}
	void send(const char *buffer, size_t size)
	{
		_sock.send((void *)buffer, size, 0, -1);
	}
	void out(const char *thiz)
	{
		std::string outstring;
		if(!_message_prefix.empty())
		{
			outstring = _message_prefix + thiz;
		} else outstring = thiz;
		this->operator >>(outstring);
	}
	void message_out(const char *thiz)
	{
		if(_messagefilters.size() > 0)
		{
			for(auto &it : _messagefilters)
			{
				if(std::string(thiz).find(it) != std::string::npos)
				{
					out(thiz);
					break;
				}
			}
			return;
		}
		out(thiz);
	}
	void message_alloc_test()
	{
		if(!_recv_buffer)
		{
			_recv_buffer = new char [_recv_buffer_size];
			return  ;
		}
		else
		{
			if((int)_recv_buffer_cursor < (int)_recv_buffer_size - 5)
			{
				return;
			}
			_recv_buffer_size <<= 1;
			char *temp = NULL;
			temp = new char [_recv_buffer_size];
			memset(temp, 0, _recv_buffer_size);

			memcpy(temp, _recv_buffer, _recv_buffer_size >> 1);
			delete [] _recv_buffer;
			_recv_buffer = temp;
		}
	}

	void receive(const char *data, unsigned size)
	{
		static lineparse telnet_line_parse_table[feed_max][lineparse_max] =
		{
				{
						lineparse_start,
							lineparse_ing,
								lineparse_ing,
									lineparse_start
				},
					{
						lineparse_unkown,
							lineparse_comp,
								lineparse_comp,
									lineparse_unkown
					}
		};

		unsigned n = 0;
		while(n < size)
		{
			feed f = data[n] != '\n' ? feed_x : feed_o;
			lineparse prev = _line;
			_line = telnet_line_parse_table[f][prev];

			if(_line == lineparse_unkown)
			{
				_recv_buffer_cursor = 0;
			}
			else if(_line == lineparse_start)
			{
				_recv_buffer_cursor = 0;
				message_alloc_test();
				memset(_recv_buffer, 0, _recv_buffer_size);
				_recv_buffer[_recv_buffer_cursor++] = data[n];
			}
			else if(_line == lineparse_ing)
			{
				message_alloc_test();
				_recv_buffer[_recv_buffer_cursor++] = data[n];
			}
			else if(_line == lineparse_comp)
			{
				message_out(_recv_buffer);
				_recv_buffer_cursor = 0;
			}
			n++;
		}
	}
	void evthandler(telnet_t *telnet, telnet_event_t *ev)
	{
		switch (ev->type) {
		case TELNET_EV_DATA:
			receive(ev->data.buffer, ev->data.size);
			break;
		case TELNET_EV_SEND:
			send(ev->data.buffer, ev->data.size, this);
			break;
		case TELNET_EV_ERROR:
			_sock.set_invalid();
			break;
		case TELNET_EV_TTYPE:
			if (ev->ttype.cmd == TELNET_TTYPE_SEND)
			{ telnet_ttype_is(telnet, getenv("TERM")); }
			break;
		case TELNET_EV_WILL:
		case TELNET_EV_WONT:
		case TELNET_EV_DO:
		case TELNET_EV_DONT:
		case TELNET_EV_SUBNEGOTIATION:
		default: break;
		}
	}
public:
	nettelnet(const std::string &srvip,
			unsigned short srvport) :
				_sock(tnsocket(AF_INET, SOCK_STREAM, 0)),
				_srvip(srvip),
				_srvport(srvport),
				_telnet(nullptr),
				_th(nullptr),
				_line(lineparse_unkown),
				_recv_buffer_cursor(0),
				_recv_buffer_size(128),
				_recv_buffer(nullptr)
	{
		static const telnet_telopt_t telopts[] = {
			{ TELNET_TELOPT_ECHO,		TELNET_WONT, TELNET_DO   },
			{ TELNET_TELOPT_TTYPE,		TELNET_WILL, TELNET_DONT },
			{ TELNET_TELOPT_COMPRESS2,	TELNET_WONT, TELNET_DO   },
			{ TELNET_TELOPT_MSSP,		TELNET_WONT, TELNET_DO   },
			{ -1, 0, 0 }
		};
		_telnet = telnet_init(telopts, evthandler, 0, this);
	}
	virtual ~nettelnet()
	{
		_sock.set_invalid();

		if(_th)
		{
			delete _th;
			_th = nullptr;
		}
		if(_recv_buffer)
		{
			delete [] _recv_buffer;
		}
		if(_telnet)
		{
			telnet_free(_telnet);
		}
	}
	int connect(int timeout = -1)
	{
		return tnsocket::sock_condition::ok ==
				_sock.connect(_srvip,
						_srvport,
						timeout) ? 1 : -1;
	}

	int receiving(bool bother)
	{
		if(bother)
		{
			_th = new std::thread([&]()->void{
						receiving();
			});
			return 1;
		}
		receiving();
		return 1;
	}
	int put(char *buffer, unsigned size)
	{
		static char crlf[] = { '\r', '\n' };
		for(unsigned i = 0; i < size; i++)
		{
			if (buffer[i] == '\r' || buffer[i] == '\n') {
				telnet_send(_telnet, crlf, 2);
			} else {
				telnet_send(_telnet, buffer + i, 1);
			}
		}
		return size;
	}
	void setmessage_prefix(const std::string &str)
	{
		_message_prefix = str;
	}
	void addmessage_filter(const std::string &str)
	{
		_messagefilters.push_back(str);
	}
	virtual void operator >> (const std::string str) = 0;
};

class nettelnet_default : public nettelnet
{
public:
	nettelnet_default(const std::string &srvip,
			unsigned short srvport) :
			nettelnet(srvip, srvport){}
	virtual ~nettelnet_default(){}
	virtual void operator >> (const std::string str)
	{
		printf("%s\n", str.c_str());
	}
};
