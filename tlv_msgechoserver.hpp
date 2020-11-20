#pragma once


class tlv_msgechoserver : public tcpserver
{
	class message_manager :  public tcpserver
		{
		tlv_msgechoserver &_thiz;
		public:
			message_manager(const std::string &ip,
					unsigned short port,
					tlv_msgechoserver &thiz) : tcpserver(ip, port), _thiz(thiz){}
			virtual void newclient_was_incoming(tnsocket &&client)
			{
				printf("register new client was incoming from %s\n", client.accepted_get_ip().c_str());
				printf("start reading data...\n");
				nettlv_receiver r(client);
				if(!r(1000))
				{
					printf("register reading data... fail\n");
					return;
				}
				printf("register read data\n");
				printf("register type = %d\n", r.get_type());
				printf("register length = %d\n", r.get_length());
				if(r.get_length() > 0)
				{
					printf("register value = %s\n", r.get_value().c_str());
				}
				else
				{
					printf("register value = nullptr\n");
				}
				_thiz.message_load(r.get_type(), r.get_value());
			}
		};

	friend class message_manager;
	threadpool _clientpool;
	message_manager *_mansrv;
private:
	std::list<std::pair<unsigned, std::string>> _msg_echo_list;
	std::mutex _sync;

	bool echo_msg_response(nettlv_receiver &receiver, tnsocket &sock)
	{
		printf("echo msg response\n");
		std::pair<bool, std::string > res = get_echo_msg(receiver.get_type());
		if(res.first)
		{
			nettlv_sender s(receiver.get_type(),
					res.second.empty() ? 0 : res.second.size(),
					res.second.empty() ? nullptr : (unsigned char *)res.second.c_str(),
					false,
					sock);
			bool res = s();

			printf("response type = %d\n", s.get_type());
			printf("response length = %d\n", s.get_length());
			if(s.get_length() > 0)
			{
				printf("response value = %s\n", s.get_value().c_str());
			}
			else
			{
				printf("response value = nullptr\n");
			}

			printf("response result = %s\n", res ? "true" : "false");


			return res;
		}
		printf("can't find response list\n");
		return res.first;
	}
	virtual void newclient_was_incoming(tnsocket &&client)
	{

		printf("new client was incoming... throw!\n");
		class client_access : public threadpool::object
		{
			tnsocket _csoc;
			tlv_msgechoserver &_thiz;
		public:
			client_access(tnsocket &&sock, tlv_msgechoserver &thiz) :
				threadpool::object(),
				_csoc(std::move(sock)),
				_thiz(thiz){}
			void operator()()
			{
				printf("new client was incoming from %s\n", _csoc.accepted_get_ip().c_str());
				printf("start reading data...\n");

				nettlv_receiver r(_csoc);
				if(!r(1000))
				{
					printf("reading data... fail\n");
					return;
				}
				printf("read data\n");
				printf("type = %d\n", r.get_type());
				printf("length = %d\n", r.get_length());
				if(r.get_length() > 0)
				{
					printf("value = %s\n", r.get_value().c_str());
				}
				else
				{
					printf("value = nullptr\n");
				}
				_thiz.echo_msg_response(r, _csoc);
			}
		};
		_clientpool.work(_clientpool.make_work<client_access>(std::move(client), *this));
	}

	std::pair<bool, std::string >get_echo_msg(unsigned type)
	{
		std::lock_guard<std::mutex> s(_sync);
		for(auto &it : _msg_echo_list)
		{
			if(type == it.first)
			{
				return std::make_pair(true, it.second);
			}
		}
		return std::make_pair(false, std::string());
	}
public:

	tlv_msgechoserver(const std::string &ip, unsigned short port) :
		tcpserver(ip, port), _clientpool(10),_mansrv(nullptr){}
	virtual ~tlv_msgechoserver()
	{
		if(_mansrv)
		{
			delete _mansrv;
			_mansrv = nullptr;
		}
	}

	void message_load(unsigned type,  const std::string &value)
	{
		std::lock_guard<std::mutex> s(_sync);
		_msg_echo_list.push_back(std::make_pair(type, value));
	}
	virtual int package_from_file_message_load(char const *file){return -1;}
	virtual int package_from_network_message_load(const std::string &ip, unsigned short port)
	{
		_mansrv = new message_manager(ip, port,
				*this);
		_mansrv->start(true);
		return 1;
	}
};

