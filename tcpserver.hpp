#pragma once
class tcpserver : public tnsocket
{
protected:
	std::string _ip;
	unsigned short _port;
	std::thread *_th;
	int _pipe[2];

	void start()
	{
		fds _fds(fds::_element(_pipe[0],
				true,
				true,
				true,
				true),
				fds::_element(_fd,
				true,
				true,
				true,
				true));
		while(1)
		{
			fds::fds_search_res res = _fds(-1);
			TN_ASSERT(_fds.has(res));/*we are not use timeout*/

			fds::_element resp_pipe= _fds.get(res,
							fds::_element(_pipe[0],
									true,
									false,
									true));
			fds::_element resp_sock= _fds.get(res,
										fds::_element(_fd,
												true,
												true,
												true));

			if(resp_pipe &&
					resp_pipe.read())
			{
				break;
			}
			if(resp_sock)
			{

				tnsocket newclient = accept();
				TN_ASSERT(newclient.isaccepted());
				newclient_was_incoming(std::move(newclient));
			}
		}
	}
	bool listen_setup()
	{
		if(pipe(_pipe) < 0)
		{
			return false;
		}
		return tnsocket::listen_setup(_ip, _port);
	}

	tcpserver(const std::string &ip, unsigned short port) :
		tnsocket(AF_INET, SOCK_STREAM, 0), _ip(std::string()),
		_port(port),
		_th(nullptr){}
	virtual ~tcpserver()
	{
		if(_th)
		{
			char  d[1];
			write(_pipe[1], d, 1);
			_th->join();
			delete _th;
			_th = nullptr;
		}
	}
	tnsocket::sock_condition connect(const std::string &toip, unsigned short toport, int timeout = -1) = delete;
	tnsocket::sr recvfrom(void *p, unsigned l, int f, const std::string &toip, unsigned short toport, int timeout = 0, sr_break_status f_status = nullptr) = delete;
	tnsocket::sr sendto(void *p, unsigned l, int f, const std::string &toip, unsigned short toport, int timeout = 0, sr_break_status f_status = nullptr) = delete;
	tnsocket::sr recv(void *p, unsigned l, int f, int timeout = 0, sr_break_status f_status = nullptr) = delete;
	tnsocket::sr send(void *p, unsigned l, int f, int timeout = 0, sr_break_status f_status = nullptr) = delete;
	bool isaccepted() = delete;
	std::string accepted_get_ip() = delete;
	int accepted_get_port() = delete;
	virtual void newclient_was_incoming(tnsocket &&client) = 0;

public:
	void start(bool other)
	{
		TN_ASSERT(listen_setup());

		if(other)
		{
			_th = new std::thread([&]()->void{start();});
			return;
		}
		start();
	}
};
