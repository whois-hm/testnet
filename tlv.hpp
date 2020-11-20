#pragma once
class tlv
{
protected:
	unsigned _t;
	unsigned _l;
	unsigned char *_v;
	tlv() : _t(0), _l(0), _v(nullptr){}
	virtual ~tlv()
	{
		free_value();
		_t = 0;
		_l = 0;
	}
	void realloc_value(unsigned size)
	{
		free_value();
		if(size)
		{
			_v = new unsigned char [size];
			memset(_v, 0, size);
		}
	}
	void free_value()
	{
		if(_v)
		{
			delete [] _v;
			_v = nullptr;
		}
	}
	unsigned type_t_size() const
	{
		return sizeof(_t);
	}
	unsigned type_l_size() const
	{
		return sizeof(_l);
	}
	unsigned tl_size()
	{
		return type_t_size() +
				type_l_size();
	}
public:
	unsigned get_type() 			 { return _t; }
	unsigned get_length() 		 { return _l; }
	unsigned char *ref_value() 	 { return _v; }
	std::string get_value()
	{
		if(ref_value())
		{
			return std::string((char *)ref_value());
		}
		return "";
	}
};

class nettlv_receiver : public tlv
{

	tnsocket &_sock;
	unsigned _readbytes;
public:
	nettlv_receiver(tnsocket &sock) :
		tlv(), _sock(sock), _readbytes(0){}
	operator bool()
	{
		if(_readbytes >= tl_size())
		{
			if(get_length() > 0)
			{
				return _readbytes >= tl_size() + get_length();
			}
			return true;
		}
		return false;
	}
	bool operator ()(int timeout = -1)
	{
		flowtime ft(timeout);
		tnsocket::sr type_res = _sock.recv((void *)&_t, type_t_size(), 0, ft.remaintime());

		if(_sock.sr_condition_ok(type_res) &&
				ft.flow())
		{
			_readbytes += _sock.sr_readbyte(type_res);
			tnsocket::sr length_res = _sock.recv((void *)&_l, type_l_size(), 0, ft.remaintime());
			if(_sock.sr_condition_ok(length_res) &&
							ft.flow())
			{
				_readbytes += _sock.sr_readbyte(length_res);
				if(get_length() > 0)
				{
					realloc_value(_l);

					tnsocket::sr value_res = _sock.recv(ref_value(), get_length(), 0, ft.remaintime());
					if(_sock.sr_condition_ok(value_res))
					{
						_readbytes += _sock.sr_readbyte(value_res);
					}
				}
			}
		}

		return *this;
	}
};

class nettlv_sender : public tlv
{
	tnsocket &_sock;
	unsigned _sendbytes;
	bool _a;
public:
	virtual ~nettlv_sender()
	{
		if(_a) free_value();
		else _v = nullptr;
	}
	nettlv_sender(unsigned t, unsigned l, unsigned char *v, bool a, tnsocket &sock) :
		tlv(), _sock(sock), _sendbytes(0)
	{
			_t = t;
			_l = l;
			_a = a;
			if(a && l > 0)
			{
				realloc_value(l);
				memcpy(_v, v, l);
			}
			else
			{
				_v = v;
			}
	}
	operator bool()
	{
		if(_sendbytes >= tl_size())
		{
			if(get_length() > 0)
			{
				return _sendbytes >= tl_size() + get_length();
			}
			return true;
		}
		return false;
	}
	bool operator ()(int timeout = -1)
	{
		flowtime ft(timeout);
		tnsocket::sr type_res = _sock.send((void *)&_t, type_t_size(), 0, ft.remaintime());


		if(_sock.sr_condition_ok(type_res) &&
				ft.flow())
		{
			_sendbytes += _sock.sr_readbyte(type_res);
			tnsocket::sr length_res = _sock.send((void *)&_l, type_l_size(), 0, ft.remaintime());
			if(_sock.sr_condition_ok(length_res) &&
							ft.flow())
			{
				_sendbytes += _sock.sr_readbyte(length_res);
				if(get_length() > 0)
				{
					tnsocket::sr value_res = _sock.send(ref_value(), get_length(), 0, ft.remaintime());
					if(_sock.sr_condition_ok(value_res))
					{
						_sendbytes += _sock.sr_readbyte(value_res);
					}
				}
			}
		}

		return *this;
	}
};
