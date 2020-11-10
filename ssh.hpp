#pragma once


class netssh_session
{
protected:
	std::string _srvid;
	std::string _srvip;
	unsigned short _srvport;
	int _verbosity;
	enum ssh_publickey_hash_type _publickey_hash_type;
	ssh_session _session;
	ssh_key _srv_pubkey;
	unsigned char *_srv_pubkey_hash;
	unsigned _srv_pubkey_hashlen;
	void netssh_last_error(const std::string pr)
	{
		if(_verbosity)
		{
			printf("netssh last error what : %s\n",
					(pr + (_session ?
							ssh_get_error(_session) :
							""))
							.c_str());
		}
	}

	virtual int verify_server(enum ssh_known_hosts_e e)
	{
		char *hexa = nullptr;
		char buf[10];
		char *p;

		do
		{
			if(e == SSH_KNOWN_HOSTS_OK)
			{
				return 1;
			}
			if(e == SSH_KNOWN_HOSTS_ERROR)
			{
				return -1;
			}
//			if(e == SSH_KNOWN_HOSTS_CHANGED)
//			{
//				printf("The host key for this server was not found but an other"
//						"type of key exists.\n");
//				printf("An attacker might change the default server key to"
//						"confuse your client into thinking the key does not exist\n");
//				return -1;
//			}
			if(e == SSH_KNOWN_HOSTS_NOT_FOUND ||
					e == SSH_KNOWN_HOSTS_UNKNOWN ||
					e == SSH_KNOWN_HOSTS_CHANGED)
			{
				hexa = ssh_get_hexa(_srv_pubkey_hash, _srv_pubkey_hashlen);
				printf("The server is notfound or unknown. Do you trust the host key?\n");
				printf("Public key hash: %s\n", hexa);
				ssh_string_free_char(hexa);

				p = fgets(buf, sizeof(buf), stdin);
				if(p == nullptr)
				{
					return -1;
				}
				if(strncasecmp(buf, "yes", 3))
				{
					return -1;
				}
				if(ssh_session_update_known_hosts(_session) != SSH_OK)
				{
					return -1;
				}
			}
			return 1;
		}while(0);

		return -1;
	}
	virtual int auth_methods(int methods)
	{
		char password[128] = {0, };

		if (!(methods & SSH_AUTH_METHOD_PASSWORD))
		{
			return -1;
		}
        if (ssh_getpass("Password: ",
                password,
                sizeof(password),
                0,
                0) < 0)
        {

            return -1;
        }
		return ssh_userauth_password(_session,
				nullptr,
                password) == SSH_AUTH_SUCCESS ? 1
						: -1;
	}

	netssh_session(const std::string &srvid,
			const std::string srvip,
			unsigned short srvport,
			enum ssh_publickey_hash_type publickey_hash_type,
			int verbosity) :
		_srvid(srvid),
		_srvip(srvip),
		_srvport(srvport),
		_verbosity(verbosity),
		_publickey_hash_type(publickey_hash_type),
		_session(ssh_new()),
		_srv_pubkey(nullptr),
		_srv_pubkey_hash(nullptr),
		_srv_pubkey_hashlen(0)

	{
		TN_ASSERT(_session != nullptr);
	}
public:
	virtual ~netssh_session()
	{
		if(_srv_pubkey)
		{
			ssh_key_free(_srv_pubkey);
		}
		if(_srv_pubkey_hash)
		{
			ssh_clean_pubkey_hash(&_srv_pubkey_hash);
		}
		if(_session)
		{
			ssh_disconnect(_session);
			ssh_free(_session);
		}
		_srv_pubkey = nullptr;
		_session = nullptr;
		_srv_pubkey_hash = nullptr;
		_srv_pubkey_hashlen = 0;
	}
	int connect(unsigned timeout = 0)
	{
		int rc;
		ssh_options_set(_session, SSH_OPTIONS_HOST, (_srvid + "@" + _srvip).c_str() );
		ssh_options_set(_session, SSH_OPTIONS_LOG_VERBOSITY, &_verbosity);
		ssh_options_set(_session, SSH_OPTIONS_PORT, &_srvport);
		ssh_options_set(_session, SSH_OPTIONS_TIMEOUT, &timeout);
		do
		{
			if(ssh_connect(_session) != SSH_OK)
			{
				netssh_last_error("connet ");
				return -1;
			}
			if(ssh_get_server_publickey(_session, &_srv_pubkey) != SSH_OK)
			{
				netssh_last_error("get server publickey ");
				return -1;
			}
			if(ssh_get_publickey_hash(_srv_pubkey,
					_publickey_hash_type,
					&_srv_pubkey_hash,
					&_srv_pubkey_hashlen) != SSH_OK)
			{
				netssh_last_error("get server publickey ");
				return -1;
			}
			if(verify_server(ssh_session_is_known_server(_session)) < 0)
			{
				netssh_last_error("verify_server ");
				return -1;
			}
			rc = ssh_userauth_none(_session, NULL);
			if(rc == SSH_AUTH_ERROR)
			{
				netssh_last_error("userauth none  ");
				return -1;
			}
			if(rc == SSH_AUTH_SUCCESS)
			{
				break;
			}

			if(auth_methods(ssh_userauth_list(_session, nullptr)) < 0)
			{
				netssh_last_error("auth_methods ");
				return -1;
			}
		}while(0);

		return 1;
	}
};


