#pragma once


class netscp : public netssh
{
protected:

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
			if(e == SSH_KNOWN_HOSTS_CHANGED)
			{
				printf("The host key for this server was not found but an other"
						"type of key exists.\n");
				printf("An attacker might change the default server key to"
						"confuse your client into thinking the key does not exist\n");
				return -1;
			}
			if(e == SSH_KNOWN_HOSTS_NOT_FOUND ||
					e == SSH_KNOWN_HOSTS_UNKNOWN)
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
//		if (ssh_getpass("Password: ",
//				password,
//				sizeof(password),
//				0,
//				0) < 0)
//		{
//
//			return -1;
//		}
		return ssh_userauth_password(_session,
				nullptr,
				"guseoxhdtls") == SSH_AUTH_SUCCESS ? 1
						: -1;
	}
	std::string get_download_current_dir()
	{
		std::string targetdir = _download_root_dir;

		for(auto &it : _download_recursive_dirs)
		{
			targetdir += "/" + it;
		}
		return targetdir;
	}

	void pull_request_in_newfile(ssh_scp scp, int state)
	{
		if(state == SSH_SCP_REQUEST_NEWFILE)
		{
			std::string filename = ssh_scp_request_get_filename(scp);
			size_t filesize = ssh_scp_request_get_size(scp);;
			int permission = ssh_scp_request_get_permissions(scp);
			int fd;

			std::string fullpath = std::string(get_download_current_dir() + "/" + filename).c_str();

			ssh_scp_accept_request(scp);

			fd = open(fullpath.c_str(),
					O_RDWR | O_CREAT | O_SYNC,
					permission);
			if(filesize <= 0)
			{
				char a[1];
				ssh_scp_read(scp,a,1);
				close(fd);
				printf("download %s complete [%d/%d]\n", filename.c_str(), 0, filesize);
				return;
			}
			if(fd < 0)
			{
				printf("download fail open error %s\n", filename.c_str());
				return;
			}

			unsigned char *buffer = new unsigned char [filesize];
			unsigned idx = 0;
			do
			{
				int size = ssh_scp_read(scp,buffer + idx,filesize - idx);
				if(size <= 0)
				{
					break;
				}
				idx += size;
				printf("download %s[%d/%d]\r", filename.c_str(), idx, filesize);
			}while(idx < filesize);
			printf("\n");

			if(idx >= filesize)
			{
				write(fd, buffer, filesize);
				close(fd);
				delete buffer;
				printf("download %s complete[%d/%d]\n", filename.c_str(), idx, filesize);
				return;
			}
			delete buffer;
			printf("download fail size diff %s\n", filename.c_str());
			close(fd);
		}

	}
	void pull_request_in_warnning(ssh_scp scp, int state)
	{
		if(state == SSH_SCP_REQUEST_WARNING)
		{
			printf("warning: %s\n",ssh_scp_request_get_warning(scp));
		}
	}
	void pull_reqeust_in_newdir(ssh_scp scp, int state)
	{
		if(state == SSH_SCP_REQUEST_NEWDIR)
		{
			std::string adddir = ssh_scp_request_get_filename(scp);
			int permission = ssh_scp_request_get_permissions(scp);

			printf("enter directory %s, perms 0%o\n",adddir.c_str(), permission);

			_download_recursive_dirs.push_back(adddir);
			ssh_scp_accept_request(scp);

			printf("we making directory %s\n", get_download_current_dir().c_str());
			mkdir(get_download_current_dir().c_str(), permission);
		}
	}
	void pull_request_in_enddir(int state)
	{
		if(state == SSH_SCP_REQUEST_ENDDIR)
		{
			printf("leave directory %s\n",_download_recursive_dirs.back().c_str());
			_download_recursive_dirs.pop_back();
		}
	}
	void pull_request_in_endof(int state)
	{
		  if(state == SSH_SCP_REQUEST_EOF)
		  {
			  printf("end of requests\n");
		  }
	}
	std::string _download_root_dir;
	std::list<std::string> _download_recursive_dirs;
public:
	netscp(const std::string &srvid,
			const std::string srvip,
			unsigned short srvport,
			enum ssh_publickey_hash_type publickey_hash_type,
			int verbosity) : netssh(srvid, srvip, srvport, publickey_hash_type, verbosity) { }
	virtual ~netscp() { }
    virtual void channel_close() {}
    virtual  int channel_open()
	{
		return 1;
	}
    int download(const std::string &path, const std::string &to)
    {
		bool res = -1;
		int pr_res;
		_download_root_dir = to;
		_download_recursive_dirs.clear();

		ssh_scp scp=ssh_scp_new(_session, SSH_SCP_READ | SSH_SCP_RECURSIVE, path.c_str());
		do
		{
		  if(ssh_scp_init(scp) != SSH_OK)
		  {
			  netssh_last_error("ssh_scp_init ");
			  break;
		  }

		  do
		  {

			  pr_res = ssh_scp_pull_request(scp);
			  pull_request_in_newfile(scp, pr_res);
			  pull_request_in_warnning(scp, pr_res);
			  pull_reqeust_in_newdir(scp, pr_res);
			  pull_request_in_enddir(pr_res);
			  pull_request_in_endof(pr_res);
		  } while (pr_res != SSH_ERROR &&
				  pr_res != SSH_SCP_REQUEST_EOF);
		}while(0);
		ssh_scp_close(scp);
		ssh_scp_free(scp);
		return res;
    }
};

