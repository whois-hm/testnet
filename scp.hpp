#pragma once


class netscp : public netssh_session
{
protected:
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
			int verbosity) : netssh_session(srvid, srvip, srvport, publickey_hash_type, verbosity) { }
	virtual ~netscp() { }
    int download(const std::string &path, const std::string &to)
    {
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
		return pr_res == SSH_SCP_REQUEST_EOF ? 1 : -1;
    }
    std::tuple<std::string, std::string, bool> getsplit_target(const std::string &url)
	{
    	std::vector<std::string> url_split;
    	std::string token;
    	std::stringstream ss(url);
    	char split = '/';
    	if(url.empty())
    	{
    		return std::make_tuple("","",false);
    	}
    	while(std::getline(ss, token, split))
    	{
    		if(token.size() > 0)
    		{
    			url_split.push_back(token);
    		}
    	}
    	if(url_split.size() <= 0)
    	{
    		if(url[0] != '/')
    		{
    			return std::make_tuple("","",false);
    		}
    	}

    	std::string fpath = url[0] == '/' ? "/" : "./";
    	std::string target = url_split[url_split.size() - 1];
    	for(int i = 0; i < url_split.size() - 1; i++)
    	{
    		fpath += url_split[i];
    		fpath += "/";
    	}
    	return std::make_tuple(fpath, target, true);

	}
    void upload_file(ssh_scp scp, const std::string &fpath, const std::string &to, const std::string &target, int &err)
    {
    	if(err < 0)
    	{
    		printf("can't upload file : %s (error code return) %d\n", target.c_str(), err);
    		return;
    	}
    	struct stat size;
    	stat(fpath.c_str(), &size);
    	unsigned filesize = size.st_size;
    	unsigned filesize_gap = 1024;
    	unsigned writedsize = 0;
    	unsigned remainfilesize = filesize;


    	int fd = open(fpath.c_str(), O_RDWR | O_SYNC, 777);
    	if(fd < 0)
    	{
    		printf("can't upload file : %s (open error) ignored\n", to.c_str());
    		return;
    	}
    	printf("upload file push: %s\n", to.c_str());

    	if(SSH_OK != ssh_scp_push_file(scp, to.c_str(), filesize, S_IRUSR | S_IWUSR))
    	{
    		printf("can't upload file : %s (remote push error : %s)\n", to.c_str(), ssh_get_error(_session));
    		close(fd);
    		err = -2;
			return;
    	}
    	if(remainfilesize <= 0)
		{
    		char dump[1];
    		ssh_scp_write(scp, dump, 0);
			close(fd);
			return;
		}

    	unsigned char *buffer = new unsigned char[filesize];
    	size_t res = read(fd, buffer, filesize);
    	if(res != size.st_size)
    	{
    		printf("can't upload file : %s (size error)\n", to.c_str());
    		close(fd);
    		err = -3;
    		return;
    	}

    	while(remainfilesize)
    	{
    		int next_write_size = remainfilesize >= filesize_gap ? filesize_gap : remainfilesize;

    		if(SSH_OK != ssh_scp_write(scp, buffer + writedsize, next_write_size))
    		{
    			delete buffer;
    			close(fd);
    			err = -4;
				return;
    		}

    		remainfilesize -= next_write_size;
    		writedsize += next_write_size;
    		printf("upload write : %s (%d/%d(byte))\r", target.c_str(), writedsize, filesize);
    	}

    	printf("\n");
    	delete buffer;
    	close(fd);
    }
    void upload_enter_directory(ssh_scp scp, const std::string &fpath, const std::string &to, const std::string &target, int &err)
    {
    	if(err < 0)
    	{
    		printf("can't upload directory : %s (error code return %d)\n", target.c_str(), err);
    		return;
    	}
    	printf("upload directory push : %s\n", to.c_str());
    	if(SSH_OK != ssh_scp_push_directory(scp, to.c_str(), S_IRWXU))
    	{
    		printf("can't push directory : %s (error code return %d)\n", target.c_str(), err);
    		err = -9;
    	}
    }
    void upload_leave_directory(ssh_scp scp)
    {
    	ssh_scp_leave_directory(scp);
    }
    void upload_test(ssh_scp scp, const std::string &fpath, const std::string &to, int &err)
    {
    	DIR *dir_ptr = nullptr;
    	struct dirent *file = nullptr;

    	std::tuple<std::string, std::string, bool > split =  getsplit_target(fpath);
    	if(!std::get<2>(split))
    	{
    		return;
    	}
    	std::string path = std::get<0>(split);
    	std::string target = std::get<1>(split);

    	std::string nextfpath = (path + "/" + target);
		std::string nexttopath = to + "/" + target;
		if(target[0] == '.')
		{
			return;
		}

		//printf("upload test : %s\n", nextfpath.c_str());
    	if((dir_ptr = opendir(nextfpath.c_str())) != nullptr)
    	{

    		upload_enter_directory(scp, nextfpath, nexttopath, target, err);
    		while((file = readdir(dir_ptr)) != nullptr)
    		{
    			upload_test(scp, nextfpath + "/" + file->d_name, nexttopath, err);
    		}
    		upload_leave_directory(scp);
    		return ;
    	}

    	upload_file(scp, nextfpath, nexttopath, target, err);
    }
    int upload(const std::string &fpath, const std::string &to)
    {
    	int errorcode = 1;
		ssh_scp scp=ssh_scp_new(_session, SSH_SCP_WRITE | SSH_SCP_RECURSIVE, to.c_str());
		if(SSH_OK == ssh_scp_init(scp))
		{
			upload_test(scp, fpath, to , errorcode);
			ssh_scp_close(scp);
			ssh_scp_free(scp);
			return 1;
		}
		ssh_scp_close(scp);
		ssh_scp_free(scp);
		return -1;
    }
};

