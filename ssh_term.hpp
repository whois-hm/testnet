#pragma once
class netssh_term : public netssh_session
{
	ssh_channel _channel;

public:
	netssh_term(const std::string &srvid,
			const std::string srvip,
			unsigned short srvport,
			enum ssh_publickey_hash_type publickey_hash_type,
			int verbosity) :
				netssh_session(srvid, srvip, srvport, publickey_hash_type, verbosity),_channel(ssh_channel_new(_session))
		{
			TN_ASSERT(_session != nullptr);
		}
	virtual ~netssh_term()
	{
		ssh_channel_send_eof(_channel);
		ssh_channel_close(_channel);
		ssh_channel_free(_channel);
		_channel = nullptr;
	}
	int exec()
	{
		char buffer[256];
		int nbytes, nwritten;

		if(ssh_channel_open_session(_channel) != SSH_OK)
		{
			return -1;
		}
		if(ssh_channel_request_pty(_channel) != SSH_OK)
		{
		  return -1;
		}

		if(ssh_channel_change_pty_size(_channel, 80, 24) != SSH_OK)
		{
			return -1;
		}

		if(ssh_channel_request_shell(_channel) != SSH_OK)
		{
			return -1;
		}

		while (ssh_channel_is_open(_channel) &&
			 !ssh_channel_is_eof(_channel))
		{
			struct timeval timeout;
			ssh_channel in_channels[2], out_channels[2];
			fd_set fds;
			int maxfd;

			timeout.tv_sec = 30;
			timeout.tv_usec = 0;
			in_channels[0] = _channel;
			in_channels[1] = NULL;
			FD_ZERO(&fds);
			FD_SET(0, &fds);
			FD_SET(ssh_get_fd(_session), &fds);
			maxfd = ssh_get_fd(_session) + 1;

			ssh_select(in_channels, out_channels, maxfd, &fds, &timeout);

			if (out_channels[0] != NULL)
			{
			  nbytes = ssh_channel_read(_channel, buffer, sizeof(buffer), 0);
			  if (nbytes < 0) return SSH_ERROR;
			  if (nbytes > 0)
			  {

				nwritten = write(1, buffer, nbytes);

				  nwritten = nbytes;
				if (nwritten != nbytes) return SSH_ERROR;
			  }
			}

			if (FD_ISSET(0, &fds))
			{
			  nbytes = read(0, buffer, sizeof(buffer));
			  if (nbytes < 0) return SSH_ERROR;
			  if (nbytes > 0)
			  {

				nwritten = ssh_channel_write(_channel, buffer, nbytes);
				nwritten = nbytes;
				if (nbytes != nwritten) return SSH_ERROR;
			  }
			}
		}

		return SSH_OK;
	}
};
