#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdarg.h>
#include <inttypes.h>
#include <math.h>
#include <signal.h>
#include <malloc.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <semaphore.h>
#include <mqueue.h>
#include <execinfo.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/vtimes.h>
#include <linux/types.h>
#include <linux/fb.h>
#include <linux/input.h>
#include <linux/videodev2.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <sys/shm.h>
#include <sys/un.h>
#include <type_traits>
#include <iostream>
#include <execinfo.h>
#include <stdexcept>
#include <vector>
#include <list>
#include <algorithm>
#include <thread>
#include <chrono>
#include <map>
#include <memory>
#include <tuple>
#include <mutex>
#include <atomic>
#include <locale>
#include <codecvt>
#include <fstream>
#include <iostream>
#include <functional>
#include <sstream>
#include <string>
#include <condition_variable>
#include <future>
#include <cassert>
#include "libssh/libssh.h"
#include "libtelnet.h"
#define TN_WANNING_LOGGING
#define TN_LOG_SIZE	1024
#define TN_ASSERT(x) assert(x);
#define TN_POSITION_LOG() printf("%s(%d)\n", __FUNCTION__, __LINE__)


inline void __TN_WARNNING_LOG__(const char *file,
		const char *func,
		int line,
		const char *format,
		...)
{
#if defined TN_WANNING_LOGGING
	va_list s;
	std::string prefix = "[tn warnning] ";
	prefix += file;
	prefix +=" ";
	prefix += func;
	prefix +=" ";
	prefix += std::to_string(line);
	prefix +=" ";
	unsigned prefixlen = prefix.size();

	unsigned out_bufferlen = prefix.size() +
			TN_LOG_SIZE + 10;
	char out_buffer[out_bufferlen] = {0, };

	memcpy(out_buffer, prefix.c_str(), prefixlen);

	va_start(s, format);
	vsnprintf(out_buffer + prefixlen,
			out_bufferlen - prefixlen,
		format,
		s);
	va_end(s);
	out_buffer[out_bufferlen - 1] = 0;
	printf("%s", out_buffer);
#endif
}

#define TN_WARNNING_LOG(f, ...) __TN_WARNNING_LOG__(__FILE__, __FUNCTION__, __LINE__, f, ##__VA_ARGS__)

struct throw_register_sys_except
{
	static void sys_except(int nsig)
	{
		printf("system has been %s\n", nsig == SIGSEGV ? "sigsegv" : "sigabrt");
		void *backtrace_addr [10] = { nullptr, };
		int size = 0;

		size = backtrace(backtrace_addr, 10);

		if(size > 0)
		{
			for(int i = 0; i < size; i++)
			{
				printf("addr2line -f -C -e testNet %08x\n", (unsigned)backtrace_addr[i]);
			}
		}
		else
		{
			printf("can't know exception address\n");
		}

	}
	throw_register_sys_except()
	{
		signal(SIGSEGV, throw_register_sys_except::sys_except);
		signal(SIGABRT, throw_register_sys_except::sys_except);
	}
};

#include "fds.hpp"
#include "flowtime.hpp"
#include "tnsock.hpp"
#include "ifaddrdevice.hpp"
#include "icmp.hpp"
#include "ftpclient.hpp"
#include "ssh.hpp"
#include "telnet.hpp"

