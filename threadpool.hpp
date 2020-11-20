#pragma once



class threadpool final
{
public:
	class object
	{
		friend class threadpool;
	private:
		virtual void _cond_wait(){}
		virtual void _cond_wakeup(){}
	protected:
		object(){}
		virtual  ~object(){}
		virtual void operator()() = 0;
	};
	class future_object : public object
	{
		friend class threadpool;
		bool _proc;
		std::condition_variable _fu_cond_q;
		std::mutex _fu_m;
		virtual void _cond_wait()
		{
			std::unique_lock<std::mutex> lock(_fu_m);
				_fu_cond_q.wait(lock, [&]()->bool{
					return _proc;
				});
		}
		virtual void _cond_wakeup()
		{
			_proc = true;
			_fu_cond_q.notify_one();
		}
			protected:
		future_object() :
			object(), _proc(false){}
		virtual ~future_object(){}
		virtual void operator()() = 0;
	};
private:
	unsigned _nthreads;
	bool _stop;
	std::queue<std::shared_ptr<object>> _workbox;
	std::vector<std::thread> _workers;
	std::condition_variable _cond_q;
	std::mutex _workbox_m;
	bool wait_condition(std::unique_lock<std::mutex> &lock)
	{
		_cond_q.wait(lock, [&]()->bool{
			return !_workbox.empty() || _stop;
		});
		if(_stop && _workbox.empty())
		{
			return false;
		}
		return true;
	}
	void working(std::unique_lock<std::mutex> &lock)
	{
		auto work = _workbox.front();
		_workbox.pop();
		lock.unlock();
		(*work)();
		work->_cond_wakeup();
	}
	void workroutine()
	{
		do
		{
			std::unique_lock<std::mutex> lock(_workbox_m);
			if(!wait_condition(lock))
			{
				break;
			}
			working(lock);
		}while(true);
	}
public:
	~threadpool()
	{
		_stop = true;
		_cond_q.notify_all();
		for(auto &it : _workers)
		{
			it.join();
		}
	}
	threadpool(unsigned nthreads = 1) :
		_nthreads(nthreads), _stop(false)
	{
		_workers.reserve(_nthreads);
		while(nthreads-- >= 1)
		{
			_workers.emplace_back([&]()->void{
				workroutine();});
		}
	}
	unsigned remain_workbox()
	{
		std::unique_lock<std::mutex> lock(_workbox_m);
		return _workbox.size();
	}

	template <class T>
	void work(const std::shared_ptr<T>& w)
	{
		{
			std::unique_lock<std::mutex> lock(_workbox_m);
			_workbox.push(w);
		}
		_cond_q.notify_one();
		w->_cond_wait();
	}
	template <class T, class ...Args>
	std::shared_ptr<T> make_work(Args&&... args)
	{
		return std::shared_ptr<T>(new T(std::forward<Args>(args)...));
	}

};
