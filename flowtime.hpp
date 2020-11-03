#pragma once
class flowtime
{
	int _appointedtime;
	int _remaintime;
	bool _isinfinitetime;
	std::chrono::milliseconds _startclock;
public:
	flowtime(int appointedtime) :
		_appointedtime(appointedtime),
		_remaintime(appointedtime),
		_isinfinitetime(appointedtime < 0){ reset_at(); }
	virtual ~flowtime() { }
	bool is_infinite_flow() 		const { return _isinfinitetime; }
	int remaintime() 				const { return _remaintime; }
	int appointedtime() 			const { return _appointedtime; }
	bool can_nextflow() 			const { return is_infinite_flow() || remaintime() >= 0; }
	bool expired()					const { return !can_nextflow();}
	bool flow() {
		check_at();
		return can_nextflow();
	}

	void start_at()
	{
		_remaintime = _appointedtime;
		_startclock = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::system_clock::now().time_since_epoch());
	}
	void reset_at()
	{
		start_at();
	}
	void check_at()
	{

		auto at = std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::system_clock::now().time_since_epoch());
		if(_startclock.count() == 0)
		{
			_startclock = at;
		}
		auto elapse_at = at - _startclock;
		if(elapse_at.count() > _remaintime/*zero can be trying*/) { _remaintime = -1; }
		else { _remaintime -= elapse_at.count(); }
		_startclock = at;
	}

};
