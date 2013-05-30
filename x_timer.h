/******************************************************************************/
/* x_timer.h                                                                  */
/******************************************************************************/

#ifndef __X_TIMER_H__
#define __X_TIMER_H__

#include <sys/time.h>
#include <sys/types.h>

#include <time.h>

struct x_timer {
	int enable;
	struct timespec start;
	struct timespec timeout;
	struct timespec expires;
};

#define x_timeout_global(_timeout, _sec, _nsec) \
	struct timespec _timeout = { .tv_sec = _sec, .tv_nsec = _nsec, }

#define tv_set(_tv, _sec, _nsec) \
do { \
	_tv.tv_sec = _sec; \
	_tv.tv_nsec = _nsec; \
} while(0)

#define tv_cpy(_dest, _src) \
do { \
	_dest.tv_sec = _src.tv_sec; \
	_dest.tv_nsec = _src.tv_nsec; \
} while(0)

#define tv_add(_tv_1, _tv_2) \
do { \
	_tv_1.tv_sec += _tv_2.tv_sec; \
	_tv_1.tv_nsec += _tv_2.tv_nsec; \
	if (_tv_1.tv_nsec >= 1000000000) { \
		_tv_1.tv_nsec -= 1000000000; \
		_tv_1.tv_sec += 1; \
	} \
} while(0)

#define tv_sub(_tv_1, _tv_2) \
({ \
	struct timespec __res; \
	__res.tv_sec = _tv_1.tv_sec - _tv_2.tv_sec; \
	__res.tv_nsec = _tv_1.tv_nsec - _tv_2.tv_nsec; \
	if (__res.tv_nsec < 0) { \
		__res.tv_nsec += 1000000000; \
		__res.tv_sec -= 1; \
	} \
	__res; \
})

#define tv_cmp(_tv_1, _tv_2) \
({ \
	int __res = 0; \
	if (_tv_1.tv_sec < _tv_2.tv_sec) \
		__res = -1; \
	else if (_tv_1.tv_sec > _tv_2.tv_sec) \
		__res = 1; \
	else if (_tv_1.tv_sec == _tv_2.tv_sec) { \
		if (_tv_1.tv_nsec < _tv_2.tv_nsec) \
			__res = -1; \
		else if (_tv_1.tv_nsec > _tv_2.tv_nsec) \
			__res = 1; \
		else \
			__res = 0; \
	} \
	__res; \
})

#define x_timer_start(_timer) \
do { \
	struct timespec __curr_time; \
	clock_gettime(CLOCK_MONOTONIC, &__curr_time); \
	_timer.enable = 1; \
	tv_cpy(_timer.start, __curr_time); \
} while(0)

#define x_timer_set(_timer, _timeout) \
do { \
	struct timespec __curr_time; \
	clock_gettime(CLOCK_MONOTONIC, &__curr_time); \
	_timer.enable = 1; \
	tv_cpy(_timer.start, __curr_time); \
	tv_cpy(_timer.timeout, _timeout); \
	tv_cpy(_timer.expires, _timer.start); \
	tv_add(_timer.expires, _timer.timeout); \
} while(0)

#define x_timer_set_second(_timer, _timeout) \
do { \
	struct timespec __curr_time; \
	struct timespec __timeout; \
	tv_set(__timeout, _timeout, 0); \
	clock_gettime(CLOCK_MONOTONIC, &__curr_time); \
	_timer.enable = 1; \
	tv_cpy(_timer.start, __curr_time); \
	tv_cpy(_timer.timeout, __timeout); \
	tv_cpy(_timer.expires, _timer.start); \
	tv_add(_timer.expires, _timer.timeout); \
} while(0)

#define x_timer_set_ms(_timer, _timeout) \
do { \
	struct timespec __curr_time; \
	struct timespec __timeout; \
	tv_set(__timeout, _timeout / 1000, (_timeout % 1000) * 1000000); \
	clock_gettime(CLOCK_MONOTONIC, &__curr_time); \
	_timer.enable = 1; \
	tv_cpy(_timer.start, __curr_time); \
	tv_cpy(_timer.timeout, __timeout); \
	tv_cpy(_timer.expires, _timer.start); \
	tv_add(_timer.expires, _timer.timeout); \
} while(0)

#define x_timer_set_us(_timer, _timeout) \
do { \
	struct timespec __curr_time; \
	struct timespec __timeout; \
	tv_set(__timeout, _timeout / 1000000, (_timeout % 1000000) * 1000); \
	clock_gettime(CLOCK_MONOTONIC, &__curr_time); \
	_timer.enable = 1; \
	tv_cpy(_timer.start, __curr_time); \
	tv_cpy(_timer.timeout, __timeout); \
	tv_cpy(_timer.expires, _timer.start); \
	tv_add(_timer.expires, _timer.timeout); \
} while(0)

#define x_timer_set_ns(_timer, _timeout) \
do { \
	struct timespec __curr_time; \
	struct timespec __timeout; \
	tv_set(__timeout, _timeout / 1000000000, (_timeout % 1000000000) * 1); \
	clock_gettime(CLOCK_MONOTONIC, &__curr_time); \
	_timer.enable = 1; \
	tv_cpy(_timer.start, __curr_time); \
	tv_cpy(_timer.timeout, __timeout); \
	tv_cpy(_timer.expires, _timer.start); \
	tv_add(_timer.expires, _timer.timeout); \
} while(0)

#define x_timer_stop(_timer) \
do { \
	_timer.enable = 0; \
} while(0)

#define is_x_timer_enable(_timer) \
({ \
	int __res = 0; \
	__res = _timer.enable; \
	__res; \
})

#define is_x_timer_active(_timer) \
({ \
	int __res = 0; \
	struct timespec __curr_time; \
	clock_gettime(CLOCK_MONOTONIC, &__curr_time); \
	if ((tv_cmp(_timer.expires, __curr_time) > 0) && (tv_cmp(_timer.start, __curr_time) <= 0)) \
		__res = 1; \
	else \
		__res = 0; \
	__res; \
})

#define is_x_timer_fired(_timer) \
({ \
	int __res = 0; \
	struct timespec __curr_time; \
	clock_gettime(CLOCK_MONOTONIC, &__curr_time); \
	if ((tv_cmp(_timer.expires, __curr_time) > 0) && (tv_cmp(_timer.start, __curr_time) <= 0)) \
		__res = 0; \
	else \
		__res = 1; \
	__res; \
})

#define get_x_timer_value_ms(_timer) \
({ \
	int __res = -1; \
	struct timespec __curr_time, __sub; \
	clock_gettime(CLOCK_MONOTONIC, &__curr_time); \
	if (_timer.enable) { \
		__sub = tv_sub(__curr_time, _timer.start); \
		__res = __sub.tv_sec * 1000 + __sub.tv_nsec / 1000000; \
	} \
	__res; \
})

#define get_x_timer_value_us(_timer) \
({ \
	int __res = -1; \
	struct timespec __curr_time, __sub; \
	clock_gettime(CLOCK_MONOTONIC, &__curr_time); \
	if (_timer.enable) { \
		__sub = tv_sub(__curr_time, _timer.start); \
		__res = __sub.tv_sec * 1000 + __sub.tv_nsec / 1000; \
	} \
	__res; \
})

#endif //__X_TIMER_H__

/******************************************************************************/
/* end of x_timer.h                                                           */
/******************************************************************************/
