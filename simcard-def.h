/******************************************************************************/
/* simcard-def.h                                                              */
/******************************************************************************/

#ifndef __SIMCARD_DEF_H__
#define __SIMCARD_DEF_H__

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <sys/types.h>
#endif

#define SIMCARD_MAX_DATA_LENGTH 512

enum {
	SIMCARD_CONTAINER_TYPE_DATA = 0,
	SIMCARD_CONTAINER_TYPE_RESET = 1,
	SIMCARD_CONTAINER_TYPE_SPEED = 2,
	SIMCARD_CONTAINER_TYPE_MONITOR = 3,
};

struct simcard_data {
	struct simcard_data_header {
		u_int32_t type;
		u_int32_t length;
	} __attribute__((packed)) header;
	union {
		u_int8_t data[SIMCARD_MAX_DATA_LENGTH];
		u_int32_t reset;
		u_int32_t speed;
		u_int32_t monitor;
	} __attribute__((packed)) container;
} __attribute__((packed));

#endif //__SIMCARD_DEF_H__

/******************************************************************************/
/* end of simcard-def.h                                                       */
/******************************************************************************/
