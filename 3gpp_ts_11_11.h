/******************************************************************************/
/* 3gpp_ts_11_11.h                                                            */
/******************************************************************************/

#ifndef __3GPP_TS_11_11_H__
#define __3GPP_TS_11_11_H__

#include <sys/types.h>

#define SIM_GSM_CLA 0xa0

enum {
	SIM_GSM_INS_SELECT				= 0xa4,		// to SIM
	SIM_GSM_INS_STATUS				= 0xf2,		// from SIM
	SIM_GSM_INS_READ_BINARY			= 0xb0,		// from SIM
	SIM_GSM_INS_UPDATE_BINARY		= 0xd6,		// to SIM
	SIM_GSM_INS_READ_RECORD			= 0xb2,		// from SIM
	SIM_GSM_INS_UPDATE_RECORD		= 0xdc,		// to SIM
	SIM_GSM_INS_SEEK				= 0xa2,		// to SIM
	SIM_GSM_INS_INCREASE			= 0x32,		// to SIM
	SIM_GSM_INS_VERIFY_CHV			= 0x20,		// to SIM
	SIM_GSM_INS_CHANGE_CHV			= 0x24,		// to SIM
	SIM_GSM_INS_DISABLE_CHV			= 0x26,		// to SIM
	SIM_GSM_INS_ENABLE_CHV			= 0x28,		// to SIM
	SIM_GSM_INS_UNBLOCK_CHV			= 0x2c,		// to SIM
	SIM_GSM_INS_INVALIDATE			= 0x04,		// to SIM (no data)
	SIM_GSM_INS_REHABILIDATE		= 0x44,		// to SIM (no data)
	SIM_GSM_INS_RUN_GSM_ALGORITHM	= 0x88,		// to SIM
	SIM_GSM_INS_SLEEP				= 0xfa,		// to SIM (no data)
	SIM_GSM_INS_GET_RESPONSE		= 0xc0,		// from SIM
	SIM_GSM_INS_TERMINAL_PROFILE	= 0x10,		// to SIM
	SIM_GSM_INS_ENVELOPE			= 0xc2,		// to SIM
	SIM_GSM_INS_FETCH				= 0x12,		// from SIM
	SIM_GSM_INS_TERMINAL_RESPONSE	= 0x10,		// to SIM
};

#endif //__3GPP_TS_11_11_H__

/******************************************************************************/
/* end of 3gpp_ts_11_11.h                                                     */
/******************************************************************************/
