/******************************************************************************/
/* 3gpp_ts_101_221.h                                                          */
/******************************************************************************/

#ifndef __3GPP_TS_101_221_H__
#define __3GPP_TS_101_221_H__

#include <sys/types.h>

#define SIM_UICC_CLA 0x80

enum {
	SIM_UICC_INS_SELECT					= 0xa4,		// 0x 4x 6x xx xx xx w SIM
	SIM_UICC_INS_STATUS					= 0xf2,		// xx xx xx 8x cx ex r SIM
	SIM_UICC_INS_READ_BINARY			= 0xb0,		// 0x 4x 6x xx xx xx r SIM
	SIM_UICC_INS_UPDATE_BINARY			= 0xd6,		// 0x 4x 6x xx xx xx w SIM
	SIM_UICC_INS_READ_RECORD			= 0xb2,		// 0x 4x 6x xx xx xx r SIM
	SIM_UICC_INS_UPDATE_RECORD			= 0xdc,		// 0x 4x 6x xx xx xx w SIM
	SIM_UICC_INS_SEARCH_RECORD			= 0xa2,		// 0x 4x 6x xx xx xx w SIM
	SIM_UICC_INS_INCREASE				= 0x32,		// xx xx xx 8x cx ex w SIM
	SIM_UICC_INS_RETRIEVE_DATA			= 0xcb,		// xx xx xx 8x cx ex r SIM
	SIM_UICC_INS_SET_DATA				= 0xdb,		// xx xx xx 8x cx ex w SIM
	SIM_UICC_INS_VERIFY					= 0x20,		// 0x 4x 6x xx xx xx w SIM
	SIM_UICC_INS_CHANGE_PIN				= 0x24,		// 0x 4x 6x xx xx xx w SIM
	SIM_UICC_INS_DISABLE_PIN			= 0x26,		// 0x 4x 6x xx xx xx w SIM
	SIM_UICC_INS_ENABLE_PIN				= 0x28,		// 0x 4x 6x xx xx xx w SIM
	SIM_UICC_INS_UNBLOCK_PIN			= 0x2c,		// 0x 4x 6x xx xx xx w SIM
	SIM_UICC_INS_DEACTIVATE_FILE		= 0x04,		// 0x 4x 6x xx xx xx w SIM
	SIM_UICC_INS_ACTIVATE_FILE			= 0x44,		// 0x 4x 6x xx xx xx w SIM
	SIM_UICC_INS_AUTHENTICATE			= 0x88,		// 0x 4x 6x xx xx xx w SIM
	SIM_UICC_INS_AUTHENTICATE_1			= 0x89,		// 0x 4x 6x xx xx xx w SIM
	SIM_UICC_INS_GET_CHALLENGE			= 0x84,		// 0x 4x 6x xx xx xx r SIM
	SIM_UICC_INS_TERMINAL_CAPABILITY	= 0xAA,		// xx xx xx 80 xx xx w SIM
	SIM_UICC_INS_TERMINAL_PROFILE		= 0x10,		// xx xx xx 80 xx xx w SIM
	SIM_UICC_INS_ENVELOPE				= 0xc2,		// xx xx xx 80 xx xx w SIM
	SIM_UICC_INS_FETCH					= 0x12,		// xx xx xx 80 xx xx r SIM
	SIM_UICC_INS_TERMINAL_RESPONSE		= 0x14,		// xx xx xx 80 xx xx w SIM
	SIM_UICC_INS_MANAGE_CHANNEL			= 0x70,		// 0x 4x 6x xx xx xx w SIM
	SIM_UICC_INS_MANAGE_SECURE_CHANNEL	= 0x73,		// 0x 4x 6x xx xx xx ? SIM
	SIM_UICC_INS_TRANSACT_DATA			= 0x75,		// 0x 4x 6x xx xx xx x SIM (P1 b3=0 - r, P1 b3=1 - r)
	SIM_UICC_INS_GET_RESPONSE			= 0xc0,		// 0x 4x 6x xx xx xx r SIM
};

extern int get_3gpp_ts_101_221_cla8x_ins_type(u_int8_t ins);

#endif //__3GPP_TS_101_221_H__

/******************************************************************************/
/* end of 3gpp_ts_101_221.h                                                   */
/******************************************************************************/
