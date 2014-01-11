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
	SIM_GSM_INS_TERMINAL_RESPONSE	= 0x14,		// to SIM
};

enum {
	MACRO_GET_ICCID_STATE_DONE = MACRO_GENERIC_STATE_DONE,
	MACRO_GET_ICCID_STATE_INIT = MACRO_GENERIC_STATE_INIT,
	MACRO_GET_ICCID_STATE_CHECK_SELECT_3F00,
	MACRO_GET_ICCID_STATE_CHECK_SELECT_2FE2,
	MACRO_GET_ICCID_STATE_CHECK_GET_RESPONSE_2FE2,
	MACRO_GET_ICCID_STATE_CHECK_READ_BINARY_2FE2,
};

enum {
	MACRO_GET_IMSI_STATE_DONE = MACRO_GENERIC_STATE_DONE,
	MACRO_GET_IMSI_STATE_INIT = MACRO_GENERIC_STATE_INIT,
	MACRO_GET_IMSI_STATE_CHECK_SELECT_3F00,
	MACRO_GET_IMSI_STATE_CHECK_SELECT_7F20,
	MACRO_GET_IMSI_STATE_CHECK_SELECT_6F07,
	MACRO_GET_IMSI_STATE_CHECK_GET_RESPONSE_6F07,
	MACRO_GET_IMSI_STATE_CHECK_READ_BINARY_6F07,
};

enum {
	MACRO_GET_SPN_STATE_DONE = MACRO_GENERIC_STATE_DONE,
	MACRO_GET_SPN_STATE_INIT = MACRO_GENERIC_STATE_INIT,
	MACRO_GET_SPN_STATE_CHECK_SELECT_3F00,
	MACRO_GET_SPN_STATE_CHECK_SELECT_7F20,
	MACRO_GET_SPN_STATE_CHECK_SELECT_6F46,
	MACRO_GET_SPN_STATE_CHECK_GET_RESPONSE_6F46,
	MACRO_GET_SPN_STATE_CHECK_READ_BINARY_6F46,
};

enum {
	MACRO_GET_MSISDN_STATE_DONE = MACRO_GENERIC_STATE_DONE,
	MACRO_GET_MSISDN_STATE_INIT = MACRO_GENERIC_STATE_INIT,
	MACRO_GET_MSISDN_STATE_CHECK_SELECT_3F00,
	MACRO_GET_MSISDN_STATE_CHECK_SELECT_7F10,
	MACRO_GET_MSISDN_STATE_CHECK_SELECT_6F40,
	MACRO_GET_MSISDN_STATE_CHECK_GET_RESPONSE_6F40,
	MACRO_GET_MSISDN_STATE_CHECK_READ_RECORD_6F40,
};

enum {
	MACRO_ERASE_SMS_STATE_DONE = MACRO_GENERIC_STATE_DONE,
	MACRO_ERASE_SMS_STATE_INIT = MACRO_GENERIC_STATE_INIT,
	MACRO_ERASE_SMS_STATE_CHECK_SELECT_3F00,
	MACRO_ERASE_SMS_STATE_CHECK_SELECT_7F10,
	MACRO_ERASE_SMS_STATE_CHECK_SELECT_6F3C,
	MACRO_ERASE_SMS_STATE_CHECK_GET_RESPONSE_6F3C,
	MACRO_ERASE_SMS_STATE_CHECK_UPDATE_RECORD_6F3C,
};

extern int get_3gpp_ts_11_11_claa0_ins_type(u_int8_t ins);

extern int gsm_sim_cmd_is_done(struct iso_iec_7816_device *device);
extern int gsm_sim_cmd_get_iccid_sm(struct iso_iec_7816_device *device, int init);
extern int gsm_sim_cmd_get_imsi_sm(struct iso_iec_7816_device *device, int init);
extern int gsm_sim_cmd_get_spn_sm(struct iso_iec_7816_device *device, int init);
extern int gsm_sim_cmd_get_msisdn_sm(struct iso_iec_7816_device *device, int init);
extern int gsm_sim_cmd_erase_sms_sm(struct iso_iec_7816_device *device, int init);

#endif //__3GPP_TS_11_11_H__

/******************************************************************************/
/* end of 3gpp_ts_11_11.h                                                     */
/******************************************************************************/
