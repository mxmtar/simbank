/******************************************************************************/
/* 3gpp_ts_11_11.c                                                            */
/******************************************************************************/

#include <sys/types.h>

#include <errno.h>
#include <iconv.h>
#include <stdio.h>
#include <string.h>

#include "iso_iec_7816.h"
#include "3gpp_ts_11_11.h"
#include "3gpp_ts_23_038.h"

//------------------------------------------------------------------------------
// get_3gpp_ts_11_11_claa0_ins_type()
//------------------------------------------------------------------------------
int get_3gpp_ts_11_11_claa0_ins_type(u_int8_t ins)
{
	switch (ins) {
		// read
		case SIM_GSM_INS_STATUS:
		case SIM_GSM_INS_READ_BINARY:
		case SIM_GSM_INS_READ_RECORD:
		case SIM_GSM_INS_GET_RESPONSE:
		case SIM_GSM_INS_FETCH:
			return -1;
		// write
		case SIM_GSM_INS_SELECT:
		case SIM_GSM_INS_UPDATE_BINARY:
		case SIM_GSM_INS_UPDATE_RECORD:
		case SIM_GSM_INS_SEEK:
		case SIM_GSM_INS_INCREASE:
		case SIM_GSM_INS_VERIFY_CHV:
		case SIM_GSM_INS_CHANGE_CHV:
		case SIM_GSM_INS_DISABLE_CHV:
		case SIM_GSM_INS_ENABLE_CHV:
		case SIM_GSM_INS_UNBLOCK_CHV:
		case SIM_GSM_INS_INVALIDATE:
		case SIM_GSM_INS_REHABILIDATE:
		case SIM_GSM_INS_RUN_GSM_ALGORITHM:
		case SIM_GSM_INS_SLEEP:
		case SIM_GSM_INS_TERMINAL_PROFILE:
		case SIM_GSM_INS_ENVELOPE:
		case SIM_GSM_INS_TERMINAL_RESPONSE:
			return 1;
		default:
			return 0;
	}
}
//------------------------------------------------------------------------------
// end of get_3gpp_ts_11_11_claa0_ins_type()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// gsm_sim_cmd_is_done()
//------------------------------------------------------------------------------
int gsm_sim_cmd_is_done(struct iso_iec_7816_device *device)
{
	if (device->macro_state == MACRO_GENERIC_STATE_DONE) {
		return -1;
	} else {
		return -0;
	}
}
//------------------------------------------------------------------------------
// end of gsm_sim_cmd_is_done()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// gsm_sim_cmd_get_iccid_sm()
//------------------------------------------------------------------------------
int gsm_sim_cmd_get_iccid_sm(struct iso_iec_7816_device *device, int init)
{
	size_t i, j;
	u_int8_t cmd_header[5];
	u_int8_t cmd_data[2];
	int rc = -1;

	if (init) {
		device->macro_state = MACRO_GET_ICCID_STATE_INIT;
	}

	switch (device->macro_state) {
		case MACRO_GET_ICCID_STATE_INIT:
			cmd_header[0] = SIM_GSM_CLA;
			cmd_header[1] = SIM_GSM_INS_SELECT;
			cmd_header[2] = 0x00;
			cmd_header[3] = 0x00;
			cmd_header[4] = 0x02;
			cmd_data[0] = 0x3f;
			cmd_data[1] = 0x00;
			iso_iec_7816_device_command_build(device, cmd_header, CMD_WRITE|CMD_SERVICE, cmd_data, 2);
			device->macro_state = MACRO_GET_ICCID_STATE_CHECK_SELECT_3F00;
			rc = 0;
			break;
		case MACRO_GET_ICCID_STATE_CHECK_SELECT_3F00:
			if (device->command.sw1 == 0x9f) {
				cmd_header[0] = SIM_GSM_CLA;
				cmd_header[1] = SIM_GSM_INS_SELECT;
				cmd_header[2] = 0x00;
				cmd_header[3] = 0x00;
				cmd_header[4] = 0x02;
				cmd_data[0] = 0x2f;
				cmd_data[1] = 0xe2;
				iso_iec_7816_device_command_build(device, cmd_header, CMD_WRITE|CMD_SERVICE, cmd_data, 2);
				device->macro_state = MACRO_GET_ICCID_STATE_CHECK_SELECT_2FE2;
				rc = 0;
			} else {
				device->macro_state = MACRO_GET_ICCID_STATE_DONE;
			}
			break;
		case MACRO_GET_ICCID_STATE_CHECK_SELECT_2FE2:
			if (device->command.sw1 == 0x9f) {
				cmd_header[0] = SIM_GSM_CLA;
				cmd_header[1] = SIM_GSM_INS_GET_RESPONSE;
				cmd_header[2] = 0x00;
				cmd_header[3] = 0x00;
				cmd_header[4] = device->command.sw2;
				iso_iec_7816_device_command_build(device, cmd_header, CMD_SERVICE, NULL, 0);
				device->macro_state = MACRO_GET_ICCID_STATE_CHECK_GET_RESPONSE_2FE2;
				rc = 0;
			} else {
				device->macro_state = MACRO_GET_ICCID_STATE_DONE;
			}
			break;
		case MACRO_GET_ICCID_STATE_CHECK_GET_RESPONSE_2FE2:
			if ((device->command.sw1 & 0x90) == 0x90) {
				cmd_header[0] = SIM_GSM_CLA;
				cmd_header[1] = SIM_GSM_INS_READ_BINARY;
				cmd_header[2] = 0x00;
				cmd_header[3] = 0x00;
				cmd_header[4] = device->command.data_rd[3];
				iso_iec_7816_device_command_build(device, cmd_header, CMD_SERVICE, NULL, 0);
				device->macro_state = MACRO_GET_ICCID_STATE_CHECK_READ_BINARY_2FE2;
				rc = 0;
			} else {
				device->macro_state = MACRO_GET_ICCID_STATE_DONE;
			}
			break;
		case MACRO_GET_ICCID_STATE_CHECK_READ_BINARY_2FE2:
			if ((device->command.sw1 & 0x90) == 0x90) {
				memset(device->iccid, 0xf, sizeof(device->iccid));
				for (i = 0, j = 0; i < 10; i++) {
					device->iccid[j++] = device->command.data_rd[i] & 0xf;
					device->iccid[j++] = (device->command.data_rd[i] >> 4) & 0xf;
				}
				for (j = 0; j < sizeof(device->iccid); j++) {
					switch (device->iccid[j]) {
						case 0: case 1: case 2: case 3:case 4:
						case 5: case 6: case 7: case 8:case 9:
							device->iccid[j] += '0';
							break;
						default:
							device->iccid[j] = '\0';
							break;
					}
				}
				device->iccid_len = strlen(device->iccid);
				rc = 0;
			}
			device->macro_state = MACRO_GET_ICCID_STATE_DONE;
			break;
		default:
			device->macro_state = MACRO_GET_ICCID_STATE_DONE;
			break;
	}

	return rc;
}
//------------------------------------------------------------------------------
// end of gsm_sim_cmd_get_iccid_sm()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// gsm_sim_cmd_get_spn_sm()
//------------------------------------------------------------------------------
int gsm_sim_cmd_get_spn_sm(struct iso_iec_7816_device *device, int init)
{
	size_t i, len;
	u_int16_t ucs2buf[24];

	char *ibuf, *obuf;
	size_t ilen, olen;
	iconv_t tc;

	u_int8_t cmd_header[5];
	u_int8_t cmd_data[2];
	int rc = -1;

	if (init) {
		device->macro_state = MACRO_GET_SPN_STATE_INIT;
	}

	switch (device->macro_state) {
		case MACRO_GET_SPN_STATE_INIT:
			cmd_header[0] = SIM_GSM_CLA;
			cmd_header[1] = SIM_GSM_INS_SELECT;
			cmd_header[2] = 0x00;
			cmd_header[3] = 0x00;
			cmd_header[4] = 0x02;
			cmd_data[0] = 0x3f;
			cmd_data[1] = 0x00;
			iso_iec_7816_device_command_build(device, cmd_header, CMD_WRITE|CMD_SERVICE, cmd_data, 2);
			device->macro_state = MACRO_GET_SPN_STATE_CHECK_SELECT_3F00;
			rc = 0;
			break;
		case MACRO_GET_SPN_STATE_CHECK_SELECT_3F00:
			if (device->command.sw1 == 0x9f) {
				cmd_header[0] = SIM_GSM_CLA;
				cmd_header[1] = SIM_GSM_INS_SELECT;
				cmd_header[2] = 0x00;
				cmd_header[3] = 0x00;
				cmd_header[4] = 0x02;
				cmd_data[0] = 0x7f;
				cmd_data[1] = 0x20;
				iso_iec_7816_device_command_build(device, cmd_header, CMD_WRITE|CMD_SERVICE, cmd_data, 2);
				device->macro_state = MACRO_GET_SPN_STATE_CHECK_SELECT_7F20;
				rc = 0;
			} else {
				device->macro_state = MACRO_GET_SPN_STATE_DONE;
			}
			break;
		case MACRO_GET_SPN_STATE_CHECK_SELECT_7F20:
			if (device->command.sw1 == 0x9f) {
				cmd_header[0] = SIM_GSM_CLA;
				cmd_header[1] = SIM_GSM_INS_SELECT;
				cmd_header[2] = 0x00;
				cmd_header[3] = 0x00;
				cmd_header[4] = 0x02;
				cmd_data[0] = 0x6f;
				cmd_data[1] = 0x46;
				iso_iec_7816_device_command_build(device, cmd_header, CMD_WRITE|CMD_SERVICE, cmd_data, 2);
				device->macro_state = MACRO_GET_SPN_STATE_CHECK_SELECT_6F46;
				rc = 0;
			} else {
				device->macro_state = MACRO_GET_SPN_STATE_DONE;
			}
			break;
		case MACRO_GET_SPN_STATE_CHECK_SELECT_6F46:
			if (device->command.sw1 == 0x9f) {
				cmd_header[0] = SIM_GSM_CLA;
				cmd_header[1] = SIM_GSM_INS_GET_RESPONSE;
				cmd_header[2] = 0x00;
				cmd_header[3] = 0x00;
				cmd_header[4] = device->command.sw2;
				iso_iec_7816_device_command_build(device, cmd_header, CMD_SERVICE, NULL, 0);
				device->macro_state = MACRO_GET_SPN_STATE_CHECK_GET_RESPONSE_6F46;
				rc = 0;
			} else if ((device->command.sw1 == 0x94) && (device->command.sw2 == 0x04)) {
				device->spn_len = 0;
				device->macro_state = MACRO_GET_SPN_STATE_DONE;
				rc = 0;
			} else {
				device->macro_state = MACRO_GET_SPN_STATE_DONE;
			}
			break;
		case MACRO_GET_SPN_STATE_CHECK_GET_RESPONSE_6F46:
			if ((device->command.sw1 & 0x90) == 0x90) {
				cmd_header[0] = SIM_GSM_CLA;
				cmd_header[1] = SIM_GSM_INS_READ_BINARY;
				cmd_header[2] = 0x00;
				cmd_header[3] = 0x00;
				cmd_header[4] = device->command.data_rd[3];
				iso_iec_7816_device_command_build(device, cmd_header, CMD_SERVICE, NULL, 0);
				device->macro_state = MACRO_GET_SPN_STATE_CHECK_READ_BINARY_6F46;
				rc = 0;
			} else {
				device->macro_state = MACRO_GET_SPN_STATE_DONE;
			}
			break;
		case MACRO_GET_SPN_STATE_CHECK_READ_BINARY_6F46:
			if ((device->command.sw1 & 0x90) == 0x90) {
				device->spn_len = 0;
				memset(device->spn, 0, sizeof(device->spn));
				memset(ucs2buf, 0, sizeof(ucs2buf));
				len = 0;
				if ((device->command.data_rd[1] & 0x80) == 0x80) {
					;
				} else {
					for (i = 1; i < 17; i++) {
						if (device->command.data_rd[i] == 0xff) {
							break;
						} else {
							ucs2buf[len++] = gsm_decode_GSM7_symbol(device->command.data_rd[i]);
						}
					}
				}
				if (len) {
					tc = iconv_open("UTF-8", "UCS-2LE");
					if (tc != (iconv_t)-1) {
						ibuf = (char *)ucs2buf;
						ilen = len * 2;
						obuf = device->spn;
						olen = sizeof(device->spn);
						len = iconv(tc, &ibuf, &ilen, &obuf, &olen);
						if (len != (size_t)-1) {
							device->spn_len = sizeof(device->spn) - olen;
							rc = 0;
						}
						iconv_close(tc);
					}
				} else {
					rc = 0;
				}
			}
			device->macro_state = MACRO_GET_SPN_STATE_DONE;
			break;
		default:
			device->macro_state = MACRO_GET_SPN_STATE_DONE;
			break;
	}

	return rc;
}
//------------------------------------------------------------------------------
// end of gsm_sim_cmd_get_spn_sm()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// gsm_sim_cmd_get_msisdn_sm()
//------------------------------------------------------------------------------
int gsm_sim_cmd_get_msisdn_sm(struct iso_iec_7816_device *device, int init)
{
	size_t start, end;
	size_t i, j;
	u_int8_t cmd_header[5];
	u_int8_t cmd_data[2];
	int rc = -1;

	if (init) {
		device->macro_state = MACRO_GET_MSISDN_STATE_INIT;
	}

	switch (device->macro_state) {
		case MACRO_GET_MSISDN_STATE_INIT:
			cmd_header[0] = SIM_GSM_CLA;
			cmd_header[1] = SIM_GSM_INS_SELECT;
			cmd_header[2] = 0x00;
			cmd_header[3] = 0x00;
			cmd_header[4] = 0x02;
			cmd_data[0] = 0x3f;
			cmd_data[1] = 0x00;
			iso_iec_7816_device_command_build(device, cmd_header, CMD_WRITE|CMD_SERVICE, cmd_data, 2);
			device->macro_state = MACRO_GET_MSISDN_STATE_CHECK_SELECT_3F00;
			rc = 0;
			break;
		case MACRO_GET_MSISDN_STATE_CHECK_SELECT_3F00:
			if (device->command.sw1 == 0x9f) {
				cmd_header[0] = SIM_GSM_CLA;
				cmd_header[1] = SIM_GSM_INS_SELECT;
				cmd_header[2] = 0x00;
				cmd_header[3] = 0x00;
				cmd_header[4] = 0x02;
				cmd_data[0] = 0x7f;
				cmd_data[1] = 0x10;
				iso_iec_7816_device_command_build(device, cmd_header, CMD_WRITE|CMD_SERVICE, cmd_data, 2);
				device->macro_state = MACRO_GET_MSISDN_STATE_CHECK_SELECT_7F10;
				rc = 0;
			} else {
				device->macro_state = MACRO_GET_MSISDN_STATE_DONE;
			}
			break;
		case MACRO_GET_MSISDN_STATE_CHECK_SELECT_7F10:
			if (device->command.sw1 == 0x9f) {
				cmd_header[0] = SIM_GSM_CLA;
				cmd_header[1] = SIM_GSM_INS_SELECT;
				cmd_header[2] = 0x00;
				cmd_header[3] = 0x00;
				cmd_header[4] = 0x02;
				cmd_data[0] = 0x6f;
				cmd_data[1] = 0x40;
				iso_iec_7816_device_command_build(device, cmd_header, CMD_WRITE|CMD_SERVICE, cmd_data, 2);
				device->macro_state = MACRO_GET_MSISDN_STATE_CHECK_SELECT_6F40;
				rc = 0;
			} else {
				device->macro_state = MACRO_GET_MSISDN_STATE_DONE;
			}
			break;
		case MACRO_GET_MSISDN_STATE_CHECK_SELECT_6F40:
			if (device->command.sw1 == 0x9f) {
				cmd_header[0] = SIM_GSM_CLA;
				cmd_header[1] = SIM_GSM_INS_GET_RESPONSE;
				cmd_header[2] = 0x00;
				cmd_header[3] = 0x00;
				cmd_header[4] = device->command.sw2;
				iso_iec_7816_device_command_build(device, cmd_header, CMD_SERVICE, NULL, 0);
				device->macro_state = MACRO_GET_MSISDN_STATE_CHECK_GET_RESPONSE_6F40;
				rc = 0;
			} else {
				device->macro_state = MACRO_GET_MSISDN_STATE_DONE;
			}
			break;
		case MACRO_GET_MSISDN_STATE_CHECK_GET_RESPONSE_6F40:
			if ((device->command.sw1 & 0x90) == 0x90) {
				cmd_header[0] = SIM_GSM_CLA;
				cmd_header[1] = SIM_GSM_INS_READ_RECORD;
				cmd_header[2] = 0x01;
				cmd_header[3] = 0x04;
				cmd_header[4] = device->command.data_rd[14];
				iso_iec_7816_device_command_build(device, cmd_header, CMD_SERVICE, NULL, 0);
				device->macro_state = MACRO_GET_MSISDN_STATE_CHECK_READ_RECORD_6F40;
				rc = 0;
			} else {
				device->macro_state = MACRO_GET_MSISDN_STATE_DONE;
			}
			break;
		case MACRO_GET_MSISDN_STATE_CHECK_READ_RECORD_6F40:
			if ((device->command.sw1 & 0x90) == 0x90) {
				start = device->command.length_rd - 14;
				if (device->command.data_rd[start] == 0xff) {
					device->msisdn_len = 0;
					device->msisdn[0] = '\0';
					rc = 0;
				} else if (device->command.data_rd[start] <= 20) {
					end = start + device->command.data_rd[start] + 1;
					start++;
					device->msisdn_len = 0;
					memset(device->msisdn, 0xf, sizeof(device->msisdn));
					j = 0;
					if (device->command.data_rd[start] == 0x91) {
						device->msisdn[j++] = '+';
					}
					start++;
					for (i = start; i < end; i++) {
						device->msisdn[j++] = device->command.data_rd[i] & 0xf;
						device->msisdn[j++] = (device->command.data_rd[i] >> 4) & 0xf;
					}
					for (i = 0; i < sizeof(device->msisdn); i++) {
						switch (device->msisdn[i]) {
							case '+':
								break;
							case 0: case 1: case 2: case 3:case 4:
							case 5: case 6: case 7: case 8:case 9:
								device->msisdn[i] += '0';
								break;
							default:
								device->msisdn[i] = '\0';
								break;
						}
					}
					device->msisdn_len = strlen(device->msisdn);
					rc = 0;
				}
			}
			device->macro_state = MACRO_GET_MSISDN_STATE_DONE;
			break;
		default:
			device->macro_state = MACRO_GET_MSISDN_STATE_DONE;
			break;
	}

	return rc;
}
//------------------------------------------------------------------------------
// end of gsm_sim_cmd_get_msisdn_sm()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// gsm_sim_cmd_erase_sms_sm()
//------------------------------------------------------------------------------
int gsm_sim_cmd_erase_sms_sm(struct iso_iec_7816_device *device, int init)
{
	size_t i;
	u_int8_t cmd_header[5];
	u_int8_t cmd_data[256];
	int rc = -1;

	if (init) {
		device->macro_state = MACRO_ERASE_SMS_STATE_INIT;
	}

	switch (device->macro_state) {
		case MACRO_ERASE_SMS_STATE_INIT:
			cmd_header[0] = SIM_GSM_CLA;
			cmd_header[1] = SIM_GSM_INS_SELECT;
			cmd_header[2] = 0x00;
			cmd_header[3] = 0x00;
			cmd_header[4] = 0x02;
			cmd_data[0] = 0x3f;
			cmd_data[1] = 0x00;
			iso_iec_7816_device_command_build(device, cmd_header, CMD_WRITE|CMD_SERVICE, cmd_data, 2);
			device->macro_state = MACRO_ERASE_SMS_STATE_CHECK_SELECT_3F00;
			rc = 0;
			break;
		case MACRO_ERASE_SMS_STATE_CHECK_SELECT_3F00:
			if (device->command.sw1 == 0x9f) {
				cmd_header[0] = SIM_GSM_CLA;
				cmd_header[1] = SIM_GSM_INS_SELECT;
				cmd_header[2] = 0x00;
				cmd_header[3] = 0x00;
				cmd_header[4] = 0x02;
				cmd_data[0] = 0x7f;
				cmd_data[1] = 0x10;
				iso_iec_7816_device_command_build(device, cmd_header, CMD_WRITE|CMD_SERVICE, cmd_data, 2);
				device->macro_state = MACRO_ERASE_SMS_STATE_CHECK_SELECT_7F10;
				rc = 0;
			} else {
				device->macro_state = MACRO_ERASE_SMS_STATE_DONE;
			}
			break;
		case MACRO_ERASE_SMS_STATE_CHECK_SELECT_7F10:
			if (device->command.sw1 == 0x9f) {
				cmd_header[0] = SIM_GSM_CLA;
				cmd_header[1] = SIM_GSM_INS_SELECT;
				cmd_header[2] = 0x00;
				cmd_header[3] = 0x00;
				cmd_header[4] = 0x02;
				cmd_data[0] = 0x6f;
				cmd_data[1] = 0x3c;
				iso_iec_7816_device_command_build(device, cmd_header, CMD_WRITE|CMD_SERVICE, cmd_data, 2);
				device->macro_state = MACRO_ERASE_SMS_STATE_CHECK_SELECT_6F3C;
				rc = 0;
			} else {
				device->macro_state = MACRO_ERASE_SMS_STATE_DONE;
			}
			break;
		case MACRO_ERASE_SMS_STATE_CHECK_SELECT_6F3C:
			if (device->command.sw1 == 0x9f) {
				cmd_header[0] = SIM_GSM_CLA;
				cmd_header[1] = SIM_GSM_INS_GET_RESPONSE;
				cmd_header[2] = 0x00;
				cmd_header[3] = 0x00;
				cmd_header[4] = device->command.sw2;
				iso_iec_7816_device_command_build(device, cmd_header, CMD_SERVICE, NULL, 0);
				device->macro_state = MACRO_ERASE_SMS_STATE_CHECK_GET_RESPONSE_6F3C;
				rc = 0;
			} else {
				device->macro_state = MACRO_ERASE_SMS_STATE_DONE;
			}
			break;
		case MACRO_ERASE_SMS_STATE_CHECK_GET_RESPONSE_6F3C:
			if ((device->command.sw1 & 0x90) == 0x90) {
				device->sms_index = 0;
				device->sms_count = device->command.data_rd[3];
				device->sms_count += device->command.data_rd[2] * 256;
				device->sms_length = device->command.data_rd[14];
				device->sms_count /= device->sms_length;
				if (device->sms_index != device->sms_count) {
					cmd_header[0] = SIM_GSM_CLA;
					cmd_header[1] = SIM_GSM_INS_UPDATE_RECORD;
					cmd_header[2] = ++device->sms_index;
					cmd_header[3] = 0x04;
					cmd_header[4] = device->sms_length;
					for (i = 0; i < device->sms_length; i++) {
						cmd_data[i] = i;
					}
					iso_iec_7816_device_command_build(device, cmd_header, CMD_WRITE|CMD_SERVICE, cmd_data, device->sms_length);
					device->macro_state = MACRO_ERASE_SMS_STATE_CHECK_UPDATE_RECORD_6F3C;
				} else {
					device->macro_state = MACRO_ERASE_SMS_STATE_DONE;
				}
				rc = 0;
			} else {
				device->macro_state = MACRO_ERASE_SMS_STATE_DONE;
			}
			break;
		case MACRO_ERASE_SMS_STATE_CHECK_UPDATE_RECORD_6F3C:
			if ((device->command.sw1 & 0x90) == 0x90) {
				if (device->sms_index != device->sms_count) {
					cmd_header[0] = SIM_GSM_CLA;
					cmd_header[1] = SIM_GSM_INS_UPDATE_RECORD;
					cmd_header[2] = ++device->sms_index;
					cmd_header[3] = 0x04;
					cmd_header[4] = device->sms_length;
					for (i = 0; i < device->sms_length; i++) {
						cmd_data[i] = i;
					}
					iso_iec_7816_device_command_build(device, cmd_header, CMD_WRITE|CMD_SERVICE, cmd_data, device->sms_length);
					device->macro_state = MACRO_ERASE_SMS_STATE_CHECK_UPDATE_RECORD_6F3C;
				} else {
					device->macro_state = MACRO_ERASE_SMS_STATE_DONE;
				}
				rc = 0;
			} else {
				device->macro_state = MACRO_ERASE_SMS_STATE_DONE;
			}
			break;
		default:
			device->macro_state = MACRO_ERASE_SMS_STATE_DONE;
			break;
	}

	return rc;
}
//------------------------------------------------------------------------------
// end of gsm_sim_cmd_erase_sms_sm()
//------------------------------------------------------------------------------

/******************************************************************************/
/* end of 3gpp_ts_11_11.c                                                     */
/******************************************************************************/
