/******************************************************************************/
/* iso_iec_7816.c                                                             */
/******************************************************************************/

#include <sys/types.h>

#include <stdio.h>
#include <string.h>

#include "iso_iec_7816.h"

static void iso_iec_7816_device_atr_init(struct iso_iec_7816_device *device)
{
	device->atr.length = 0;
	device->atr.__expected = 2;
	device->atr.__next = ATR_BYTE_TS;
	device->atr.__y = 0;
	device->atr.__i = 0;
	device->atr.__abcd = 4;
	device->atr.__historical = 0;
	device->atr.__proto = 0;
	device->atr.__proto_deafult = 1;
}

//------------------------------------------------------------------------------
// iso_iec_7816_device_atr_is_complete()
//------------------------------------------------------------------------------
int iso_iec_7816_device_atr_is_complete(struct iso_iec_7816_device *device)
{
	if (device->atr.length == device->atr.__expected) {
		return -1;
	} else {
		return 0;
	}
}
//------------------------------------------------------------------------------
// end of iso_iec_7816_device_atr_is_complete()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// iso_iec_7816_device_atr_need_tck()
//------------------------------------------------------------------------------
static inline int iso_iec_7816_device_atr_need_tck(struct iso_iec_7816_device *device)
{
	u_int16_t proto;

	if (device->atr.__proto_deafult) {
		proto = 1;
	} else {
		proto = device->atr.__proto;
	}

	proto >>= 1;

	if (proto) {
		return -1;
	} else {
		return 0;
	}
}
//------------------------------------------------------------------------------
// end of iso_iec_7816_device_atr_need_tck()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// iso_iec_7816_device_atr_read_byte()
//------------------------------------------------------------------------------
int iso_iec_7816_device_atr_read_byte(struct iso_iec_7816_device *device, u_int8_t byte)
{
	size_t i;
	u_int8_t chk;
	u_int8_t proto;
	int ext;

	device->atr.data[device->atr.length++] = byte;

	switch (device->atr.__next) {
		case ATR_BYTE_TS:
			if (byte == 0x3b) {
				device->atr.__next = ATR_BYTE_T0;
			} else {
				return -1;
			}
			break;
		case ATR_BYTE_T0:
			// get historical bytes length
			device->atr.__historical = byte & 0xf;
			device->atr.__expected += device->atr.__historical;
		case ATR_BYTE_TABCD:
			if (device->atr.__abcd == 4) {
				// reset TX counter
				device->atr.__abcd = 0;
				// store T indicator
				proto = byte & 0xf;
				if (device->atr.__i) {
					// check proto number
					if ((1 << proto) >= device->atr.__proto) {
						device->atr.__proto_deafult = 0;
						device->atr.__proto |= (1 << proto); // set proto number
					} else {
						return -1;
					}
				}
				// store Y indicator
				device->atr.__y = (byte >> 4) & 0xf;
				// increment Y index
				device->atr.__i++;
			}
			// get next byte type
			if (device->atr.__y) {
				while (device->atr.__abcd < 4) {
					device->atr.__abcd++;
					ext = device->atr.__y & 1;
					device->atr.__y >>= 1;
					if (ext) {
						device->atr.__next = ATR_BYTE_TABCD;
						device->atr.__expected++;
						break;
					}
				}
			} else if (device->atr.__historical) {
				device->atr.__next = ATR_BYTE_HISTORICAL;
			} else if (iso_iec_7816_device_atr_need_tck(device)) {
				device->atr.__next = ATR_BYTE_TCK;
				device->atr.__expected += 1;
			} else {
				device->atr.__next = ATR_BYTE_UNKNOWN;
			}
			break;
		case ATR_BYTE_HISTORICAL:
			if (device->atr.__historical--) {
				device->atr.__next = ATR_BYTE_HISTORICAL;
				if ((!device->atr.__historical) && (iso_iec_7816_device_atr_need_tck(device))) {
					device->atr.__next = ATR_BYTE_TCK;
					device->atr.__expected += 1;
				}
			} else {
				device->atr.__next = ATR_BYTE_UNKNOWN;
			}
			break;
		case ATR_BYTE_TCK:
			chk = 0;
			for (i = 1; i < device->atr.length; i++) {
				chk ^= device->atr.data[i];
			}
			if (chk) {
				return -1;
			}
			device->atr.__next = ATR_BYTE_UNKNOWN;
			break;
		default:
			return -1;
	}

	return 0;
}
//------------------------------------------------------------------------------
// end of iso_iec_7816_device_atr_read_byte()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// iso_iec_7816_device_atr_get_TA1()
//------------------------------------------------------------------------------
u_int8_t iso_iec_7816_device_atr_get_TA1(struct iso_iec_7816_device *device)
{
	if (device->atr.data[1] & 0x10) {
		return device->atr.data[2];
	} else {
		return 0x11;
	}
}
//------------------------------------------------------------------------------
// end of iso_iec_7816_device_atr_get_TA1()
//------------------------------------------------------------------------------

static void iso_iec_7816_device_pps_init(struct iso_iec_7816_device *device)
{
	device->pps.length = 0;
	device->pps.__expected = 3;
	device->pps.__next = PPS_BYTE_S;
	
	device->pps.pps0 = 0;
	device->pps.pps1 = 0;
	device->pps.pps2 = 0;
	device->pps.pps3 = 0;
}

//------------------------------------------------------------------------------
// iso_iec_7816_device_pps_is_complete()
//------------------------------------------------------------------------------
int iso_iec_7816_device_pps_is_complete(struct iso_iec_7816_device *device)
{
	if (device->pps.length == device->pps.__expected) {
		return -1;
	} else {
		return 0;
	}
}
//------------------------------------------------------------------------------
// end of iso_iec_7816_device_pps_is_complete()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// iso_iec_7816_device_pps_read_byte()
//------------------------------------------------------------------------------
int iso_iec_7816_device_pps_read_byte(struct iso_iec_7816_device *device, u_int8_t byte)
{
	size_t i;
	u_int8_t chk;

	device->pps.data[device->pps.length++] = byte;

	switch (device->pps.__next) {
		case PPS_BYTE_S:
			if (byte != 0xff) {
				return -1;
			} else {
				device->pps.__next = PPS_BYTE_0;
			}
			break;
		case PPS_BYTE_0:
			if ((byte & 0x0f) != (device->pps.pps0 & 0x0f)) {
				return -1;
			}
			if ((byte & 0x10) == 0x10) {
				device->pps.__next = PPS_BYTE_1;
				device->pps.__expected += 1;
			} else if ((byte & 0x20) == 0x20) {
				device->pps.__next = PPS_BYTE_2;
				device->pps.__expected += 1;
			} else if ((byte & 0x40) == 0x40) {
				device->pps.__next = PPS_BYTE_3;
				device->pps.__expected += 1;
			} else {
				device->pps.__next = PPS_BYTE_PCK;
			}
			break;
		case PPS_BYTE_1:
			if (byte != device->pps.pps1) {
				return -1;
			}
			if ((byte & 0x20) == 0x20) {
				device->pps.__next = PPS_BYTE_2;
				device->pps.__expected += 1;
			} else if ((byte & 0x40) == 0x40) {
				device->pps.__next = PPS_BYTE_3;
				device->pps.__expected += 1;
			} else {
				device->pps.__next = PPS_BYTE_PCK;
			}
			break;
		case PPS_BYTE_2:
			if (byte != device->pps.pps2) {
				return -1;
			}
			if ((byte & 0x40) == 0x40) {
				device->pps.__next = PPS_BYTE_3;
				device->pps.__expected += 1;
			} else {
				device->pps.__next = PPS_BYTE_PCK;
			}
			break;
		case PPS_BYTE_3:
			if (byte != device->pps.pps3) {
				return -1;
			}
			device->pps.__next = PPS_BYTE_PCK;
			break;
		case PPS_BYTE_PCK:
			chk = 0;
			for (i = 0; i < device->pps.length; i++) {
				chk ^= device->pps.data[i];
			}
			if (chk) {
				return -1;
			}
			device->pps.__next = PPS_BYTE_UNKNOWN;
			break;
		default:
			return -1;
	}

	return 0;
}
//------------------------------------------------------------------------------
// end of iso_iec_7816_device_pps_read_byte()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// iso_iec_7816_device_pps_request_build()
//------------------------------------------------------------------------------
u_int32_t iso_iec_7816_device_pps_request_build(struct iso_iec_7816_device *device, u_int8_t *buff, u_int8_t T, u_int8_t TA1)
{
	u_int32_t len = 0;
	u_int8_t pck = 0;

	device->pps.pps0 = 0x10 | (T & 0x0f);
	device->pps.pps1 = TA1;

	buff[0] = 0xff;
	pck ^= buff[0];
	len++;

	buff[1] = device->pps.pps0;
	pck ^= buff[1];
	len++;

	buff[2] = device->pps.pps1;
	pck ^= buff[2];
	len++;

	buff[3] = 0;
	buff[3] ^= pck;
	len++;

	return len;
}
//------------------------------------------------------------------------------
// end of iso_iec_7816_device_pps_request_build()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// iso_iec_7816_device_command_is_complete()
//------------------------------------------------------------------------------
int iso_iec_7816_device_command_is_complete(struct iso_iec_7816_device *device)
{
	if (device->command.__count == device->command.__expected) {
		return -1;
	} else {
		return 0;
	}
}
//------------------------------------------------------------------------------
// end of iso_iec_7816_device_command_is_complete()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// iso_iec_7816_device_command_is_sent()
//------------------------------------------------------------------------------
int iso_iec_7816_device_command_is_sent(struct iso_iec_7816_device *device)
{
	if ((device->command.flags & CMD_SENT) == CMD_SENT) {
		return -1;
	} else {
		return 0;
	}
}
//------------------------------------------------------------------------------
// end of iso_iec_7816_device_command_is_sent()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// iso_iec_7816_device_command_is_write()
//------------------------------------------------------------------------------
int iso_iec_7816_device_command_is_write(struct iso_iec_7816_device *device)
{
	if ((device->command.flags & CMD_WRITE) == CMD_WRITE) {
		return -1;
	} else {
		return 0;
	}
}
//------------------------------------------------------------------------------
// end of iso_iec_7816_device_command_is_write()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// iso_iec_7816_device_command_is_service()
//------------------------------------------------------------------------------
int iso_iec_7816_device_command_is_service(struct iso_iec_7816_device *device)
{
	if ((device->command.flags & CMD_SERVICE) == CMD_SERVICE) {
		return -1;
	} else {
		return 0;
	}
}
//------------------------------------------------------------------------------
// end of iso_iec_7816_device_command_is_service()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// iso_iec_7816_device_command_is_acknowledge()
//------------------------------------------------------------------------------
int iso_iec_7816_device_command_is_acknowledge(struct iso_iec_7816_device *device, u_int8_t ack)
{
	if (device->command.header.ins == ack) {
		return -1;
	} else {
		return 0;
	}
}
//------------------------------------------------------------------------------
// end of iso_iec_7816_device_command_is_acknowledge()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// iso_iec_7816_device_command_read_byte()
//------------------------------------------------------------------------------
int iso_iec_7816_device_command_read_byte(struct iso_iec_7816_device *device, u_int8_t byte)
{
	switch (device->command.__next) {
		case CMD_BYTE_PROCEDURE:
			if (byte == 0x60) {
				device->command.__next = CMD_BYTE_PROCEDURE;
			} else if (((byte >= 0x61) && (byte <= 0x6f)) || ((byte >= 0x90) && (byte <= 0x9f))) {
				device->command.__count++;
				device->command.sw1 = byte;
				device->command.__next = CMD_BYTE_SW2;
			} else if (byte == device->command.header.ins) {
				if ((device->command.flags & CMD_WRITE) == CMD_WRITE) {
					device->command.__next = CMD_BYTE_PROCEDURE;
				} else {
					device->command.__expected += (device->command.header.p3)?(device->command.header.p3):(256);
					device->command.__next = CMD_BYTE_DATA_BURST;
				}
			} else if ((byte ^ 0xff) == device->command.header.ins) {
				device->command.__expected++;
				device->command.__next = CMD_BYTE_DATA_SINGLE;
			} else {
				return -1;
			}
			break;
		case CMD_BYTE_SW2:
			device->command.__count++;
			device->command.sw2 = byte;
			device->command.__next = CMD_BYTE_UNKNOWN;
			break;
		case CMD_BYTE_DATA_BURST:
			device->command.__count++;
			device->command.data_rd[device->command.length_rd++] = byte;
			if (device->command.length_rd < (device->command.__expected - 2)) {
				device->command.__next = CMD_BYTE_DATA_BURST;
			} else {
				device->command.__next = CMD_BYTE_PROCEDURE;
			}
			break;
		case CMD_BYTE_DATA_SINGLE:
			device->command.__count++;
			device->command.data_rd[device->command.length_rd++] = byte;
			device->command.__next = CMD_BYTE_PROCEDURE;
			break;
		default:
			return -1;
	}

	return 0;
}
//------------------------------------------------------------------------------
// end of iso_iec_7816_device_command_read_byte()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// iso_iec_7816_device_command_build()
//------------------------------------------------------------------------------
void iso_iec_7816_device_command_build(struct iso_iec_7816_device *device, void *header, u_int32_t flags, void *data, size_t length)
{
	memcpy(&device->command.header, header, sizeof(struct iso_iec_7816_T0_command_header));

	device->command.flags = flags;

	if ((device->command.length_wr = length)) {
		memcpy(device->command.data_wr, data, length);
	}

	device->command.sw1 = 0;
	device->command.sw2 = 0;

	device->command.length_rd = 0;

	device->command.__count = 0;
	device->command.__expected = 2;

	device->command.__next = CMD_BYTE_PROCEDURE;

	device->command.flags |= CMD_SENT;
}
//------------------------------------------------------------------------------
// end of iso_iec_7816_device_command_build()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// iso_iec_7816_device_reset()
//------------------------------------------------------------------------------
void iso_iec_7816_device_reset(struct iso_iec_7816_device *device, u_int32_t frequency)
{
	device->frequency = frequency;

	device->F = 372;
	device->D = 1;
	device->N = 0;
	device->WI = 10;

	device->etu = (1000000000LLU * device->F) / (device->frequency * device->D);

	device->GT = 12 * device->etu;
	device->WT = 9600 * device->etu;

	// init device ATR data
	iso_iec_7816_device_atr_init(device);

	// init device PPS data
	iso_iec_7816_device_pps_init(device);
}
//------------------------------------------------------------------------------
// end of iso_iec_7816_device_reset()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// iso_iec_7816_device_apply_data_rate()
//------------------------------------------------------------------------------
void iso_iec_7816_device_apply_data_rate(struct iso_iec_7816_device *device, u_int8_t T, u_int8_t TA1)
{
	switch ((TA1 >> 4) & 0x0f) {
		default:
		case 0x0:
		case 0x1:
			device->F = 372;
			break;
		case 0x2:
			device->F = 558;
			break;
		case 0x3:
			device->F = 744;
			break;
		case 0x4:
			device->F = 1116;
			break;
		case 0x5:
			device->F = 1488;
			break;
		case 0x6:
			device->F = 1860;
			break;
		case 0x9:
			device->F = 512;
			break;
		case 0xa:
			device->F = 768;
			break;
		case 0xb:
			device->F = 1024;
			break;
		case 0xc:
			device->F = 1536;
			break;
		case 0xd:
			device->F = 2048;
			break;
	}

	switch (TA1 & 0x0f) {
		default:
		case 0x1:
			device->D = 1;
			break;
		case 0x2:
			device->D = 2;
			break;
		case 0x3:
			device->D = 4;
			break;
		case 0x4:
			device->D = 8;
			break;
		case 0x5:
			device->D = 16;
			break;
		case 0x6:
			device->D = 32;
			break;
		case 0x7:
			device->D = 64;
			break;
		case 0x8:
			device->D = 12;
			break;
		case 0x9:
			device->D = 20;
			break;
	}

	device->etu = (1000000000LLU * device->F) / (device->frequency * device->D);

	device->GT = (12 + device->N) * device->etu;

	if (T == 0) {
		device->WT = (1000000000LLU * 960 * device->WI * device->F) / device->frequency;
	}
}
//------------------------------------------------------------------------------
// end of iso_iec_7816_device_apply_data_rate()
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// get_iso_iec_7816_cla0x_ins_type()
//------------------------------------------------------------------------------
int get_iso_iec_7816_cla0x_ins_type(u_int8_t ins)
{
	switch (ins) {
		// read
		case SIM_IIC_INS_GET_CHALLENGE:
		case SIM_IIC_INS_READ_BINARY:
		case SIM_IIC_INS_READ_RECORDS:
		case SIM_IIC_INS_GET_RESPONSE:
		case SIM_IIC_INS_GET_DATA:
			return -1;
		// write
		case SIM_IIC_INS_DEACTIVATE_FILE:
		case SIM_IIC_INS_ERASE_RECORDS:
		case SIM_IIC_INS_ERASE_BINARY:
		case SIM_IIC_INS_ERASE_BINARY_1:
		case SIM_IIC_INS_PERFORM_SCQL_OPERATION:
		case SIM_IIC_INS_PERFORM_TRANSACTION_OPERATION:
		case SIM_IIC_INS_PERFORM_USER_OPERATION:
		case SIM_IIC_INS_VERIFY:
		case SIM_IIC_INS_VERIFY_1:
		case SIM_IIC_INS_MANAGE_SECURITY_ENVIRONMENT:
		case SIM_IIC_INS_CHANGE_REFERENCE_DATA:
		case SIM_IIC_INS_DISABLE_VERIFICATION_REQUIREMENT:
		case SIM_IIC_INS_ENABLE_VERIFICATION_REQUIREMENT:
		case SIM_IIC_INS_PERFORM_SECURITY_OPERATION:
		case SIM_IIC_INS_RESET_RETRY_COUNTER:
		case SIM_IIC_INS_ACTIVATE_FILE:
		case SIM_IIC_INS_GENERATE_ASYMMETRIC_KEY_PAIR:
		case SIM_IIC_INS_MANAGE_CHANNEL:
		case SIM_IIC_INS_EXTERNAL_MUTUAL_AUTHENTICATE:
		case SIM_IIC_INS_GENERAL_AUTHENTICATE:
		case SIM_IIC_INS_GENERAL_AUTHENTICATE_1:
		case SIM_IIC_INS_INTERNAL_AUTHENTICATE:
		case SIM_IIC_INS_SEARCH_BINARY:
		case SIM_IIC_INS_SEARCH_BINARY_1:
		case SIM_IIC_INS_SEARCH_RECORD:
		case SIM_IIC_INS_SELECT:
		case SIM_IIC_INS_READ_BINARY_1:
		case SIM_IIC_INS_READ_RECORDS_1:
		case SIM_IIC_INS_ENVELOPE:
		case SIM_IIC_INS_ENVELOPE_1:
		case SIM_IIC_INS_GET_DATA_1:
		case SIM_IIC_INS_WRITE_BINARY:
		case SIM_IIC_INS_WRITE_BINARY_1:
		case SIM_IIC_INS_WRITE_RECORD:
		case SIM_IIC_INS_UPDATE_BINARY:
		case SIM_IIC_INS_UPDATE_BINARY_1:
		case SIM_IIC_INS_PUT_DATA:
		case SIM_IIC_INS_PUT_DATA_1:
		case SIM_IIC_INS_UPDATE_RECORD:
		case SIM_IIC_INS_UPDATE_RECORD_1:
		case SIM_IIC_INS_CREATE_FILE:
		case SIM_IIC_INS_APPEND_RECORD:
		case SIM_IIC_INS_DELETE_FILE:
		case SIM_IIC_INS_TERMINATE_DF:
		case SIM_IIC_INS_TERMINATE_EF:
		case SIM_IIC_INS_TERMINATE_CARD_USAGE:
			return 1;
		default:
			return 0;
	}
}
//------------------------------------------------------------------------------
// end of get_iso_iec_7816_cla0x_ins_type()
//------------------------------------------------------------------------------

/******************************************************************************/
/* end of iso_iec_7816.c                                                      */
/******************************************************************************/
