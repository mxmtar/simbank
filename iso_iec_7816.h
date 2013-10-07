/******************************************************************************/
/* iso_iec_7816.h                                                             */
/******************************************************************************/

#ifndef __ISO_IEC_7816_H__
#define __ISO_IEC_7816_H__

#include <sys/types.h>

#define SIM_IIC_CLA 0x00

enum {
	SIM_IIC_INS_DEACTIVATE_FILE						= 0x04,	// to SIM
	SIM_IIC_INS_ERASE_RECORDS						= 0x0C,	// to SIM (no data)
	SIM_IIC_INS_ERASE_BINARY						= 0x0E,	// to SIM
	SIM_IIC_INS_ERASE_BINARY_1						= 0x0F,	// to SIM
	SIM_IIC_INS_PERFORM_SCQL_OPERATION				= 0x10,	// to SIM (maybe)
	SIM_IIC_INS_PERFORM_TRANSACTION_OPERATION		= 0x12,	// to SIM (maybe)
	SIM_IIC_INS_PERFORM_USER_OPERATION				= 0x14,	// to SIM (maybe)
	SIM_IIC_INS_VERIFY								= 0x20,	// to SIM
	SIM_IIC_INS_VERIFY_1							= 0x21,	// to SIM
	SIM_IIC_INS_MANAGE_SECURITY_ENVIRONMENT			= 0x22,	// to SIM
	SIM_IIC_INS_CHANGE_REFERENCE_DATA				= 0x24,	// to SIM
	SIM_IIC_INS_DISABLE_VERIFICATION_REQUIREMENT	= 0x26,	// to SIM
	SIM_IIC_INS_ENABLE_VERIFICATION_REQUIREMENT		= 0x28,	// to SIM
	SIM_IIC_INS_PERFORM_SECURITY_OPERATION			= 0x2A,	// to SIM
	SIM_IIC_INS_RESET_RETRY_COUNTER					= 0x2C,	// to SIM
	SIM_IIC_INS_ACTIVATE_FILE						= 0x44,	// to SIM
	SIM_IIC_INS_GENERATE_ASYMMETRIC_KEY_PAIR		= 0x46,	// to SIM
	SIM_IIC_INS_MANAGE_CHANNEL						= 0x70,	// to SIM (no data)
	SIM_IIC_INS_EXTERNAL_MUTUAL_AUTHENTICATE		= 0x82,	// to SIM
	SIM_IIC_INS_GET_CHALLENGE						= 0x84,	// from SIM
	SIM_IIC_INS_GENERAL_AUTHENTICATE				= 0x86,	// to SIM
	SIM_IIC_INS_GENERAL_AUTHENTICATE_1				= 0x87,	// to SIM
	SIM_IIC_INS_INTERNAL_AUTHENTICATE				= 0x88,	// to SIM
	SIM_IIC_INS_SEARCH_BINARY						= 0xA0,	// to SIM
	SIM_IIC_INS_SEARCH_BINARY_1						= 0xA1,	// to SIM
	SIM_IIC_INS_SEARCH_RECORD						= 0xA2,	// to SIM
	SIM_IIC_INS_SELECT								= 0xA4,	// to SIM
	SIM_IIC_INS_READ_BINARY							= 0xB0,	// from SIM
	SIM_IIC_INS_READ_BINARY_1						= 0xB1,	// to SIM
	SIM_IIC_INS_READ_RECORDS						= 0xB2,	// from SIM
	SIM_IIC_INS_READ_RECORDS_1						= 0xB3,	// to SIM
	SIM_IIC_INS_GET_RESPONSE						= 0xC0,	// from SIM
	SIM_IIC_INS_ENVELOPE							= 0xC2,	// to SIM
	SIM_IIC_INS_ENVELOPE_1							= 0xC3,	// to SIM
	SIM_IIC_INS_GET_DATA							= 0xCA,	// from SIM
	SIM_IIC_INS_GET_DATA_1							= 0xCB,	// to SIM
	SIM_IIC_INS_WRITE_BINARY						= 0xD0,	// to SIM
	SIM_IIC_INS_WRITE_BINARY_1						= 0xD1,	// to SIM
	SIM_IIC_INS_WRITE_RECORD						= 0xD2,	// to SIM
	SIM_IIC_INS_UPDATE_BINARY						= 0xD6,	// to SIM
	SIM_IIC_INS_UPDATE_BINARY_1						= 0xD7,	// to SIM
	SIM_IIC_INS_PUT_DATA							= 0xDA,	// to SIM
	SIM_IIC_INS_PUT_DATA_1							= 0xDB,	// to SIM
	SIM_IIC_INS_UPDATE_RECORD						= 0xDC,	// to SIM
	SIM_IIC_INS_UPDATE_RECORD_1						= 0xDD,	// to SIM
	SIM_IIC_INS_CREATE_FILE							= 0xE0,	// to SIM
	SIM_IIC_INS_APPEND_RECORD						= 0xE2,	// to SIM
	SIM_IIC_INS_DELETE_FILE							= 0xE4,	// to SIM
	SIM_IIC_INS_TERMINATE_DF						= 0xE6,	// to SIM
	SIM_IIC_INS_TERMINATE_EF						= 0xE8,	// to SIM
	SIM_IIC_INS_TERMINATE_CARD_USAGE				= 0xFE,	// to SIM (no data)
};


#define ATR_MAXLEN 33
#define PPS_MAXLEN 6
#define CMD_MAXLEN 256

enum {
	ATR_BYTE_UNKNOWN = 0,
	ATR_BYTE_TS,
	ATR_BYTE_T0,
	ATR_BYTE_TABCD,
	ATR_BYTE_HISTORICAL,
	ATR_BYTE_TCK,
};

enum {
	PPS_BYTE_UNKNOWN = 0,
	PPS_BYTE_S,
	PPS_BYTE_0,
	PPS_BYTE_1,
	PPS_BYTE_2,
	PPS_BYTE_3,
	PPS_BYTE_PCK,
};

enum {
	CMD_BYTE_UNKNOWN = 0,
	CMD_BYTE_PROCEDURE,
	CMD_BYTE_DATA_BURST,
	CMD_BYTE_DATA_SINGLE,
	CMD_BYTE_SW2,
};

enum {
	CMD_SERVICE = (1 << 0),
	CMD_WRITE = (1 << 1),
	CMD_SENT = (1 << 2),
};

enum {
	MACRO_GENERIC_STATE_DONE = -1,
	MACRO_GENERIC_STATE_INIT = 0,
};

struct iso_iec_7816_device {
	u_int32_t frequency;
	u_int32_t F;
	u_int32_t D;
	u_int32_t N;
	u_int32_t WI;

	u_int32_t etu;

	u_int32_t GT;
	u_int32_t WT;


	struct atr {
		u_int8_t data[ATR_MAXLEN];
		size_t length;

		size_t __expected;
		int __next;
		u_int8_t __y;
		u_int8_t __i;
		u_int8_t __abcd;
		u_int8_t __historical;
		u_int16_t __proto;
		int __proto_deafult;
	} atr;

	struct pps {
		u_int8_t pps0;
		u_int8_t pps1;
		u_int8_t pps2;
		u_int8_t pps3;

		u_int8_t data[PPS_MAXLEN];
		size_t length;

		size_t __expected;
		int __next;
	} pps;

	struct command {

		struct iso_iec_7816_T0_command_header {
			u_int8_t cla;
			u_int8_t ins;
			u_int8_t p1;
			u_int8_t p2;
			u_int8_t p3;
		} __attribute__((packed)) header;

		u_int8_t data_wr[CMD_MAXLEN];
		size_t length_wr;

		u_int8_t data_rd[CMD_MAXLEN];
		size_t length_rd;

		u_int8_t sw1;
		u_int8_t sw2;

		u_int32_t flags;

		int __next;
		size_t __expected;
		size_t __count;

	} command;

	int macro_state;

	char iccid[24];
	size_t iccid_len;

	char spn[48];
	size_t spn_len;

	char msisdn[20];
	size_t msisdn_len;

	size_t sms_count;
	size_t sms_index;
	size_t sms_length;

};

extern int iso_iec_7816_device_atr_is_complete(struct iso_iec_7816_device *device);
extern int iso_iec_7816_device_atr_read_byte(struct iso_iec_7816_device *device, u_int8_t byte);
extern u_int8_t iso_iec_7816_device_atr_get_TA1(struct iso_iec_7816_device *device);

extern int iso_iec_7816_device_pps_is_complete(struct iso_iec_7816_device *device);
extern int iso_iec_7816_device_pps_read_byte(struct iso_iec_7816_device *device, u_int8_t byte);
extern u_int32_t iso_iec_7816_device_pps_request_build(struct iso_iec_7816_device *device, u_int8_t *buff, u_int8_t T, u_int8_t TA1);

extern int iso_iec_7816_device_command_is_complete(struct iso_iec_7816_device *device);
extern int iso_iec_7816_device_command_is_sent(struct iso_iec_7816_device *device);
extern int iso_iec_7816_device_command_is_write(struct iso_iec_7816_device *device);
extern int iso_iec_7816_device_command_is_service(struct iso_iec_7816_device *device);
extern int iso_iec_7816_device_command_is_acknowledge(struct iso_iec_7816_device *device, u_int8_t ack);
extern int iso_iec_7816_device_command_read_byte(struct iso_iec_7816_device *device, u_int8_t byte);
extern void iso_iec_7816_device_command_build(struct iso_iec_7816_device *device, void *header, u_int32_t flags, void *data, size_t length);

extern void iso_iec_7816_device_reset(struct iso_iec_7816_device *device, u_int32_t frequency);
extern void iso_iec_7816_device_apply_data_rate(struct iso_iec_7816_device *device, u_int8_t T, u_int8_t TA1);

extern int get_iso_iec_7816_cla0x_ins_type(u_int8_t ins);

#endif //__ISO_IEC_7816_H__

/******************************************************************************/
/* end of iso_iec_7816.h                                                      */
/******************************************************************************/
