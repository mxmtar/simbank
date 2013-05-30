/******************************************************************************/
/* iso_iec_7816.h                                                             */
/******************************************************************************/

#ifndef __ISO_IEC_7816_H__
#define __ISO_IEC_7816_H__

#include <sys/types.h>

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

#endif //__ISO_IEC_7816_H__

/******************************************************************************/
/* end of iso_iec_7816.h                                                      */
/******************************************************************************/
