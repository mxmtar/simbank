/******************************************************************************/
/* ss9006.h                                                                   */
/******************************************************************************/

#ifndef __SS9006_H__
#define __SS9006_H__

#include <sys/types.h>

enum {
	SS9006_OPC_AUTHORIZATION		= 0x01,
	SS9006_OPC_COMBINED				= 0x83,
	SS9006_OPC_SIM_LED_HIDE			= 0xf4,
	SS9006_OPC_SIM_LED_SHOW			= 0xf5,
	SS9006_OPC_SIM_STATUS			= 0xf8,
	SS9006_OPC_SIM_BIND				= 0xf9,
	SS9006_OPC_SIM_UNBIND			= 0xfa,
	SS9006_OPC_SIM_BLOCK			= 0xfb,
	SS9006_OPC_SIM_RESET			= 0xfd,
	SS9006_OPC_EXTENSION			= 0xff,
};

enum {
	SS9006_EXT_OPC_CLI_CONTROL_SET	= 0x00,
	SS9006_EXT_OPC_CLI_INFO			= 0x01,
	SS9006_EXT_OPC_SIM_INFO			= 0x02,
	SS9006_EXT_OPC_SIM_LOG_ENABLE	= 0x03,
	SS9006_EXT_OPC_SIM_LOG_DISABLE	= 0x04,
	SS9006_EXT_OPC_SIM_LOG_DELETE	= 0x05,
	SS9006_EXT_OPC_SIM_DUMP_ENABLE	= 0x06,
	SS9006_EXT_OPC_SIM_DUMP_DISABLE	= 0x07,
	SS9006_EXT_OPC_SIM_DUMP_DELETE	= 0x08,
	SS9006_EXT_OPC_SIM_TEST_SELECT	= 0x09,
	SS9006_EXT_OPC_KEEP_ALIVE		= 0x80,
};

struct ss9006_base_header {
	u_int8_t opc;
	u_int8_t data0;
	u_int8_t data1;
} __attribute__((packed));

struct ss9006_sim_generic_request {
	u_int8_t opc;
	u_int8_t sim;
	u_int8_t reserved;
} __attribute__((packed));

struct ss9006_sim_extension_request {
	u_int8_t ext;
	u_int8_t opc;
	u_int8_t sel;
} __attribute__((packed));

struct ss9006_authorization_request {
	u_int8_t hex01;
	u_int16_t checksum;
	u_int8_t user[20];
	u_int8_t password[20];
} __attribute__((packed));

struct ss9006_authorization_response {
	u_int8_t hex01;
	u_int8_t status;
	u_int8_t reserved;
} __attribute__((packed));

struct ss9006_sim_status_response {
	u_int8_t hexf8;
	u_int16_t reserved;
	u_int8_t sim[200];
} __attribute__((packed));

struct ss9006_sim_reset_response {
	u_int8_t hexfd;
	u_int8_t sim;
	u_int8_t reserved;
	u_int8_t length;
	u_int16_t crc;
	u_int8_t atr[33];
} __attribute__((packed));

struct ss9006_combined_header {
	u_int8_t cmd;
	u_int16_t length;
} __attribute__((packed));

struct ss9006_combined_chunk_header {
	u_int8_t sim;
	u_int16_t length;
} __attribute__((packed));

#endif //__SS9006_H__

/******************************************************************************/
/* end of ss9006.h                                                            */
/******************************************************************************/
