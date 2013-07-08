/******************************************************************************/
/* 3gpp_ts_101_221.c                                                          */
/******************************************************************************/

#include <sys/types.h>

#include <stdio.h>
#include <string.h>

#include "iso_iec_7816.h"
#include "3gpp_ts_101_221.h"

//------------------------------------------------------------------------------
// get_3gpp_ts_101_221_cla8x_ins_type()
//------------------------------------------------------------------------------
int get_3gpp_ts_101_221_cla8x_ins_type(u_int8_t ins)
{
	switch (ins) {
		// read
		case SIM_UICC_INS_STATUS:
		case SIM_UICC_INS_RETRIEVE_DATA:
		case SIM_UICC_INS_FETCH:
			return -1;
		// write
		case SIM_UICC_INS_INCREASE:
		case SIM_UICC_INS_SET_DATA:
		case SIM_UICC_INS_TERMINAL_CAPABILITY:
		case SIM_UICC_INS_TERMINAL_PROFILE:
		case SIM_UICC_INS_ENVELOPE:
		case SIM_UICC_INS_TERMINAL_RESPONSE:
			return 1;
		default:
			return 0;
	}
}
//------------------------------------------------------------------------------
// end of get_3gpp_ts_101_221_cla8x_ins_type()
//------------------------------------------------------------------------------

/******************************************************************************/
/* end of 3gpp_ts_101_221.c                                                   */
/******************************************************************************/
