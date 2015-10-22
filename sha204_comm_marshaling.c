/*
 * \file
 *
 * \brief ATSHA204 file that implements the command marshaling layer for the device
 *
 *
 * Copyright (c) 2011-2012 Atmel Corporation. All rights reserved.
 *
 * \asf_license_start
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The name of Atmel may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with an
 *    Atmel microcontroller product.
 *
 * THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * \asf_license_stop
 *
 */

#include <string.h>                    // needed for memcpy()

#include "sha204_lib_return_codes.h"   // declarations of function return codes
#include "sha204_comm_marshaling.h"

/** \brief This function checks the parameters for sha204m_execute().
 *
 * \param[in, out] args pointer to parameter structure
 * \return status of the operation
 */
static uint8_t sha204m_check_parameters(int fd,struct sha204_command_parameters *args)
{
#ifdef SHA204_CHECK_PARAMETERS

	uint8_t len = args->data_len_1 + args->data_len_2 + args->data_len_3 + SHA204_CMD_SIZE_MIN;
	if (!args->tx_buffer || args->tx_size < len || args->rx_size < SHA204_RSP_SIZE_MIN || !args->rx_buffer)
		return SHA204_BAD_PARAM;

	if ((args->data_len_1 > 0 && !args->data_1) || (args->data_len_2 > 0 && !args->data_2) || (args->data_len_3 > 0 && !args->data_3))
		return SHA204_BAD_PARAM;

	// Check parameters depending on op-code.
	switch (args->op_code) {
	case SHA204_CHECKMAC:
		if (
				// no null pointers allowed
				!args->data_1 || !args->data_2
				// No reserved bits should be set.
				|| (args->param_1 | CHECKMAC_MODE_MASK) != CHECKMAC_MODE_MASK
				// key_id > 15 not allowed
				|| args->param_2 > SHA204_KEY_ID_MAX
			)
			return SHA204_BAD_PARAM;
		break;

	case SHA204_DERIVE_KEY:
		if (((args->param_1 & ~DERIVE_KEY_RANDOM_FLAG) != 0)
					 || (args->param_2 > SHA204_KEY_ID_MAX))
			return SHA204_BAD_PARAM;
		break;

	case SHA204_DEVREV:
		break;

	case SHA204_GENDIG:
		if ((args->param_1 != GENDIG_ZONE_OTP) && (args->param_1 != GENDIG_ZONE_DATA))
			return SHA204_BAD_PARAM;
		break;

	case SHA204_HMAC:
		if ((args->param_1 & ~HMAC_MODE_MASK) != 0)
			return SHA204_BAD_PARAM;
		break;

	case SHA204_LOCK:
		if (((args->param_1 & ~LOCK_ZONE_MASK) != 0)
					|| ((args->param_1 & LOCK_ZONE_NO_CRC) && (args->param_2 != 0)))
			return SHA204_BAD_PARAM;
		break;

	case SHA204_MAC:
		if (((args->param_1 & ~MAC_MODE_MASK) != 0)
					|| (((args->param_1 & MAC_MODE_BLOCK2_TEMPKEY) == 0) && !args->data_1))
			return SHA204_BAD_PARAM;
		break;

	case SHA204_NONCE:
		if (!args->data_1
				|| (args->param_1 > NONCE_MODE_PASSTHROUGH)
				|| (args->param_1 == NONCE_MODE_INVALID)
			)
			return SHA204_BAD_PARAM;
		break;

	case SHA204_PAUSE:
		break;

	case SHA204_RANDOM:
		if (args->param_1 > RANDOM_NO_SEED_UPDATE)
			return SHA204_BAD_PARAM;
		break;

	case SHA204_READ:
		if (((args->param_1 & ~READ_ZONE_MASK) != 0)
					|| ((args->param_1 & READ_ZONE_MODE_32_BYTES) && (args->param_1 == SHA204_ZONE_OTP)))
			return SHA204_BAD_PARAM;
		break;

	case SHA204_UPDATE_EXTRA:
		if (args->param_1 > UPDATE_CONFIG_BYTE_86)
			return SHA204_BAD_PARAM;
		break;

	case SHA204_WRITE:
		if (!args->data_1 || ((args->param_1 & ~WRITE_ZONE_MASK) != 0))
			return SHA204_BAD_PARAM;
		break;

	default:
		// unknown op-code
		return SHA204_BAD_PARAM;
	}

	return SHA204_SUCCESS;

#else
	return SHA204_SUCCESS;
#endif
}


/** \brief This function creates a command packet, sends it, and receives its response.
 * \param[in, out]  args pointer to parameter structure
 * \return status of the operation
 */
uint8_t sha204m_execute(int fd, struct sha204_command_parameters *args)
{
	uint8_t *p_buffer;
	uint8_t len;
	struct sha204_send_and_receive_parameters comm_parameters = {
		.tx_buffer = args->tx_buffer,
		.rx_buffer = args->rx_buffer
	};

	uint8_t ret_code = sha204m_check_parameters(fd,args);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;

	// Supply delays and response size.
	switch (args->op_code) {
	case SHA204_CHECKMAC:
		comm_parameters.poll_delay = CHECKMAC_DELAY;
		comm_parameters.poll_timeout = CHECKMAC_EXEC_MAX - CHECKMAC_DELAY;
		comm_parameters.rx_size = CHECKMAC_RSP_SIZE;
		break;

	case SHA204_DERIVE_KEY:
		comm_parameters.poll_delay = DERIVE_KEY_DELAY;
		comm_parameters.poll_timeout = DERIVE_KEY_EXEC_MAX - DERIVE_KEY_DELAY;
		comm_parameters.rx_size = DERIVE_KEY_RSP_SIZE;
		break;

	case SHA204_DEVREV:
		comm_parameters.poll_delay = DEVREV_DELAY;
		comm_parameters.poll_timeout = DEVREV_EXEC_MAX - DEVREV_DELAY;
		comm_parameters.rx_size = DEVREV_RSP_SIZE;
		break;

	case SHA204_GENDIG:
		comm_parameters.poll_delay = GENDIG_DELAY;
		comm_parameters.poll_timeout = GENDIG_EXEC_MAX - GENDIG_DELAY;
		comm_parameters.rx_size = GENDIG_RSP_SIZE;
		break;

	case SHA204_HMAC:
		comm_parameters.poll_delay = HMAC_DELAY;
		comm_parameters.poll_timeout = HMAC_EXEC_MAX - HMAC_DELAY;
		comm_parameters.rx_size = HMAC_RSP_SIZE;
		break;

	case SHA204_LOCK:
		comm_parameters.poll_delay = LOCK_DELAY;
		comm_parameters.poll_timeout = LOCK_EXEC_MAX - LOCK_DELAY;
		comm_parameters.rx_size = LOCK_RSP_SIZE;
		break;

	case SHA204_MAC:
		comm_parameters.poll_delay = MAC_DELAY;
		comm_parameters.poll_timeout = MAC_EXEC_MAX - MAC_DELAY;
		comm_parameters.rx_size = MAC_RSP_SIZE;
		break;

	case SHA204_NONCE:
		comm_parameters.poll_delay = NONCE_DELAY;
		comm_parameters.poll_timeout = NONCE_EXEC_MAX - NONCE_DELAY;
		comm_parameters.rx_size = args->param_1 == NONCE_MODE_PASSTHROUGH
							? NONCE_RSP_SIZE_SHORT : NONCE_RSP_SIZE_LONG;
		break;

	case SHA204_PAUSE:
		comm_parameters.poll_delay = PAUSE_DELAY;
		comm_parameters.poll_timeout = PAUSE_EXEC_MAX - PAUSE_DELAY;
		comm_parameters.rx_size = PAUSE_RSP_SIZE;
		break;

	case SHA204_RANDOM:
		comm_parameters.poll_delay = RANDOM_DELAY;
		comm_parameters.poll_timeout = RANDOM_EXEC_MAX - RANDOM_DELAY;
		comm_parameters.rx_size = RANDOM_RSP_SIZE;
		break;

	case SHA204_READ:
		comm_parameters.poll_delay = READ_DELAY;
		comm_parameters.poll_timeout = READ_EXEC_MAX - READ_DELAY;
		comm_parameters.rx_size = (args->param_1 & SHA204_ZONE_COUNT_FLAG)
							? READ_32_RSP_SIZE : READ_4_RSP_SIZE;
		break;

	case SHA204_UPDATE_EXTRA:
		comm_parameters.poll_delay = UPDATE_DELAY;
		comm_parameters.poll_timeout = UPDATE_EXEC_MAX - UPDATE_DELAY;
		comm_parameters.rx_size = UPDATE_RSP_SIZE;
		break;

	case SHA204_WRITE:
		comm_parameters.poll_delay = WRITE_DELAY;
		comm_parameters.poll_timeout = WRITE_EXEC_MAX - WRITE_DELAY;
		comm_parameters.rx_size = WRITE_RSP_SIZE;
		break;

	default:
		comm_parameters.poll_delay = 0;
		comm_parameters.poll_timeout = SHA204_COMMAND_EXEC_MAX;
		comm_parameters.rx_size = args->rx_size;
	}

	// Assemble command.
	len = args->data_len_1 + args->data_len_2 + args->data_len_3 + SHA204_CMD_SIZE_MIN;
	p_buffer = args->tx_buffer;
	*p_buffer++ = len;
	*p_buffer++ = args->op_code;
	*p_buffer++ = args->param_1;
	*p_buffer++ = args->param_2 & 0xFF;
	*p_buffer++ = args->param_2 >> 8;

	if (args->data_len_1 > 0) {
		memcpy(p_buffer, args->data_1, args->data_len_1);
		p_buffer += args->data_len_1;
	}
	if (args->data_len_2 > 0) {
		memcpy(p_buffer, args->data_2, args->data_len_2);
		p_buffer += args->data_len_2;
	}
	if (args->data_len_3 > 0) {
		memcpy(p_buffer, args->data_3, args->data_len_3);
		p_buffer += args->data_len_3;
	}

	sha204c_calculate_crc(len - SHA204_CRC_SIZE, args->tx_buffer, p_buffer);

	// Send command and receive response.
	return sha204c_send_and_receive(fd,&comm_parameters);
}
