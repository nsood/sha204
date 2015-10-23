/*
 * $safeprojectname$.c
 *
 * Created: 7/10/2013 1:56:24 PM
 *  Author: easanghanwa
 */ 

#include "atsha204_ctc_d1_solutions.h"

#define I2C_BUS       "/dev/i2c-0"
#define ATSHA204_ADDR  0x64

void sha256_init(sha256_ctx *ctx)
{
#ifndef UNROLL_LOOPS
    int i;
    for (i = 0; i < 8; i++) {
        ctx->h[i] = sha256_h0[i];
    }
#else
    ctx->h[0] = sha256_h0[0]; ctx->h[1] = sha256_h0[1];
    ctx->h[2] = sha256_h0[2]; ctx->h[3] = sha256_h0[3];
    ctx->h[4] = sha256_h0[4]; ctx->h[5] = sha256_h0[5];
    ctx->h[6] = sha256_h0[6]; ctx->h[7] = sha256_h0[7];
#endif /* !UNROLL_LOOPS */

    ctx->len = 0;
    ctx->tot_len = 0;
}

void sha256_update(sha256_ctx *ctx, const uint8 *message,
                   uint32 len)
{
    uint32 block_nb;
    uint32 new_len, rem_len, tmp_len;
    const uint8 *shifted_message;

    tmp_len = SHA256_BLOCK_SIZE - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(&ctx->block[ctx->len], message, rem_len);

    if (ctx->len + len < SHA256_BLOCK_SIZE) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / SHA256_BLOCK_SIZE;

    shifted_message = message + rem_len;

    sha256_transf(ctx, ctx->block, 1);
    sha256_transf(ctx, shifted_message, block_nb);

    rem_len = new_len % SHA256_BLOCK_SIZE;

    memcpy(ctx->block, &shifted_message[block_nb << 6],
           rem_len);

    ctx->len = rem_len;
    ctx->tot_len += (block_nb + 1) << 6;
}

void sha256_final(sha256_ctx *ctx, uint8 *digest)
{
    uint32 block_nb;
    uint32 pm_len;
    uint32 len_b;

#ifndef UNROLL_LOOPS
    int i;
#endif

    block_nb = (1 + ((SHA256_BLOCK_SIZE - 9)
                     < (ctx->len % SHA256_BLOCK_SIZE)));

    len_b = (ctx->tot_len + ctx->len) << 3;
    pm_len = block_nb << 6;

    memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
    ctx->block[ctx->len] = 0x80;
    UNPACK32(len_b, ctx->block + pm_len - 4);

    sha256_transf(ctx, ctx->block, block_nb);

#ifndef UNROLL_LOOPS
    for (i = 0 ; i < 8; i++) {
        UNPACK32(ctx->h[i], &digest[i << 2]);
    }
#else
   UNPACK32(ctx->h[0], &digest[ 0]);
   UNPACK32(ctx->h[1], &digest[ 4]);
   UNPACK32(ctx->h[2], &digest[ 8]);
   UNPACK32(ctx->h[3], &digest[12]);
   UNPACK32(ctx->h[4], &digest[16]);
   UNPACK32(ctx->h[5], &digest[20]);
   UNPACK32(ctx->h[6], &digest[24]);
   UNPACK32(ctx->h[7], &digest[28]);
#endif /* !UNROLL_LOOPS */
}

void sha256(const uint8 *message, uint32 len, uint8 *digest)
{
    sha256_ctx ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, message, len);
    sha256_final(&ctx, digest);
}

uint8_t sha204h_mac(struct sha204h_mac_in_out param)
{
	// Local Variables
	uint8_t temporary[SHA204_MSG_SIZE_MAC];
	uint8_t i;
	uint8_t *p_temp;
	
	// Check parameters
	if (	!param.response
			|| ((param.mode & ~MAC_MODE_MASK) != 0)
			|| (((param.mode & MAC_MODE_BLOCK1_TEMPKEY) == 0) && !param.key)
			|| (((param.mode & MAC_MODE_BLOCK2_TEMPKEY) == 0) && !param.challenge)
			|| (((param.mode & MAC_MODE_USE_TEMPKEY_MASK) != 0) && !param.temp_key)
			|| (((param.mode & MAC_MODE_INCLUDE_OTP_64) != 0) && !param.otp)
			|| (((param.mode & MAC_MODE_INCLUDE_OTP_88) != 0) && !param.otp)
			|| (((param.mode & MAC_MODE_INCLUDE_SN) != 0) && !param.sn) )
		return SHA204_BAD_PARAM;
	
	// Check TempKey fields validity if TempKey is used
	if (	((param.mode & MAC_MODE_USE_TEMPKEY_MASK) != 0) &&
			// TempKey.CheckFlag must be 0 and TempKey.Valid must be 1
			(  (param.temp_key->check_flag != 0)
			|| (param.temp_key->valid != 1) 
			// If either mode parameter bit 0 or bit 1 are set, mode parameter bit 2 must match temp_key.source_flag
			// Logical not (!) are used to evaluate the expression to TRUE/FALSE first before comparison (!=)
			|| (!(param.mode & MAC_MODE_SOURCE_FLAG_MATCH) != !(param.temp_key->source_flag)) ))
		return SHA204_CMD_FAIL;
	
	// Start calculation
	p_temp = temporary;
		
	// (1) first 32 bytes
	if (param.mode & MAC_MODE_BLOCK1_TEMPKEY) {
		memcpy(p_temp, param.temp_key->value, 32);    // use TempKey.Value
		p_temp += 32;
	} else {
		memcpy(p_temp, param.key, 32);                // use Key[KeyID]
		p_temp += 32;
	}
	
	// (2) second 32 bytes
	if (param.mode & MAC_MODE_BLOCK2_TEMPKEY) {
		memcpy(p_temp, param.temp_key->value, 32);    // use TempKey.Value
		p_temp += 32;
	} else {
		memcpy(p_temp, param.challenge, 32);          // use challenge
		p_temp += 32;
	}
	
	// (3) 1 byte opcode
	*p_temp++ = SHA204_MAC;
	
	// (4) 1 byte mode parameter
	*p_temp++ = param.mode;
	
	// (5) 2 bytes keyID
	*p_temp++ = param.key_id & 0xFF;
	*p_temp++ = (param.key_id >> 8) & 0xFF;
	
	// (6, 7) 8 bytes OTP[0:7] or 0x00's, 3 bytes OTP[8:10] or 0x00's
	if (param.mode & MAC_MODE_INCLUDE_OTP_88) {
		memcpy(p_temp, param.otp, 11);            // use OTP[0:10], Mode:5 is overridden
		p_temp += 11;
	} else {
		if (param.mode & MAC_MODE_INCLUDE_OTP_64) {
			memcpy(p_temp, param.otp, 8);         // use 8 bytes OTP[0:7] for (6)
			p_temp += 8;
		} else {
			for (i = 0; i < 8; i++) {             // use 8 bytes 0x00's for (6)
				*p_temp++ = 0x00;
			}
		}
		
		for (i = 0; i < 3; i++) {                 // use 3 bytes 0x00's for (7)
			*p_temp++ = 0x00;
		}
	}
	
	// (8) 1 byte SN[8] = 0xEE
	*p_temp++ = SHA204_SN_8;
	
	// (9) 4 bytes SN[4:7] or 0x00's
	if (param.mode & MAC_MODE_INCLUDE_SN) {
		memcpy(p_temp, &param.sn[4], 4);     //use SN[4:7] for (9)
		p_temp += 4;
	} else {
		for (i = 0; i < 4; i++) {            //use 0x00's for (9)
			*p_temp++ = 0x00;
		}
	}
	
	// (10) 2 bytes SN[0:1] = 0x0123
	*p_temp++ = SHA204_SN_0;
	*p_temp++ = SHA204_SN_1;
	
	// (11) 2 bytes SN[2:3] or 0x00's
	if (param.mode & MAC_MODE_INCLUDE_SN) {
		memcpy(p_temp, &param.sn[2], 2);     //use SN[2:3] for (11)
		p_temp += 2;
	} else {
		for (i = 0; i < 2; i++) {            //use 0x00's for (11)
			*p_temp++ = 0x00;
		}       
	}
	
	// This is the resulting MAC digest
	sha256(temporary, SHA204_MSG_SIZE_MAC, param.response);
	
	// Update TempKey fields
	param.temp_key->valid = 0;
	
	return SHA204_SUCCESS;
}

uint8_t sha204p_wakeup(int fd)
{
	unsigned char wakeup = 0;
	int ret = write(fd,&wakeup,1);
	if(ret != 1)
	//	printf(">>>sha204p_wakeup	:	%d\n",ret);	
	usleep(SHA204_WAKEUP_DELAY * 1000);

	return ;
}

uint8_t sha204h_nonce(struct sha204h_nonce_in_out param)
{
	// Local Variables
	uint8_t temporary[SHA204_MSG_SIZE_NONCE];	
	uint8_t *p_temp;
	
	// Check parameters
	if (	!param.temp_key || !param.num_in
			|| (param.mode > NONCE_MODE_PASSTHROUGH)
			|| (param.mode == NONCE_MODE_INVALID)
			|| (param.mode == NONCE_MODE_SEED_UPDATE && !param.rand_out)
			|| (param.mode == NONCE_MODE_NO_SEED_UPDATE && !param.rand_out) )
		return SHA204_BAD_PARAM;

	// Calculate or pass-through the nonce to TempKey.Value
	if ((param.mode == NONCE_MODE_SEED_UPDATE) || (param.mode == NONCE_MODE_NO_SEED_UPDATE)) {
		// Calculate nonce using SHA-256 (refer to datasheet)
		p_temp = temporary;
		
		memcpy(p_temp, param.rand_out, 32);
		p_temp += 32;
		
		memcpy(p_temp, param.num_in, 20);
		p_temp += 20;
		
		*p_temp++ = SHA204_NONCE;
		*p_temp++ = param.mode;
		*p_temp++ = 0x00;
			
		sha256(temporary, SHA204_MSG_SIZE_NONCE, param.temp_key->value);
		
		// Update TempKey.SourceFlag to 0 (random)
		param.temp_key->source_flag = 0;
	} else if (param.mode == NONCE_MODE_PASSTHROUGH) {
		// Pass-through mode
		memcpy(param.temp_key->value, param.num_in, 32);
		
		// Update TempKey.SourceFlag to 1 (not random)
		param.temp_key->source_flag = 1;
	}
	
	// Update TempKey fields
	param.temp_key->key_id = 0;
	param.temp_key->gen_data = 0;
	param.temp_key->check_flag = 0;
	param.temp_key->valid = 1;
	
	return SHA204_SUCCESS;
}
void sha204c_calculate_crc(uint8_t length, uint8_t *data, uint8_t *crc) {
	uint8_t counter;
	uint16_t crc_register = 0;
	uint16_t polynom = 0x8005;
	uint8_t shift_register;
	uint8_t data_bit, crc_bit;

	for (counter = 0; counter < length; counter++) {
	  for (shift_register = 0x01; shift_register > 0x00; shift_register <<= 1) {
		 data_bit = (data[counter] & shift_register) ? 1 : 0;
		 crc_bit = crc_register >> 15;

		 // Shift CRC to the left by 1.
		 crc_register <<= 1;

		 if ((data_bit ^ crc_bit) != 0)
			crc_register ^= polynom;
	  }
	}
	crc[0] = (uint8_t) (crc_register & 0x00FF);
	crc[1] = (uint8_t) (crc_register >> 8);
}

uint8_t sha204c_check_crc(uint8_t *response)
{
	uint8_t crc[SHA204_CRC_SIZE];
	uint8_t count = response[SHA204_BUFFER_POS_COUNT];

	count -= SHA204_CRC_SIZE;
	sha204c_calculate_crc(count, response, crc);

	return (crc[0] == response[count] && crc[1] == response[count + 1])
		? SHA204_SUCCESS : SHA204_BAD_CRC;
}

uint8_t sha204p_send_command(int fd,uint8_t count, uint8_t *command)
{
	return sha204p_send(fd, SHA204_I2C_PACKET_FUNCTION_NORMAL, count, command);
}

uint8_t sha204p_idle(int fd)
{
	return sha204p_send(fd, SHA204_I2C_PACKET_FUNCTION_IDLE, 0, NULL);
}
uint8_t sha204p_sleep(int fd)
{
	return sha204p_send(fd, SHA204_I2C_PACKET_FUNCTION_SLEEP, 0, NULL);
}
uint8_t sha204p_receive_response(int fd, uint8_t size, uint8_t *response)
{
	int ret,i;
	unsigned char count;
	unsigned char *p;

	read(fd,&response[0],1);

	count = response[0];
	printf("\n>>>receive_response	:	%x\n",count);
	if ((count < SHA204_RSP_SIZE_MIN) || (count > SHA204_RSP_SIZE_MAX))
		return SHA204_INVALID_SIZE;

	ret = read(fd,response+1,count-1);
	if (ret != -1)
	{
		printf("   >>>receive_response	:	%x \n",ret);	
		p = response+1;
		for(i=0;i<ret;i++,p++){
			printf("%3x",*p);
			if(i%10 ==9) printf("\n");					
		}
		if(i == ret) printf("\n");
	}

	return (ret>0) ?  SHA204_SUCCESS : ret;
}

uint8_t sha204c_send_and_receive(int fd,struct sha204_send_and_receive_parameters *args)
{
	uint8_t ret_code = SHA204_FUNC_FAIL;

	uint8_t count = args->tx_buffer[SHA204_BUFFER_POS_COUNT];
	uint8_t count_minus_crc = count - SHA204_CRC_SIZE;

	sha204c_calculate_crc(count_minus_crc, args->tx_buffer, args->tx_buffer + count_minus_crc);

	ret_code = sha204p_send_command(fd,count, args->tx_buffer);
	usleep(args->poll_delay * 1000);
	do {
		ret_code = sha204p_receive_response(fd, args->rx_size, args->rx_buffer);
	} while ((ret_code == SHA204_RX_NO_RESPONSE));

	ret_code = sha204c_check_crc(args->rx_buffer);

	return ret_code;
}

uint8_t sha204m_execute(int fd, struct sha204_command_parameters *args)
{
	uint8_t *p_buffer;
	uint8_t len;
	struct sha204_send_and_receive_parameters comm_parameters = {
		.tx_buffer = args->tx_buffer,
		.rx_buffer = args->rx_buffer
	};

	// Supply delays and response size.
	switch (args->op_code) {

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

void random_challenge_response_authentication(int fd) {
	
	static uint8_t status = SHA204_SUCCESS;
	static uint8_t random_number[0x20] = {0};		// Random number returned by Random NONCE command
	static uint8_t computed_response[0x20] = {0};	// Host computed expected response
	static uint8_t atsha204_response[0x20] = {0};	// Actual response received from the ATSHA204 device
	struct sha204h_nonce_in_out nonce_param;		// Parameter for nonce helper function
	struct sha204h_mac_in_out mac_param;			// Parameter for mac helper function
	struct sha204h_temp_key computed_tempkey;		// TempKey parameter for nonce and mac helper function

	//add by jli :That before every executing  cmd sent to ATSHA204 chip  should have waked it up once!
	sha204p_wakeup(fd);
	
	printf("Random Chal_Response r_1\n");
	
	cmd_args.op_code = SHA204_NONCE;
	cmd_args.param_1 = NONCE_MODE_NO_SEED_UPDATE;
	cmd_args.param_2 = NONCE_PARAM2;
	cmd_args.data_len_1 = NONCE_NUMIN_SIZE;
	cmd_args.data_1 = num_in;
	cmd_args.data_len_2 = 0;
	cmd_args.data_2 = NULL;
	cmd_args.data_len_3 = 0;
	cmd_args.data_3 = NULL;
	cmd_args.tx_size = NONCE_COUNT_SHORT;			
	cmd_args.tx_buffer = global_tx_buffer;
	cmd_args.rx_size = NONCE_RSP_SIZE_LONG;			 
	cmd_args.rx_buffer = global_rx_buffer;
	status = sha204m_execute(fd,&cmd_args);
	sha204p_idle(fd);
	if(status != SHA204_SUCCESS) { printf("FAILED! (1)r_2\n"); return; }
	
	// Capture the random number from the NONCE command if it were successful
	status = memcpy(random_number,&global_rx_buffer[1],0x20);
	
	// *** STEP 2:	COMPUTE THE EQUIVALENT NONCE ON THE HOST SIDE
	//
	//				Go the easy way using the host helper functions provided with 
	//				the ATSHA204 library.
	
	nonce_param.mode = NONCE_MODE_NO_SEED_UPDATE;
	nonce_param.num_in = num_in;
	nonce_param.rand_out = random_number;
	nonce_param.temp_key = &computed_tempkey;
	status = sha204h_nonce(nonce_param);
	if(status != SHA204_SUCCESS) { printf("FAILED! (2)r_3\n"); return; }

	
	// *** STEP 3:	ISSUE THE MAC COMMAND
	//
	//				Starting from a randomized internal state of the ATSHA204 device
	//				guarantees that this MAC command call is executing a random
	//				challenge-response authentication. 
	
	// Issue the MAC command
	cmd_args.op_code = SHA204_MAC;
	cmd_args.param_1 = MAC_MODE_BLOCK2_TEMPKEY;
	cmd_args.param_2 = KEY_ID_0;
	cmd_args.data_len_1 = 0; 
	cmd_args.data_1 = NULL;
	cmd_args.data_len_2 = 0;
	cmd_args.data_2 = NULL;
	cmd_args.data_len_3 = 0;
	cmd_args.data_3 = NULL;
	cmd_args.tx_size = MAC_COUNT_SHORT;
	cmd_args.tx_buffer = global_tx_buffer;
	cmd_args.rx_size = MAC_RSP_SIZE;
	cmd_args.rx_buffer = global_rx_buffer;
	status = sha204m_execute(fd,&cmd_args);
	sha204p_sleep(fd);
	if(status != SHA204_SUCCESS) { printf("FAILED! (3)r_4\n"); return; }
	
	// Capture actual response from the ATSHA204 device
	memcpy(atsha204_response,&global_rx_buffer[1],0x20);
	
	
	// *** STEP 4:	DYNAMICALLY VALIDATE THE (MAC) RESPONSE
	//				
	//				Note that this requires knowledge of the actual secret key
	//				value.
	
	mac_param.mode = MAC_MODE_BLOCK2_TEMPKEY;
	mac_param.key_id = KEY_ID_0;
	mac_param.challenge = NULL;
	mac_param.key = secret_key_value;
	mac_param.otp = NULL;
	mac_param.sn = NULL;
	mac_param.response = computed_response;
	mac_param.temp_key = &computed_tempkey;
	status = sha204h_mac(mac_param);
	if(status != SHA204_SUCCESS) { printf("FAILED! (4)r_5\n"); return; }
	
	
	// Moment of truth: Compare the received response with the dynamically computed expected response.
	status = memcmp(computed_response,atsha204_response,0x20);
	if ( !status ) {	
		printf("SUCCESS!^_^\n");
	} else {
		 printf("FAILED! (4)r_6\n"); 
		 return; 
	}
	
	return;
}

int main(int argc,char* argv[])
{
	int fd;
	
	if ((fd = open(I2C_BUS, O_RDWR)) < 0) {
		printf("Unable to open i2c control file");
		exit(1);
	}

	if (ioctl(fd, I2C_SLAVE, ATSHA204_ADDR) < 0) {
		printf("Set chip address failed\n");
	}
	
	//atsha204_DevRev_cmd(fd);

	//atsha204_personalization(fd);

	random_challenge_response_authentication(fd);
	close(fd);
	
	return 0;
}


