/*
 * random_challenge_response_authentication.c
 *
 * Created: 10/9/2013 9:15:46 PM
 *  Author: easanghanwa
 */ 

#include "random_challenge_response_authentication.h"

void random_challenge_response_authentication(int fd) {
	
	static uint8_t status = SHA204_SUCCESS;
	static uint8_t random_number[0x20] = {0};		// Random number returned by Random NONCE command
	static uint8_t computed_response[0x20] = {0};	// Host computed expected response
	static uint8_t atsha204_response[0x20] = {0};	// Actual response received from the ATSHA204 device
	struct sha204h_nonce_in_out nonce_param;		// Parameter for nonce helper function
	struct sha204h_mac_in_out mac_param;			// Parameter for mac helper function
	struct sha204h_temp_key computed_tempkey;		// TempKey parameter for nonce and mac helper function

	
	printf("Random Chal_Response r_1\n");
	
	// Notes: 
	// 1.	Random Challenge-Response involves the use of a random
	//		challenge for EVERY authentication process. A host with a good
	//		source of random number generation can simply ensure the challenge
	//		is random while making a simple MAC command call.  
	//
	// 2.	A host without a good random generator may be tempted to use the
	//		ATSHA204 random command to obtain a random number from the device.
	//		While the random number obtained through this process is of the 
	//		highest quality, the process is susceptible to man-in-the-middle
	//		attack, whereby the attacker simply intercepts the random number
	//		and sent the host a non-random number.
	//
	// 3.	Host systems without good random number generators and wanting to
	//		avoid the susceptibility to man-in-the-middle attack described in
	//		note #2 above can use the authentication process involving the
	//		ATSHA204 NONCE command in Random Mode.  The NONCE command guarantees
	//		an internal random state within the ATSHA204 device that is virtually
	//		impossible to fake.  This is the process exemplified in this exercise.
	
	
	// *** STEP 1:	ISSUE A NONCE WITH NO EEPROM SEED UPDATE ***
	// 
	//				The NONCE command generates an internal random state
	//				in the ATSHA204 device. Note that the actual random NONCE is 
	//				a value computed using an internally generated random number
	//				and other device parameters.  The NONCE command emits this
	//				random value for the host to use for host side computation of
	//				an equivalent NONCE.  Capture this random number and keep for
	//				use with computing the equivalent NONCE on the host side.
	
	// Issue the NONCE command
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
		printf("SUCCESS!_r00\n");
	} else {
		 printf("FAILED! (4)_r6\n"); 
		 return; 
	}
	
	return;
}
