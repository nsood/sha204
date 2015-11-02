/*
 * encrypted_read.c
 *
 * Created: 11/2/2015 
 *  Author: jli@acorn-net.com
 */ 

#include "sha204_lib_return_codes.h"   // declarations of function return codes
#include "sha204_comm_marshaling.h"
#include "sha204_helper.h"
#include "atsha204_ctc_d1_solutions.h"

uint8_t nonce_in[20] = {
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
						0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
						0x10, 0x11, 0x12, 0x13
};
	
uint8_t stored_key_value[0x20] = {0};

void encrypted_read(int fd, uint16_t key_id, uint16_t slot) {
	int i;
	static uint8_t status = SHA204_SUCCESS;
	static uint8_t readdata[0x20] = {0};
	static uint8_t random_number[0x20] = {0};		// Random number returned by Random NONCE command
	static uint8_t computed_response[0x20] = {0};	// Host computed expected response
	static uint8_t atsha204_nonce[0x20] = {0};	
	struct sha204h_nonce_in_out nonce_param;		// Parameter for nonce helper function
	struct sha204h_gen_dig_in_out gendig_param;	// Parameter for mac helper function
	struct sha204h_temp_key computed_tempkey;		// TempKey parameter for nonce and mac helper function

	//add by jli :That before every executing  cmd sent to ATSHA204 chip  should have waked it up once!
	sha204p_wakeup(fd);
	
	printf("ATSHA204A encrypted read  !\n");

	cmd_args.op_code = SHA204_NONCE;
	cmd_args.param_1 = NONCE_MODE_SEED_UPDATE;
	cmd_args.param_2 = NONCE_PARAM2;
	cmd_args.data_len_1 = NONCE_NUMIN_SIZE;
	cmd_args.data_1 = nonce_in;
	cmd_args.data_len_2 = 0;
	cmd_args.data_2 = NULL;
	cmd_args.data_len_3 = 0;
	cmd_args.data_3 = NULL;
	cmd_args.tx_size = NONCE_COUNT_SHORT;			
	cmd_args.tx_buffer = global_tx_buffer;
	cmd_args.rx_size = NONCE_RSP_SIZE_LONG;			 
	cmd_args.rx_buffer = global_rx_buffer;
	status = sha204m_execute(fd,&cmd_args);
	//sha204p_idle(fd);
	if(status != SHA204_SUCCESS) { printf(" Mathine NONCE  FAILED! \n"); return; }
	
	// Capture the random number from the NONCE command if it were successful
	memcpy(random_number,&global_rx_buffer[1],0x20);

	
	nonce_param.mode = NONCE_MODE_SEED_UPDATE;
	nonce_param.num_in = nonce_in;
	nonce_param.rand_out = random_number;
	nonce_param.temp_key = &computed_tempkey;
	status = sha204h_nonce(nonce_param);
	if(status != SHA204_SUCCESS) { printf("HOST   NONCE  FAILED! \n"); return; }
	
	
	cmd_args.op_code = SHA204_GENDIG;
	cmd_args.param_1 = GENDIG_ZONE_DATA;
	cmd_args.param_2 = key_id;
	cmd_args.data_len_1 = 0; 
	cmd_args.data_1 = NULL;
	cmd_args.data_len_2 = 0;
	cmd_args.data_2 = NULL;
	cmd_args.data_len_3 = 0;
	cmd_args.data_3 = NULL;
	cmd_args.tx_size = SHA204_CMD_SIZE_MIN;
	cmd_args.tx_buffer = global_tx_buffer;
	cmd_args.rx_size = GENDIG_RSP_SIZE;
	cmd_args.rx_buffer = global_rx_buffer;
	status = sha204m_execute(fd,&cmd_args);
	//sha204p_sleep(fd);
	if(status != SHA204_SUCCESS) { printf("Mathine  GENGID  FAILED! \n"); return; }
	
	//Host gengid option
	gendig_param.zone = GENDIG_ZONE_DATA;
	gendig_param.key_id = key_id;
	gendig_param.stored_value = stored_key_value;
	gendig_param.temp_key = &computed_tempkey;
	status = sha204h_gen_dig(gendig_param);
	if(status != SHA204_SUCCESS) { printf("HOST   GENDIG  FAILED! \n"); return; }
	memcpy(atsha204_nonce,computed_tempkey.value,0x20);

	//Read option
	cmd_args.op_code = SHA204_READ;
	cmd_args.param_1 = SHA204_ZONE_DATA|SHA204_ZONE_COUNT_FLAG;
	cmd_args.param_2 =  (uint16_t)(slot * 8);
	cmd_args.data_len_1 = 0;
	cmd_args.data_1 = NULL;
	cmd_args.data_len_2 = 0;
	cmd_args.data_2 = NULL;
	cmd_args.data_len_3 = 0;
	cmd_args.data_3 = NULL;
	cmd_args.tx_size = 0x30;
	cmd_args.tx_buffer = global_tx_buffer;
	cmd_args.rx_size = 0x30;
	cmd_args.rx_buffer = global_rx_buffer;
	//sha204p_wakeup(fd);	
	status = sha204m_execute(fd,&cmd_args);
	//sha204p_sleep(fd);
	memcpy(readdata,&global_rx_buffer[1],0x20);
	if(status != SHA204_SUCCESS) { printf("FAILED! a_read_data\n"); return ; }

	printf("XOR operation :\n\t");
	for(i=0;i<32;i++){
		printf("%3x",atsha204_nonce[i]);	
	}
	printf("\n^\t");
	
	for(i=0;i<32;i++){
		printf("%3x",readdata[i]);	
	}
	printf("\n");
	
	for(i=0;i<34;i++){
		printf("---");	
	}
	printf("---\n\t");
	
	//XOR option
	for(i=0;i<32;i++){
		readdata[i] = atsha204_nonce[i] ^ readdata[i];
		printf("%3x",readdata[i]);	
	}
	printf("\n");



}
