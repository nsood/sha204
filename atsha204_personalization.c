/*
 * atsha204_personalization.c
 *
 * Created: 10/9/2013 5:31:18 AM
 *  Author: easanghanwa
 */ 

#include "atsha204_personalization.h"

void atsha204_personalization(int fd) {
	static uint8_t status = SHA204_SUCCESS;
	static uint8_t config_params[0x04] = {0};
	static uint8_t slot_content [0x20] = {0};
	uint8_t i = 0;

	
	printf("PERSONALIZATION!_!\n");


	// **** EXERCISE: SLOTS 0 & 1 CONFIGURATION
	// Configure slots 0 and 1 as follows:
	//		- Slot 0 for storage of a non-readable and non-modifiable key.
	//		- Program slot 0 key to hex: 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55
	//		- Slot 1 for storage of a modifiable and encrypted-readable key.
	//		- Program slot 1 key to hex: 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11
	
	// Decide the slot configuration parameters
	config_params[0] = 0x80;	// Slot 0 : IsSecret, Read Key = 0x00
	config_params[1] = 0x80;	// Slot 0 : Write Never, Write Key = 0x00;
	config_params[2] = 0xC0;	// Slot 1 : Is Secret, Encrypted Readable, Read Key = 0x00
	config_params[3] = 0xF0;	// Slot 1 : Encrypted writes, Write Key = 0x00
	
	// Write the configuration parameters to the slot
	cmd_args.op_code = SHA204_WRITE;
	cmd_args.param_1 = SHA204_ZONE_CONFIG;
	cmd_args.param_2 = SLOT_CONFIG_0_1_ADDRESS;
	cmd_args.data_len_1 = SHA204_ZONE_ACCESS_4;
	cmd_args.data_1 = config_params;
	cmd_args.data_len_2 = 0;
	cmd_args.data_2 = NULL;
	cmd_args.data_len_3 = 0;
	cmd_args.data_3 = NULL;
	cmd_args.tx_size = 0x10;
	cmd_args.tx_buffer = global_tx_buffer;
	cmd_args.rx_size = 0x10;
	cmd_args.rx_buffer = global_rx_buffer;
	sha204m_execute(fd,&cmd_args);
	sha204p_sleep(fd); 
	if(status != SHA204_SUCCESS) {printf("FAILED! p_1\n"); return; }
	
	

	// **** EXERCISE: SLOTS 2 & 3 CONFIGURATION	
	// Configure slots 2 and 3 as follows:
	//		- Slot 2 for encrypted reads and encrypted writes. Use key 1 for reads, key 0 for writes.
	//		- Leave factory default content as initial value in slot 2.
	//		- Slot 3 for encrypted reads and clear writes. Use key 1 for reads.
	//		- Leave factory default content as initial value in slot 3
	
	// Decide the slot configuration parameters
	config_params[0] = 0x41;	// Slot 2 : Encrypted Reads, Read Key = 0x01
	config_params[1] = 0x40;	// Slot 2 : Encrypted Writes, Write Key = 0x00;
	config_params[2] = 0x41;	// Slot 3 : Encrypted Reads, Read Key = 0x01
	config_params[3] = 0x00;	// Slot 3 : Clear writes, Write Key = 0x00
	
	// Write the configuration parameters to the slot
	cmd_args.op_code = SHA204_WRITE;
	cmd_args.param_1 = SHA204_ZONE_CONFIG;
	cmd_args.param_2 = SLOT_CONFIG_2_3_ADDRESS;
	cmd_args.data_len_1 = SHA204_ZONE_ACCESS_4;
	cmd_args.data_1 = config_params;
	cmd_args.data_len_2 = 0;
	cmd_args.data_2 = NULL;
	cmd_args.data_len_3 = 0;
	cmd_args.data_3 = NULL;
	cmd_args.tx_size = 0x10;
	cmd_args.tx_buffer = global_tx_buffer;
	cmd_args.rx_size = 0x10;
	cmd_args.rx_buffer = global_rx_buffer;
	sha204m_execute(fd,&cmd_args);
	sha204p_sleep(fd); 
	if(status != SHA204_SUCCESS) { printf("FAILED! p_2\n"); return; }
	
	
	// **** LOCK THE CONFIGURATION ZONE.  
	
	// Perform the configuration lock:
	cmd_args.op_code = SHA204_LOCK;
	cmd_args.param_1 = LOCK_ZONE_NO_CRC;
	cmd_args.param_2 = LOCK_PARAM2_NO_CRC;
	cmd_args.data_len_1 = 0X00;
	cmd_args.data_1 = NULL;
	cmd_args.data_len_2 = 0;
	cmd_args.data_2 = NULL;
	cmd_args.data_len_3 = 0;
	cmd_args.data_3 = NULL;
	cmd_args.tx_size = 0x10;
	cmd_args.tx_buffer = global_tx_buffer;
	cmd_args.rx_size = 0x10;
	cmd_args.rx_buffer = global_rx_buffer;
	sha204m_execute(fd,&cmd_args);
	sha204p_sleep(fd); 	
	if(status != SHA204_SUCCESS) {printf("FAILED p_3!\n"); return; }
	
	
	
	// **** INITIALIZE SLOT CONTENT
	
	// Slot 0: Program Initial Content
	for(i=0x00; i<0x20; i++) {
		slot_content[i] = 0x55;
	}
	cmd_args.op_code = SHA204_WRITE;
	cmd_args.param_1 = SHA204_ZONE_DATA|SHA204_ZONE_COUNT_FLAG;
	cmd_args.param_2 = SLOT_0_ADDRESS;
	cmd_args.data_len_1 = SHA204_ZONE_ACCESS_32;
	cmd_args.data_1 = slot_content;
	cmd_args.data_len_2 = 0;
	cmd_args.data_2 = NULL;
	cmd_args.data_len_3 = 0;
	cmd_args.data_3 = NULL;
	cmd_args.tx_size = 0x30;
	cmd_args.tx_buffer = global_tx_buffer;
	cmd_args.rx_size = 0x10;
	cmd_args.rx_buffer = global_rx_buffer;
	sha204m_execute(fd,&cmd_args);
	sha204p_sleep(fd);
	if(status != SHA204_SUCCESS) { printf("FAILED! p_4\n"); return; }
	


	// Slot 1: Program Initial Content
	for(i=0x00; i<0x20; i++) {
		slot_content[i] = 0x11;
	}
	cmd_args.op_code = SHA204_WRITE;
	cmd_args.param_1 = SHA204_ZONE_DATA|SHA204_ZONE_COUNT_FLAG;
	cmd_args.param_2 = SLOT_1_ADDRESS;
	cmd_args.data_len_1 = SHA204_ZONE_ACCESS_32;
	cmd_args.data_1 = slot_content;
	cmd_args.data_len_2 = 0;
	cmd_args.data_2 = NULL;
	cmd_args.data_len_3 = 0;
	cmd_args.data_3 = NULL;
	cmd_args.tx_size = 0x30;
	cmd_args.tx_buffer = global_tx_buffer;
	cmd_args.rx_size = 0x10;
	cmd_args.rx_buffer = global_rx_buffer;
	sha204m_execute(fd,&cmd_args);
	sha204p_sleep(fd);
	if(status != SHA204_SUCCESS) { printf("FAILED! p_5\n"); return; }
	


	// **** LOCK THE DATA REGION.
	
	// Perform the configuration lock:
	cmd_args.op_code = SHA204_LOCK;
	cmd_args.param_1 = LOCK_ZONE_NO_CONFIG|LOCK_ZONE_NO_CRC;
	cmd_args.param_2 = LOCK_PARAM2_NO_CRC;
	cmd_args.data_len_1 = 0X00;
	cmd_args.data_1 = NULL;
	cmd_args.data_len_2 = 0;
	cmd_args.data_2 = NULL;
	cmd_args.data_len_3 = 0;
	cmd_args.data_3 = NULL;
	cmd_args.tx_size = 0x10;
	cmd_args.tx_buffer = global_tx_buffer;
	cmd_args.rx_size = 0x10;
	cmd_args.rx_buffer = global_rx_buffer;
	status = sha204m_execute(fd,&cmd_args);
	sha204p_sleep(fd);
	if(status != SHA204_SUCCESS) { printf("FAILED! p_6\n"); return; }
	
 	// Verify Complete Lock By Inspecting the LOCK CONFIG and LOCK VALUE registers 
	// Perform the configuration lock:
	cmd_args.op_code = SHA204_READ;
	cmd_args.param_1 = SHA204_ZONE_CONFIG;
	cmd_args.param_2 = EXTRA_SELECTOR_LOCK_ADDRESS;
	cmd_args.data_len_1 = 0X00;
	cmd_args.data_1 = NULL;
	cmd_args.data_len_2 = 0x00;
	cmd_args.data_2 = NULL;
	cmd_args.data_len_3 = 0x00;
	cmd_args.data_3 = NULL;
	cmd_args.tx_size = 0x10;
	cmd_args.tx_buffer = global_tx_buffer;
	cmd_args.rx_size = 0x10;
	cmd_args.rx_buffer = global_rx_buffer;
	status = sha204m_execute(fd,&cmd_args);
	sha204p_sleep(fd);
	if(status != SHA204_SUCCESS) { printf("FAILED! p_7\n"); return; }
		
		


		
	if((global_rx_buffer[0x03] != 0x00) || (global_rx_buffer[0x04] != 00)) { printf("FAILED! p_8\n"); return; }
	
	printf("SUCCESSFUL! p_00\n");
	 
	 
	return;
}
