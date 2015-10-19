/*
 * atsha204_DevRev_cmd.c
 *
 * Created: 10/6/2013 6:20:42 AM
 *  Author: easanghanwa
 */ 

#include "atsha204_DevRev_cmd.h"


void atsha204_DevRev_cmd(void){
	
	static uint8_t status = SHA204_SUCCESS;
		
	// Message via LCD
	write_lcd(1,"ATSHA204 DevRev CMD");

	// Wake the ATSHA204 Device
	status = sha204p_wakeup();
	if(status != SHA204_SUCCESS) { write_lcd(2,"Wakeup FAILED!"); return; }
	

	// Use the DevRev command to check communication to chip by validating value received.
	// Note that DevRev value is not constant over future revisions of the chip so failure
	// of this function may not mean bad connection.
	cmd_args.op_code		= SHA204_DEVREV;				// ATSHA204 Command OpCode Parameter
	cmd_args.param_1		= 0x00;							// ATSHA204 Command Param1 Parameter
	cmd_args.param_2		= 0x00;							// ATSHA204 Command Param2 Parameter
	cmd_args.data_len_1		= 0x00;							// Length in bytes of first data content
	cmd_args.data_1			= NULL;							// Pointer to buffer containing first data set
	cmd_args.data_len_2		= 0x00;							// Length in bytes of second data content
	cmd_args.data_2			= NULL;							// Pointer to buffer containing second data set
	cmd_args.data_len_3		= 0x00;							// Length in bytes of third data content
	cmd_args.data_3			= NULL;							// Pointer to buffer containing third data set
	cmd_args.tx_size		= DEVREV_COUNT;					// Size of the transmit buffer
	cmd_args.tx_buffer		= global_tx_buffer;				// Pointer to the transmit buffer
	cmd_args.rx_size		= sizeof(global_rx_buffer);		// Size of the receive buffer
	cmd_args.rx_buffer		= global_rx_buffer;				// Pointer to the receive buffer
	status = sha204m_execute(&cmd_args);						// Marshals the parameters and executes the command

	sha204p_sleep();  // Put the chip to sleep in case you stop to examine buffer contents 
	

	// validate the received value for DevRev
	if( status == SHA204_SUCCESS ) {
		if( memcmp(&global_rx_buffer[1],ATSHA204_DEVREV_VALUE,0x04)) { write_lcd(2,"FAILED!"); return; }
	}	
	else { write_lcd(2,"FAILED!"); return; }
		
	write_lcd(2,"SUCCESS!");
		
	return;
}

