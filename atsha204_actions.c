#include "atsha204_ctc_d1_solutions.h"

/**********************************************************************
*Function	:	atsha204_read_conf
*Arguments	:	int fd				---file description
*				int slot, 				---atsha204a  slot
*				uint8_t *read_conf	---read out two args
*description	:	can read the config at any time
**********************************************************************/
uint8_t   atsha204_read_conf(int fd, int slot, uint8_t *read_conf)
{
	uint8_t status = SHA204_SUCCESS;
	uint8_t	flag =0;

	if(slot  < 0  ||slot  > 15) {
		return -1 ;
	}
	flag = slot % 2;
	
	// Write the configuration parameters to the slot
	cmd_args.op_code = SHA204_READ;
	cmd_args.param_1 = SHA204_ZONE_CONFIG;
	cmd_args.param_2 = (uint16_t)(slot /2 +5);
	cmd_args.data_len_1 = 0;
	cmd_args.data_1 = NULL;
	cmd_args.data_len_2 = 0;
	cmd_args.data_2 = NULL;
	cmd_args.data_len_3 = 0;
	cmd_args.data_3 = NULL;
	cmd_args.tx_size = 0x10;
	cmd_args.tx_buffer = global_tx_buffer;
	cmd_args.rx_size = 0x10;
	cmd_args.rx_buffer = global_rx_buffer;
	//sha204p_wakeup(fd);
	status = sha204m_execute(fd,&cmd_args);
	//sha204p_idle(fd);
	if(status != SHA204_SUCCESS) { printf("FAILED! a_read_conf\n"); return -1; }
	if(flag == 0){
		memcpy(read_conf,&global_rx_buffer[1],0x02);
	}else{
		memcpy(read_conf,&global_rx_buffer[3],0x02);
	}

	return  status;
	
}
/**********************************************************************
*Function	:	atsha204_read_data
*Arguments	:	int fd				---file description
*				int slot, 				---atsha204a  slot
*				uint8_t *readdata		---read out 32 bytes key
*description	:	seem to nothing after chip locked
**********************************************************************/
uint8_t atsha204_read_data(int fd, int slot,uint8_t *readdata)
{
	uint8_t status = SHA204_SUCCESS;
	if(slot  < 0  ||slot  > 15){return -1;}
	uint16_t slot_addr = (uint16_t)(slot * 8);
	
	cmd_args.op_code = SHA204_READ;
	cmd_args.param_1 = SHA204_ZONE_DATA|SHA204_ZONE_COUNT_FLAG;
	cmd_args.param_2 = slot_addr;
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
	if(status != SHA204_SUCCESS) { printf("FAILED! a_read_data\n"); return -1; }

	return status;
	
}
/**********************************************************************
*Function	:	atsha204_write_conf
*Arguments	:	int fd				---file description
*				int slot, 				---atsha204a  slot
*				uint8_t 	conf_low_8_bits,	
						conf_high_8_bits
*description	:	can write config before locking the config zone
**********************************************************************/
uint8_t atsha204_write_conf(int fd, int slot, uint8_t conf_low_8_bits, uint8_t conf_high_8_bits)
{
	uint8_t status = SHA204_SUCCESS;
	uint8_t read_conf[2]={0};
	uint8_t flag =0;
	uint8_t config_params[4] = {0};
	
	if(slot  < 0  ||slot  > 15){return  -1;}
	flag = slot % 2;
	if(flag == 0 ){
		atsha204_read_conf(fd, slot+1,read_conf);
		config_params[0] = conf_low_8_bits;
		config_params[1] = conf_high_8_bits;
		config_params[2] = read_conf[0];
		config_params[3] =  read_conf[1];
	}else{
		atsha204_read_conf(fd, slot-1,read_conf);
		config_params[2] = conf_low_8_bits;
		config_params[3] = conf_high_8_bits;
		config_params[0] = read_conf[0];
		config_params[1] =  read_conf[1];
	}

	cmd_args.op_code = SHA204_WRITE;
	cmd_args.param_1 = SHA204_ZONE_CONFIG;
	cmd_args.param_2 = (uint16_t)(slot / 2 +5);
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
	//sha204p_wakeup(fd);
	status = sha204m_execute(fd,&cmd_args);
	//sha204p_idle(fd);
	if(status != SHA204_SUCCESS) { printf("FAILED! CONF ZONE is locked! \n"); return -1; }
	
}

/**********************************************************************
*Function	:	atsha204_lock_conf
*Arguments	:	int fd				---file description
*description	:	lock the config zone ,
				after this action can write data successfully
**********************************************************************/
uint8_t atsha204_lock_conf(int fd)
{
	uint8_t status = SHA204_SUCCESS;
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
	//sha204p_wakeup(fd);	
	status = sha204m_execute(fd,&cmd_args);
	//sha204p_sleep(fd);
	if(status != SHA204_SUCCESS) { printf("FAILED! a_lock_conf\n"); return -1; }
}

/**********************************************************************
*Function	:	atsha204_write_data
*Arguments	:	int fd				---file description
*				int slot, 				---atsha204a  slot
*				uint8_t *write_data	---write in 32 bytes key
*description	:	after lock the config can do this action successfully
				and  can NOT write anymore after LOCK the data zone
**********************************************************************/
uint8_t atsha204_write_data(int fd, int slot,  uint8_t *write_data)
{
	uint8_t status = SHA204_SUCCESS;
	if(slot  < 0  ||slot  > 15){return -1;}
	uint16_t slot_addr = (uint16_t)(slot * 8);
	
	cmd_args.op_code = SHA204_WRITE;
	cmd_args.param_1 = SHA204_ZONE_DATA|SHA204_ZONE_COUNT_FLAG;
	cmd_args.param_2 = slot_addr;
	cmd_args.data_len_1 = SHA204_ZONE_ACCESS_32;
	cmd_args.data_1 = write_data;
	cmd_args.data_len_2 = 0;
	cmd_args.data_2 = NULL;
	cmd_args.data_len_3 = 0;
	cmd_args.data_3 = NULL;
	cmd_args.tx_size = 0x30;
	cmd_args.tx_buffer = global_tx_buffer;
	cmd_args.rx_size = 0x10;
	cmd_args.rx_buffer = global_rx_buffer;
	//sha204p_wakeup(fd);	
	status = sha204m_execute(fd,&cmd_args);
	//sha204p_sleep(fd);
	if(status != SHA204_SUCCESS) { printf("FAILED! a_write_data\n"); return -1; }
}

/**********************************************************************
*Function	:	atsha204_lock_data
*Arguments	:	int fd				---file description
*description	:	be carefully running this action
				because almost action be disable after it done
**********************************************************************/
uint8_t atsha204_lock_data(int fd)
{
	uint8_t status = SHA204_SUCCESS;
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
	sha204p_wakeup(fd);
	status = sha204m_execute(fd,&cmd_args);
	//sha204p_sleep(fd);
	if(status != SHA204_SUCCESS) { printf("FAILED! a_lock_data\n"); return -1; }
}

