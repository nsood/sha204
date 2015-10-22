/*
 * $safeprojectname$.c
 *
 * Created: 7/10/2013 1:56:24 PM
 *  Author: easanghanwa
 */ 

#include "atsha204_ctc_d1_solutions.h"

#define I2C_BUS       "/dev/i2c-0"
#define ATSHA204_ADDR  0x64

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
	cmd_args.op_code = SHA204_READ;
	cmd_args.param_1 = SHA204_ZONE_CONFIG;
	cmd_args.param_2 = SLOT_CONFIG_2_3_ADDRESS;
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
	sha204p_wakeup(fd);
	sha204m_execute(fd,&cmd_args);
	sha204p_sleep(fd);
	
	//atsha204_DevRev_cmd(fd);

	//atsha204_personalization(fd);

	//random_challenge_response_authentication(fd);
	close(fd);
	
	return 0;
}


