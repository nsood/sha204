/*
 * $safeprojectname$.c
 *
 * Created: 7/10/2013 1:56:24 PM
 *  Author: easanghanwa
  * Modified:jli@acorn-net.com
 */ 

#include "atsha204_ctc_d1_solutions.h"

#define I2C_BUS       "/dev/i2c-0"
#define ATSHA204_ADDR  0x64

int main(int argc,char* argv[])
{
	int fd,i,j;
	static uint8_t status = SHA204_SUCCESS;
	uint8_t serect[32] = {0};	//the key of slot 0
	uint8_t tmp_conf[2];
	uint8_t tmp_key[32];
	uint8_t key_15[32]={	
						0xff,0xff,0x68,0xb7,0xb8 ,0x01,0xbe,0x66,
						0x2C,0xec,0x74,0x68,0x0F,0xe4,0x7D,0xc1,
						0xc6,0x72,0x54,0x3A,0xe5,0xbe,0xda,0x2e,
						0x91,0x9A,0xe5,0x0D,0x32,0xa1,0xff,0xff
	};

	uint8_t key_0[0x20] = {
						0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
						0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
						0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
						0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55
	};

	if ((fd = open(I2C_BUS, O_RDWR)) < 0) {
		printf("Unable to open i2c control file");
		exit(1);
	}

	if (ioctl(fd, I2C_SLAVE, ATSHA204_ADDR) < 0) {
		printf("Set chip address failed\n");
	}
	encrypted_write(fd,  0, serect,4,key_0);
	encrypted_read(fd,  0, serect,4,tmp_key);
	for(i=0;i<32;i++){
		printf("%02x",tmp_key[i]);
		if(31 == i) printf("\n");
	}
	encrypted_write(fd,  0,serect, 4,key_15);	
	encrypted_read(fd,  0,serect, 4,tmp_key);
	for(i=0;i<32;i++){
		printf("%02x",tmp_key[i]);
		if(31 == i) printf("\n");
	}	
	//atsha204_read_data(fd,1,tmp_key);
	//atsha204_write_data(fd,10,key_15);
	//atsha204_read_conf(fd, 15, tmp_conf);
	//atsha204_write_conf(fd,15,0,0);
	//atsha204_lock_conf(fd);
	//atsha204_lock_data(fd);

	//atsha204_DevRev_cmd(fd);

	//atsha204_personalization(fd);

	//random_challenge_response_authentication(fd,15,key_15);
	close(fd);
	
	return 0;
}


