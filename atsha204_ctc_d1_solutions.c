/*
 * $safeprojectname$.c
 *
 * Created: 7/10/2013 1:56:24 PM
 *  Author: easanghanwa
 */ 

#include "atsha204_ctc_d1_solutions.h"

#define I2C_BUS       "/dev/i2c-0"
#define ATSHA204_ADDR  0x64

int main(void)
{
	int fd;
	if ((fd = open(I2C_BUS, O_RDWR)) < 0) {
		printf("Unable to open i2c control file");
		exit(1);
	}

	if (ioctl(fd, I2C_SLAVE, ATSHA204_ADDR) < 0) {
		printf("Set chip address failed\n");
	}

	 // atsha204_DevRev_cmd(fd);

	 // atsha204_personalization(fd);

	random_challenge_response_authentication(fd);


	return 0;
}


