/*
 * atsha204_i2c.c
 *
 * Created: 10/6/2013 5:28:22 AM
 *  Author: easanghanwa
 */ 

#include "atsha204_i2c.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

enum i2c_word_address {
	SHA204_I2C_PACKET_FUNCTION_RESET,  //!< Reset device.
	SHA204_I2C_PACKET_FUNCTION_SLEEP,  //!< Put device into Sleep mode.
	SHA204_I2C_PACKET_FUNCTION_IDLE,   //!< Put device into Idle mode.
	SHA204_I2C_PACKET_FUNCTION_NORMAL  //!< Write / evaluate data that follow this word address byte.
};

uint8_t sha204p_wakeup(int fd)
{
	unsigned char wakeup = 0;
	
	write(fd,&wakeup,1);
	//sha204h_delay_ms(SHA204_WAKEUP_DELAY);
	usleep(SHA204_WAKEUP_DELAY * 1000);

	return ;
}

static uint8_t sha204p_send(int fd, uint8_t word_address, uint8_t count, uint8_t *buffer)
{
	int ret;
	unsigned char *array = malloc((count+1)*sizeof(unsigned char));

	array[0] = word_address;
	memcpy(array+1,buffer,count);

	ret = write(fd,array,count+1);
	free(array);
	return ret;
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



uint8_t sha204p_reset_io(int fd)
{
	return sha204p_send(fd, SHA204_I2C_PACKET_FUNCTION_RESET, 0, NULL);
}


uint8_t sha204p_receive_response(int fd, uint8_t size, uint8_t *response)
{
	int ret,count;
	unsigned char *array;

	read(fd,array,1);
	count = array[0];
	if ((count < SHA204_RSP_SIZE_MIN) || (count > SHA204_RSP_SIZE_MAX))
		return SHA204_INVALID_SIZE;

	array = malloc(count*sizeof(unsigned char));

	ret = read(fd,array+1,count-1);
	if (ret != count-1)
		printf("receive response : count wrong !\n");
	return ret;
}

uint8_t sha204p_resync(int fd, uint8_t size, uint8_t *response)
{
	
}

