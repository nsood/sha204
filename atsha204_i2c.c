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
	int ret = write(fd,&wakeup,1);
	if(ret != 1)
	//	printf(">>>sha204p_wakeup	:	%d\n",ret);	
	usleep(SHA204_WAKEUP_DELAY * 1000);

	return ;
}

static uint8_t sha204p_send(int fd, uint8_t word_address, uint8_t count, uint8_t *buffer)
{
	int ret,i;
	unsigned char *r;
	unsigned char *array = (unsigned char*)malloc((count+1)*sizeof(unsigned char));

	printf("\n>>>sha204p_send		:word_addr :%d count :%d\n",word_address,count);		

	if(i == count && i != 0)
		printf("\n");

	array[0] = word_address;
	memcpy(array+1,buffer,count);

	ret = write(fd,array,count+1);
	printf("   >>>send_write	:count :%d\n",ret);
	
	r = buffer;
	for(i=0;i<count;++i,r++) {
		printf("%3x",*r);
		if(i%10 ==9) printf("\n");					
	}
	
	free(array);
	return (ret == count+1) ?  SHA204_SUCCESS : ret;
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

uint8_t sha204p_resync(int fd, uint8_t size, uint8_t *response)
{
	usleep(100*1000);
	return  SHA204_SUCCESS;
}

