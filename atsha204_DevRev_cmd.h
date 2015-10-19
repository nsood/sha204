/*
 * atsha204_DevRev_cmd.h
 *
 * Created: 10/6/2013 6:21:09 AM
 *  Author: easanghanwa
 */ 



#ifndef ATSHA204_DEVREV_CMD_H_
#define ATSHA204_DEVREV_CMD_H_

#include "atsha204_ctc_d1_solutions.h"

// The ATSHA204 device revision
const uint8_t ATSHA204_DEVREV_VALUE[WRITE_BUFFER_SIZE_SHORT] = {0x00, 0x00, 0x00, 0x04};


// Function Prototypes
void atsha204_DevRev_cmd(int fd);

#endif /* ATSHA204_DEVREV_CMD_H_ */
