/*
 * atsha204_i2c.h
 *
 * Created: 10/6/2013 5:28:46 AM
 *  Author: easanghanwa
 */ 


#ifndef ATSHA204_I2C_H_
#define ATSHA204_I2C_H_

#include "atsha204_ctc_d1_solutions.h"

// error codes for physical hardware dependent module
// Codes in the range 0x00 to 0xF7 are shared between physical interfaces (SWI, TWI, SPI).
// Codes in the range 0xF8 to 0xFF are special for the particular interface.
#define I2C_FUNCTION_RETCODE_SUCCESS     ((uint8_t) 0x00) //!< Communication with device succeeded.
#define I2C_FUNCTION_RETCODE_COMM_FAIL   ((uint8_t) 0xF0) //!< Communication with device failed.
#define I2C_FUNCTION_RETCODE_TIMEOUT     ((uint8_t) 0xF1) //!< Communication timed out.
#define I2C_FUNCTION_RETCODE_NACK        ((uint8_t) 0xF8) //!< TWI nack

// Upper Layer Compliance Definitions
#define I2C_CLOCK				ATSHA204_I2C_SPEED


#endif /* ATSHA204_I2C_H_ */
