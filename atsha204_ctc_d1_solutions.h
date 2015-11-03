#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <string.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>

#ifndef ATSHA204_CTC_D1_H_
#define ATSHA204_CTC_D1_H_

// ATSHA204 Specific
#include "sha256.h"
#include "atsha204_i2c.h"
#include "sha204_helper.h"
#include "sha204_physical.h"            
#include "sha204_lib_return_codes.h"      
#include "sha204_comm.h" 
#include "sha204_comm_marshaling.h"
#include "sha204_config.h"

// Global Definitions
static uint8_t global_tx_buffer[SHA204_CMD_SIZE_MAX];	// Global Transmit Buffer
static uint8_t global_rx_buffer[SHA204_RSP_SIZE_MAX];	// Global Receive Buffer
struct sha204_command_parameters cmd_args;				// Global Generalized Command Parameter


//! Topics 
extern void atsha204_DevRev_cmd(int fd);
extern void atsha204_personalization(int fd);
extern void random_challenge_response_authentication(int fd, uint16_t key_id, uint8_t *secret_key_value);
extern uint8_t encrypted_read(int fd, uint16_t key_id, uint8_t *key_value, uint16_t slot, uint8_t *readdata);
extern uint8_t encrypted_write(int fd, uint16_t key_id, uint8_t *key_value, uint16_t slot, uint8_t *writedata) ;

//atsha204_actions
uint8_t atsha204_read_conf(int fd, int slot, uint8_t *read_conf);
uint8_t atsha204_read_data(int fd, int slot, uint8_t *read_data);
uint8_t atsha204_write_conf(int fd, int slot, uint8_t conf_low_8_bits, uint8_t conf_high_8_bits);
uint8_t atsha204_write_data(int fd, int slot,  uint8_t *write_data);
uint8_t atsha204_lock_conf(int fd);
uint8_t atsha204_lock_data(int fd);


#define NONCE_PARAM2					((uint16_t) 0x0000)		//nonce param2. always zero
#define HMAC_MODE_EXCLUDE_OTHER_DATA	((uint8_t) 0x00)		//!< HMAC mode excluded other data
#define HMAC_MODE_INCLUDE_OTP_88		((uint8_t) 0x10)		//!< HMAC mode bit   4: include first 88 OTP bits
#define HMAC_MODE_INCLUDE_OTP_64		((uint8_t) 0x20)		//!< HMAC mode bit   5: include first 64 OTP bits
#define HMAC_MODE_INCLUDE_SN			((uint8_t) 0x40)		//!< HMAC mode bit   6: include serial number
#define DERIVE_KEY_RANDOM_NONCE			((uint8_t) 0x00)		//Derive key mode using random nonce
#define MAC_MODE_NO_TEMPKEY				((uint8_t) 0x00)		//MAC mode using internal key and challenge to get MAC result
#define LOCK_PARAM2_NO_CRC				((uint16_t) 0x0000)		//Lock mode : not using checksum to validate the data written
#define CHECKMAC_PASSWORD_MODE			((uint8_t) 0X01)		//CheckMac mode : password check operation


// DEVICE Modes Address
#define DEVICE_MODES_ADDRESS			((uint16_t) 0x0004)
#define DEVICE_MODES_BYTE_SIZE			(4)			


//Key ID in 16 bit boundaries
#define KEY_ID_0						((uint16_t) 0x0000)
#define KEY_ID_1						((uint16_t) 0x0001)
#define KEY_ID_2						((uint16_t) 0x0002)
#define KEY_ID_3						((uint16_t) 0x0003)
#define KEY_ID_4						((uint16_t) 0x0004)
#define KEY_ID_5						((uint16_t) 0x0005)
#define KEY_ID_6						((uint16_t) 0x0006)
#define KEY_ID_7						((uint16_t) 0x0007)
#define KEY_ID_8						((uint16_t) 0x0008)
#define KEY_ID_9						((uint16_t) 0x0009)
#define KEY_ID_10						((uint16_t) 0x000A)
#define KEY_ID_11						((uint16_t) 0x000B)
#define KEY_ID_12						((uint16_t) 0x000C)
#define KEY_ID_13						((uint16_t) 0x000D)
#define KEY_ID_14						((uint16_t) 0x000E)
#define KEY_ID_15						((uint16_t) 0x000F)

//Slot ID in 16 bit boundaries
#define SLOT_ID_0						((uint16_t) 0x0000)
#define SLOT_ID_1						((uint16_t) 0x0001)
#define SLOT_ID_2						((uint16_t) 0x0002)
#define SLOT_ID_3						((uint16_t) 0x0003)
#define SLOT_ID_4						((uint16_t) 0x0004)
#define SLOT_ID_5						((uint16_t) 0x0005)
#define SLOT_ID_6						((uint16_t) 0x0006)
#define SLOT_ID_7						((uint16_t) 0x0007)
#define SLOT_ID_8						((uint16_t) 0x0008)
#define SLOT_ID_9						((uint16_t) 0x0009)
#define SLOT_ID_10						((uint16_t) 0x000A)
#define SLOT_ID_11						((uint16_t) 0x000B)
#define SLOT_ID_12						((uint16_t) 0x000C)
#define SLOT_ID_13						((uint16_t) 0x000D)
#define SLOT_ID_14						((uint16_t) 0x000E)
#define SLOT_ID_15						((uint16_t) 0x000F)


//Slot configuration address
#define SLOT_CONFIG_0_1_ADDRESS			((uint16_t) 0x0005)
#define SLOT_CONFIG_2_3_ADDRESS			((uint16_t) 0x0006)
#define SLOT_CONFIG_4_5_ADDRESS			((uint16_t) 0x0007)
#define SLOT_CONFIG_6_7_ADDRESS			((uint16_t) 0x0008)
#define SLOT_CONFIG_8_9_ADDRESS			((uint16_t) 0x0009)
#define SLOT_CONFIG_10_11_ADDRESS		((uint16_t) 0x000A)
#define SLOT_CONFIG_12_13_ADDRESS		((uint16_t) 0x000B)
#define SLOT_CONFIG_14_15_ADDRESS		((uint16_t) 0x000C)

//Slot key address
#define SLOT_0_ADDRESS					((uint16_t) 0x0000)
#define SLOT_1_ADDRESS					((uint16_t) 0x0008)
#define SLOT_2_ADDRESS					((uint16_t) 0x0010)
#define SLOT_3_ADDRESS					((uint16_t) 0x0018)
#define SLOT_4_ADDRESS					((uint16_t) 0x0020)
#define SLOT_5_ADDRESS					((uint16_t) 0x0028)
#define SLOT_6_ADDRESS					((uint16_t) 0x0030)
#define SLOT_7_ADDRESS					((uint16_t) 0x0038)
#define SLOT_8_ADDRESS					((uint16_t) 0x0040)
#define SLOT_9_ADDRESS					((uint16_t) 0x0048)
#define SLOT_10_ADDRESS					((uint16_t) 0x0050)
#define SLOT_11_ADDRESS					((uint16_t) 0x0058)
#define SLOT_12_ADDRESS					((uint16_t) 0x0060)
#define SLOT_13_ADDRESS					((uint16_t) 0x0068)
#define SLOT_14_ADDRESS					((uint16_t) 0x0070)
#define SLOT_15_ADDRESS					((uint16_t) 0x0078)


/*!
 * *** Read/Write granularity and address specifiers ***
 */
#define CONFIG_READ_SHORT				((uint8_t)0x00)
#define CONFIG_READ_LONG				((uint8_t)0x80)
#define CONFIG_WRITE_SHORT				((uint8_t)0x00)
#define CONFIG_WRITE_LONG				((uint8_t)0x80)

#define OTP_READ_SHORT					((uint8_t)0x01)
#define OTP_READ_LONG					((uint8_t)0x81)
#define OTP_BLOCK_0_ADDRESS				((uint16_t)0x0000)			//!< Base address of the first 32 bytes of the OTP region
#define OTP_BLOCK_1_ADDRESS				((uint16_t)0x0008)			//!< Base address of the second 32 bytes of the OTP region

#define DATA_READ_SHORT					((uint8_t)0x02)
#define DATA_READ_LONG					((uint8_t)0x82)

#define CONFIG_BLOCK_0_ADDRESS			((uint16_t)0x0000)
#define CONFIG_BLOCK_1_ADDRESS			((uint16_t)0x0008)
#define CONFIG_BLOCK_2_ADDRESS			((uint16_t)0x0010)


/*!
 * Word base addresses for UseFlag and UpdateCount bits 
 *	Even bytes address UseFlag
 *  Odd bytes address UpdateCount
 */
#define SLOT_0_1_USE_UPDATE_ADDRESS		((uint16_t) 0x000D)		// Word 13
#define SLOT_2_3_USE_UPDATE_ADDRESS		((uint16_t) 0x000E)		// Word 14
#define SLOT_4_5_USE_UPDATE_ADDRESS		((uint16_t) 0x000F)		// Word 15
#define SLOT_6_7_USE_UPDATE_ADDRESS		((uint16_t) 0x0010)		// Word 16

/*!
 *	*** LAST KEY USE ADDRESS AND SIZE ***
 */
#define LAST_KEY_USE_ADDRESS			((uint16_t) 0X0011)		// Word 17
#define LAST_KEY_USE_BYTE_SIZE			((uint8_t) 0x10)		// 16 bytes
/*!
 *	*** USER EXTRA, SELECTOR, and LOCK bytes address
 */
#define EXTRA_SELECTOR_LOCK_ADDRESS		((uint16_t) 0x0015)		// Word 21

//write parameter (additional)
#define WRITE_BUFFER_SIZE_SHORT			(4)						//buffer size for 4 bytes write
#define WRITE_BUFFER_SIZE_LONG			(32)					//buffer size for 32 bytes write
#define WRITE_DATA_START_IDX			(5)						//index for the first data in write buffer
#define WRITE_DATA_END_IDX_4_BYTES		(9)						//index for the last data in 4 bytes write buffer
#define WRITE_DATA_END_IDX_32_BYTES		(37)					//index for the last data in 32 bytes write buffer
#define WRITE_ZONE_MODE_32_BYTES        ((uint8_t) 0x80)		//!< write mode: 32 bytes

//read parameter (additional)
#define READ_BUFFER_SIZE_SHORT			(4)						//buffer size for 4 bytes read
#define READ_BUFFER_SIZE_LONG			(32)					//buffer size for 32 bytes write
#define READ_DATA_START_IDX				(1)						//index for the first data in read buffer
#define READ_DATA_END_IDX_4_BYTES		(5)						//index for the last data in 4 bytes read buffer
#define READ_DATA_END_IDX_32_BYTES		(33)					//index for the last data in 32 bytes write buffer

// random command
#define RANDOM_NEW_SEED					(0x00)					// Update EEPROM seed
#define RANDOM_EXISTING_SEED			(0x01)					// Use existing EEPROM seed

// CheckMac Command
#define CHECKMAC_NO_TMPKEY_NO_DATA		(0x00)					// Mode: No Tempkey, No Other Data


#endif /* ATSHA204_CTC_D1_H_  */
