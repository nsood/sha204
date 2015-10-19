/*
 * atsha204_i2c.c
 *
 * Created: 10/6/2013 5:28:22 AM
 *  Author: easanghanwa
 */ 

#include "atsha204_i2c.h"

/** \brief I2C Interface Options */
twi_master_options_t atsha204_i2c_opts = {
	.chip	= ATSHA204_I2C_CHIP_7BIT_ADDRESS,	// ATAES132 device I2C address
	.speed	= ATSHA204_I2C_SPEED				// I2C clock speed
};

/** \brief I2C Data and Payload Parameters Structure */
twi_package_t atsha204_packet = {
	.addr			= NULL,	//	Memory access base address.
	.addr_length	= 0,	//	Length in bytes of the address.
	.buffer			= NULL,	//	Container to hold read or write data.
	.chip			= 0,	//	The ATAES132 device bus address.
	.length			= 0,	//	Payload size in bytes.
	.no_wait		= false	//	Wait if bus is busy (true) or not (false).
};

/** \brief This enumeration lists all packet types sent to a SHA204 device.
 *
 * The following byte stream is sent to a SHA204 TWI device:
 *    {I2C start} {I2C address} {word address} [{data}] {I2C stop}.
 * Data are only sent after a word address of value #SHA204_I2C_PACKET_FUNCTION_NORMAL.
 */
enum i2c_word_address {
	SHA204_I2C_PACKET_FUNCTION_RESET,  //!< Reset device.
	SHA204_I2C_PACKET_FUNCTION_SLEEP,  //!< Put device into Sleep mode.
	SHA204_I2C_PACKET_FUNCTION_IDLE,   //!< Put device into Idle mode.
	SHA204_I2C_PACKET_FUNCTION_NORMAL  //!< Write / evaluate data that follow this word address byte.
};


/** \brief This enumeration lists flags for I2C read or write addressing. */
enum i2c_read_write_flag {
	I2C_WRITE = (uint8_t) 0x00,  //!< write command flag
	I2C_READ  = (uint8_t) 0x01   //!< read command flag
};



/** \brief This function initializes and enables the I2C peripheral.
 * */
void i2c_enable (void) {
	twi_master_setup(ATSHA204_I2C_A3BU_HEADER, &atsha204_i2c_opts);
	twi_master_enable(ATSHA204_I2C_A3BU_HEADER);
	return;
}

/** \brief This function disables the I2C peripheral. */
void i2c_disable(void) {
	twi_master_disable(ATSHA204_I2C_A3BU_HEADER);
	return;
}

/** \brief This function sends bytes to an I2C device.
 * \param[in] count number of bytes to send
 * \param[in] data pointer to tx buffer
 * \return status of the operation
 */
uint8_t i2c_send_bytes(uint8_t count, uint8_t *data) {
	
	// Prepare the packet structure
	atsha204_packet.chip		=	(uint8_t) ATSHA204_I2C_CHIP_7BIT_ADDRESS;
	atsha204_packet.buffer		=	(void*) data;
	atsha204_packet.length		=	count;
	
	// Send the packet
	// May consider adding loop escape here depending on the hardware.  
	while (twi_master_write(ATSHA204_I2C_A3BU_HEADER, &atsha204_packet) != TWI_SUCCESS);
	
	return I2C_FUNCTION_RETCODE_SUCCESS;
}

/** \brief This function receives one byte from an I2C device.
 *
 * \param[out] data pointer to received byte
 * \return status of the operation
 */
uint8_t i2c_receive_byte(uint8_t *data) {	
	// Prepare the packet structure
	atsha204_packet.chip		=	(uint8_t) ATSHA204_I2C_CHIP_7BIT_ADDRESS;
	atsha204_packet.buffer		=	(void*) data;
	atsha204_packet.length		=	1;
	
	// Perform a multi-byte read access then check the result.
	// May consider adding loop escape here depending on the hardware.  
	while(twi_master_read(ATSHA204_I2C_A3BU_HEADER, &atsha204_packet) != TWI_SUCCESS);

	return I2C_FUNCTION_RETCODE_SUCCESS;
}


/** \brief This function receives bytes from an I2C device
 *         and sends a Stop.
 *
 * \param[in] count number of bytes to receive
 * \param[out] data pointer to rx buffer
 * \return status of the operation
 */
uint8_t i2c_receive_bytes(uint8_t count, uint8_t *data) {	
	// Prepare the packet structure
	atsha204_packet.chip		=	(uint8_t) ATSHA204_I2C_CHIP_7BIT_ADDRESS;
	atsha204_packet.buffer		=	(void*) data;
	atsha204_packet.length		=	count;
	
	// Perform a multi-byte read access then check the result.
	// May consider adding loop escape here depending on the hardware.  
	while(twi_master_read(ATSHA204_I2C_A3BU_HEADER, &atsha204_packet) != TWI_SUCCESS);

	return I2C_FUNCTION_RETCODE_SUCCESS;
}

/** 
 * \brief This I2C function generates a Wake-up pulse and delays.
 * \return status of the operation
 */
uint8_t sha204p_wakeup(void)
{
	twi_package_t twi_package;
	twi_options_t twi_options = {.speed = 133333};
   
	// Set SDA low for 60 us. Speed is therefore: f = 1 / 0.00006 / 8 = 133,333.
	// Generating the Stop condition adds 20 us for this particular implementation / target,
	// but a longer wake pulse is okay.
	twi_master_disable(ATSHA204_I2C_A3BU_HEADER);
	int twi_master_setup_status = twi_master_setup(ATSHA204_I2C_A3BU_HEADER, &twi_options);
	if (twi_master_setup_status != STATUS_OK)
		return SHA204_COMM_FAIL;

	twi_package.chip = 0;
	twi_package.addr_length = 0;
	twi_package.length = 0;
	twi_package.buffer = NULL;

	// This call will return a nack error.
	(void) twi_master_write(ATSHA204_I2C_A3BU_HEADER, &twi_package);

	//sha204h_delay_ms(SHA204_WAKEUP_DELAY);
	delay_ms(SHA204_WAKEUP_DELAY);
	
	// Set I2C speed back to communication speed.
	twi_master_enable(ATSHA204_I2C_A3BU_HEADER);
	twi_options.speed = ATSHA204_I2C_SPEED;
	return (uint8_t) twi_master_setup(ATSHA204_I2C_A3BU_HEADER, &twi_options);
}

/** 
 * \brief This function sends a I2C packet enclosed by a I2C start and stop to a SHA204 device.
 *
 *         This function combines a I2C packet send sequence that is common to all packet types.
 *         Only if word_address is \ref SHA204_I2C_PACKET_FUNCTION_NORMAL, count and buffer parameters are
 *         expected to be non-zero.
 * \param[in] word_address packet function code listed in #i2c_word_address
 * \param[in] count number of bytes in data buffer
 * \param[in] buffer pointer to data buffer
 * \return status of the operation
 */
static uint8_t sha204p_send(uint8_t word_address, uint8_t count, uint8_t *buffer)
{
	twi_package_t twi_package = {
		.chip = (uint8_t) ATSHA204_I2C_CHIP_7BIT_ADDRESS,
		.addr_length = 1,
		.length = count,
		.buffer = (void *) buffer,
		.addr[0] = word_address
	};
	return (twi_master_write(ATSHA204_I2C_A3BU_HEADER, &twi_package) ? SHA204_COMM_FAIL : SHA204_SUCCESS);
}


/** 
 * \brief This I2C function sends a command to the device.
 * \param[in] count number of bytes to send
 * \param[in] command pointer to command buffer
 * \return status of the operation
 */
uint8_t sha204p_send_command(uint8_t count, uint8_t *command)
{
	return sha204p_send(SHA204_I2C_PACKET_FUNCTION_NORMAL, count, command);
}


/** 
 * \brief This I2C function puts the SHA204 device into idle state.
 * \return status of the operation
 */
uint8_t sha204p_idle(void)
{
	return sha204p_send(SHA204_I2C_PACKET_FUNCTION_IDLE, 0, NULL);
}


/** 
 * \brief This I2C function puts the SHA204 device into low-power state.
 * \return status of the operation
 */
uint8_t sha204p_sleep(void)
{
	return sha204p_send(SHA204_I2C_PACKET_FUNCTION_SLEEP, 0, NULL);
}


/** 
 * \brief This I2C function resets the I/O buffer of the SHA204 device.
 * \return status of the operation
 */
uint8_t sha204p_reset_io(void)
{
	return sha204p_send(SHA204_I2C_PACKET_FUNCTION_RESET, 0, NULL);
}


/** 
 * \brief This I2C function receives a response from the SHA204 device.
 *
 * \param[in] size size of receive buffer
 * \param[out] response pointer to receive buffer
 * \return status of the operation
 */
uint8_t sha204p_receive_response(uint8_t size, uint8_t *response)
{
    // Read count.
	twi_package_t twi_package = {
		.chip = (uint8_t) ATSHA204_I2C_CHIP_7BIT_ADDRESS,
		.addr_length = 0,
		.length = 1,
		.buffer = (void *) response
	};
	status_code_t i2c_status = twi_master_read(ATSHA204_I2C_A3BU_HEADER, &twi_package);
	if (i2c_status != STATUS_OK)
	    return (i2c_status == ERR_TIMEOUT ? SHA204_TIMEOUT : SHA204_RX_NO_RESPONSE);

	uint8_t count = response[SHA204_BUFFER_POS_COUNT];
	if ((count < SHA204_RSP_SIZE_MIN) || (count > SHA204_RSP_SIZE_MAX))
		return SHA204_INVALID_SIZE;
	   
	// Read packet remainder.
    twi_package.length = (count > size) ? size : count;
    twi_package.length--;
    twi_package.buffer = response + 1;
    return (twi_master_read(ATSHA204_I2C_A3BU_HEADER, &twi_package) ? SHA204_COMM_FAIL : SHA204_SUCCESS);
}


/** 
 * \brief This I2C function resynchronizes communication.
 *
 * Parameters are not used for I2C.\n
 * Re-synchronizing communication is done in a maximum of three steps
 * listed below. This function implements the first step. Since
 * steps 2 and 3 (sending a Wake-up token and reading the response)
 * are the same for I2C and SWI, they are
 * implemented in the communication layer (\ref sha204c_resync).
 * See the excerpt from the SHA204 data sheet below.
  <ol>
     <li>
       To ensure an IO channel reset, the system should send
       the standard I2C software reset sequence, as follows:
       <ul>
         <li>a Start condition</li>
         <li>nine cycles of SCL, with SDA held high</li>
         <li>another Start condition</li>
         <li>a Stop condition</li>
       </ul>
       It should then be possible to send a read sequence and
       if synchronization has completed properly the ATSHA204 will
       acknowledge the device address. The chip may return data or
       may leave the bus floating (which the system will interpret
       as a data value of 0xFF) during the data periods.\n
       If the chip does acknowledge the device address, the system
       should reset the internal address counter to force the
       ATSHA204 to ignore any partial input command that may have
       been sent. This can be accomplished by sending a write
       sequence to word address 0x00 (Reset), followed by a
       Stop condition.
     </li>
     <li>
       If the chip does NOT respond to the device address with an ACK,
       then it may be asleep. In this case, the system should send a
       complete Wake token and wait t_whi after the rising edge. The
       system may then send another read sequence and if synchronization
       has completed the chip will acknowledge the device address.
     </li>
     <li>
       If the chip still does not respond to the device address with
       an acknowledge, then it may be busy executing a command. The
       system should wait the longest TEXEC and then send the
       read sequence, which will be acknowledged by the chip.
     </li>
  </ol>
 * \param[in] size size of response buffer
 * \param[out] response pointer to response buffer
 * \return status of the operation
 */
uint8_t sha204p_resync(uint8_t size, uint8_t *response)
{
	// Generate Start, nine clocks, Stop.
	// (Adding a Repeat Start before the Stop would additionally
	// prevent erroneously writing a byte, but a Stop right after a
	// Start is not "legal" for I2C and the SHA204 will not write
	// anything without a successful CRC check.)
	twi_package_t twi_package = {
		.chip = (uint8_t) 0xFF,
		.addr_length = 1,
		.length = 0,
		.buffer = (void *) response,
		.addr[0] = 0
	};
	(void) twi_master_read(ATSHA204_I2C_A3BU_HEADER, &twi_package);

	return sha204p_reset_io();
}


/*
// Dummy Function
uint8_t i2c_send_start(void) {
	return I2C_FUNCTION_RETCODE_SUCCESS;
}

// Dummy Function
uint8_t i2c_send_stop(void) {
	return I2C_FUNCTION_RETCODE_SUCCESS;
}

*/