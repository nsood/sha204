/*
 * $safeprojectname$.c
 *
 * Created: 7/10/2013 1:56:24 PM
 *  Author: easanghanwa
 */ 

#include "atsha204_ctc_d1_solutions.h"


int main(void)
{
	struct keyboard_event input;
	
	// Initialize the workshop environment
	   atsha204_workshop_env_init();
	
	// Clear the exercise selector pointer
	 p_app_entry = NULL;
	
	//#########################################################################
	/** \brief The ATSHA204 DevRev Command
	 *	
	 *	DevRev command returns a single four-byte word representing the revision 
	 *  number of the device. Software should not depend on this value as it may 
	 *  change from time to time.  It is used this workshop to check proper
	 *  connectivity to kit and device.
	 */
	 // p_app_entry = atsha204_DevRev_cmd;
	
	//#########################################################################
	/** \brief ATSHA204 Personalization
	 *  
	 *  Personalization configures the ATSHA204 device with a custom security
	 *  profile.
	 */
	 //  p_app_entry = atsha204_personalization;
	
	//#########################################################################
	/** \brief ATSHA204 Random Challenge-Response Authentication
	 *  
	 *  Authentication with protection against replay attacks.
	 */
	 // p_app_entry = random_challenge_response_authentication;
	

	//#########################################################################
	//	Execute selected application
	//	****************************
		p_app_entry();
	//#########################################################################
	
	
	while (true) {
		keyboard_get_key_state(&input);
		if (input.type == KEYBOARD_RELEASE) {
			break;
		}
	}
	
	// should never get here
	return 0;
}


void atsha204_workshop_env_init (void) {
	sysclk_init();
	board_init();
	pmic_init();
	gfx_mono_init();
		
	// Initialize interrupt vectors.
	irq_initialize_vectors();

	// Enable interrupts.
	cpu_irq_enable();
	
	// Enable display back light
	gpio_set_pin_high(NHD_C12832A1Z_BACKLIGHT);

	// Enable the I2C interface connecting the ATSHA204 device.
	i2c_enable();
	
	// Splash a welcome message onto the LCD Screen.
	gfx_mono_draw_string("ATSHA204 CTC D1", 0, 0, &sysfont);	
	gfx_mono_draw_string("Welcome!", 0, 20, &sysfont);	

	// Initialize USB CDC class for terminal communications.
	// cdc_start();

	return;	
}

void write_lcd(uint8_t line, const char data[22]){
	// Clear the line then draw new characters
	switch (line)
	{
	case 1 :
		gfx_mono_draw_string("                     ", 0, 0, &sysfont);
		gfx_mono_draw_string(data, 0, 0, &sysfont);
		break;
	case 2 :
		gfx_mono_draw_string("                     ", 0, 20, &sysfont);
		gfx_mono_draw_string(data, 0, 20, &sysfont);
		break;
	}
		
	return;
}

void write_terminal(const char data[81]) {
	int i;
	
	do{
		udi_cdc_putc(data[i]);
		if( i>80) udi_cdc_putc("\r\n");
	}
	while(data[i++] != '\n');
		
	return;
}

