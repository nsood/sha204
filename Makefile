cc=arm-linux-gnueabihf-gcc

crypto : atsha204_ctc_d1_solutions.o atsha204_DevRev_cmd.o atsha204_i2c.o atsha204_personalization.o random_challenge_response_authentication.o sha204_comm.o sha204_comm_marshaling.o sha204_helper.o sha256.o

atsha204_ctc_d1_solutions.o : atsha204_ctc_d1_solutions.h atsha204_ctc_d1_solutions.c atsha204_DevRev_cmd.o atsha204_personalization.o random_challenge_response_authentication.o
	cc -c atsha204_ctc_d1_solutions.c

atsha204_DevRev_cmd.o : atsha204_DevRev_cmd.h atsha204_DevRev_cmd.c sha204_comm_marshaling.o atsha204_i2c.o
	cc -c atsha204_DevRev_cmd.c

atsha204_personalization.o : atsha204_personalization.h atsha204_personalization.c sha204_comm_marshaling.o atsha204_i2c.o
	cc -c atsha204_personalization.c

random_challenge_response_authentication.o : random_challenge_response_authentication.h random_challenge_response_authentication.c sha204_comm_marshaling.o atsha204_i2c.o sha204_helper.o
	cc -c random_challenge_response_authentication.c

sha204_comm.o : sha204_comm.h sha204_comm.c atsha204_i2c.o
	cc -c sha204_comm.c

sha204_comm_marshaling.o : sha204_comm_marshaling.h sha204_comm_marshaling.c sha204_comm.o
	cc -c sha204_comm_marshaling.c

sha204_helper.o : sha204_helper.h sha204_helper.c sha256.o
	cc -c sha204_helper.c

sha256.o : sha256.h sha256.c
	cc -c sha256.c

clean : 
	rm crypto atsha204_ctc_d1_solutions.o atsha204_DevRev_cmd.o atsha204_i2c.o atsha204_personalization.o random_challenge_response_authentication.o sha204_comm.o sha204_comm_marshaling.o sha204_helper.o sha256.o
