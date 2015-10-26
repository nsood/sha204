#CC = arm-linux-gnueabihf-gcc-4.7.3
INC = $(CFLAGS)

crypto : atsha204_ctc_d1_solutions.o atsha204_DevRev_cmd.o atsha204_i2c.o atsha204_personalization.o random_challenge_response_authentication.o sha204_comm.o sha204_comm_marshaling.o sha204_helper.o sha256.o
	$(CC) -o crypto atsha204_ctc_d1_solutions.o atsha204_DevRev_cmd.o atsha204_i2c.o atsha204_personalization.o random_challenge_response_authentication.o sha204_comm.o sha204_comm_marshaling.o sha204_helper.o sha256.o

atsha204_ctc_d1_solutions.o : atsha204_ctc_d1_solutions.h atsha204_ctc_d1_solutions.c atsha204_DevRev_cmd.h atsha204_personalization.h random_challenge_response_authentication.h
	$(CC) -c $(INC) atsha204_ctc_d1_solutions.c 

atsha204_DevRev_cmd.o : atsha204_DevRev_cmd.h atsha204_DevRev_cmd.c sha204_comm_marshaling.h atsha204_i2c.h
	$(CC) -c $(INC) atsha204_DevRev_cmd.c 

atsha204_personalization.o : atsha204_personalization.h atsha204_personalization.c sha204_comm_marshaling.h atsha204_i2c.h
	$(CC) -c $(INC) atsha204_personalization.c 

random_challenge_response_authentication.o : random_challenge_response_authentication.h random_challenge_response_authentication.c sha204_comm_marshaling.h atsha204_i2c.h sha204_helper.h
	$(CC) -c $(INC) random_challenge_response_authentication.c 

sha204_comm.o : sha204_comm.h sha204_comm.c atsha204_i2c.h
	$(CC) -c $(INC) sha204_comm.c 

sha204_comm_marshaling.o : sha204_comm_marshaling.h sha204_comm_marshaling.c sha204_comm.h
	$(CC) -c  $(INC) sha204_comm_marshaling.c 

sha204_helper.o : sha204_helper.h sha204_helper.c sha256.h
	$(CC) -c $(INC) sha204_helper.c 

sha256.o : sha256.h sha256.c
	$(CC) -c  $(INC) sha256.c

clean : 
	rm  atsha204_ctc_d1_solutions.o atsha204_DevRev_cmd.o atsha204_i2c.o atsha204_personalization.o random_challenge_response_authentication.o sha204_comm.o sha204_comm_marshaling.o sha204_helper.o sha256.o
