crypto : atsha204_uboot.c atsha204_uboot.h

	$(CC) -o  crypto atsha204_uboot.c

clean : 
	rm crypto 
