/*
 * $safeprojectname$.c
 *
 * Created: 7/10/2013 1:56:24 PM
 *  Author: easanghanwa
 */ 
#include <common.h>
#include <command.h>

#include <i2c.h>
#include <malloc.h>

#include "sha204.h"

#define ATSHA204_ADDR  0x64

enum i2c_word_address {
	SHA204_I2C_PACKET_FUNCTION_RESET,  //!< Reset device.
	SHA204_I2C_PACKET_FUNCTION_SLEEP,  //!< Put device into Sleep mode.
	SHA204_I2C_PACKET_FUNCTION_IDLE,   //!< Put device into Idle mode.
	SHA204_I2C_PACKET_FUNCTION_NORMAL  //!< Write / evaluate data that follow this word address byte.
};

uint8_t num_in[20] = {
						0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
						0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
						0x10, 0x11, 0x12, 0x13
};
	
uint8_t secret_key_value[0x20] = {
						0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
						0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
						0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
						0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55
};

#define SHFR(x, n)    (x >> n)
#define ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define CH(x, y, z)  ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define SHA256_F1(x) (ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SHA256_F2(x) (ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SHA256_F3(x) (ROTR(x,  7) ^ ROTR(x, 18) ^ SHFR(x,  3))
#define SHA256_F4(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHFR(x, 10))

#define UNPACK32(x, str)                      \
{                                             \
    *((str) + 3) = (uint8) ((x)      );       \
    *((str) + 2) = (uint8) ((x) >>  8);       \
    *((str) + 1) = (uint8) ((x) >> 16);       \
    *((str) + 0) = (uint8) ((x) >> 24);       \
}

#define PACK32(str, x)                        \
{                                             \
    *(x) =   ((uint32) *((str) + 3)      )    \
           | ((uint32) *((str) + 2) <<  8)    \
           | ((uint32) *((str) + 1) << 16)    \
           | ((uint32) *((str) + 0) << 24);   \
}


/* Macros used for loops unrolling */

#define SHA256_SCR(i)                         \
{                                             \
    w[i] =  SHA256_F4(w[i -  2]) + w[i -  7]  \
          + SHA256_F3(w[i - 15]) + w[i - 16]; \
}

#define SHA256_EXP(a, b, c, d, e, f, g, h, j)               \
{                                                           \
    t1 = wv[h] + SHA256_F2(wv[e]) + CH(wv[e], wv[f], wv[g]) \
         + sha256_k[j] + w[j];                              \
    t2 = SHA256_F1(wv[a]) + MAJ(wv[a], wv[b], wv[c]);       \
    wv[d] += t1;                                            \
    wv[h] = t1 + t2;                                        \
}

//flash uint32 sha256_h0[8] =
uint32 sha256_h0[8] =
            {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

//flash uint32 sha256_k[64] =
uint32 sha256_k[64] =
            {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
             0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
             0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
             0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
             0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
             0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
             0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
             0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
             0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void sha256_transf(sha256_ctx *ctx, const uint8 *message,
                   uint32 block_nb)
{
    uint32 w[64];
    uint32 wv[8];
//	uint32 *wv = &zram32[eob32(zram)-8];
//	uint32 *w = &zram32[eob32(zram)-(8+64)];

    uint32 t1, t2;
    const uint8 *sub_block;
    int i;

#ifndef UNROLL_LOOPS
    int j;
#endif

    for (i = 0; i < (int) block_nb; i++) {
        sub_block = message + (i << 6);

#ifndef UNROLL_LOOPS
        for (j = 0; j < 16; j++) {
            PACK32(&sub_block[j << 2], &w[j]);
        }

        for (j = 16; j < 64; j++) {
            SHA256_SCR(j);
        }

        for (j = 0; j < 8; j++) {
            wv[j] = ctx->h[j];
        }

        for (j = 0; j < 64; j++) {
            t1 = wv[7] + SHA256_F2(wv[4]) + CH(wv[4], wv[5], wv[6])
                + sha256_k[j] + w[j];
            t2 = SHA256_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }

        for (j = 0; j < 8; j++) {
            ctx->h[j] += wv[j];
        }
#else
        PACK32(&sub_block[ 0], &w[ 0]); PACK32(&sub_block[ 4], &w[ 1]);
        PACK32(&sub_block[ 8], &w[ 2]); PACK32(&sub_block[12], &w[ 3]);
        PACK32(&sub_block[16], &w[ 4]); PACK32(&sub_block[20], &w[ 5]);
        PACK32(&sub_block[24], &w[ 6]); PACK32(&sub_block[28], &w[ 7]);
        PACK32(&sub_block[32], &w[ 8]); PACK32(&sub_block[36], &w[ 9]);
        PACK32(&sub_block[40], &w[10]); PACK32(&sub_block[44], &w[11]);
        PACK32(&sub_block[48], &w[12]); PACK32(&sub_block[52], &w[13]);
        PACK32(&sub_block[56], &w[14]); PACK32(&sub_block[60], &w[15]);

        SHA256_SCR(16); SHA256_SCR(17); SHA256_SCR(18); SHA256_SCR(19);
        SHA256_SCR(20); SHA256_SCR(21); SHA256_SCR(22); SHA256_SCR(23);
        SHA256_SCR(24); SHA256_SCR(25); SHA256_SCR(26); SHA256_SCR(27);
        SHA256_SCR(28); SHA256_SCR(29); SHA256_SCR(30); SHA256_SCR(31);
        SHA256_SCR(32); SHA256_SCR(33); SHA256_SCR(34); SHA256_SCR(35);
        SHA256_SCR(36); SHA256_SCR(37); SHA256_SCR(38); SHA256_SCR(39);
        SHA256_SCR(40); SHA256_SCR(41); SHA256_SCR(42); SHA256_SCR(43);
        SHA256_SCR(44); SHA256_SCR(45); SHA256_SCR(46); SHA256_SCR(47);
        SHA256_SCR(48); SHA256_SCR(49); SHA256_SCR(50); SHA256_SCR(51);
        SHA256_SCR(52); SHA256_SCR(53); SHA256_SCR(54); SHA256_SCR(55);
        SHA256_SCR(56); SHA256_SCR(57); SHA256_SCR(58); SHA256_SCR(59);
        SHA256_SCR(60); SHA256_SCR(61); SHA256_SCR(62); SHA256_SCR(63);

        wv[0] = ctx->h[0]; wv[1] = ctx->h[1];
        wv[2] = ctx->h[2]; wv[3] = ctx->h[3];
        wv[4] = ctx->h[4]; wv[5] = ctx->h[5];
        wv[6] = ctx->h[6]; wv[7] = ctx->h[7];

        SHA256_EXP(0,1,2,3,4,5,6,7, 0); SHA256_EXP(7,0,1,2,3,4,5,6, 1);
        SHA256_EXP(6,7,0,1,2,3,4,5, 2); SHA256_EXP(5,6,7,0,1,2,3,4, 3);
        SHA256_EXP(4,5,6,7,0,1,2,3, 4); SHA256_EXP(3,4,5,6,7,0,1,2, 5);
        SHA256_EXP(2,3,4,5,6,7,0,1, 6); SHA256_EXP(1,2,3,4,5,6,7,0, 7);
        SHA256_EXP(0,1,2,3,4,5,6,7, 8); SHA256_EXP(7,0,1,2,3,4,5,6, 9);
        SHA256_EXP(6,7,0,1,2,3,4,5,10); SHA256_EXP(5,6,7,0,1,2,3,4,11);
        SHA256_EXP(4,5,6,7,0,1,2,3,12); SHA256_EXP(3,4,5,6,7,0,1,2,13);
        SHA256_EXP(2,3,4,5,6,7,0,1,14); SHA256_EXP(1,2,3,4,5,6,7,0,15);
        SHA256_EXP(0,1,2,3,4,5,6,7,16); SHA256_EXP(7,0,1,2,3,4,5,6,17);
        SHA256_EXP(6,7,0,1,2,3,4,5,18); SHA256_EXP(5,6,7,0,1,2,3,4,19);
        SHA256_EXP(4,5,6,7,0,1,2,3,20); SHA256_EXP(3,4,5,6,7,0,1,2,21);
        SHA256_EXP(2,3,4,5,6,7,0,1,22); SHA256_EXP(1,2,3,4,5,6,7,0,23);
        SHA256_EXP(0,1,2,3,4,5,6,7,24); SHA256_EXP(7,0,1,2,3,4,5,6,25);
        SHA256_EXP(6,7,0,1,2,3,4,5,26); SHA256_EXP(5,6,7,0,1,2,3,4,27);
        SHA256_EXP(4,5,6,7,0,1,2,3,28); SHA256_EXP(3,4,5,6,7,0,1,2,29);
        SHA256_EXP(2,3,4,5,6,7,0,1,30); SHA256_EXP(1,2,3,4,5,6,7,0,31);
        SHA256_EXP(0,1,2,3,4,5,6,7,32); SHA256_EXP(7,0,1,2,3,4,5,6,33);
        SHA256_EXP(6,7,0,1,2,3,4,5,34); SHA256_EXP(5,6,7,0,1,2,3,4,35);
        SHA256_EXP(4,5,6,7,0,1,2,3,36); SHA256_EXP(3,4,5,6,7,0,1,2,37);
        SHA256_EXP(2,3,4,5,6,7,0,1,38); SHA256_EXP(1,2,3,4,5,6,7,0,39);
        SHA256_EXP(0,1,2,3,4,5,6,7,40); SHA256_EXP(7,0,1,2,3,4,5,6,41);
        SHA256_EXP(6,7,0,1,2,3,4,5,42); SHA256_EXP(5,6,7,0,1,2,3,4,43);
        SHA256_EXP(4,5,6,7,0,1,2,3,44); SHA256_EXP(3,4,5,6,7,0,1,2,45);
        SHA256_EXP(2,3,4,5,6,7,0,1,46); SHA256_EXP(1,2,3,4,5,6,7,0,47);
        SHA256_EXP(0,1,2,3,4,5,6,7,48); SHA256_EXP(7,0,1,2,3,4,5,6,49);
        SHA256_EXP(6,7,0,1,2,3,4,5,50); SHA256_EXP(5,6,7,0,1,2,3,4,51);
        SHA256_EXP(4,5,6,7,0,1,2,3,52); SHA256_EXP(3,4,5,6,7,0,1,2,53);
        SHA256_EXP(2,3,4,5,6,7,0,1,54); SHA256_EXP(1,2,3,4,5,6,7,0,55);
        SHA256_EXP(0,1,2,3,4,5,6,7,56); SHA256_EXP(7,0,1,2,3,4,5,6,57);
        SHA256_EXP(6,7,0,1,2,3,4,5,58); SHA256_EXP(5,6,7,0,1,2,3,4,59);
        SHA256_EXP(4,5,6,7,0,1,2,3,60); SHA256_EXP(3,4,5,6,7,0,1,2,61);
        SHA256_EXP(2,3,4,5,6,7,0,1,62); SHA256_EXP(1,2,3,4,5,6,7,0,63);

        ctx->h[0] += wv[0]; ctx->h[1] += wv[1];
        ctx->h[2] += wv[2]; ctx->h[3] += wv[3];
        ctx->h[4] += wv[4]; ctx->h[5] += wv[5];
        ctx->h[6] += wv[6]; ctx->h[7] += wv[7];
#endif /* !UNROLL_LOOPS */
    }
}

void sha256_init(sha256_ctx *ctx)
{
#ifndef UNROLL_LOOPS
    int i;
    for (i = 0; i < 8; i++) {
        ctx->h[i] = sha256_h0[i];
    }
#else
    ctx->h[0] = sha256_h0[0]; ctx->h[1] = sha256_h0[1];
    ctx->h[2] = sha256_h0[2]; ctx->h[3] = sha256_h0[3];
    ctx->h[4] = sha256_h0[4]; ctx->h[5] = sha256_h0[5];
    ctx->h[6] = sha256_h0[6]; ctx->h[7] = sha256_h0[7];
#endif /* !UNROLL_LOOPS */

    ctx->len = 0;
    ctx->tot_len = 0;
}

void sha256_Update(sha256_ctx *ctx, const uint8 *message,
                   uint32 len)
{
    uint32 block_nb;
    uint32 new_len, rem_len, tmp_len;
    const uint8 *shifted_message;

    tmp_len = SHA256_BLOCK_SIZE - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(&ctx->block[ctx->len], message, rem_len);

    if (ctx->len + len < SHA256_BLOCK_SIZE) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / SHA256_BLOCK_SIZE;

    shifted_message = message + rem_len;

    sha256_transf(ctx, ctx->block, 1);
    sha256_transf(ctx, shifted_message, block_nb);

    rem_len = new_len % SHA256_BLOCK_SIZE;

    memcpy(ctx->block, &shifted_message[block_nb << 6],
           rem_len);

    ctx->len = rem_len;
    ctx->tot_len += (block_nb + 1) << 6;
}

void sha256_final(sha256_ctx *ctx, uint8 *digest)
{
    uint32 block_nb;
    uint32 pm_len;
    uint32 len_b;

#ifndef UNROLL_LOOPS
    int i;
#endif

    block_nb = (1 + ((SHA256_BLOCK_SIZE - 9)
                     < (ctx->len % SHA256_BLOCK_SIZE)));

    len_b = (ctx->tot_len + ctx->len) << 3;
    pm_len = block_nb << 6;

    memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
    ctx->block[ctx->len] = 0x80;
    UNPACK32(len_b, ctx->block + pm_len - 4);

    sha256_transf(ctx, ctx->block, block_nb);

#ifndef UNROLL_LOOPS
    for (i = 0 ; i < 8; i++) {
        UNPACK32(ctx->h[i], &digest[i << 2]);
    }
#else
   UNPACK32(ctx->h[0], &digest[ 0]);
   UNPACK32(ctx->h[1], &digest[ 4]);
   UNPACK32(ctx->h[2], &digest[ 8]);
   UNPACK32(ctx->h[3], &digest[12]);
   UNPACK32(ctx->h[4], &digest[16]);
   UNPACK32(ctx->h[5], &digest[20]);
   UNPACK32(ctx->h[6], &digest[24]);
   UNPACK32(ctx->h[7], &digest[28]);
#endif /* !UNROLL_LOOPS */
}

void sha256(const uint8 *message, uint32 len, uint8 *digest)
{
    sha256_ctx ctx;

    sha256_init(&ctx);
    sha256_Update(&ctx, message, len);
    sha256_final(&ctx, digest);
}

uint8_t sha204h_mac(struct sha204h_mac_in_out param)
{
	// Local Variables
	uint8_t temporary[SHA204_MSG_SIZE_MAC];
	uint8_t i;
	uint8_t *p_temp;
	
	// Check parameters
	if (	!param.response
			|| ((param.mode & ~MAC_MODE_MASK) != 0)
			|| (((param.mode & MAC_MODE_BLOCK1_TEMPKEY) == 0) && !param.key)
			|| (((param.mode & MAC_MODE_BLOCK2_TEMPKEY) == 0) && !param.challenge)
			|| (((param.mode & MAC_MODE_USE_TEMPKEY_MASK) != 0) && !param.temp_key)
			|| (((param.mode & MAC_MODE_INCLUDE_OTP_64) != 0) && !param.otp)
			|| (((param.mode & MAC_MODE_INCLUDE_OTP_88) != 0) && !param.otp)
			|| (((param.mode & MAC_MODE_INCLUDE_SN) != 0) && !param.sn) )
		return SHA204_BAD_PARAM;
	
	// Check TempKey fields validity if TempKey is used
	if (	((param.mode & MAC_MODE_USE_TEMPKEY_MASK) != 0) &&
			// TempKey.CheckFlag must be 0 and TempKey.Valid must be 1
			(  (param.temp_key->check_flag != 0)
			|| (param.temp_key->valid != 1) 
			// If either mode parameter bit 0 or bit 1 are set, mode parameter bit 2 must match temp_key.source_flag
			// Logical not (!) are used to evaluate the expression to TRUE/FALSE first before comparison (!=)
			|| (!(param.mode & MAC_MODE_SOURCE_FLAG_MATCH) != !(param.temp_key->source_flag)) ))
		return SHA204_CMD_FAIL;
	
	// Start calculation
	p_temp = temporary;
		
	// (1) first 32 bytes
	if (param.mode & MAC_MODE_BLOCK1_TEMPKEY) {
		memcpy(p_temp, param.temp_key->value, 32);    // use TempKey.Value
		p_temp += 32;
	} else {
		memcpy(p_temp, param.key, 32);                // use Key[KeyID]
		p_temp += 32;
	}
	
	// (2) second 32 bytes
	if (param.mode & MAC_MODE_BLOCK2_TEMPKEY) {
		memcpy(p_temp, param.temp_key->value, 32);    // use TempKey.Value
		p_temp += 32;
	} else {
		memcpy(p_temp, param.challenge, 32);          // use challenge
		p_temp += 32;
	}
	
	// (3) 1 byte opcode
	*p_temp++ = SHA204_MAC;
	
	// (4) 1 byte mode parameter
	*p_temp++ = param.mode;
	
	// (5) 2 bytes keyID
	*p_temp++ = param.key_id & 0xFF;
	*p_temp++ = (param.key_id >> 8) & 0xFF;
	
	// (6, 7) 8 bytes OTP[0:7] or 0x00's, 3 bytes OTP[8:10] or 0x00's
	if (param.mode & MAC_MODE_INCLUDE_OTP_88) {
		memcpy(p_temp, param.otp, 11);            // use OTP[0:10], Mode:5 is overridden
		p_temp += 11;
	} else {
		if (param.mode & MAC_MODE_INCLUDE_OTP_64) {
			memcpy(p_temp, param.otp, 8);         // use 8 bytes OTP[0:7] for (6)
			p_temp += 8;
		} else {
			for (i = 0; i < 8; i++) {             // use 8 bytes 0x00's for (6)
				*p_temp++ = 0x00;
			}
		}
		
		for (i = 0; i < 3; i++) {                 // use 3 bytes 0x00's for (7)
			*p_temp++ = 0x00;
		}
	}
	
	// (8) 1 byte SN[8] = 0xEE
	*p_temp++ = SHA204_SN_8;
	
	// (9) 4 bytes SN[4:7] or 0x00's
	if (param.mode & MAC_MODE_INCLUDE_SN) {
		memcpy(p_temp, &param.sn[4], 4);     //use SN[4:7] for (9)
		p_temp += 4;
	} else {
		for (i = 0; i < 4; i++) {            //use 0x00's for (9)
			*p_temp++ = 0x00;
		}
	}
	
	// (10) 2 bytes SN[0:1] = 0x0123
	*p_temp++ = SHA204_SN_0;
	*p_temp++ = SHA204_SN_1;
	
	// (11) 2 bytes SN[2:3] or 0x00's
	if (param.mode & MAC_MODE_INCLUDE_SN) {
		memcpy(p_temp, &param.sn[2], 2);     //use SN[2:3] for (11)
		p_temp += 2;
	} else {
		for (i = 0; i < 2; i++) {            //use 0x00's for (11)
			*p_temp++ = 0x00;
		}       
	}
	
	// This is the resulting MAC digest
	sha256(temporary, SHA204_MSG_SIZE_MAC, param.response);
	
	// Update TempKey fields
	param.temp_key->valid = 0;
	
	return SHA204_SUCCESS;
}

void sha204p_wakeup(unsigned char chip)
{
	unsigned char wakeup = 0;
	int ret = i2c_write(0,0,0,&wakeup,1);
	if(ret != 1)
		printf(">>>sha204p_wakeup	:	%d\n",ret);	
	udelay(SHA204_WAKEUP_DELAY * 1000);

	return ;
}

uint8_t sha204h_nonce(struct sha204h_nonce_in_out param)
{
	// Local Variables
	uint8_t temporary[SHA204_MSG_SIZE_NONCE];	
	uint8_t *p_temp;
	
	// Check parameters
	if (	!param.temp_key || !param.num_in
			|| (param.mode > NONCE_MODE_PASSTHROUGH)
			|| (param.mode == NONCE_MODE_INVALID)
			|| (param.mode == NONCE_MODE_SEED_UPDATE && !param.rand_out)
			|| (param.mode == NONCE_MODE_NO_SEED_UPDATE && !param.rand_out) )
		return SHA204_BAD_PARAM;

	// Calculate or pass-through the nonce to TempKey.Value
	if ((param.mode == NONCE_MODE_SEED_UPDATE) || (param.mode == NONCE_MODE_NO_SEED_UPDATE)) {
		// Calculate nonce using SHA-256 (refer to datasheet)
		p_temp = temporary;
		
		memcpy(p_temp, param.rand_out, 32);
		p_temp += 32;
		
		memcpy(p_temp, param.num_in, 20);
		p_temp += 20;
		
		*p_temp++ = SHA204_NONCE;
		*p_temp++ = param.mode;
		*p_temp++ = 0x00;
			
		sha256(temporary, SHA204_MSG_SIZE_NONCE, param.temp_key->value);
		
		// Update TempKey.SourceFlag to 0 (random)
		param.temp_key->source_flag = 0;
	} else if (param.mode == NONCE_MODE_PASSTHROUGH) {
		// Pass-through mode
		memcpy(param.temp_key->value, param.num_in, 32);
		
		// Update TempKey.SourceFlag to 1 (not random)
		param.temp_key->source_flag = 1;
	}
	
	// Update TempKey fields
	param.temp_key->key_id = 0;
	param.temp_key->gen_data = 0;
	param.temp_key->check_flag = 0;
	param.temp_key->valid = 1;
	
	return SHA204_SUCCESS;
}
void sha204c_calculate_crc(uint8_t length, uint8_t *data, uint8_t *crc) {
	uint8_t counter;
	uint16_t crc_register = 0;
	uint16_t polynom = 0x8005;
	uint8_t shift_register;
	uint8_t data_bit, crc_bit;

	for (counter = 0; counter < length; counter++) {
	  for (shift_register = 0x01; shift_register > 0x00; shift_register <<= 1) {
		 data_bit = (data[counter] & shift_register) ? 1 : 0;
		 crc_bit = crc_register >> 15;

		 // Shift CRC to the left by 1.
		 crc_register <<= 1;

		 if ((data_bit ^ crc_bit) != 0)
			crc_register ^= polynom;
	  }
	}
	crc[0] = (uint8_t) (crc_register & 0x00FF);
	crc[1] = (uint8_t) (crc_register >> 8);
}

uint8_t sha204c_check_crc(uint8_t *response)
{
	uint8_t crc[SHA204_CRC_SIZE];
	uint8_t count = response[SHA204_BUFFER_POS_COUNT];

	count -= SHA204_CRC_SIZE;
	sha204c_calculate_crc(count, response, crc);

	return (crc[0] == response[count] && crc[1] == response[count + 1])
		? SHA204_SUCCESS : SHA204_BAD_CRC;
}
static uint8_t sha204p_send(unsigned char chip, uint8_t word_address, uint8_t count, uint8_t *buffer)
{
	int ret,i=0;
	unsigned char *r;
	unsigned char *array = (unsigned char*)malloc((count+1)*sizeof(unsigned char));

	printf("\n>>>sha204p_send		:word_addr :%d count :%d\n",word_address,count);		

	if(i == count && i != 0)
		printf("\n");

	array[0] = word_address;
	memcpy(array+1,buffer,count);

	i2c_set_bus_num(0);
	ret = i2c_write(chip,0,0,array,count+1);
	printf("   >>>send_write	:count :%d\n",ret);
	
	r = buffer;
	for(i=0;i<count;++i,r++) {
		printf("%3x",*r);
		if(i%10 ==9) printf("\n");					
	}
	
	free(array);
	return (ret == count+1) ?  SHA204_SUCCESS : ret;
}



uint8_t sha204p_send_command(unsigned char chip,uint8_t count, uint8_t *command)
{
	return sha204p_send(chip, SHA204_I2C_PACKET_FUNCTION_NORMAL, count, command);
}

uint8_t sha204p_idle(unsigned char chip)
{
	return sha204p_send(chip, SHA204_I2C_PACKET_FUNCTION_IDLE, 0, NULL);
}
uint8_t sha204p_sleep(unsigned char chip)
{
	return sha204p_send(chip, SHA204_I2C_PACKET_FUNCTION_SLEEP, 0, NULL);
}
uint8_t sha204p_receive_response(unsigned char chip, uint8_t size, uint8_t *response)
{
	int ret,i;
	unsigned char count;
	unsigned char *p;

	i2c_set_bus_num(0);
	i2c_read(chip,0,0,&response[0],1);

	count = response[0];
	printf("\n>>>receive_response	:	%x\n",count);
	if ((count < SHA204_RSP_SIZE_MIN) || (count > SHA204_RSP_SIZE_MAX))
		return SHA204_INVALID_SIZE;

	i2c_set_bus_num(0);
	ret = i2c_read(chip,0,0,response+1,count-1);
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

uint8_t sha204c_send_and_receive(unsigned char chip,struct sha204_send_and_receive_parameters *args)
{
	uint8_t ret_code = SHA204_FUNC_FAIL;

	uint8_t count = args->tx_buffer[SHA204_BUFFER_POS_COUNT];
	uint8_t count_minus_crc = count - SHA204_CRC_SIZE;

	sha204c_calculate_crc(count_minus_crc, args->tx_buffer, args->tx_buffer + count_minus_crc);

	ret_code = sha204p_send_command(chip,count, args->tx_buffer);
	udelay(args->poll_delay * 1000);
	do {
		ret_code = sha204p_receive_response(chip, args->rx_size, args->rx_buffer);
	} while ((ret_code == SHA204_RX_NO_RESPONSE));

	ret_code = sha204c_check_crc(args->rx_buffer);

	return ret_code;
}

uint8_t sha204m_execute(unsigned char chip, struct sha204_command_parameters *args)
{
	uint8_t *p_buffer;
	uint8_t len;
	struct sha204_send_and_receive_parameters comm_parameters = {
		.tx_buffer = args->tx_buffer,
		.rx_buffer = args->rx_buffer
	};

	// Supply delays and response size.
	switch (args->op_code) {

	case SHA204_MAC:
		comm_parameters.poll_delay = MAC_DELAY;
		comm_parameters.poll_timeout = MAC_EXEC_MAX - MAC_DELAY;
		comm_parameters.rx_size = MAC_RSP_SIZE;
		break;

	case SHA204_NONCE:
		comm_parameters.poll_delay = NONCE_DELAY;
		comm_parameters.poll_timeout = NONCE_EXEC_MAX - NONCE_DELAY;
		comm_parameters.rx_size = args->param_1 == NONCE_MODE_PASSTHROUGH
							? NONCE_RSP_SIZE_SHORT : NONCE_RSP_SIZE_LONG;
		break;

	default:
		comm_parameters.poll_delay = 0;
		comm_parameters.poll_timeout = SHA204_COMMAND_EXEC_MAX;
		comm_parameters.rx_size = args->rx_size;
	}

	// Assemble command.
	len = args->data_len_1 + args->data_len_2 + args->data_len_3 + SHA204_CMD_SIZE_MIN;
	p_buffer = args->tx_buffer;
	*p_buffer++ = len;
	*p_buffer++ = args->op_code;
	*p_buffer++ = args->param_1;
	*p_buffer++ = args->param_2 & 0xFF;
	*p_buffer++ = args->param_2 >> 8;

	if (args->data_len_1 > 0) {
		memcpy(p_buffer, args->data_1, args->data_len_1);
		p_buffer += args->data_len_1;
	}
	if (args->data_len_2 > 0) {
		memcpy(p_buffer, args->data_2, args->data_len_2);
		p_buffer += args->data_len_2;
	}
	if (args->data_len_3 > 0) {
		memcpy(p_buffer, args->data_3, args->data_len_3);
		p_buffer += args->data_len_3;
	}

	sha204c_calculate_crc(len - SHA204_CRC_SIZE, args->tx_buffer, p_buffer);

	// Send command and receive response.
	return sha204c_send_and_receive(chip,&comm_parameters);
}

void do_random_challenge_response_authentication() {

	unsigned char chip = ATSHA204_ADDR;
	
	static uint8_t status = SHA204_SUCCESS;
	static uint8_t random_number[0x20] = {0};		// Random number returned by Random NONCE command
	static uint8_t computed_response[0x20] = {0};	// Host computed expected response
	static uint8_t atsha204_response[0x20] = {0};	// Actual response received from the ATSHA204 device
	struct sha204h_nonce_in_out nonce_param;		// Parameter for nonce helper function
	struct sha204h_mac_in_out mac_param;			// Parameter for mac helper function
	struct sha204h_temp_key computed_tempkey;		// TempKey parameter for nonce and mac helper function

	//add by jli :That before every executing  cmd sent to ATSHA204 chip  should have waked it up once!
	sha204p_wakeup(chip);
	
	printf("Random Chal_Response r_1\n");
	
	cmd_args.op_code = SHA204_NONCE;
	cmd_args.param_1 = NONCE_MODE_NO_SEED_UPDATE;
	cmd_args.param_2 = NONCE_PARAM2;
	cmd_args.data_len_1 = NONCE_NUMIN_SIZE;
	cmd_args.data_1 = num_in;
	cmd_args.data_len_2 = 0;
	cmd_args.data_2 = NULL;
	cmd_args.data_len_3 = 0;
	cmd_args.data_3 = NULL;
	cmd_args.tx_size = NONCE_COUNT_SHORT;			
	cmd_args.tx_buffer = global_tx_buffer;
	cmd_args.rx_size = NONCE_RSP_SIZE_LONG;			 
	cmd_args.rx_buffer = global_rx_buffer;
	status = sha204m_execute(chip,&cmd_args);
	sha204p_idle(chip);
	if(status != SHA204_SUCCESS) { printf("FAILED! (1)r_2\n"); return; }
	
	// Capture the random number from the NONCE command if it were successful
	memcpy(random_number,&global_rx_buffer[1],0x20);
	
	// *** STEP 2:	COMPUTE THE EQUIVALENT NONCE ON THE HOST SIDE
	//
	//				Go the easy way using the host helper functions provided with 
	//				the ATSHA204 library.
	
	nonce_param.mode = NONCE_MODE_NO_SEED_UPDATE;
	nonce_param.num_in = num_in;
	nonce_param.rand_out = random_number;
	nonce_param.temp_key = &computed_tempkey;
	status = sha204h_nonce(nonce_param);
	if(status != SHA204_SUCCESS) { printf("FAILED! (2)r_3\n"); return; }

	
	// *** STEP 3:	ISSUE THE MAC COMMAND
	//
	//				Starting from a randomized internal state of the ATSHA204 device
	//				guarantees that this MAC command call is executing a random
	//				challenge-response authentication. 
	
	// Issue the MAC command
	cmd_args.op_code = SHA204_MAC;
	cmd_args.param_1 = MAC_MODE_BLOCK2_TEMPKEY;
	cmd_args.param_2 = KEY_ID_0;
	cmd_args.data_len_1 = 0; 
	cmd_args.data_1 = NULL;
	cmd_args.data_len_2 = 0;
	cmd_args.data_2 = NULL;
	cmd_args.data_len_3 = 0;
	cmd_args.data_3 = NULL;
	cmd_args.tx_size = MAC_COUNT_SHORT;
	cmd_args.tx_buffer = global_tx_buffer;
	cmd_args.rx_size = MAC_RSP_SIZE;
	cmd_args.rx_buffer = global_rx_buffer;
	status = sha204m_execute(chip,&cmd_args);
	sha204p_sleep(chip);
	if(status != SHA204_SUCCESS) { printf("FAILED! (3)r_4\n"); return; }
	
	// Capture actual response from the ATSHA204 device
	memcpy(atsha204_response,&global_rx_buffer[1],0x20);
	
	
	// *** STEP 4:	DYNAMICALLY VALIDATE THE (MAC) RESPONSE
	//				
	//				Note that this requires knowledge of the actual secret key
	//				value.
	
	mac_param.mode = MAC_MODE_BLOCK2_TEMPKEY;
	mac_param.key_id = KEY_ID_0;
	mac_param.challenge = NULL;
	mac_param.key = secret_key_value;
	mac_param.otp = NULL;
	mac_param.sn = NULL;
	mac_param.response = computed_response;
	mac_param.temp_key = &computed_tempkey;
	status = sha204h_mac(mac_param);
	if(status != SHA204_SUCCESS) { printf("FAILED! (4)r_5\n"); return; }
	
	
	// Moment of truth: Compare the received response with the dynamically computed expected response.
	status = memcmp(computed_response,atsha204_response,0x20);
	if ( !status ) {	
		printf("SUCCESS!^_^\n");
	} else {
		 printf("FAILED! (4)r_6\n"); 
		 return; 
	}
	
	return;
}

static cmd_tbl_t cmd_sha204_sub[] = {
	U_BOOT_CMD_MKENT(rcra, 0, 1, do_random_challenge_response_authentication, "", ""),
};

static int do_sha204(cmd_tbl_t * cmdtp, int flag, int argc, char * const argv[])
{
	cmd_tbl_t *c;

	if (argc < 2)
		return CMD_RET_USAGE;

	/* Strip off leading 'oled' command argument */
	argc--;
	argv++;

	c = find_cmd_tbl(argv[0], &cmd_sha204_sub[0], ARRAY_SIZE(cmd_sha204_sub));

	if (c)
		return c->cmd(cmdtp, flag, argc, argv);
	else
		return CMD_RET_USAGE;
}

static char sha204_help_text[] =
"sha204 rcra	--sha204 random_challenge_response_authentication\n";

U_BOOT_CMD(
	sha204, 4, 1, do_sha204,
	"ATSHA204A",
	sha204_help_text
);

