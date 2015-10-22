#ifndef SHA2_H
#define SHA2_H

#define SHA224_DIGEST_SIZE ( 224 / 8)
#define SHA256_DIGEST_SIZE ( 256 / 8)

#define SHA256_BLOCK_SIZE  ( 512 / 8)
#define SHA224_BLOCK_SIZE  SHA256_BLOCK_SIZE

#ifndef SHA2_TYPES
#define SHA2_TYPES
typedef unsigned char uint8;
typedef unsigned int  uint16;
typedef unsigned long uint32;
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32 tot_len;
    uint32 len;
    uint8 block[2 * SHA256_BLOCK_SIZE];
    uint32 h[8];
} sha256_ctx;

void sha256_init(sha256_ctx * ctx);
void sha256_update(sha256_ctx *ctx, const uint8 *message, uint32 len);
void sha256_final(sha256_ctx *ctx, uint8 *digest);
void sha256(const uint8 *message, uint32 len, uint8 *digest);

#ifdef __cplusplus
}
#endif

#endif /* !SHA2_H */

