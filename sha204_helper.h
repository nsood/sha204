//         ATMEL Microcontroller Software Support  -  Colorado Springs, CO -
// ----------------------------------------------------------------------------
// DISCLAIMER:  THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
// DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
// EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// ----------------------------------------------------------------------------

/** \file
 *  \brief  Declarations and Prototypes for SHA204 Helper Functions
 *  \author Tuwuh Sarwoprasojo, Atmel Bali Team
 *  \date   September 1, 2011
 */

/** \mainpage SHA204 Helper Functions
 *
 *  The SHA204 helper functions provide host cryptographic functionality for ATSHA204 client device.
 *  The helper functions are intended to accompany the SHA204 library functions.
 *  It can be used directly by Application layer, or integrated in API layer.
 *
 *  There are 9 functions:
 *  -# Nonce calculation function, sha204h_nonce()
 *  -# MAC calculation function, sha204h_mac()
 *  -# HMAC calculation function, sha204h_hmac()
 *  -# GenDig calculation function, sha204h_gen_dig()
 *  -# DeriveKey calculation function, sha204h_derive_key()
 *  -# DeriveKey Input MAC calculation function, sha204h_derive_key_mac()
 *  -# Encryption and input MAC calculation function for Write, sha204h_encrypt()
 *  -# Decryption function for Read, sha204h_decrypt()
 *  -# CRC calculation function (chained), sha204h_calculate_crc_chain()
 */
 
#ifndef SHA204_HELPER_H
#   define SHA204_HELPER_H

//-------------------
// Macro definitions
//-------------------
// SHA-256 message sizes
#define SHA204_MSG_SIZE_NONCE            (55)  // (32+20+1+1+1)
#define SHA204_MSG_SIZE_MAC              (88)  // (32+32+1+1+2+8+3+1+4+2+2)
#define SHA204_MSG_SIZE_HMAC_INNER       (152) // (32+32+32+32+1+1+2+8+3+1+4+2+2)
#define SHA204_MSG_SIZE_HMAC_OUTER       (96)  // (32+32+32)
#define SHA204_MSG_SIZE_GEN_DIG          (96)  // (32+1+1+2+1+2+25+32)
#define SHA204_MSG_SIZE_DERIVE_KEY       (96)  // (32+1+1+2+1+2+25+32)
#define SHA204_MSG_SIZE_DERIVE_KEY_MAC   (39)  // (32+1+1+2+1+2)
#define SHA204_MSG_SIZE_ENCRYPT_MAC      (96)  // (32+1+1+2+1+2+25+32)

// SN[0:1] and SN[8]
#define SHA204_SN_0               (0x01)
#define SHA204_SN_1               (0x23)
#define SHA204_SN_8               (0xEE)

// Command parameter definitions (that is not defined in sha204_comm_marshaling.h)
#define MAC_MODE_USE_TEMPKEY_MASK    ((uint8_t) 0x03)
#ifndef GENDIG_ZONE_CONFIG
	#define GENDIG_ZONE_CONFIG       ((uint8_t) 0)
#endif //GENDIG_ZONE_CONFIG


//-----------------------
// Structure for TempKey
//-----------------------
/** \struct sha204h_temp_key
 *  \brief Structure to hold TempKey fields
 *  \var sha204h_temp_key::value
 *       \brief The value of TempKey. Nonce (from nonce command) or Digest (from GenDig command) 
 *  \var sha204h_temp_key::key_id
 *       \brief If TempKey was generated by GenDig (see the GenData and CheckFlag bits), these bits indicate which key was used in its computation.
 *  \var sha204h_temp_key::source_flag
 *       \brief The source of the randomness in TempKey: 0=Rand, 1=Input.
 *  \var sha204h_temp_key::gen_data
 *       \brief Indicates if TempKey has been generated by GenDig using Data zone.
 *  \var sha204h_temp_key::check_flag
 *       \brief Not used in the library.
 *  \var sha204h_temp_key::valid
 *       \brief Indicates if the information in TempKey is valid.
 */
struct sha204h_temp_key {
	uint8_t value[32];
	uint8_t key_id :4;
	uint8_t source_flag :1;
	uint8_t gen_data :1;
	uint8_t check_flag :1;
	uint8_t valid :1;
};


//----------------------------------------
// Structures for input/output parameters
//----------------------------------------
/** \struct sha204h_nonce_in_out
 *  \brief Input/output parameters for function sha204h_nonce().
 *  \var sha204h_nonce_in_out::mode
 *       \brief [in] Mode parameter used in Nonce command (Param1).
 *  \var sha204h_nonce_in_out::num_in
 *       \brief [in] Pointer to 20-byte NumIn data used in Nonce command.
 *  \var sha204h_nonce_in_out::rand_out
 *       \brief [in] Pointer to 32-byte RandOut data from Nonce command.
 *  \var sha204h_nonce_in_out::temp_key
 *       \brief [in,out] Pointer to TempKey structure.
 */
struct sha204h_nonce_in_out {
	uint8_t mode; 
	uint8_t *num_in;
	uint8_t *rand_out;
	struct sha204h_temp_key *temp_key;
};


/** \struct sha204h_mac_in_out
 *  \brief Input/output parameters for function sha204h_mac().
 *  \var sha204h_mac_in_out::mode
 *       \brief [in] Mode parameter used in MAC command (Param1).
 *  \var sha204h_mac_in_out::key_id
 *       \brief [in] KeyID parameter used in MAC command (Param2).
 *  \var sha204h_mac_in_out::challenge
 *       \brief [in] Pointer to 32-byte Challenge data used in MAC command, depending on mode.
 *  \var sha204h_mac_in_out::key
 *       \brief [in] Pointer to 32-byte key used to generate MAC digest.
 *  \var sha204h_mac_in_out::otp
 *       \brief [in] Pointer to 11-byte OTP, optionally included in MAC digest, depending on mode.
 *  \var sha204h_mac_in_out::sn
 *       \brief [in] Pointer to 9-byte SN, optionally included in MAC digest, depending on mode.
 *  \var sha204h_mac_in_out::response
 *       \brief [out] Pointer to 32-byte SHA-256 digest (MAC).
 *  \var sha204h_mac_in_out::temp_key
 *       \brief [in,out] Pointer to TempKey structure.
 */
struct sha204h_mac_in_out {
	uint8_t mode;
	uint16_t key_id;
	uint8_t *challenge;
	uint8_t *key;
	uint8_t *otp;
	uint8_t *sn;
	uint8_t *response;
	struct sha204h_temp_key *temp_key;
};


/** \struct sha204h_hmac_in_out
 *  \brief Input/output parameters for function sha204h_hmac().
 *  \var sha204h_hmac_in_out::mode
 *       \brief [in] Mode parameter used in HMAC command (Param1).
 *  \var sha204h_hmac_in_out::key_id
 *       \brief [in] KeyID parameter used in HMAC command (Param2).
 *  \var sha204h_hmac_in_out::key
 *       \brief [in] Pointer to 32-byte key used to generate HMAC digest.
 *  \var sha204h_hmac_in_out::otp
 *       \brief [in] Pointer to 11-byte OTP, optionally included in HMAC digest, depending on mode.
 *  \var sha204h_hmac_in_out::sn
 *       \brief [in] Pointer to 9-byte SN, optionally included in HMAC digest, depending on mode.
 *  \var sha204h_hmac_in_out::response
 *       \brief [out] Pointer to 32-byte SHA-256 HMAC digest.
 *  \var sha204h_hmac_in_out::temp_key
 *       \brief [in,out] Pointer to TempKey structure.
 */
struct sha204h_hmac_in_out {
	uint8_t mode;
	uint16_t key_id;
	uint8_t *key;
	uint8_t *otp;
	uint8_t *sn;
	uint8_t *response;
	struct sha204h_temp_key *temp_key;
};


/** \struct sha204h_gen_dig_in_out
 *  \brief Input/output parameters for function sha204h_gen_dig().
 *  \var sha204h_gen_dig_in_out::zone
 *       \brief [in] Zone parameter used in GenDig command (Param1).
 *  \var sha204h_gen_dig_in_out::key_id
 *       \brief [in] KeyID parameter used in GenDig command (Param2).
 *  \var sha204h_gen_dig_in_out::stored_value
 *       \brief [in] Pointer to 32-byte stored value, can be a data slot, OTP page, configuration zone, or hardware transport key.
 *  \var sha204h_gen_dig_in_out::temp_key
 *       \brief [in,out] Pointer to TempKey structure.
 */
struct sha204h_gen_dig_in_out {
	uint8_t zone;
	uint16_t key_id;
	uint8_t *stored_value;
	struct sha204h_temp_key *temp_key;
};


/** \struct sha204h_derive_key_in_out
 *  \brief Input/output parameters for function sha204h_derive_key().
 *  \var sha204h_derive_key_in_out::random
 *       \brief [in] Random parameter used in DeriveKey command (Param1).
 *  \var sha204h_derive_key_in_out::target_key_id
 *       \brief [in] KeyID to be derived, TargetKey parameter used in DeriveKey command (Param2).
 *  \var sha204h_derive_key_in_out::parent_key
 *       \brief [in] Pointer to 32-byte ParentKey. Set equal to target_key if Roll Key operation is intended.
 *  \var sha204h_derive_key_in_out::target_key
 *       \brief [out] Pointer to 32-byte TargetKey.
 *  \var sha204h_derive_key_in_out::temp_key
 *       \brief [in,out] Pointer to TempKey structure.
 */
struct sha204h_derive_key_in_out {
	uint8_t random;
	uint16_t target_key_id;
	uint8_t *parent_key;
	uint8_t *target_key;
	struct sha204h_temp_key *temp_key;
};


/** \struct sha204h_derive_key_mac_in_out
 *  \brief Input/output parameters for function sha204h_derive_key_mac().
 *  \var sha204h_derive_key_mac_in_out::random
 *       \brief [in] Random parameter used in DeriveKey command (Param1).
 *  \var sha204h_derive_key_mac_in_out::target_key_id
 *       \brief [in] KeyID to be derived, TargetKey parameter used in DeriveKey command (Param2).
 *  \var sha204h_derive_key_mac_in_out::parent_key
 *       \brief [in] Pointer to 32-byte ParentKey. ParentKey here is always SlotConfig[TargetKey].WriteKey, regardless whether the operation is Roll or Create.
 *  \var sha204h_derive_key_mac_in_out::mac
 *       \brief [out] Pointer to 32-byte Mac.
 */
struct sha204h_derive_key_mac_in_out {
	uint8_t random;
	uint16_t target_key_id;
	uint8_t *parent_key;
	uint8_t *mac;
};


/** \struct sha204h_encrypt_in_out
 *  \brief Input/output parameters for function sha204h_encrypt().
 *  \var sha204h_encrypt_in_out::zone
 *       \brief [in] Zone parameter used in Write (Param1).
 *  \var sha204h_encrypt_in_out::address
 *       \brief [in] Address parameter used in Write command (Param2).
 *  \var sha204h_encrypt_in_out::data
 *       \brief [in,out] Pointer to 32-byte data. Input cleartext data, output encrypted data to Write command (Value field).
 *  \var sha204h_encrypt_in_out::mac
 *       \brief [out] Pointer to 32-byte Mac. Can be set to NULL if input MAC is not required by the Write command (write to OTP, unlocked user zone).
 *  \var sha204h_encrypt_in_out::temp_key
 *       \brief [in,out] Pointer to TempKey structure.
 */
struct sha204h_encrypt_in_out {
	uint8_t zone;
	uint16_t address;
	uint8_t *data;
	uint8_t *mac;
	struct sha204h_temp_key *temp_key;
};


/** \struct sha204h_decrypt_in_out
 *  \brief Input/output parameters for function sha204h_decrypt().
 *  \var sha204h_decrypt_in_out::data
 *       \brief [in,out] Pointer to 32-byte data. Input encrypted data from Read command (Contents field), output decrypted.
 *  \var sha204h_decrypt_in_out::temp_key
 *       \brief [in,out] Pointer to TempKey structure.
 */
struct sha204h_decrypt_in_out {
	uint8_t *data;
	struct sha204h_temp_key *temp_key;
};


//---------------------
// Function prototypes
//---------------------

#endif //SHA204_HELPER_H
