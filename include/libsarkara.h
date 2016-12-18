
#ifndef cheddar_generated_libsarkara_h
#define cheddar_generated_libsarkara_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>



typedef enum SARKARA_ERR_AEAD_DECRYPTION {
	SARKARA_ERR_AEAD_DECRYPTION_OK,
	SARKARA_ERR_AEAD_DECRYPTION_LENGTH,
	SARKARA_ERR_AEAD_DECRYPTION_AUTH_FAIL,
	SARKARA_ERR_AEAD_DECRYPTION_OTHER,
} SARKARA_ERR_AEAD_DECRYPTION;

bool sarkara_aead_ascon_encrypt(uint8_t const* key, uint8_t const* nonce, uint8_t const* aad, c_uint aad_len, uint8_t const* data, c_uint data_len, uint8_t* out);

bool sarkara_aead_ascon_decrypt(uint8_t const* key, uint8_t const* nonce, uint8_t const* aad, c_uint aad_len, uint8_t const* data, c_uint data_len, uint8_t* out, SARKARA_ERR_AEAD_DECRYPTION* out_err);

bool sarkara_aead_hhbb_encrypt(uint8_t const* key, uint8_t const* nonce, uint8_t const* aad, c_uint aad_len, uint8_t const* data, c_uint data_len, uint8_t* out);

bool sarkara_aead_hhbb_decrypt(uint8_t const* key, uint8_t const* nonce, uint8_t const* aad, c_uint aad_len, uint8_t const* data, c_uint data_len, uint8_t* out, SARKARA_ERR_AEAD_DECRYPTION* out_err);

bool sarkara_aead_hrhb_encrypt(uint8_t const* key, uint8_t const* nonce, uint8_t const* aad, c_uint aad_len, uint8_t const* data, c_uint data_len, uint8_t* out);

bool sarkara_aead_hrhb_decrypt(uint8_t const* key, uint8_t const* nonce, uint8_t const* aad, c_uint aad_len, uint8_t const* data, c_uint data_len, uint8_t* out, SARKARA_ERR_AEAD_DECRYPTION* out_err);



#ifdef __cplusplus
}
#endif


#endif
