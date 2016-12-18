use std::{ slice, ptr };
use libc::{ uint8_t, c_uint };
use sarkara::aead::{ AeadCipher, DecryptFail, Ascon, General, RivGeneral };
use sarkara::stream::HC256;
use sarkara::auth::HMAC;
use sarkara::hash::Blake2b;

type BHMAC = HMAC<Blake2b>;
type HHBB = General<HC256, BHMAC, Blake2b>;
type HRHB = RivGeneral<HC256, BHMAC, Blake2b>;


#[repr(C)]
pub enum SARKARA_ERR_AEAD_DECRYPTION {
    SARKARA_ERR_AEAD_DECRYPTION_OK,
    SARKARA_ERR_AEAD_DECRYPTION_LENGTH,
    SARKARA_ERR_AEAD_DECRYPTION_AUTH_FAIL,
    SARKARA_ERR_AEAD_DECRYPTION_OTHER
}

impl From<DecryptFail> for SARKARA_ERR_AEAD_DECRYPTION {
    fn from(err: DecryptFail) -> SARKARA_ERR_AEAD_DECRYPTION {
        match err {
            DecryptFail::LengthError => SARKARA_ERR_AEAD_DECRYPTION::SARKARA_ERR_AEAD_DECRYPTION_LENGTH,
            DecryptFail::AuthenticationFail => SARKARA_ERR_AEAD_DECRYPTION::SARKARA_ERR_AEAD_DECRYPTION_AUTH_FAIL,
            DecryptFail::Other(_) => SARKARA_ERR_AEAD_DECRYPTION::SARKARA_ERR_AEAD_DECRYPTION_OTHER
        }
    }
}


#[no_mangle]
pub unsafe extern fn sarkara_aead_ascon_encrypt(
    key: *const uint8_t, nonce: *const uint8_t,
    aad: *const uint8_t, aad_len: c_uint,
    data: *const uint8_t, data_len: c_uint,
    out: *mut uint8_t
) -> bool {
    let key = slice::from_raw_parts(key, Ascon::key_length());
    let nonce = slice::from_raw_parts(nonce, Ascon::nonce_length());
    let aad = slice::from_raw_parts(aad, aad_len as usize);
    let data = slice::from_raw_parts(data, data_len as usize);
    let ciphertext = Ascon::new(key).with_aad(aad).encrypt(nonce, data);

    ptr::copy(ciphertext.as_ptr(), out, ciphertext.len());

    true
}

#[no_mangle]
pub unsafe extern fn sarkara_aead_ascon_decrypt(
    key: *const uint8_t, nonce: *const uint8_t,
    aad: *const uint8_t, aad_len: c_uint,
    data: *const uint8_t, data_len: c_uint,
    out: *mut uint8_t,
    out_err: *mut SARKARA_ERR_AEAD_DECRYPTION
) -> bool {
    let key = slice::from_raw_parts(key, Ascon::key_length());
    let nonce = slice::from_raw_parts(nonce, Ascon::nonce_length());
    let aad = slice::from_raw_parts(aad, aad_len as usize);
    let data = slice::from_raw_parts(data, data_len as usize);

    match Ascon::new(key).with_aad(aad).decrypt(nonce, data) {
        Ok(plaintext) => {
            ptr::copy(plaintext.as_ptr(), out, plaintext.len());
            ptr::write(out_err, SARKARA_ERR_AEAD_DECRYPTION::SARKARA_ERR_AEAD_DECRYPTION_OK);
            true
        },
        Err(err) => {
            ptr::write(out_err, err.into());
            false
        }
    }
}

#[no_mangle]
pub unsafe extern fn sarkara_aead_hhbb_encrypt(
    key: *const uint8_t, nonce: *const uint8_t,
    aad: *const uint8_t, aad_len: c_uint,
    data: *const uint8_t, data_len: c_uint,
    out: *mut uint8_t
) -> bool {
    let key = slice::from_raw_parts(key, HHBB::key_length());
    let nonce = slice::from_raw_parts(nonce, HHBB::nonce_length());
    let aad = slice::from_raw_parts(aad, aad_len as usize);
    let data = slice::from_raw_parts(data, data_len as usize);
    let ciphertext = HHBB::new(key).with_aad(aad).encrypt(nonce, data);

    ptr::copy(ciphertext.as_ptr(), out, ciphertext.len());

    true
}

#[no_mangle]
pub unsafe extern fn sarkara_aead_hhbb_decrypt(
    key: *const uint8_t, nonce: *const uint8_t,
    aad: *const uint8_t, aad_len: c_uint,
    data: *const uint8_t, data_len: c_uint,
    out: *mut uint8_t,
    out_err: *mut SARKARA_ERR_AEAD_DECRYPTION
) -> bool {
    let key = slice::from_raw_parts(key, HHBB::key_length());
    let nonce = slice::from_raw_parts(nonce, HHBB::nonce_length());
    let aad = slice::from_raw_parts(aad, aad_len as usize);
    let data = slice::from_raw_parts(data, data_len as usize);

    match HHBB::new(key).with_aad(aad).decrypt(nonce, data) {
        Ok(plaintext) => {
            ptr::copy(plaintext.as_ptr(), out, plaintext.len());
            ptr::write(out_err, SARKARA_ERR_AEAD_DECRYPTION::SARKARA_ERR_AEAD_DECRYPTION_OK);
            true
        },
        Err(err) => {
            ptr::write(out_err, err.into());
            false
        }
    }
}


#[no_mangle]
pub unsafe extern fn sarkara_aead_hrhb_encrypt(
    key: *const uint8_t, nonce: *const uint8_t,
    aad: *const uint8_t, aad_len: c_uint,
    data: *const uint8_t, data_len: c_uint,
    out: *mut uint8_t
) -> bool {
    let key = slice::from_raw_parts(key, HRHB::key_length());
    let nonce = slice::from_raw_parts(nonce, HRHB::nonce_length());
    let aad = slice::from_raw_parts(aad, aad_len as usize);
    let data = slice::from_raw_parts(data, data_len as usize);
    let ciphertext = HRHB::new(key).with_aad(aad).encrypt(nonce, data);

    ptr::copy(ciphertext.as_ptr(), out, ciphertext.len());

    true
}

#[no_mangle]
pub unsafe extern fn sarkara_aead_hrhb_decrypt(
    key: *const uint8_t, nonce: *const uint8_t,
    aad: *const uint8_t, aad_len: c_uint,
    data: *const uint8_t, data_len: c_uint,
    out: *mut uint8_t,
    out_err: *mut SARKARA_ERR_AEAD_DECRYPTION
) -> bool {
    let key = slice::from_raw_parts(key, HRHB::key_length());
    let nonce = slice::from_raw_parts(nonce, HRHB::nonce_length());
    let aad = slice::from_raw_parts(aad, aad_len as usize);
    let data = slice::from_raw_parts(data, data_len as usize);

    match HRHB::new(key).with_aad(aad).decrypt(nonce, data) {
        Ok(plaintext) => {
            ptr::copy(plaintext.as_ptr(), out, plaintext.len());
            ptr::write(out_err, SARKARA_ERR_AEAD_DECRYPTION::SARKARA_ERR_AEAD_DECRYPTION_OK);
            true
        },
        Err(err) => {
            ptr::write(out_err, err.into());
            false
        }
    }
}
