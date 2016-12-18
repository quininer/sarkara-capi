#![feature(try_from)]

extern crate libc;
extern crate sarkara;

pub mod aead;

pub use aead::*;


// aead!(fn sarkara_aead_hhbb_encrypt, fn sarkara_aead_hhbb_decrypt, HHBB);
// aead!(fn sarkara_aead_hrhb_encrypt, fn sarkara_aead_hrhb_decrypt, HRHB);
