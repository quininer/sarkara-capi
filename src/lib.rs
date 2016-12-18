#![cfg_attr(any(target_arch = "asmjs", target_arch = "wasm32"), feature(link_args))]

extern crate libc;
extern crate sarkara;

pub mod aead;

pub use aead::*;


#[cfg(any(target_arch = "asmjs", target_arch = "wasm32"))]
#[link_args = "-s EXPORTED_FUNCTIONS=[\
    '_sarkara_aead_ascon_encrypt',\
    '_sarkara_aead_ascon_decrypt',\
]"]
extern {}

#[cfg(any(target_arch = "asmjs", target_arch = "wasm32"))]
pub fn main() {}
