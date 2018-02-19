#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate nom;

#[cfg(not(feature = "std"))]
mod std {
  pub use core::{cmp, convert, fmt, iter, mem, ops, option, result, slice, str};
  pub mod prelude {
    pub use core::prelude as v1;
  }
}

pub mod fdt;
