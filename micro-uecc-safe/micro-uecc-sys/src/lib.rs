#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

// We could generate bindings into OUT_DIR and it will work,
// but VSCode RLS does not see that, so we generate the file
// inside the src folder and export everything from bindings
// module. This also help to easily find the file instead
// of searching inside target/build/... folder.
// include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
pub use bindings::*;
mod bindings;

