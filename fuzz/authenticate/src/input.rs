use libafl::{
    bolts::AsSlice,
    inputs::{BytesInput, HasTargetBytes},
};
use std::cmp::min;
use std::mem;

#[repr(C)]
pub struct TestCase {
    state_protocol: u32,
    out_len: u32,
    plaintext_len: u32,
    out_data: *const u8,
    plaintext: *const u8,
}

impl From<&BytesInput> for TestCase {
    fn from(bytes: &BytesInput) -> Self {
        let mut tc: TestCase = unsafe { mem::zeroed() };

        let target_bytes = bytes.target_bytes();
        let slice = target_bytes.as_slice();
        if slice.len() >= 8 {
            tc.state_protocol = u32::from_le_bytes(slice[0..4].try_into().expect("no me gusta"));

            tc.out_len = u16::from_le_bytes(slice[4..6].try_into().expect("no me gusta")) as u32;
            tc.plaintext_len = u16::from_le_bytes(slice[6..8].try_into().expect("no me gusta")) as u32;

            tc.out_len = min(tc.out_len, slice.len() as u32 - 8);
            tc.plaintext_len = min(tc.plaintext_len, slice.len() as u32 - 8 - tc.out_len);

            tc.out_data = slice[8..8 + tc.out_len as usize].as_ptr();
            tc.plaintext = slice[8 + tc.out_len as usize..8 + (tc.out_len+tc.plaintext_len) as usize].as_ptr();
        }

        tc
    }
}

extern "C" {
    pub fn CustomFuzzerTestOneInput(tc: *const TestCase) -> i32;
}
