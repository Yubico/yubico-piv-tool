use libafl::{
    bolts::AsSlice,
    inputs::{BytesInput, HasTargetBytes},
};
use std::cmp::min;
use std::mem;

#[repr(C)]
pub struct TestCase {
    state_protocol: u32,
    in_len: u32,
    out_len: u32,
    in_data: *const u8,
    out_data: *const u8,
}

impl From<&BytesInput> for TestCase {
    fn from(bytes: &BytesInput) -> Self {
        let mut tc: TestCase = unsafe { mem::zeroed() };

        let target_bytes = bytes.target_bytes();
        let slice = target_bytes.as_slice();
        if slice.len() > 8 {
            tc.state_protocol = u32::from_le_bytes(slice[0..4].try_into().expect("no me gusta"));

            let in_chunks: u32 = slice[4] as u32;
            let last_chunk: u32 = slice[5] as u32;

            tc.in_len = in_chunks * 255 + last_chunk;
            tc.out_len = u16::from_le_bytes(slice[6..8].try_into().expect("no me gusta")) as u32;

            tc.in_len = min(tc.in_len, (slice.len() - 8) as u32);
            tc.in_data = slice[8..8 + tc.in_len as usize].as_ptr();

            tc.out_len = min(tc.out_len, (slice.len() as u32 - (8 + tc.in_len)) as u32);
            tc.out_data = slice
                [8 + tc.in_len as usize..8 + tc.in_len as usize + tc.out_len as usize]
                .as_ptr();
        }

        tc
    }
}

extern "C" {
    pub fn CustomFuzzerTestOneInput(tc: *const TestCase) -> i32;
}
