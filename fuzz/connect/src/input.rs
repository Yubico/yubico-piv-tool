use libafl::{
    bolts::AsSlice,
    inputs::{BytesInput, HasTargetBytes},
};
use std::cmp::min;

#[repr(C)]
pub struct TestCase {
    pub state_protocol: u32,
    pub pcsc_data_len: u32,
    pub readers_len: u32,
    pub plaintext_len: u32,
    pub pcsc_data: *const u8,
    pub readers: *const u8,
    pub plaintext: *const u8,
}

impl TestCase {
    pub fn from<'a>(&'a mut self, bytes: &'a BytesInput) {
        /* since we are taking pointers to raw data in the BytesInput object
         * we need to ensure that the two arguments have the same lifetime
         * otherwise, the pointers might end up corrupted when the harness executes
         */
        let target_bytes = bytes.target_bytes();
        let slice = target_bytes.as_slice();
        if slice.len() >= 16 {
            self.state_protocol = u32::from_le_bytes(slice[0..4].try_into().expect("no me gusta"));

            self.pcsc_data_len =
                u32::from_le_bytes(slice[4..8].try_into().expect("no me gusta")) as u32;
            self.readers_len =
                u32::from_le_bytes(slice[8..12].try_into().expect("no me gusta")) as u32;
            self.plaintext_len =
                u32::from_le_bytes(slice[12..16].try_into().expect("no me gusta")) as u32;

            self.pcsc_data_len = min(self.pcsc_data_len, slice.len() as u32 - 16);
            self.readers_len = min(
                self.readers_len,
                slice.len() as u32 - 16 - self.pcsc_data_len,
            );
            self.plaintext_len = min(
                self.plaintext_len,
                slice.len() as u32 - 16 - self.pcsc_data_len - self.readers_len,
            );

            let pcsc_data_start = 16;
            let readers_start = pcsc_data_start + self.pcsc_data_len as usize;
            let plaintext_start = readers_start + self.readers_len as usize;
            let plaintext_end = plaintext_start + self.plaintext_len as usize;

            self.pcsc_data = slice[pcsc_data_start..readers_start].as_ptr();
            self.readers = slice[readers_start..plaintext_start].as_ptr();
            self.plaintext = slice[plaintext_start..plaintext_end].as_ptr();
        }
    }
}

extern "C" {
    pub fn CustomFuzzerTestOneInput(tc: *const TestCase) -> i32;
}
