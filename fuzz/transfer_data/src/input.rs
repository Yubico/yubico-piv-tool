use libafl::{
    bolts::AsSlice,
    inputs::{BytesInput, HasTargetBytes},
};
use std::cmp::min;

#[repr(C)]
pub struct TestCase {
    state_protocol: u32,
    in_len: u32,
    pcsc_data_len: u32,
    in_data: *const u8,
    pcsc_data: *const u8,
}

impl TestCase {
    pub fn from<'a>(&'a mut self, bytes: &'a BytesInput) {
        let target_bytes = bytes.target_bytes();
        let slice = target_bytes.as_slice();
        if slice.len() > 12 {
            self.state_protocol = u32::from_le_bytes(slice[0..4].try_into().expect("no me gusta"));

            self.in_len = u32::from_le_bytes(slice[4..8].try_into().expect("no me gusta"));
            self.pcsc_data_len =
                u32::from_le_bytes(slice[8..12].try_into().expect("no me gusta")) as u32;

            self.in_len = min(self.in_len, slice.len() as u32 - 12);
            self.pcsc_data_len = min(self.pcsc_data_len, slice.len() as u32 - 12 - self.in_len);

            let in_data_start = 12;
            let pcsc_data_start = in_data_start + self.in_len as usize;
            let pcsc_data_end = pcsc_data_start + self.pcsc_data_len as usize;

            self.in_data = slice[in_data_start..pcsc_data_start].as_ptr();
            self.pcsc_data = slice[pcsc_data_start..pcsc_data_end].as_ptr();
        }
    }
}

extern "C" {
    pub fn CustomFuzzerTestOneInput(tc: *const TestCase) -> i32;
}
