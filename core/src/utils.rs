pub fn u8_slice_to_16_vec(x: &[u8]) -> Vec<u16> {
    x.chunks(2).map(|a| u16::from_be_bytes([a[0], a[1]])).collect()
}
