use core::convert::TryInto;

pub(crate) fn is_default<T: Default + PartialEq>(t: &T) -> bool {
    *t == Default::default()
}

pub fn hex_serialize<S, T>(x: &T, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: AsRef<[u8]>,
{
    s.serialize_str(&hex::encode(x.as_ref()))
}

// fn hex_deserialize<'a, 'de, D, T>(deserializer: D) -> Result<T, D::Error>
// where
//     D: serde::Deserializer<'de>,
//     T: From<&'a [u8]>,
// {
//     let s: &str = serde::de::Deserialize::deserialize(deserializer)?;
//     let mut s = String::from(s);
//     s.retain(|c| !c.is_whitespace());
//     // let v = hex::decode(&s).expect(format!("Hex decoding failed for {}", &s));
//     let v = hex::decode(&s).expect("Hex decoding failed!");

//     let t = T::from(&v);
//     Ok(t)
// }

// NB: const-generics for this case coming soooon (Rust 1.51?)
pub fn hex_deserialize_256<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: From<[u8; 32]>,
{
    let s: &str = serde::de::Deserialize::deserialize(deserializer)?;
    let mut s = String::from(s);
    s.retain(|c| !c.is_whitespace());
    // let v = hex::decode(&s).expect(format!("Hex decoding failed for {}", &s));
    let v: [u8; 32] = hex::decode(&s)
        .expect("Hex decoding failed!")
        .try_into()
        .unwrap();

    let t = T::from(v);
    Ok(t)
}

pub fn hex_deserialize_32<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: From<[u8; 4]>,
{
    let s: &str = serde::de::Deserialize::deserialize(deserializer)?;
    let mut s = String::from(s);
    s.retain(|c| !c.is_whitespace());
    // let v = hex::decode(&s).expect(format!("Hex decoding failed for {}", &s));
    let v: [u8; 4] = hex::decode(&s)
        .expect("Hex decoding failed!")
        .try_into()
        .unwrap();

    let t = T::from(v);
    Ok(t)
}

/// Length after block padding
pub fn block_pad_len(len: usize) -> usize {
    16 * ((len + 15) / 16)
}

/// Pad to multiple of AES block (16 bytes = 128 bits)
pub fn block_pad(data: &mut Vec<u8>) {
    let size = data.len();
    data.resize(block_pad_len(size), 0);
}

/// Padded to multiple of AES block (16 bytes = 128 bits)
pub fn block_padded(data: &[u8]) -> Vec<u8> {
    let mut data = Vec::from(data);
    block_pad(&mut data);
    data
}

/// Length after word-padding
pub fn word_pad_len(len: usize) -> usize {
    4 * ((len + 3) / 4)
}

/// Pad to multiple of machine word (4 bytes = 32 bits)
pub fn word_pad(data: &mut Vec<u8>) {
    let size = data.len();
    data.resize(word_pad_len(size), 0);
}

/// Padded to multiple of machine word (4 bytes = 32 bits)
pub fn word_padded(data: &[u8]) -> Vec<u8> {
    let mut data = Vec::from(data);
    word_pad(&mut data);
    data
}
