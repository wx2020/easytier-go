use std::hash::{Hasher, DefaultHasher};

fn digest(str1: &str, str2: &str) -> [u8; 32] {
    let mut hasher = DefaultHasher::new();
    hasher.write(str1.as_bytes());
    hasher.write(str2.as_bytes());
    let mut digest = [0u8; 32];
    for index in 0..4 {
        digest[index * 8..(index + 1) * 8].copy_from_slice(&hasher.finish().to_be_bytes());
        hasher.write(&digest[..(index + 1) * 8]);
    }
    digest
}

fn main() {
    for (name, secret) in [("mesh", "secret"), ("", "machine-id"), ("test", "")] {
        let bytes = digest(name, secret);
        print!("{name:?} {secret:?} ");
        for byte in bytes {
            print!("{byte:02x}");
        }
        println!();
    }
}
