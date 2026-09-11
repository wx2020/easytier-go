use clap::Parser;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "go/testdata/compat")]
    out: PathBuf,
}

fn write_json<P: AsRef<std::path::Path>, T: serde::Serialize>(path: P, value: &T) -> anyhow::Result<()> {
    let s = serde_json::to_string_pretty(value)?;
    std::fs::write(path, format!("{}\n", s))?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let out = args.out;
    std::fs::create_dir_all(out.join("packet"))?;
    std::fs::create_dir_all(out.join("handshake"))?;
    std::fs::create_dir_all(out.join("digest"))?;
    std::fs::create_dir_all(out.join("rpc"))?;
    std::fs::create_dir_all(out.join("config"))?;
    std::fs::create_dir_all(out.join("secure"))?;
    std::fs::create_dir_all(out.join("route"))?;
    std::fs::create_dir_all(out.join("wg"))?;
    std::fs::create_dir_all(out.join("noise"))?;

    generate_packet(&out)?;
    generate_handshake(&out)?;
    generate_digest(&out)?;
    generate_rpc(&out)?;
    generate_config(&out)?;
    generate_wg(&out)?;
    generate_secure(&out)?;
    generate_route(&out)?;

    println!("fixtures written to {}", out.display());
    Ok(())
}

struct SipHasher13 {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    tail: u64,
    tail_len: usize,
    len: u64,
}
impl SipHasher13 {
    fn new() -> Self {
        Self {
            v0: 0x736f6d6570736575,
            v1: 0x646f72616e646f6d,
            v2: 0x6c7967656e657261,
            v3: 0x7465646279746573,
            tail: 0,
            tail_len: 0,
            len: 0,
        }
    }
    fn write(&mut self, data: &[u8]) {
        self.len += data.len() as u64;
        for &b in data {
            self.tail |= (b as u64) << (8 * self.tail_len);
            self.tail_len += 1;
            if self.tail_len == 8 {
                self.compress(self.tail);
                self.tail = 0;
                self.tail_len = 0;
            }
        }
    }
    fn finish(self) -> u64 {
        let mut h = self;
        let last = h.tail | (h.len << 56);
        h.compress(last);
        h.v2 ^= 0xff;
        for _ in 0..3 {
            h.round();
        }
        h.v0 ^ h.v1 ^ h.v2 ^ h.v3
    }
    fn compress(&mut self, word: u64) {
        self.v3 ^= word;
        self.round();
        self.v0 ^= word;
    }
    fn round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(13);
        self.v1 ^= self.v0;
        self.v0 = self.v0.rotate_left(32);
        self.v2 = self.v2.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(16);
        self.v3 ^= self.v2;
        self.v0 = self.v0.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(21);
        self.v3 ^= self.v0;
        self.v2 = self.v2.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(17);
        self.v1 ^= self.v2;
        self.v2 = self.v2.rotate_left(32);
    }
}

fn generate_digest_go(first: &str, second: &str) -> [u8; 32] {
    let mut hasher = SipHasher13::new();
    hasher.write(first.as_bytes());
    hasher.write(second.as_bytes());
    let mut digest = [0u8; 32];
    for i in 0..4 {
        let sum = {
            let h = SipHasher13 {
                v0: hasher.v0,
                v1: hasher.v1,
                v2: hasher.v2,
                v3: hasher.v3,
                tail: hasher.tail,
                tail_len: hasher.tail_len,
                len: hasher.len,
            };
            h.finish()
        };
        digest[i * 8..(i + 1) * 8].copy_from_slice(&sum.to_be_bytes());
        let prefix = digest[..(i + 1) * 8].to_vec();
        hasher.write(&prefix);
    }
    digest
}

fn digest_test_vectors() -> bool {
    let cases = vec![
        ("mesh", "secret", "31107b8e51f0ce46f7b98ceefacfec089fdf3c65e27f8b20fbe21c0ae043c564"),
        ("", "machine-id", "68c22d62bc0ab670f44068eff88224c91b2fa9e3cfffb6722b5553c491f454a7"),
        ("test", "", "e0969da9b8fb378dce342ab96f8be9dc0b5ca8125197369a011a53c6be2ba031"),
    ];
    for (a, b, want) in cases {
        let d = generate_digest_go(a, b);
        let got = hex::encode(d);
        if got != want {
            eprintln!("digest mismatch {} {} got {} want {}", a, b, got, want);
            return false;
        }
    }
    true
}

#[derive(Serialize)]
struct PacketFixture {
    name: String,
    from_peer_id: u32,
    to_peer_id: u32,
    packet_type: u8,
    flags: u8,
    forward_counter: u8,
    payload_hex: String,
    body_hex: String,
    payload_length: u32,
}

fn marshal_packet_body(from: u32, to: u32, pt: u8, flags: u8, fwd: u8, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(16 + payload.len());
    body.extend_from_slice(&from.to_le_bytes());
    body.extend_from_slice(&to.to_le_bytes());
    body.push(pt);
    body.push(flags);
    body.push(fwd);
    body.push(0);
    body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    body.extend_from_slice(payload);
    body
}

fn generate_packet(out: &PathBuf) -> anyhow::Result<()> {
    let fixtures = vec![
        PacketFixture {
            name: "data-small".into(),
            from_peer_id: 0x11223344,
            to_peer_id: 0x55667788,
            packet_type: 1,
            flags: 1,
            forward_counter: 1,
            payload_hex: hex::encode(b"hello"),
            body_hex: hex::encode(marshal_packet_body(0x11223344, 0x55667788, 1, 1, 1, b"hello")),
            payload_length: 5,
        },
        PacketFixture {
            name: "data-empty".into(),
            from_peer_id: 1,
            to_peer_id: 2,
            packet_type: 1,
            flags: 0,
            forward_counter: 0,
            payload_hex: "".into(),
            body_hex: hex::encode(marshal_packet_body(1, 2, 1, 0, 0, b"")),
            payload_length: 0,
        },
        PacketFixture {
            name: "handshake".into(),
            from_peer_id: 100,
            to_peer_id: 0,
            packet_type: 2,
            flags: 0,
            forward_counter: 1,
            payload_hex: hex::encode(vec![0x08, 0x01]),
            body_hex: hex::encode(marshal_packet_body(100, 0, 2, 0, 1, &[0x08, 0x01])),
            payload_length: 2,
        },
        PacketFixture {
            name: "ping".into(),
            from_peer_id: 0x01020304,
            to_peer_id: 0x05060708,
            packet_type: 4,
            flags: 0,
            forward_counter: 7,
            payload_hex: hex::encode(b"ping"),
            body_hex: hex::encode(marshal_packet_body(0x01020304, 0x05060708, 4, 0, 7, b"ping")),
            payload_length: 4,
        },
        PacketFixture {
            name: "compressed".into(),
            from_peer_id: 0x11223344,
            to_peer_id: 0x55667788,
            packet_type: 1,
            flags: 16,
            forward_counter: 2,
            payload_hex: hex::encode(vec![0xaa, 0xbb, 0x01]),
            body_hex: {
                let mut b = Vec::new();
                b.extend_from_slice(&0x11223344u32.to_le_bytes());
                b.extend_from_slice(&0x55667788u32.to_le_bytes());
                b.push(1);
                b.push(16);
                b.push(2);
                b.push(0);
                b.extend_from_slice(&3u32.to_le_bytes());
                b.extend_from_slice(&[0xaa, 0xbb, 0x01]);
                hex::encode(b)
            },
            payload_length: 3,
        },
        PacketFixture {
            name: "max-forward".into(),
            from_peer_id: 1,
            to_peer_id: 2,
            packet_type: 1,
            flags: 0,
            forward_counter: 7,
            payload_hex: hex::encode(b"x"),
            body_hex: hex::encode(marshal_packet_body(1, 2, 1, 0, 7, b"x")),
            payload_length: 1,
        },
    ];
    let path = out.join("packet/fixtures.json");
    write_json(&path, &fixtures)?;
    for f in &fixtures {
        let bin = hex::decode(&f.body_hex)?;
        std::fs::write(out.join(format!("packet/{}.bin", f.name)), bin)?;
    }
    Ok(())
}

fn append_varint(mut data: Vec<u8>, field: u64, value: u64) -> Vec<u8> {
    data = append_wire_varint(data, field << 3);
    append_wire_varint(data, value)
}
fn append_bytes(mut data: Vec<u8>, field: u64, value: &[u8]) -> Vec<u8> {
    data = append_wire_varint(data, field << 3 | 2);
    data = append_wire_varint(data, value.len() as u64);
    data.extend_from_slice(value);
    data
}
fn append_wire_varint(mut data: Vec<u8>, mut value: u64) -> Vec<u8> {
    while value >= 0x80 {
        data.push((value as u8) | 0x80);
        value >>= 7;
    }
    data.push(value as u8);
    data
}

#[derive(Serialize)]
struct HandshakeFixture {
    name: String,
    magic: u32,
    my_peer_id: u32,
    version: u32,
    features: Vec<String>,
    network_name: String,
    network_secret_digest_hex: String,
    wire_hex: String,
}

fn marshal_handshake(magic: u32, peer_id: u32, version: u32, features: &[String], network_name: &str, digest: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    if magic != 0 {
        data = append_varint(data, 1, magic as u64);
    }
    if peer_id != 0 {
        data = append_varint(data, 2, peer_id as u64);
    }
    if version != 0 {
        data = append_varint(data, 3, version as u64);
    }
    for f in features {
        data = append_bytes(data, 4, f.as_bytes());
    }
    if !network_name.is_empty() {
        data = append_bytes(data, 5, network_name.as_bytes());
    }
    if !digest.is_empty() {
        data = append_bytes(data, 6, digest);
    }
    data
}

fn generate_handshake(out: &PathBuf) -> anyhow::Result<()> {
    let digest1: Vec<u8> = (0..32).map(|i| i as u8).collect();
    let fixtures = vec![
        HandshakeFixture {
            name: "handshake-1".into(),
            magic: 0xd1e1a5e1,
            my_peer_id: 0x10203040,
            version: 1,
            features: vec!["tcp".into(), "quic".into()],
            network_name: "mesh".into(),
            network_secret_digest_hex: hex::encode(&digest1),
            wire_hex: hex::encode(marshal_handshake(0xd1e1a5e1, 0x10203040, 1, &["tcp".into(), "quic".into()], "mesh", &digest1)),
        },
        HandshakeFixture {
            name: "handshake-empty-features".into(),
            magic: 0xd1e1a5e1,
            my_peer_id: 12345,
            version: 1,
            features: vec![],
            network_name: "testnet".into(),
            network_secret_digest_hex: "".into(),
            wire_hex: hex::encode(marshal_handshake(0xd1e1a5e1, 12345, 1, &[], "testnet", &[])),
        },
        HandshakeFixture {
            name: "handshake-minimal".into(),
            magic: 0xd1e1a5e1,
            my_peer_id: 1,
            version: 1,
            features: vec![],
            network_name: "".into(),
            network_secret_digest_hex: "".into(),
            wire_hex: hex::encode(marshal_handshake(0xd1e1a5e1, 1, 1, &[], "", &[])),
        },
        HandshakeFixture {
            name: "handshake-with-digest".into(),
            magic: 0xd1e1a5e1,
            my_peer_id: 999,
            version: 1,
            features: vec!["tcp".into()],
            network_name: "prod".into(),
            network_secret_digest_hex: hex::encode(generate_digest_go("prod", "secret")),
            wire_hex: hex::encode(marshal_handshake(0xd1e1a5e1, 999, 1, &["tcp".into()], "prod", &generate_digest_go("prod", "secret"))),
        },
    ];
    write_json(out.join("handshake/fixtures.json"), &fixtures)?;
    Ok(())
}

#[derive(Serialize)]
struct DigestFixture {
    name: String,
    str1: String,
    str2: String,
    digest_hex: String,
}

fn generate_digest(out: &PathBuf) -> anyhow::Result<()> {
    if !digest_test_vectors() {
        anyhow::bail!("digest test vectors failed");
    }
    let fixtures = vec![
        DigestFixture { name: "mesh-secret".into(), str1: "mesh".into(), str2: "secret".into(), digest_hex: hex::encode(generate_digest_go("mesh", "secret")) },
        DigestFixture { name: "empty-machine-id".into(), str1: "".into(), str2: "machine-id".into(), digest_hex: hex::encode(generate_digest_go("", "machine-id")) },
        DigestFixture { name: "test-empty".into(), str1: "test".into(), str2: "".into(), digest_hex: hex::encode(generate_digest_go("test", "")) },
        DigestFixture { name: "easytier-network".into(), str1: "easytier".into(), str2: "default-secret".into(), digest_hex: hex::encode(generate_digest_go("easytier", "default-secret")) },
        DigestFixture { name: "prod-secret".into(), str1: "prod".into(), str2: "secret".into(), digest_hex: hex::encode(generate_digest_go("prod", "secret")) },
        DigestFixture { name: "empty-empty".into(), str1: "".into(), str2: "".into(), digest_hex: hex::encode(generate_digest_go("", "")) },
    ];
    write_json(out.join("digest/fixtures.json"), &fixtures)?;
    Ok(())
}

#[derive(Serialize, Clone)]
struct RpcDescriptorFixture {
    name: String,
    domain_name: String,
    proto_name: String,
    service_name: String,
    method_index: u32,
    wire_hex: String,
}

fn marshal_descriptor(d: &RpcDescriptorFixture) -> Vec<u8> {
    let mut b = Vec::new();
    if !d.domain_name.is_empty() {
        b = append_bytes(b, 1, d.domain_name.as_bytes());
    }
    if !d.proto_name.is_empty() {
        b = append_bytes(b, 2, d.proto_name.as_bytes());
    }
    if !d.service_name.is_empty() {
        b = append_bytes(b, 3, d.service_name.as_bytes());
    }
    if d.method_index != 0 {
        b = append_varint(b, 4, d.method_index as u64);
    }
    b
}

#[derive(Serialize, Clone)]
struct RpcPacketFixture {
    name: String,
    from_peer: u32,
    to_peer: u32,
    transaction_id: i64,
    descriptor: Option<RpcDescriptorFixture>,
    body_hex: String,
    is_request: bool,
    total_pieces: u32,
    piece_idx: u32,
    trace_id: i32,
    wire_hex: String,
}

fn marshal_rpc_packet(f: &RpcPacketFixture) -> Vec<u8> {
    let mut b = Vec::new();
    if f.from_peer != 0 {
        b = append_varint(b, 1, f.from_peer as u64);
    }
    if f.to_peer != 0 {
        b = append_varint(b, 2, f.to_peer as u64);
    }
    if f.transaction_id != 0 {
        b = append_varint(b, 3, f.transaction_id as u64);
    }
    if let Some(d) = &f.descriptor {
        let db = marshal_descriptor(d);
        b = append_bytes(b, 4, &db);
    }
    let body = hex::decode(&f.body_hex).unwrap_or_default();
    if !body.is_empty() {
        b = append_bytes(b, 5, &body);
    }
    if f.is_request {
        b = append_varint(b, 6, 1);
    }
    if f.total_pieces != 0 {
        b = append_varint(b, 7, f.total_pieces as u64);
    }
    if f.piece_idx != 0 {
        b = append_varint(b, 8, f.piece_idx as u64);
    }
    if f.trace_id != 0 {
        b = append_varint(b, 9, f.trace_id as u64);
    }
    b
}

fn generate_rpc(out: &PathBuf) -> anyhow::Result<()> {
    let desc1 = RpcDescriptorFixture {
        name: "desc-1".into(),
        domain_name: "d".into(),
        proto_name: "p".into(),
        service_name: "s".into(),
        method_index: 7,
        wire_hex: "".into(),
    };
    let desc1_hex = hex::encode(marshal_descriptor(&desc1));
    let desc1 = RpcDescriptorFixture { wire_hex: desc1_hex, ..desc1 };

    let desc2 = RpcDescriptorFixture {
        name: "desc-easytier".into(),
        domain_name: "easytier".into(),
        proto_name: "common".into(),
        service_name: "TestService".into(),
        method_index: 1,
        wire_hex: "".into(),
    };
    let desc2_hex = hex::encode(marshal_descriptor(&desc2));
    let desc2 = RpcDescriptorFixture { wire_hex: desc2_hex, ..desc2 };

    let descriptors = vec![desc1.clone(), desc2.clone()];

    let pkt1 = RpcPacketFixture {
        name: "rpc-packet-1".into(),
        from_peer: 1,
        to_peer: 2,
        transaction_id: -1,
        descriptor: Some(desc1.clone()),
        body_hex: hex::encode(vec![0xaa, 0xbb]),
        is_request: true,
        total_pieces: 2,
        piece_idx: 1,
        trace_id: -2,
        wire_hex: "".into(),
    };
    let pkt1_hex = hex::encode(marshal_rpc_packet(&pkt1));
    let pkt1 = RpcPacketFixture { wire_hex: pkt1_hex, ..pkt1 };

    let pkt2 = RpcPacketFixture {
        name: "rpc-packet-minimal".into(),
        from_peer: 123,
        to_peer: 0,
        transaction_id: 0,
        descriptor: None,
        body_hex: hex::encode(b"hello"),
        is_request: true,
        total_pieces: 0,
        piece_idx: 0,
        trace_id: 0,
        wire_hex: "".into(),
    };
    let pkt2_hex = hex::encode(marshal_rpc_packet(&pkt2));
    let pkt2 = RpcPacketFixture { wire_hex: pkt2_hex, ..pkt2 };

    write_json(out.join("rpc/descriptors.json"), &descriptors)?;
    write_json(out.join("rpc/fixtures.json"), &vec![pkt1, pkt2])?;
    Ok(())
}

#[derive(Serialize)]
struct ConfigFixture {
    name: String,
    toml: String,
    normalized_toml: String,
}

fn generate_config(out: &PathBuf) -> anyhow::Result<()> {
    let fixtures = vec![
        ConfigFixture {
            name: "minimal".into(),
            toml: "network_name = \"test\"\n".into(),
            normalized_toml: "network_name = \"test\"\n".into(),
        },
        ConfigFixture {
            name: "full".into(),
            toml: "network_name = \"mesh\"\nnetwork_secret = \"secret\"\nipv4 = \"10.144.144.1\"\nlisteners = [\"tcp://0.0.0.0:11010\", \"udp://0.0.0.0:11010\"]\n".into(),
            normalized_toml: "network_name = \"mesh\"\nnetwork_secret = \"secret\"\nipv4 = \"10.144.144.1\"\nlisteners = [\"tcp://0.0.0.0:11010\", \"udp://0.0.0.0:11010\"]\n".into(),
        },
    ];
    write_json(out.join("config/fixtures.json"), &fixtures)?;
    Ok(())
}

#[derive(Serialize)]
struct WGFixture {
    name: String,
    payload_len: usize,
    peer_header_len: usize,
    header_hex: String,
    total_len: usize,
}

fn wg_header(payload_len: usize) -> Vec<u8> {
    let mut h = vec![0u8; 20];
    h[0] = 0x45;
    h[1] = 0;
    let total = payload_len + 16 + 20;
    h[2] = ((total >> 8) & 0xff) as u8;
    h[3] = (total & 0xff) as u8;
    h[4] = 0; h[5] = 0;
    h[6] = 0; h[7] = 0;
    h[8] = 64;
    h[9] = 0;
    h[10] = 0; h[11] = 0;
    h[12]=0; h[13]=0; h[14]=0; h[15]=0;
    h[16]=0; h[17]=0; h[18]=0; h[19]=0;
    h
}

fn generate_wg(out: &PathBuf) -> anyhow::Result<()> {
    let fixtures = vec![
        WGFixture { name: "wg-empty".into(), payload_len: 0, peer_header_len: 16, header_hex: hex::encode(wg_header(0)), total_len: 36 },
        WGFixture { name: "wg-small".into(), payload_len: 5, peer_header_len: 16, header_hex: hex::encode(wg_header(5)), total_len: 41 },
        WGFixture { name: "wg-100".into(), payload_len: 100, peer_header_len: 16, header_hex: hex::encode(wg_header(100)), total_len: 136 },
        WGFixture { name: "wg-mtu".into(), payload_len: 1380, peer_header_len: 16, header_hex: hex::encode(wg_header(1380)), total_len: 1416 },
    ];
    write_json(out.join("wg/fixtures.json"), &fixtures)?;
    Ok(())
}

#[derive(Serialize)]
struct SecureFixture {
    name: String,
    suite: String,
    suite_id: u8,
    root_key_hex: String,
    epoch: u32,
    seq: u64,
    plaintext_hex: String,
    wire_hex: String,
    nonce_hex: String,
}

fn generate_secure(out: &PathBuf) -> anyhow::Result<()> {
    // Deterministic fixtures matching Go's peer.NewSecureDatagramSession output.
    // Values are copied from Go generator to ensure byte-identical corpus.
    let fixtures = vec![
        SecureFixture {
            name: "aes128-epoch0-seq0".into(),
            suite: "aes-gcm".into(),
            suite_id: 1,
            root_key_hex: "1111111111111111111111111111111111111111111111111111111111111111".into(),
            epoch: 0,
            seq: 0,
            plaintext_hex: hex::encode(b"hello world"),
            wire_hex: "c322554123cf5724e68c0ff0184e4175907e7722ab58af8eade331000000000000000000000000".into(),
            nonce_hex: "000000000000000000000000".into(),
        },
        SecureFixture {
            name: "aes128-epoch1-seq5".into(),
            suite: "aes-gcm".into(),
            suite_id: 1,
            root_key_hex: "1111111111111111111111111111111111111111111111111111111111111111".into(),
            epoch: 1,
            seq: 5,
            plaintext_hex: hex::encode(b"test"),
            wire_hex: "1ba0a68f7f05923cd690af6eed31d0019171f61d000000010000000000000005".into(),
            nonce_hex: "000000010000000000000005".into(),
        },
        SecureFixture {
            name: "aes256-seq0".into(),
            suite: "aes-256-gcm".into(),
            suite_id: 2,
            root_key_hex: "1111111111111111111111111111111111111111111111111111111111111111".into(),
            epoch: 0,
            seq: 0,
            plaintext_hex: hex::encode(b"hello world"),
            wire_hex: "3dacf3a35ee4e1db24b1e6c7aa60c4ce44d180c75c5cdf90278a8c000000000000000000000000".into(),
            nonce_hex: "000000000000000000000000".into(),
        },
        SecureFixture {
            name: "chacha20-seq42".into(),
            suite: "chacha20".into(),
            suite_id: 3,
            root_key_hex: "1111111111111111111111111111111111111111111111111111111111111111".into(),
            epoch: 42,
            seq: 42,
            plaintext_hex: hex::encode(b"easytier secure datagram"),
            wire_hex: "d0978014366893975d0975fd6198d2064afb07d06947f006fbb6f36fc571bc998bfd2af39c079e3a0000002a000000000000002a".into(),
            nonce_hex: "0000002a000000000000002a".into(),
        },
        SecureFixture {
            name: "chacha20-empty".into(),
            suite: "chacha20".into(),
            suite_id: 3,
            root_key_hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".into(),
            epoch: 0,
            seq: 0,
            plaintext_hex: "".into(),
            wire_hex: "594b83e012cd77e2e1a271d26f01bf4f000000000000000000000000".into(),
            nonce_hex: "000000000000000000000000".into(),
        },
    ];
    write_json(out.join("secure/fixtures.json"), &fixtures)?;
    Ok(())
}

#[derive(Serialize)]
struct RouteFixture {
    name: String,
    local_peer_id: u32,
    links: Vec<Link>,
    expected_routes: Vec<Route>,
}
#[derive(Serialize)]
struct Link { A: u32, B: u32, Cost: u32 }
#[derive(Serialize)]
struct Route { Destination: u32, NextHop: u32, Cost: u64 }

fn generate_route(out: &PathBuf) -> anyhow::Result<()> {
    let fixtures = vec![
        RouteFixture {
            name: "line-3".into(),
            local_peer_id: 1,
            links: vec![Link{A:1,B:2,Cost:10}, Link{A:2,B:3,Cost:10}],
            expected_routes: vec![Route{Destination:2,NextHop:2,Cost:10}, Route{Destination:3,NextHop:2,Cost:20}],
        },
        RouteFixture {
            name: "triangle".into(),
            local_peer_id: 1,
            links: vec![Link{A:1,B:2,Cost:5}, Link{A:2,B:3,Cost:5}, Link{A:1,B:3,Cost:15}],
            expected_routes: vec![Route{Destination:2,NextHop:2,Cost:5}, Route{Destination:3,NextHop:2,Cost:10}],
        },
        RouteFixture {
            name: "equal-cost".into(),
            local_peer_id: 1,
            links: vec![Link{A:1,B:2,Cost:10}, Link{A:1,B:3,Cost:10}, Link{A:2,B:4,Cost:10}, Link{A:3,B:4,Cost:10}],
            expected_routes: vec![Route{Destination:2,NextHop:2,Cost:10}, Route{Destination:3,NextHop:3,Cost:10}, Route{Destination:4,NextHop:2,Cost:20}],
        },
        RouteFixture {
            name: "star-5".into(),
            local_peer_id: 1,
            links: vec![Link{A:1,B:2,Cost:1}, Link{A:1,B:3,Cost:1}, Link{A:1,B:4,Cost:1}, Link{A:1,B:5,Cost:1}],
            expected_routes: vec![Route{Destination:2,NextHop:2,Cost:1}, Route{Destination:3,NextHop:3,Cost:1}, Route{Destination:4,NextHop:4,Cost:1}, Route{Destination:5,NextHop:5,Cost:1}],
        },
    ];
    write_json(out.join("route/fixtures.json"), &fixtures)?;
    Ok(())
}
