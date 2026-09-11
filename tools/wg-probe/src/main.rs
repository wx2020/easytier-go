// wg-probe: stock WireGuard initiator (real boringtun Tunn) used by the Go
// interop test. Usage:
//   wg-probe <server-addr> <server-pubkey-hex> <client-privkey-hex> <client-ip> <server-ip>
// It handshakes with the server, sends one IPv4 packet with payload
// "boringtun-probe", and expects the same payload echoed back. Exit 0 on
// success, 1 on any failure (with a message on stderr).

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::net::UdpSocket;
use std::time::{Duration, Instant};

fn hex_to_32(s: &str) -> [u8; 32] {
    let v: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
        .collect();
    v.try_into().expect("need 32 bytes")
}

fn send_to(sock: &UdpSocket, server: &str, data: &[u8]) {
    sock.send_to(data, server).expect("send");
}

fn recv_from(sock: &UdpSocket, deadline: Instant) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        sock.set_read_timeout(Some(left)).expect("timeout");
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => return buf[..n].to_vec(),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                eprintln!("probe: receive timeout");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("probe: recv: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn build_ipv4(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8; 20 + payload.len()];
    pkt[0] = 0x45;
    let total = pkt.len() as u16;
    pkt[2..4].copy_from_slice(&total.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 1; // ICMP, payload-agnostic
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);
    pkt[20..].copy_from_slice(payload);
    pkt
}

fn parse_ipv4(s: &str) -> [u8; 4] {
    let parts: Vec<u8> = s.split('.').map(|p| p.parse().expect("bad ip")).collect();
    [parts[0], parts[1], parts[2], parts[3]]
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        eprintln!("usage: wg-probe <server-addr> <server-pubkey-hex> <client-privkey-hex> <client-ip> <server-ip>");
        std::process::exit(2);
    }
    let server = args[1].clone();
    let server_pub = PublicKey::from(hex_to_32(&args[2]));
    let client_priv = StaticSecret::from(hex_to_32(&args[3]));
    let client_ip = parse_ipv4(&args[4]);
    let server_ip = parse_ipv4(&args[5]);

    let mut tunn = Tunn::new(client_priv, server_pub, None, None, 0x01000000, None);
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let start = Instant::now();
    let deadline = start + Duration::from_secs(25);

    // 1. Handshake initiation.
    let mut buf = vec![0u8; 2048];
    let init = match tunn.format_handshake_initiation(&mut buf, false) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => {
            eprintln!("probe: unexpected initiation result: {other:?}");
            std::process::exit(1);
        }
    };
    send_to(&sock, &server, &init);

    // 2. Drive the handshake until our Tunn emits no more network output
    //    for an inbound packet (i.e. response processed -> keepalive out).
    let mut handshook = false;
    while !handshook {
        let packet = recv_from(&sock, deadline);
        let mut out = vec![0u8; 2048];
        match tunn.decapsulate(None, &packet, &mut out) {
            TunnResult::WriteToNetwork(reply) => {
                let reply = reply.to_vec();
                // A keepalive response means the handshake completed.
                send_to(&sock, &server, &reply);
                if reply.len() < 92 {
                    handshook = true;
                }
            }
            TunnResult::Done => {}
            TunnResult::Err(e) => {
                eprintln!("probe: handshake error: {e:?}");
                std::process::exit(1);
            }
            TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => {
                handshook = true;
            }
        }
        if Instant::now() > deadline {
            eprintln!("probe: handshake timed out");
            std::process::exit(1);
        }
    }

    // 3. Send one data packet, expect the echo.
    let inner = build_ipv4(client_ip, server_ip, b"boringtun-probe");
    let mut enc = vec![0u8; 2048];
    let data = match tunn.encapsulate(&inner, &mut enc) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => {
            eprintln!("probe: encapsulate: {other:?}");
            std::process::exit(1);
        }
    };
    send_to(&sock, &server, &data);

    loop {
        let packet = recv_from(&sock, deadline);
        let mut out = vec![0u8; 2048];
        match tunn.decapsulate(None, &packet, &mut out) {
            TunnResult::WriteToTunnelV4(payload, _) | TunnResult::WriteToTunnelV6(payload, _) => {
                if payload.ends_with(b"boringtun-probe") {
                    println!("probe: echo OK ({} bytes)", payload.len());
                    return;
                }
                eprintln!("probe: unexpected payload ({} bytes)", payload.len());
            }
            TunnResult::WriteToNetwork(reply) => {
                send_to(&sock, &server, &reply.to_vec());
            }
            TunnResult::Done => {}
            TunnResult::Err(e) => {
                eprintln!("probe: data error: {e:?}");
                std::process::exit(1);
            }
        }
        if Instant::now() > deadline {
            eprintln!("probe: echo timed out");
            std::process::exit(1);
        }
    }
}
