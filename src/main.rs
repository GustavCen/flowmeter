// src/main.rs
// Flowmeter v0.0.1 - sFlow v5 header parser

use std::net::{Ipv4Addr, UdpSocket};

fn main() -> std::io::Result<()> {
    let bind_addr = "0.0.0.0:6343";

    println!("🚀 Flowmeter v0.0.1 starting...");
    println!("📡 Listening on {} for sFlow v5 packets", bind_addr);
    println!();

    let socket = UdpSocket::bind(bind_addr)?;
    let mut buf = [0u8; 2048];
    let mut packet_count: u64 = 0;

    loop {
        match socket.recv_from(&mut buf) {
            Ok((size, src)) => {
                packet_count += 1;
                println!("─────────────────────────────────────────────");
                println!(
                    "📦 Packet #{} | From: {} | Size: {} bytes",
                    packet_count, src, size
                );

                // sFlow v5 header is 28 bytes
                if size < 28 {
                    println!("⚠️  Too small to be a valid sFlow packet");
                    continue;
                }

                parse_sflow_header(&buf[..size]);
            }
            Err(e) => {
                eprintln!("❌ Error: {}", e);
            }
        }
    }
}

fn parse_sflow_header(data: &[u8]) {
    // sFlow v5 packet structure (first 28 bytes):
    // Bytes 0-3:   Version (should be 5)
    // Bytes 4-7:   IP version of agent (1=IPv4, 2=IPv6)
    // Bytes 8-11:  Agent IP address (IPv4)
    // Bytes 12-15: Sub-agent ID
    // Bytes 16-19: Sequence number
    // Bytes 20-23: System uptime (milliseconds)
    // Bytes 24-27: Number of samples in this packet

    let version = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

    if version != 5 {
        println!("⚠️  Not a sFlow v5 packet (got version {})", version);
        println!("   This is likely a test packet, not real sFlow data");
        return;
    }

    let _ip_version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let agent_ip = Ipv4Addr::new(data[8], data[9], data[10], data[11]);
    let sub_agent_id = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    let sequence_number = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
    let uptime_ms = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
    let sample_count = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);

    println!("✅ sFlow v5 packet parsed:");
    println!("   📍 Agent IP:      {}", agent_ip);
    println!("   🔢 Sub-agent ID:  {}", sub_agent_id);
    println!("   📊 Sequence #:    {}", sequence_number);
    println!("   ⏱️  Uptime:        {} seconds", uptime_ms / 1000);
    println!("   📥 Sample count:  {}", sample_count);
}
