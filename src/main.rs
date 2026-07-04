// src/main.rs
// Flowmeter v0.0.3 - sFlow v5 parser (header + flow samples + raw packet records)

use std::net::{Ipv4Addr, UdpSocket};

fn main() -> std::io::Result<()> {
    let bind_addr = "0.0.0.0:6343";

    println!("🚀 Flowmeter v0.0.3 starting...");
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

                parse_sflow_datagram(&buf[..size]);
            }
            Err(e) => {
                eprintln!("❌ Error: {}", e);
            }
        }
    }
}

// ── A tiny helper: read a big-endian u32 at `*offset`, then advance `*offset` by 4.
// `offset: &mut usize` is a *mutable reference* — the function moves the caller's
// cursor forward, so repeated calls naturally walk through the packet.
fn read_u32(data: &[u8], offset: &mut usize) -> u32 {
    let value = u32::from_be_bytes([
        data[*offset],
        data[*offset + 1],
        data[*offset + 2],
        data[*offset + 3],
    ]);
    *offset += 4;
    value
}

// ── The kinds of samples an sFlow datagram can carry.
// In sFlow the 32-bit "data format" is (enterprise << 12) | format.
// For standard sFlow, enterprise == 0, so the format is just 1/2/3/4.
enum SampleType {
    FlowSample,            // format 1
    CounterSample,         // format 2
    ExpandedFlowSample,    // format 3
    ExpandedCounterSample, // format 4
    Unknown(u32),          // anything else — keep the raw value around
}

impl SampleType {
    fn from_format(format: u32) -> Self {
        match format {
            1 => SampleType::FlowSample,
            2 => SampleType::CounterSample,
            3 => SampleType::ExpandedFlowSample,
            4 => SampleType::ExpandedCounterSample,
            other => SampleType::Unknown(other),
        }
    }

    fn label(&self) -> String {
        match self {
            SampleType::FlowSample => "Flow Sample".to_string(),
            SampleType::CounterSample => "Counter Sample".to_string(),
            SampleType::ExpandedFlowSample => "Expanded Flow Sample".to_string(),
            SampleType::ExpandedCounterSample => "Expanded Counter Sample".to_string(),
            SampleType::Unknown(raw) => format!("Unknown (format {})", raw),
        }
    }
}

fn parse_sflow_datagram(data: &[u8]) {
    // sFlow v5 datagram header (first 28 bytes, IPv4 agent):
    //   0-3   version (== 5)
    //   4-7   agent IP version (1 = IPv4)
    //   8-11  agent IP
    //   12-15 sub-agent id
    //   16-19 sequence number
    //   20-23 uptime (ms)
    //   24-27 number of samples
    let mut offset = 0usize;

    let version = read_u32(data, &mut offset);
    if version != 5 {
        println!("⚠️  Not a sFlow v5 packet (got version {})", version);
        return;
    }

    let _agent_ip_type = read_u32(data, &mut offset);
    let agent_ip = Ipv4Addr::new(
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    );
    offset += 4;
    let sub_agent_id = read_u32(data, &mut offset);
    let sequence_number = read_u32(data, &mut offset);
    let uptime_ms = read_u32(data, &mut offset);
    let sample_count = read_u32(data, &mut offset);

    println!("✅ sFlow v5 datagram:");
    println!("   📍 Agent IP:      {}", agent_ip);
    println!("   🔢 Sub-agent ID:  {}", sub_agent_id);
    println!("   📊 Sequence #:    {}", sequence_number);
    println!("   ⏱️  Uptime:        {} seconds", uptime_ms / 1000);
    println!("   📥 Sample count:  {}", sample_count);

    // `offset` is now 28 — exactly where the samples begin.
    parse_samples(data, &mut offset, sample_count);
}

// Walk the list of samples that follow the 28-byte header.
// Each sample is length-prefixed:
//   4 bytes  sample type   (data format)
//   4 bytes  sample length (bytes of data that follow)
//   N bytes  sample data
fn parse_samples(data: &[u8], offset: &mut usize, sample_count: u32) {
    for i in 0..sample_count {
        // Every sample needs at least its 8-byte type+length prefix.
        if *offset + 8 > data.len() {
            println!("   ⚠️  Truncated: ran out of bytes before sample {}", i + 1);
            return;
        }

        let raw_format = read_u32(data, offset);
        let sample_length = read_u32(data, offset) as usize;

        // The data format is (enterprise << 12) | format.
        let enterprise = raw_format >> 12;
        let format = raw_format & 0xFFF;
        let kind = SampleType::from_format(if enterprise == 0 { format } else { raw_format });

        // The declared length must actually fit in what we received.
        if *offset + sample_length > data.len() {
            println!(
                "   ⚠️  Sample {} claims {} bytes but packet is too short",
                i + 1,
                sample_length
            );
            return;
        }

        println!(
            "   ┌─ Sample {}/{}: {} ({} bytes)",
            i + 1,
            sample_count,
            kind.label(),
            sample_length
        );

        // Slice out just this sample's data so the inner parser can't read past it.
        let sample_data = &data[*offset..*offset + sample_length];

        match kind {
            SampleType::FlowSample => parse_flow_sample(sample_data),
            _ => println!("   └─ (not decoded yet)"),
        }

        // Jump straight to the next sample, regardless of what was inside.
        *offset += sample_length;
    }
}

// Inside a flow sample (format 1): decode the header fields, then walk
// the flow records that follow.
//
// flow_sample layout:
//   sequence_number (4) | source_id (4) | sampling_rate (4) | sample_pool (4)
//   drops (4) | input (4) | output (4) | flow_records_count (4) | records...
fn parse_flow_sample(data: &[u8]) {
    if data.len() < 32 {
        println!("   └─ ⚠️  Flow sample too short");
        return;
    }

    let mut offset = 0usize;
    let _seq = read_u32(data, &mut offset);
    let source_id = read_u32(data, &mut offset);
    let sampling_rate = read_u32(data, &mut offset);
    let _sample_pool = read_u32(data, &mut offset);
    let drops = read_u32(data, &mut offset);
    let input = read_u32(data, &mut offset);
    let output = read_u32(data, &mut offset);
    let record_count = read_u32(data, &mut offset);

    // source_id is packed: top 8 bits = data source type, bottom 24 bits = index.
    let src_type = source_id >> 24;
    let src_index = source_id & 0x00FF_FFFF;
    let src_kind = match src_type {
        0 => "ifIndex",
        1 => "smonVlanDataSource",
        2 => "entPhysicalEntry",
        _ => "unknown",
    };

    println!("   │  🎯 Sampling rate: 1 in {}", sampling_rate);
    println!("   │  🔌 Source:        {} {}", src_kind, src_index);
    println!("   │  🚪 Interfaces:    in {} → out {}", input, output);
    println!("   │  🗑️  Drops:         {}", drops);
    println!("   │  📦 Flow records:  {}", record_count);

    // Everything after the 32-byte flow-sample header is the records themselves.
    parse_flow_records(&data[offset..], record_count);
}

// ── v0.0.3: flow records ─────────────────────────────────────────────
// Each flow record inside a flow sample uses the SAME length-prefixed
// envelope as the samples themselves:
//   4 bytes  record type | 4 bytes  record length | N bytes data
fn parse_flow_records(data: &[u8], record_count: u32) {
    let mut offset = 0usize;
    for i in 0..record_count {
        if offset + 8 > data.len() {
            println!("   │   ⚠️  Truncated: ran out of bytes before record {}", i + 1);
            return;
        }

        let raw_format = read_u32(data, &mut offset);
        let record_length = read_u32(data, &mut offset) as usize;
        let format = raw_format & 0xFFF; // enterprise 0 assumed, same as samples

        if offset + record_length > data.len() {
            println!(
                "   │   ⚠️  Record {} claims {} bytes but sample is too short",
                i + 1,
                record_length
            );
            return;
        }
        let record_data = &data[offset..offset + record_length];

        match format {
            1 => {
                println!(
                    "   │   ┌─ Record {}: Raw Packet Header ({} bytes)",
                    i + 1,
                    record_length
                );
                parse_raw_packet_record(record_data);
            }
            other => {
                println!(
                    "   │   ── Record {}: format {} (not decoded yet)",
                    i + 1,
                    other
                );
            }
        }

        offset += record_length;
    }
}

// Raw packet header record (flow record format 1):
//   header_protocol (4) | frame_length (4) | stripped (4) | header_size (4)
//   header bytes (header_size bytes, padded up to a 4-byte boundary)
// header_protocol 1 == Ethernet. The header bytes are the first N bytes of
// an actual frame the switch sampled — a real packet, captured mid-flight.
fn parse_raw_packet_record(data: &[u8]) {
    if data.len() < 16 {
        println!("   │   └─ ⚠️  Raw packet record too short");
        return;
    }

    let mut offset = 0usize;
    let header_protocol = read_u32(data, &mut offset);
    let frame_length = read_u32(data, &mut offset);
    let _stripped = read_u32(data, &mut offset);
    let header_size = read_u32(data, &mut offset) as usize;

    if offset + header_size > data.len() {
        println!(
            "   │   └─ ⚠️  Header claims {} bytes but record is too short",
            header_size
        );
        return;
    }
    let frame = &data[offset..offset + header_size];

    println!(
        "   │   │  🖼️  Frame: {} bytes on the wire, {} captured",
        frame_length, header_size
    );

    if header_protocol != 1 {
        println!(
            "   │   └─ (header protocol {} — only Ethernet decoded)",
            header_protocol
        );
        return;
    }

    parse_ethernet(frame);
}

// Ethernet II frame:
//   bytes 0-5 dst MAC | 6-11 src MAC | 12-13 EtherType
// EtherType says what's inside: 0x0800 = IPv4, 0x86DD = IPv6.
// Note: fields are NOT 4-byte aligned anymore — we index bytes directly.
fn parse_ethernet(frame: &[u8]) {
    if frame.len() < 14 {
        println!("   │   └─ ⚠️  Frame too short for an Ethernet header");
        return;
    }

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

    match ethertype {
        0x0800 => {
            // `if let Some(x) = ...` unpacks an Option: the block runs only
            // if parse_ipv4 succeeded, with the result bound to `ip`.
            if let Some(ip) = parse_ipv4(&frame[14..]) {
                println!(
                    "   │   │  🌐 IPv4:  {} → {} ({})",
                    ip.src,
                    ip.dst,
                    protocol_name(ip.protocol)
                );
                // The transport header starts right after the IP header.
                parse_ports(&frame[14 + ip.header_len..], ip.protocol);
            } else {
                println!("   │   └─ ⚠️  IPv4 header truncated or invalid");
            }
        }
        0x86DD => println!("   │   └─ 🌐 IPv6 (not decoded yet)"),
        other => println!("   │   └─ EtherType 0x{:04x} (not decoded)", other),
    }
}

// A struct groups the fields we pulled out of the IPv4 header, so we can
// return them as ONE value instead of a pile of loose variables.
struct Ipv4Header {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,      // 6 = TCP, 17 = UDP, 1 = ICMP
    header_len: usize, // IHL * 4 — where the TCP/UDP header starts
}

// IPv4 header (min 20 bytes):
//   byte 0      version (high 4 bits) + IHL (low 4 bits, in 32-bit words)
//   byte 9      protocol
//   bytes 12-15 src IP | 16-19 dst IP
// Returns an Option: Some(header) on success, None if not parseable —
// the *caller* decides what failure means for it.
fn parse_ipv4(packet: &[u8]) -> Option<Ipv4Header> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }
    let header_len = ((packet[0] & 0x0F) as usize) * 4;
    if header_len < 20 || packet.len() < header_len {
        return None;
    }

    Some(Ipv4Header {
        src: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        dst: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        protocol: packet[9],
        header_len,
    })
}

// `&'static str` = a string literal baked into the binary, alive for the
// whole program — the cheapest kind of string to return.
fn protocol_name(protocol: u8) -> &'static str {
    match protocol {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        _ => "?",
    }
}

// TCP and UDP headers share the same first 4 bytes:
//   bytes 0-1: source port       (big-endian u16)
//   bytes 2-3: destination port  (big-endian u16)
fn parse_ports(segment: &[u8], protocol: u8) {
    if segment.len() < 4 {
        println!("   │   └─ ⚠️  Transport header truncated");
        return;
    }

    let src_port = u16::from_be_bytes([segment[0], segment[1]]);
    let dst_port = u16::from_be_bytes([segment[2], segment[3]]);

    println!(
        "   │   └─ 🔌 {} ports: {} → {}",
        protocol_name(protocol),
        src_port,
        dst_port
    );
}
