//! Fake-IP DNS support for TUN mode.
//!
//! This module answers DNS A queries with synthetic IPv4 addresses and keeps a
//! reverse mapping so TCP/UDP traffic to those addresses can be routed by the
//! original domain name.

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use log::{debug, trace};
use parking_lot::Mutex;
use rustc_hash::FxHashMap;

#[derive(Debug)]
struct FakeDnsInner {
    name_to_ip: FxHashMap<String, Ipv4Addr>,
    ip_to_name: FxHashMap<Ipv4Addr, String>,
    next_offset: u32,
}

/// Shared fake-IP allocator and DNS response builder.
#[derive(Debug, Clone)]
pub struct FakeDns {
    inner: Arc<Mutex<FakeDnsInner>>,
    base: u32,
    first_offset: u32,
    usable_count: u32,
    ttl: u32,
}

#[derive(Debug)]
struct DnsQuestion<'a> {
    id: u16,
    flags: u16,
    qname: String,
    qtype: u16,
    qclass: u16,
    question: &'a [u8],
}

impl FakeDns {
    pub fn new(range: &str, ttl: u32) -> io::Result<Self> {
        let (base, prefix_len) = parse_ipv4_cidr(range)?;
        let host_count = if prefix_len == 32 {
            1
        } else {
            1u32
                .checked_shl((32 - prefix_len) as u32)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "fake_ip range too large")
                })?
        };

        let (first_offset, usable_count) = if host_count <= 2 {
            (0, host_count)
        } else {
            // Avoid the network and broadcast addresses for conventional IPv4 ranges.
            (1, host_count - 2)
        };

        if usable_count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fake_ip range has no usable addresses",
            ));
        }

        Ok(Self {
            inner: Arc::new(Mutex::new(FakeDnsInner {
                name_to_ip: FxHashMap::default(),
                ip_to_name: FxHashMap::default(),
                next_offset: first_offset,
            })),
            base: u32::from(base),
            first_offset,
            usable_count,
            ttl,
        })
    }

    pub fn lookup_ip(&self, ip: IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(ip) => self.inner.lock().ip_to_name.get(&ip).cloned(),
            IpAddr::V6(_) => None,
        }
    }

    pub fn handle_dns_query(&self, payload: &[u8]) -> Option<Vec<u8>> {
        let question = match parse_dns_question(payload) {
            Ok(question) => question,
            Err(e) => {
                trace!("fake DNS ignored packet: {e}");
                return None;
            }
        };

        // Only IN-class A records get fake IPv4 answers. Return a valid empty
        // response for other query types so clients can fall back to A.
        let answer_ip = if question.qclass == 1 && question.qtype == 1 {
            match self.get_or_allocate(&question.qname) {
                Ok(ip) => Some(ip),
                Err(e) => {
                    debug!("fake DNS allocation failed for {}: {}", question.qname, e);
                    None
                }
            }
        } else {
            None
        };

        Some(build_dns_response(&question, answer_ip, self.ttl))
    }

    fn get_or_allocate(&self, name: &str) -> io::Result<Ipv4Addr> {
        let name = normalize_domain(name);
        let mut inner = self.inner.lock();

        if let Some(ip) = inner.name_to_ip.get(&name) {
            return Ok(*ip);
        }

        for _ in 0..self.usable_count {
            let offset = inner.next_offset;
            inner.next_offset = self.first_offset
                + ((inner.next_offset - self.first_offset + 1) % self.usable_count);

            let ip = Ipv4Addr::from(self.base.wrapping_add(offset));
            if inner.ip_to_name.contains_key(&ip) {
                continue;
            }

            inner.name_to_ip.insert(name.clone(), ip);
            inner.ip_to_name.insert(ip, name.clone());
            debug!("fake DNS allocated {} -> {}", name, ip);
            return Ok(ip);
        }

        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "fake_ip range exhausted",
        ))
    }
}

fn normalize_domain(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn parse_ipv4_cidr(range: &str) -> io::Result<(Ipv4Addr, u8)> {
    let (addr, prefix) = range.split_once('/').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "fake_ip range must be IPv4 CIDR, for example 198.18.0.0/16",
        )
    })?;

    let addr = addr.parse::<Ipv4Addr>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid fake_ip IPv4 address: {e}"),
        )
    })?;
    let prefix = prefix.parse::<u8>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid fake_ip CIDR prefix: {e}"),
        )
    })?;
    if prefix == 0 || prefix > 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fake_ip CIDR prefix must be between 1 and 32",
        ));
    }

    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let base = Ipv4Addr::from(u32::from(addr) & mask);
    Ok((base, prefix))
}

fn parse_dns_question(packet: &[u8]) -> io::Result<DnsQuestion<'_>> {
    if packet.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS packet too short",
        ));
    }

    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS packet is not a query",
        ));
    }
    if flags & 0x7800 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported DNS opcode",
        ));
    }

    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fake DNS only supports one question",
        ));
    }

    let (qname, name_end) = parse_qname(packet, 12)?;
    if packet.len() < name_end + 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS question truncated",
        ));
    }

    let qtype = u16::from_be_bytes([packet[name_end], packet[name_end + 1]]);
    let qclass = u16::from_be_bytes([packet[name_end + 2], packet[name_end + 3]]);
    let question_end = name_end + 4;

    Ok(DnsQuestion {
        id,
        flags,
        qname,
        qtype,
        qclass,
        question: &packet[12..question_end],
    })
}

fn parse_qname(packet: &[u8], mut offset: usize) -> io::Result<(String, usize)> {
    let mut labels = Vec::new();

    loop {
        let len = *packet.get(offset).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "DNS qname truncated")
        })?;
        offset += 1;

        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compressed DNS qname is not supported in questions",
            ));
        }
        if len > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid DNS label length",
            ));
        }

        let end = offset + len as usize;
        let label = packet.get(offset..end).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "DNS label truncated")
        })?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        offset = end;
    }

    if labels.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty DNS qname",
        ));
    }

    Ok((labels.join("."), offset))
}

fn build_dns_response(
    question: &DnsQuestion<'_>,
    answer_ip: Option<Ipv4Addr>,
    ttl: u32,
) -> Vec<u8> {
    let answer_len = if answer_ip.is_some() { 16 } else { 0 };
    let mut response = Vec::with_capacity(12 + question.question.len() + answer_len);

    response.extend_from_slice(&question.id.to_be_bytes());

    // QR=1, RD copied from request, RA=1, RCODE=0.
    let response_flags = 0x8000 | (question.flags & 0x0100) | 0x0080;
    response.extend_from_slice(&(response_flags as u16).to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    let answer_count = if answer_ip.is_some() { 1u16 } else { 0u16 };
    response.extend_from_slice(&answer_count.to_be_bytes()); // ANCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    response.extend_from_slice(question.question);

    if let Some(ip) = answer_ip {
        response.extend_from_slice(&[0xc0, 0x0c]); // pointer to question name
        response.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        response.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        response.extend_from_slice(&ttl.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        response.extend_from_slice(&ip.octets());
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_a(name: &str) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0x1234u16.to_be_bytes());
        packet.extend_from_slice(&0x0100u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet
    }

    #[test]
    fn allocates_and_answers_a_query() {
        let fake = FakeDns::new("198.18.0.0/16", 60).unwrap();
        let response = fake.handle_dns_query(&query_a("www.youtube.com")).unwrap();

        assert_eq!(&response[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert_eq!(&response[response.len() - 4..], &[198, 18, 0, 1]);
        assert_eq!(
            fake.lookup_ip(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))),
            Some("www.youtube.com".to_string())
        );
    }

    #[test]
    fn reuses_existing_allocation() {
        let fake = FakeDns::new("198.18.0.0/16", 60).unwrap();
        let first = fake.handle_dns_query(&query_a("naixi.net")).unwrap();
        let second = fake.handle_dns_query(&query_a("naixi.net")).unwrap();

        assert_eq!(&first[first.len() - 4..], &second[second.len() - 4..]);
    }
}
