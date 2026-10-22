use std::{fmt::Write, net::IpAddr};

use anyhow::{Context, Result, ensure};

pub(super) fn make_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut p = vec![0x53, 0x54, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    p[..2].copy_from_slice(&rand::random::<u16>().to_be_bytes());
    for label in name
        .trim_end_matches('.')
        .split('.')
        .filter(|label| !label.is_empty())
    {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.extend_from_slice(&[0, (qtype >> 8) as u8, qtype as u8, 0, 1]);
    p
}

pub(super) fn answer_ips(packet: &[u8]) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut aliases = Vec::new();
    let mut addresses = Vec::new();
    if packet.get(3).is_none_or(|flags| flags & 0x0f != 0) {
        return out;
    }
    let Some(expected) = query_name(packet) else {
        return out;
    };
    let mut pos = 12;
    let Some((qd, an, _, _)) = header_counts(packet) else {
        return out;
    };
    for _ in 0..qd {
        if let Some(next) = skip_name(packet, pos).and_then(|pos| pos.checked_add(4)) {
            pos = next;
        } else {
            return out;
        }
    }
    for _ in 0..an {
        let Some((owner, next)) = read_name(packet, pos) else {
            break;
        };
        pos = next;
        let Some(fields) = packet.get(pos..pos.saturating_add(10)) else {
            break;
        };
        let typ = u16::from_be_bytes([fields[0], fields[1]]);
        let class = u16::from_be_bytes([fields[2], fields[3]]);
        let len = u16::from_be_bytes([fields[8], fields[9]]) as usize;
        pos += 10;
        let Some(data) = packet.get(pos..pos.saturating_add(len)) else {
            break;
        };
        if class == 1 {
            if typ == 5 {
                if let Some((target, end)) = read_name(packet, pos)
                    && end == pos + len
                {
                    aliases.push((owner, target));
                }
            } else if typ == 1 && len == 4 {
                addresses.push((owner, IpAddr::from([data[0], data[1], data[2], data[3]])));
            } else if typ == 28 && len == 16 {
                let mut bytes = [0; 16];
                bytes.copy_from_slice(data);
                addresses.push((owner, IpAddr::from(bytes)));
            }
        }
        pos += len;
    }
    let mut chain = vec![expected.as_str()];
    while let Some((_, target)) = aliases
        .iter()
        .find(|(owner, _)| owner.as_str() == *chain.last().unwrap())
    {
        if chain.contains(&target.as_str()) {
            break;
        }
        chain.push(target.as_str());
    }
    for (owner, ip) in addresses {
        if chain.contains(&owner.as_str()) {
            out.push(ip);
        }
    }
    out
}

fn read_name(packet: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut pos = start;
    let mut end = None;
    let mut total = 0usize;
    for _ in 0..128 {
        let len = *packet.get(pos)?;
        if len & 0xc0 == 0xc0 {
            let offset = usize::from(len & 0x3f) << 8 | usize::from(*packet.get(pos + 1)?);
            if offset >= pos {
                return None;
            }
            end.get_or_insert(pos + 2);
            pos = offset;
            continue;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        pos += 1;
        if len == 0 {
            return Some((name, end.unwrap_or(pos)));
        }
        total += usize::from(len) + 1;
        if total > 254 {
            return None;
        }
        let bytes = packet.get(pos..pos.checked_add(usize::from(len))?)?;
        if !name.is_empty() {
            name.push('.');
        }
        for &byte in bytes {
            match byte {
                b'!'..=b'~' if byte != b'.' && byte != b'\\' => {
                    name.push(char::from(byte.to_ascii_lowercase()));
                }
                _ => write!(name, "\\{byte:03}").unwrap(),
            }
        }
        pos += usize::from(len);
    }
    None
}

pub(super) fn query(packet: &[u8]) -> Option<(String, u16, u16)> {
    if packet.len() < 12 || packet[2] & 0xf8 != 0 || packet[4..6] != [0, 1] {
        return None;
    }
    let name = query_name(packet)?;
    let end = skip_name(packet, 12)?;
    Some((
        name,
        u16::from_be_bytes([*packet.get(end)?, *packet.get(end + 1)?]),
        u16::from_be_bytes([*packet.get(end + 2)?, *packet.get(end + 3)?]),
    ))
}

pub(super) fn validate_response(request: &[u8], response: &[u8]) -> Result<()> {
    let question_end = skip_name(request, 12)
        .and_then(|end| end.checked_add(4))
        .context("invalid DNS request question")?;
    let response_end = skip_name(response, 12)
        .and_then(|end| end.checked_add(4))
        .context("invalid DNS response question")?;
    ensure!(
        response.len() >= 12
            && response[..2] == request[..2]
            && response[2] & 0x80 != 0
            && response[2] & 0x78 == request[2] & 0x78
            && response[4..6] == [0, 1]
            && response_end <= response.len()
            && question_end <= request.len()
            && response[12..response_end] == request[12..question_end],
        "DNS response does not match query"
    );
    Ok(())
}

pub(super) fn query_name(packet: &[u8]) -> Option<String> {
    read_name(packet, 12).map(|(name, _)| name)
}

pub(super) fn udp_response(
    request: &[u8],
    mut response: Vec<u8>,
    max_packet_bytes: usize,
) -> Result<Vec<u8>> {
    let request_opt = opt_record(request)?;
    let capacity = request_opt.map_or(512, |fields| {
        usize::from(u16::from_be_bytes([fields[2], fields[3]])).max(512)
    });
    let server_capacity = max_packet_bytes.min(65_507);
    if response.len() > capacity.min(server_capacity) {
        let opt_flags = if let Some(fields) = request_opt {
            Some(
                opt_record(&response)?.map_or([0, 0, fields[6], fields[7]], |fields| {
                    fields[4..8].try_into().unwrap()
                }),
            )
        } else {
            None
        };
        let end = skip_name(&response, 12).context("invalid DNS response question")? + 4;
        ensure!(end <= response.len(), "invalid DNS response question");
        response.truncate(end);
        response[2] |= 0x02;
        response[6..12].fill(0);
        if let Some(flags) = opt_flags {
            response[10..12].copy_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&[0, 0, 41]);
            response.extend_from_slice(&(server_capacity as u16).to_be_bytes());
            response.extend_from_slice(&flags);
            response.extend_from_slice(&[0, 0]);
        }
    }
    Ok(response)
}

fn opt_record(request: &[u8]) -> Result<Option<&[u8]>> {
    let (qd, an, ns, ar) = header_counts(request).context("invalid DNS header")?;
    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(request, pos).context("invalid DNS question")? + 4;
    }
    let mut opt = None;
    for index in 0..an + ns + ar {
        pos = skip_name(request, pos).context("invalid DNS record name")?;
        let fields = request.get(pos..pos + 10).context("invalid DNS record")?;
        let record_type = u16::from_be_bytes([fields[0], fields[1]]);
        if index >= an + ns && record_type == 41 {
            opt = Some(fields);
        }
        pos += 10 + usize::from(u16::from_be_bytes([fields[8], fields[9]]));
        ensure!(pos <= request.len(), "invalid DNS record data");
    }
    Ok(opt)
}

fn skip_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *packet.get(pos)?;
        if len & 0xc0 == 0xc0 {
            return (pos + 1 < packet.len()).then_some(pos + 2);
        }
        pos += 1;
        if len == 0 {
            return Some(pos);
        }
        pos += len as usize;
        if pos > packet.len() {
            return None;
        }
    }
}

fn header_counts(packet: &[u8]) -> Option<(usize, usize, usize, usize)> {
    Some((
        u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?]) as usize,
        u16::from_be_bytes([*packet.get(6)?, *packet.get(7)?]) as usize,
        u16::from_be_bytes([*packet.get(8)?, *packet.get(9)?]) as usize,
        u16::from_be_bytes([*packet.get(10)?, *packet.get(11)?]) as usize,
    ))
}

pub(super) fn cache_ttls(packet: &[u8]) -> Option<(u32, Vec<usize>)> {
    let mut offsets = Vec::new();
    let ttl = visit_ttls(packet, |offset| offsets.push(offset))?;
    Some((ttl, offsets))
}

pub(super) fn min_ttl(packet: &[u8]) -> Option<u32> {
    visit_ttls(packet, |_| {})
}

fn visit_ttls(packet: &[u8], mut visit: impl FnMut(usize)) -> Option<u32> {
    if packet.get(2)? & 0x02 != 0 || packet.get(3)? & 0x0f != 0 {
        return None;
    }
    let (qd, an, ns, ar) = header_counts(packet)?;
    if qd != 1 || an == 0 {
        return None;
    }
    let mut pos = skip_name(packet, 12)?.checked_add(4)?;
    if pos > packet.len() {
        return None;
    }
    let mut min_ttl = None;
    for _ in 0..an + ns + ar {
        pos = skip_name(packet, pos)?;
        let fields = packet.get(pos..pos.checked_add(10)?)?;
        let record_type = u16::from_be_bytes([fields[0], fields[1]]);
        let ttl = u32::from_be_bytes(fields[4..8].try_into().ok()?);
        let data_len = u16::from_be_bytes([fields[8], fields[9]]) as usize;
        let end = pos.checked_add(10 + data_len)?;
        if end > packet.len() {
            return None;
        }
        // OPT's TTL slot carries extended RCODE and flags, not a lifetime.
        if record_type != 41 {
            min_ttl = Some(min_ttl.map_or(ttl, |previous: u32| previous.min(ttl)));
            visit(pos + 4);
        }
        pos = end;
    }
    min_ttl.filter(|&ttl| ttl > 0)
}

pub(super) fn with_id(packet: &[u8], request: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        packet.len() >= 2 && request.len() >= 2,
        "invalid DNS packet"
    );
    let mut result = packet.to_vec();
    result[..2].copy_from_slice(&request[..2]);
    Ok(result)
}

pub(super) fn error_response(request: &[u8], rcode: u8) -> Result<Vec<u8>> {
    ensure!(request.len() >= 12, "invalid DNS header");
    let question_end = skip_name(request, 12)
        .and_then(|pos| pos.checked_add(4))
        .filter(|&end| end <= request.len())
        .ok_or_else(|| anyhow::anyhow!("invalid DNS question"))?;
    let mut response = request[..question_end].to_vec();
    response[2] |= 0x80;
    response[3] = (response[3] & 0x01) | rcode;
    response[4..6].copy_from_slice(&1u16.to_be_bytes());
    response[6..12].fill(0);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_names_are_not_limited_to_routing_hostnames() {
        for (name, expected) in [
            (".", ""),
            ("127.0.0.1", "127.0.0.1"),
            ("_SIP._tcp.Example.COM.", "_sip._tcp.example.com"),
            ("*.example.com", "*.example.com"),
        ] {
            assert_eq!(query(&make_query(name, 1)), Some((expected.into(), 1, 1)));
        }
        let mut packet = make_query("example.com", 1);
        packet[13] = b'.';
        assert_eq!(query_name(&packet).as_deref(), Some("\\046xample.com"));
        packet[13] = 255;
        assert_eq!(query_name(&packet).as_deref(), Some("\\255xample.com"));
        let longest = format!("{}{}", ("a".repeat(63) + ".").repeat(3), "a".repeat(61));
        assert_eq!(
            query_name(&make_query(&longest, 1)).as_deref(),
            Some(longest.as_str())
        );
        assert!(query_name(&make_query(&("a".repeat(63) + ".").repeat(4), 1)).is_none());
    }

    #[test]
    fn udp_responses_respect_edns_and_server_limits() {
        let request = make_query("example.com", 1);
        let mut response = request.clone();
        response[2..4].copy_from_slice(&[0x81, 0x80]);
        response[6..8].copy_from_slice(&40u16.to_be_bytes());
        for _ in 0..40 {
            response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
        }
        for (advertised, server_limit, truncated) in [
            (None, 4096, true),
            (Some(0u16), 4096, true),
            (Some(512), 4096, true),
            (Some(1232), 4096, false),
            (Some(4096), 512, true),
        ] {
            let mut request = request.clone();
            if let Some(size) = advertised {
                request[10..12].copy_from_slice(&1u16.to_be_bytes());
                request.extend_from_slice(&[0, 0, 41]);
                request.extend_from_slice(&size.to_be_bytes());
                request.extend_from_slice(&[0; 6]);
            }
            let reply = udp_response(&request, response.clone(), server_limit).unwrap();
            assert_eq!(reply[2] & 2 != 0, truncated);
            validate_response(&request, &reply).unwrap();
            if truncated {
                assert_eq!(reply.len(), if advertised.is_some() { 40 } else { 29 });
                assert_eq!(&reply[6..10], &[0; 4]);
                assert_eq!(opt_record(&reply).unwrap().is_some(), advertised.is_some());
            } else {
                assert_eq!(reply, response);
            }
        }
        let mut request = request;
        request[10..12].copy_from_slice(&1u16.to_be_bytes());
        request.extend_from_slice(&[0, 0, 41, 2, 0, 0, 0, 0x80, 0, 0, 0]);
        response[10..12].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0, 0, 41, 16, 0, 1, 0, 0x80, 0, 0, 0]);
        let reply = udp_response(&request, response, 4096).unwrap();
        let opt = opt_record(&reply).unwrap().unwrap();
        assert_eq!(&opt[2..4], &4096u16.to_be_bytes());
        assert_eq!(&opt[4..8], &[1, 0, 0x80, 0]);
    }

    #[test]
    fn policy_refusal_and_upstream_failure_have_distinct_rcodes() {
        let request = make_query("example.com", 1);
        for (rcode, expected) in [(5, 5), (2, 2)] {
            let response = error_response(&request, rcode).unwrap();
            assert_eq!(response[2] & 0x80, 0x80);
            assert_eq!(response[3] & 0x0f, expected);
            assert_eq!(&response[12..], &request[12..]);
        }
    }

    #[test]
    fn bootstrap_follows_out_of_order_cname_chain() {
        let mut response = make_query("alias.example", 1);
        response[2] |= 0x80;
        response[6..8].copy_from_slice(&5u16.to_be_bytes());
        let record = |packet: &mut Vec<u8>, owner: &[u8], typ: u16, data: &[u8]| {
            packet.extend_from_slice(owner);
            packet.extend_from_slice(&typ.to_be_bytes());
            packet.extend_from_slice(&1u16.to_be_bytes());
            packet.extend_from_slice(&60u32.to_be_bytes());
            packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
            packet.extend_from_slice(data);
        };
        let middle = b"\x06middle\x07example\x00";
        let final_name = b"\x05final\x07example\x00";
        record(&mut response, final_name, 1, &[192, 0, 2, 5]);
        record(
            &mut response,
            b"\x04evil\x07example\x00",
            1,
            &[192, 0, 2, 6],
        );
        record(&mut response, middle, 5, final_name);
        record(&mut response, &[0xc0, 0x0c], 5, middle);
        record(&mut response, final_name, 28, &1u128.to_be_bytes());
        assert_eq!(
            answer_ips(&response),
            vec![
                IpAddr::from([192, 0, 2, 5]),
                IpAddr::from(1u128.to_be_bytes())
            ]
        );
    }

    #[test]
    fn bootstrap_ignores_unrelated_addresses_and_follows_cname() {
        let mut response = make_query("alias.example", 1);
        response[2] |= 0x80;
        response[6..8].copy_from_slice(&3u16.to_be_bytes());
        let record = |packet: &mut Vec<u8>, name: &[u8], typ: u16, data: &[u8]| {
            packet.extend_from_slice(name);
            packet.extend_from_slice(&typ.to_be_bytes());
            packet.extend_from_slice(&1u16.to_be_bytes());
            packet.extend_from_slice(&60u32.to_be_bytes());
            packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
            packet.extend_from_slice(data);
        };
        record(&mut response, &[0xc0, 0x0c], 1, &[192, 0, 2, 1]);
        record(&mut response, &[0xc0, 0x0c], 5, b"\x04real\x07example\x00");
        record(
            &mut response,
            b"\x04real\x07example\x00",
            1,
            &[192, 0, 2, 2],
        );
        assert_eq!(
            answer_ips(&response),
            vec![IpAddr::from([192, 0, 2, 1]), IpAddr::from([192, 0, 2, 2])]
        );
        response[6..8].copy_from_slice(&4u16.to_be_bytes());
        record(
            &mut response,
            b"\x04evil\x07example\x00",
            1,
            &[192, 0, 2, 3],
        );
        assert_eq!(answer_ips(&response).len(), 2);
    }
}
