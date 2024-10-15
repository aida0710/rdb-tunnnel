use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use crate::host_ids::ip_header::IpHeader;

// フラグメントされたIPパケットを表す構造体
#[derive(Clone)]
struct IpFragment {
    data: Vec<u8>,
    offset: u16,
    more_fragments: bool,
    arrival_time: Instant,
}

// 再構築中のIPパケットを表す構造体
struct ReassemblyBuffer {
    fragments: Vec<IpFragment>,
    total_length: usize,
    last_activity: Instant,
}

pub struct IpReassembler {
    buffers: HashMap<(Ipv4Addr, Ipv4Addr, u16), ReassemblyBuffer>,
    timeout: Duration,
}

impl IpReassembler {
    pub fn new(timeout: Duration) -> Self {
        IpReassembler {
            buffers: HashMap::new(),
            timeout,
        }
    }

    pub fn process_packet(&mut self, ip_header: &IpHeader, payload: &[u8]) -> Option<Vec<u8>> {
        let key = (ip_header.src_ip, ip_header.dst_ip, ip_header.identification);
        let fragment_offset = (ip_header.flags_fragment_offset & 0x1FFF) * 8;
        let more_fragments = (ip_header.flags_fragment_offset & 0x2000) != 0;

        let fragment = IpFragment {
            data: payload.to_vec(),
            offset: fragment_offset,
            more_fragments,
            arrival_time: Instant::now(),
        };

        self.buffers.entry(key).or_insert_with(|| ReassemblyBuffer {
            fragments: Vec::new(),
            total_length: 0,
            last_activity: Instant::now(),
        }).fragments.push(fragment);

        self.try_reassemble(key)
    }

    fn try_reassemble(&mut self, key: (Ipv4Addr, Ipv4Addr, u16)) -> Option<Vec<u8>> {
        if let Some(buffer) = self.buffers.get_mut(&key) {
            buffer.fragments.sort_by_key(|f| f.offset);

            let mut reassembled = Vec::new();
            let mut expected_offset = 0;
            let mut complete = true;

            for fragment in &buffer.fragments {
                if fragment.offset != expected_offset {
                    complete = false;
                    break;
                }
                reassembled.extend_from_slice(&fragment.data);
                expected_offset = fragment.offset + fragment.data.len() as u16;
                if !fragment.more_fragments {
                    break;
                }
            }

            if complete {
                self.buffers.remove(&key);
                Some(reassembled)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let timeout = self.timeout;
        self.buffers.retain(|_, buffer| {
            now.duration_since(buffer.last_activity) < timeout
        });
    }
}