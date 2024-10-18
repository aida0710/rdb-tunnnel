use crate::host_idps::ip_header::IpHeader;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

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
    last_cleanup: Instant,
    cleanup_interval: Duration,
    max_buffers: usize,
    packets_processed: usize,
}

impl IpReassembler {
    pub fn new(timeout: Duration) -> Self {
        IpReassembler {
            buffers: HashMap::new(),
            timeout,
            last_cleanup: Instant::now(),
            cleanup_interval: Duration::from_secs(60),
            max_buffers: 5000,
            packets_processed: 0,
        }
    }

    pub fn process_packet(&mut self, ip_header: &IpHeader, payload: &[u8]) -> Option<Vec<u8>> {
        self.packets_processed += 1;
        let key = (ip_header.src_ip, ip_header.dst_ip, ip_header.identification);
        let fragment_offset = (ip_header.flags_fragment_offset & 0x1FFF) * 8;
        let more_fragments = (ip_header.flags_fragment_offset & 0x2000) != 0;

        let fragment = IpFragment {
            data: payload.to_vec(),
            offset: fragment_offset,
            more_fragments,
            arrival_time: Instant::now(),
        };

        self.cleanup_if_needed();

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

    fn cleanup_if_needed(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_cleanup) >= self.cleanup_interval ||
            self.buffers.len() > self.max_buffers ||
            self.packets_processed % 1000 == 0 // 1000パケットごとにチェック
        {
            self.cleanup();
            self.last_cleanup = now;
            self.packets_processed = 0;
        }
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
        let timeout = self.timeout;
        let initial_size = self.buffers.len();

        self.buffers.retain(|_, buffer| {
            now.duration_since(buffer.last_activity) < timeout
        });

        let cleaned_up = initial_size - self.buffers.len();
        if cleaned_up > 0 {
            println!("クリーンアップ: {} の古いIPフラグメントを削除しました", cleaned_up);
        }

        // バッファが依然として多すぎる場合、最も古いものから削除
        if self.buffers.len() > self.max_buffers {
            let mut buffers: Vec<_> = self.buffers.drain().collect();
            buffers.sort_by_key(|(_, buf)| buf.last_activity);
            buffers.truncate(self.max_buffers);
            self.buffers = buffers.into_iter().collect();
            println!("追加クリーンアップ: バッファ数を {} に制限しました", self.max_buffers);
        }
    }
}