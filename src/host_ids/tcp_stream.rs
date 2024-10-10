use std::net::Ipv4Addr;
use std::time::{Duration, Instant, SystemTime};

// TCPフラグの定義
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;

// TCPセッションの状態を表す列挙型
#[derive(Debug, PartialEq, Clone)]
pub enum TcpState {
    Listen, //TCPモジュールはリモートホストからのコネクション要求を待っている。パッシブオープンの後で入る状態と同じ。
    SynSent, //TCPモジュールは自分のコネクション要求の送信を終え、応答確認と対応するコネクション要求を待っている。
    SynReceived, //TCPモジュールは同期（SYN）セグメントを受信し、対応する同期（SYN/ACK）セグメントを送って、コネクション応答確認を待っている。
    Established, //コネクションが開かれ、データ転送が行える通常の状態になっている。受信されたデータは全てアプリケーションプロセスに渡せる。
    FinWait1, //TCPモジュールはリモートホストからのコネクション終了要求か、すでに送った終了要求の応答確認を待っている。
    FinWait2, //この状態に入るのは、TCPモジュールがリモートホストからの終了要求を待っているときである。
    CloseWait, //TCPモジュールはアプリケーションプロセスからのコネクション終了要求を待っている。
    Closing, //TCPモジュールはリモートホストからのコネクション終了要求を待っている。
    LastAck, //リモートホストに送ったコネクション終了要求について、TCPモジュールがその応答確認を待っている
    TimeWait, //コネクション終了要求応答確認をリモートホストが確実に受取るのに必要な時間が経過するまで、TCPモジュールは待機している
    Closed, //コネクションは全く存在せず、確立段階にも入っていない
    //状態移管図↓
    //https://camo.qiitausercontent.com/24d35109620da317520dc832e55b60d1e730db04/68747470733a2f2f71696974612d696d6167652d73746f72652e73332e616d617a6f6e6177732e636f6d2f302f323831332f32313639633437332d613764332d353666642d643734382d3238326331346138343637342e6a706567
}

// TCPストリームを表す構造体
#[derive(Debug)]
pub struct TcpStream {
    pub state: TcpState,
    pub client_init_seq: u32,
    pub server_init_seq: u32,
    pub client_next_seq: u32,
    pub server_next_seq: u32,
    pub client_data: Vec<u8>,
    pub server_data: Vec<u8>,
    pub last_activity: Instant,
    pub client_window: u16,
    pub server_window: u16,
    pub client_mss: u16,
    pub server_mss: u16,
    pub client_cwnd: u32,  // クライアントの輻輳ウィンドウ
    pub server_cwnd: u32,  // サーバーの輻輳ウィンドウ
    pub arrival_time: SystemTime,  // 最後のパケット到着時間
}

pub type TcpStreamKey = (Ipv4Addr, u16, Ipv4Addr, u16);

impl TcpStream {
    pub fn new(client_init_seq: u32, server_init_seq: u32) -> Self {
        TcpStream {
            state: TcpState::SynSent,
            client_init_seq,
            server_init_seq,
            client_next_seq: client_init_seq.wrapping_add(1),
            server_next_seq: server_init_seq,
            client_data: Vec::new(),
            server_data: Vec::new(),
            last_activity: Instant::now(),
            client_window: 0,
            server_window: 0,
            client_mss: 1460,  // デフォルト値
            server_mss: 1460,  // デフォルト値
            client_cwnd: 1,
            server_cwnd: 1,
            arrival_time: SystemTime::now(),
        }
    }

    pub fn update(&mut self, is_from_client: bool, seq: u32, ack: u32, flags: u8, data: &[u8], window: u16) {
        self.last_activity = Instant::now();
        self.arrival_time = SystemTime::now();

        if is_from_client {
            if seq == self.client_next_seq {
                self.client_data.extend_from_slice(data);
                self.client_next_seq = self.client_next_seq.wrapping_add(data.len() as u32);
            }
            if flags & TCP_ACK != 0 {
                self.server_next_seq = ack;
            }
            self.client_window = window;
            self.client_cwnd += 1;  // 簡略化した輻輳制御
        } else {
            if seq == self.server_next_seq {
                self.server_data.extend_from_slice(data);
                self.server_next_seq = self.server_next_seq.wrapping_add(data.len() as u32);
            }
            if flags & TCP_ACK != 0 {
                self.client_next_seq = ack;
            }
            self.server_window = window;
            self.server_cwnd += 1;  // 簡略化した輻輳制御
        }

        // 状態遷移の処理
        self.state = match (self.state.clone(), flags) {
            // サーバーが SYN を受信し、SYN_RECEIVED 状態に遷移
            (TcpState::Listen, TCP_SYN) => TcpState::SynReceived,

            // クライアントが SYN-ACK を受信し、接続確立
            (TcpState::SynSent, flags) if flags & (TCP_SYN | TCP_ACK) == (TCP_SYN | TCP_ACK) => {
                // 実際はSYN-ACK を受信したら ACK を送信するが、傍聴しているだけなので不要
                TcpState::Established
            },

            // サーバーが最後の ACK を受信し、接続確立
            (TcpState::SynReceived, TCP_ACK) => TcpState::Established,

            // 確立された接続で、一方が接続終了を開始 (FIN 送信)
            (TcpState::Established, TCP_FIN) => TcpState::FinWait1,

            // FIN 送信側が ACK を受信、または同時クローズで FIN を受信
            (TcpState::FinWait1, flags) => {
                if flags & TCP_ACK != 0 && flags & TCP_FIN == 0 {
                    // ACK のみを受信
                    TcpState::FinWait2
                } else if flags & (TCP_FIN | TCP_ACK) == (TCP_FIN | TCP_ACK) {
                    // FIN-ACK を受信（同時クローズ）
                    // 実際は FIN-ACK を受信したら ACK を送信するが、傍聴しているだけなので不要
                    TcpState::TimeWait
                } else {
                    // その他の場合は状態を変更しない
                    TcpState::FinWait1
                }
            },

            // 最後の FIN に対する ACK を受信、接続終了の準備
            (TcpState::FinWait2, TCP_ACK) => TcpState::TimeWait,

            // FIN 受信側のアプリケーションが接続を閉じ、FIN を送信
            (TcpState::CloseWait, TCP_FIN) => TcpState::LastAck,

            // 最後の FIN に対する ACK を受信、接続完全終了
            (TcpState::LastAck, TCP_ACK) => TcpState::Closed,

            // TIME_WAIT 状態で 2MSL (通常 2分) 経過後、完全にクローズ
            (TcpState::TimeWait, _) if Instant::now().duration_since(self.last_activity) > Duration::from_secs(120) => TcpState::Closed,

            // 上記以外の場合は現在の状態を維持
            (state, _) => state,
        };
    }

    pub fn set_mss(&mut self, is_client: bool, mss: u16) {
        if is_client {
            self.client_mss = mss;
        } else {
            self.server_mss = mss;
        }
    }
}