-- TimescaleDB拡張機能を有効化
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- 既存のpacketsテーブルが存在する場合は削除
DROP TABLE IF EXISTS packets CASCADE;

-- メインのpacketsテーブルを作成
CREATE TABLE IF NOT EXISTS packets
(
    id         BIGSERIAL,
    src_ip     INET        NOT NULL,
    dst_ip     INET        NOT NULL,
    src_port   INTEGER,
    dst_port   INTEGER,
    protocol   SMALLINT    NOT NULL,
    timestamp  TIMESTAMPTZ NOT NULL,
    data       BYTEA,
    raw_packet BYTEA
);

-- ハイパーテーブルを作成
-- チャンク時間間隔を1日に設定
SELECT create_hypertable('packets', 'timestamp', chunk_time_interval => INTERVAL '1 day');

-- 頻繁に検索されるカラムにインデックスを作成
CREATE INDEX idx_packets_ips ON packets (src_ip, dst_ip);
CREATE INDEX idx_packets_ports ON packets (src_port, dst_port);
CREATE INDEX idx_packets_protocol ON packets (protocol);

-- IPv4パケット用のビューを作成
CREATE VIEW ipv4_packets AS
SELECT *
FROM packets
WHERE family(src_ip) = 4;

-- IPv6パケット用のビューを作成
CREATE VIEW ipv6_packets AS
SELECT *
FROM packets
WHERE family(src_ip) = 6;

-- 特定のプロトコル用のビューを作成
CREATE VIEW tcp_packets AS
SELECT *
FROM packets
WHERE protocol = 6;

CREATE VIEW udp_packets AS
SELECT *
FROM packets
WHERE protocol = 17;

CREATE VIEW icmp_packets AS
SELECT *
FROM packets
WHERE protocol IN (1, 58);