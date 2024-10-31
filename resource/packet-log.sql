-- 既存のテーブルとビューを削除
DROP VIEW IF EXISTS icmp_packets;
DROP VIEW IF EXISTS udp_packets;
DROP VIEW IF EXISTS tcp_packets;
DROP VIEW IF EXISTS ipv6_packets;
DROP VIEW IF EXISTS ipv4_packets;
DROP TABLE IF EXISTS packets CASCADE;

-- TimescaleDB拡張機能を有効化
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- 新しいpacketsテーブルを作成
CREATE TABLE IF NOT EXISTS packets
(
    id          BIGSERIAL,
    src_mac     MACADDR     NOT NULL,
    dst_mac     MACADDR     NOT NULL,
    ether_type  INTEGER     NOT NULL,
    src_ip      INET        NOT NULL,
    dst_ip      INET        NOT NULL,
    src_port    INTEGER,
    dst_port    INTEGER,
    ip_protocol INTEGER     NOT NULL,
    timestamp   TIMESTAMPTZ NOT NULL,
    data        BYTEA,
    raw_packet  BYTEA
);

-- ハイパーテーブルを作成
SELECT create_hypertable('packets', 'timestamp', chunk_time_interval => INTERVAL '1 day');

-- インデックスを作成
CREATE INDEX idx_packets_timestamp ON packets(timestamp DESC);
CREATE INDEX idx_packets_ips ON packets(src_ip, dst_ip);

-- ICMPパケット (IPv4 ICMP と IPv6 ICMPv6)
CREATE VIEW icmp_packets AS
SELECT *
FROM packets
WHERE ip_protocol IN (1, 58);

-- ARPパケット (EtherType 0x0806)
CREATE VIEW arp_packets AS
SELECT *
FROM packets
WHERE ether_type = 2054; -- 0x0806

-- packetsテーブルのバックアップを作成
CREATE TABLE IF NOT EXISTS packets_backup AS TABLE packets;