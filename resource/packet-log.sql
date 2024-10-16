-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Create the main packets table
CREATE TABLE packets (
    id BIGSERIAL PRIMARY KEY,
    src_ip INET NOT NULL,
    dst_ip INET NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol SMALLINT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    data BYTEA,
    raw_packet BYTEA
);

-- Create hypertable
SELECT create_hypertable('packets', 'timestamp');

-- Create index on frequently queried columns
CREATE INDEX idx_packets_ips ON packets (src_ip, dst_ip);
CREATE INDEX idx_packets_ports ON packets (src_port, dst_port);
CREATE INDEX idx_packets_protocol ON packets (protocol);

-- Create a view for IPv4 packets
CREATE VIEW ipv4_packets AS
SELECT * FROM packets WHERE family(src_ip) = 4;

-- Create a view for IPv6 packets
CREATE VIEW ipv6_packets AS
SELECT * FROM packets WHERE family(src_ip) = 6;

-- Create views for specific protocols
CREATE VIEW tcp_packets AS
SELECT * FROM packets WHERE protocol = 6;

CREATE VIEW udp_packets AS
SELECT * FROM packets WHERE protocol = 17;

CREATE VIEW icmp_packets AS
SELECT * FROM packets WHERE protocol IN (1, 58);

-- Function to insert a new packet
CREATE OR REPLACE FUNCTION insert_packet(
    p_src_ip INET,
    p_dst_ip INET,
    p_src_port INTEGER,
    p_dst_port INTEGER,
    p_protocol SMALLINT,
    p_timestamp TIMESTAMPTZ,
    p_data BYTEA,
    p_raw_packet BYTEA
) RETURNS VOID AS $$
BEGIN
    INSERT INTO packets (src_ip, dst_ip, src_port, dst_port, protocol, timestamp, data, raw_packet)
    VALUES (p_src_ip, p_dst_ip, p_src_port, p_dst_port, p_protocol, p_timestamp, p_data, p_raw_packet);
END;
$$ LANGUAGE plpgsql;