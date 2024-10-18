# rdb-tunnel todo list
### rdb-tunnel

- [x] パケットのipヘッダー解析
- [ ] データベースに全てのパケットを保存
  - [ ] src_ip
  - [ ] dst_ip
  - [ ] src_port
  - [ ] dst_port
  - [ ] protocol
    - [ ] IPv4: 4
      - [ ] TCP: 6
      - [ ] UDP: 17
    - [ ] IPv6: 41
      - [ ] TCP: 6
      - [ ] UDP: 17
    - [ ] ICMP
      - [ ] IPv4用: 1
      - [ ] IPv6用 (ICMPv6): 58
  - [ ] timestamp
  - [ ] data
  - [ ] raw_packet
- [ ] データベースからパケットを取得 (pooling) //変更通知(NOTIFY)を使う案もあるが、複雑さが増すため、要検討。
- [ ] データベースに保存されたfirewallのルールを取得
- [ ] ルールに従ってパケットをフィルタリング
- [ ] 取得したパケットを再注入
