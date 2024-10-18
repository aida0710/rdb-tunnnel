# host-ids

## 実装予定の機能

| 分類          | 不正アクセス種別              | 判定条件                                            |
|-------------|-----------------------|-------------------------------------------------|
| IPヘッダー      | Unknown IP protocol   | protocolフィールドが143以上のとき                          |
|             | Land attack           | 始点IPアドレスと終点IPアドレスが同じとき                          |
|             | Short IP header       | IPヘッダーの長さがlengthフィールドの長さよりも短いとき                 |
|             | Malformed IP packet   | lengthフィールドと実際のパケットの長さが違うとき                     |
| IPオプションヘッダー | Malformed IP opt      | オプションヘッダーの構造が不正であるとき                            |
|             | Security IP opt       | Security and handling restriction headerを受信したとき |
|             | Loose routing IP opt  | Loose source routing headerを受信したとき              |
|             | Record route IP opt   | Record route headerを受信したとき                      |
|             | Stream ID IP opt      | Stream identifier headerを受信したとき                 |
|             | Strict routing IP opt | Strict source routing headerを受信したとき             |
|             | Timestamp IP opt      | Internet timestamp headerを受信したとき                |
| フラグメント      | Fragment storm        | 大量のフラグメントを受信したとき                                |
|             | Large fragment offset | フラグメントのoffsetフィールドが大きいとき                        |
|             | Too many fragment     | フラグメントの分割数が多いとき                                 |
|             | Teardrop              | teardropなどのツールによる攻撃を受けたとき                       |
|             | Same fragment offset  | フラグメントのoffsetフィールドの値が重複しているとき                   |
|             | Invalid fragment      | そのほかのリアセンブル不可能なフラグメントを受信したとき                    |
| ICMP        | ICMP source quench    | source quenchを受信したとき                            |
|             | ICMP timestamp req    | timestamp requestを受信したとき                        |
|             | ICMP timestamp reply  | timestamp replyを受信したとき                          |
|             | ICMP info request     | information requestを受信したとき                      |
|             | ICMP info reply       | information replyを受信したとき                        |
|             | ICMP mask request     | address mask requestを受信したとき                     |
|             | ICMP mask reply       | address mask replyを受信したとき                       |
|             | ICMP too large        | 1025バイト以上のICMPを受信したとき                           |
| UDP         | UDP short header      | UDPのlengthフィールドの値が8よりも小さいとき                     |
|             | UDP bomb              | UDPヘッダーのlengthフィールドの値が大きすぎるとき                   |
| TCP         | TCP no bits set       | フラグに何もセットされていないとき                               |
|             | TCP SYN and FIN       | SYNとFINが同時にセットされているとき                           |
|             | TCP FIN and no ACK    | ACKのないFINを受信したとき                                |
| FTP         | FTP improper port     | PORTやPASVコマンドで指定されるポート番号が1024〜65535の範囲でないとき     |
