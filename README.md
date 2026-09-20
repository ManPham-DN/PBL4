# mini-NIDS — Engine phát hiện xâm nhập tự viết (thay thế Snort)

Viết bằng Python + Scapy theo yêu cầu của thầy: **không dùng Snort**, tự xây
dựng một engine tương tự để tích hợp vào dự án PBL4.

## Kiến trúc (map 1-1 với vai trò của Snort trong pipeline cũ)

```
Card mạng (ens33)
   │  Scapy sniff()
   ▼
Packet Sniffer  ──► Protocol Parser (build_context)
                        │  tách IP / ICMP / ARP / TCP / UDP
                        ▼
                  Detection Engine (DetectorManager + rules.json)
                        │  port_scan / flood / arp_spoof / signature
                        ▼
                  Alert Logger (alert_json.txt, JSON Lines)
                        │
                        ▼
        watcher.js (chokidar, usePolling) — KHÔNG ĐỔI GÌ
                        │
                        ▼
              Backend Node.js → Socket.io → Dashboard
```

Vì `alert_logger.py` ghi ra đúng các trường mà `watcher.js` đang đọc
(`timestamp`, `pkt_num`, `proto`, `pkt_len`, `src_ap`, `dst_ap`, `rule`,
`action`, `msg`, `class`, `priority`, `src_addr`, `src_port`, `dst_addr`,
`dst_port`), nên toàn bộ phần backend/dashboard đã làm **không cần sửa**,
chỉ cần trỏ watcher sang file log mới.

## Cấu trúc file

| File | Vai trò |
|---|---|
| `engine.py` | Điểm vào chính: sniff gói tin + parser (tương đương DAQ + decoder của Snort) |
| `detectors.py` | Detection engine: port scan, flood, ARP spoofing, signature matching |
| `alert_logger.py` | Ghi alert ra JSON Lines, format tương thích `watcher.js` cũ |
| `rules.json` | Tập luật — tương đương file `.rules` của Snort, nhưng ở dạng JSON dễ chỉnh |
| `test_offline.py` | Test logic detection bằng gói tin giả, KHÔNG cần root / card mạng thật |

## Chạy trên VM Ubuntu (VM đang chạy Snort trước đây)

```bash
cd mini_nids
pip install scapy --break-system-packages

# Chạy thử offline trước (không cần sudo, không cần card mạng thật)
python3 test_offline.py

# Chạy thật trên interface ens33 (cần quyền bắt gói tin)
sudo python3 engine.py -i ens33 -l /var/log/mini_nids -r rules.json -v
```

Tham số `-i / -l / -r` được đặt tên giống style command của Snort
(`-i ens33 -A alert_json -l /var/log/snort`) để man dễ liên hệ khi trình bày
với thầy.

### Chạy KHÔNG cần root (đúng hướng OS-layer đã định cho Snort)

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
python3 engine.py -i ens33 -l /var/log/mini_nids
```

Lưu ý: `setcap` áp lên chính binary `python3`, nên mọi script Python trên máy
đều có quyền này — trong báo cáo nên nêu rõ đây là trade-off, và hướng nâng
cấp thực tế là build 1 binary riêng (C) hoặc dùng systemd service với
`AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`.

## Tập luật hiện có (`rules.json`)

| SID | Loại | Mô tả |
|---|---|---|
| 1000001 | port_scan | TCP port scan — ≥10 cổng khác nhau từ 1 IP trong 5s |
| 1000002 | flood | ICMP flood — ≥50 gói ping từ 1 IP trong 3s |
| 1000003 | flood | UDP flood — ≥100 gói từ 1 IP trong 3s |
| 1000004 | flood | TCP SYN flood — ≥80 gói SYN từ 1 IP trong 3s |
| 1000005 | arp_spoof | 1 IP đổi MAC bất thường (ARP reply) |
| 1000006 | signature | ICMP Echo Request đơn lẻ (demo signature rule) |

Có thể thêm luật mới bằng cách thêm object vào `rules.json`, không cần sửa code.

## Active response — tự động chặn IP tấn công (tuỳ chọn, giống tính năng IPS)

Mặc định engine chỉ **alert**, không tự chặn gì. Muốn bật chặn tự động:

```bash
# Bước 1: LUÔN test bằng dry-run trước để chắc chắn không tự khoá nhầm
sudo python3 engine.py -i ens33 -l /var/log/mini_nids \
    --enable-block --dry-run-block \
    --protected-ips 192.168.1.1,192.168.1.10

# Bước 2: Khi đã yên tâm, bỏ --dry-run-block để chặn thật qua iptables
sudo python3 engine.py -i ens33 -l /var/log/mini_nids \
    --enable-block \
    --protected-ips 192.168.1.1,192.168.1.10 \
    --unblock-after 300
```

- `--protected-ips`: danh sách IP KHÔNG BAO GIỜ bị chặn — luôn khai báo IP gateway,
  IP server chạy dashboard/backend, IP máy admin.
- `--unblock-after`: sau bao nhiêu giây thì tự gỡ chặn 1 IP (tránh khoá oan vĩnh viễn
  nếu là false positive). Mặc định 300s.
- Khi tắt engine (Ctrl+C), toàn bộ IP đang bị chặn sẽ **tự động được gỡ**
  (xem `blocker.unblock_all()`), tránh để sót rule iptables mồ côi trên máy.

### Vì sao chỉ rule port scan (sid 1000001) có `"action": "block"` mặc định?

TCP port scan là loại **khó giả mạo IP nguồn nhất**: kẻ quét bắt buộc phải dùng
IP thật để nhận lại SYN-ACK/RST mới xác định được cổng nào đang mở. Ngược lại,
ICMP/UDP flood và cả TCP SYN flood đều **có thể bị giả mạo IP nguồn** dễ dàng
(không cần hoàn tất handshake) — nếu tự động block các rule này, kẻ tấn công
có thể giả IP của gateway/DNS nội bộ để khiến mini-NIDS tự chặn nhầm, gây DoS
ngược cho chính hệ thống. Muốn bật block cho rule khác, chỉ cần đổi
`"action": "alert"` thành `"action": "block"` trong `rules.json` — nhưng nên
nêu rõ trade-off này trong báo cáo khi bảo vệ đồ án.

## Test tấn công từ Kali (giữ nguyên kịch bản cũ)

- `nmap -sS <IP_Ubuntu>` → kích hoạt rule 1000001 (port scan)
- `hping3 --flood -1 <IP_Ubuntu>` → kích hoạt rule 1000002 (ICMP flood)
- `hping3 --flood -S -p 80 <IP_Ubuntu>` → kích hoạt rule 1000004 (SYN flood)
- `arpspoof -i eth0 -t <IP_Ubuntu> <gateway>` → kích hoạt rule 1000005 (ARP spoofing)

## Những điểm cần lưu ý khi báo cáo với thầy

1. **So sánh với Snort**: đây là kiến trúc **rule-based / threshold-based
   IDS** đơn giản hoá — Snort dùng detection engine phức tạp hơn nhiều
   (protocol-aware inspection, preprocessors, stream reassembly...).
   Nên nêu rõ đây là bản thu gọn phục vụ mục đích học thuật.
2. **Hiệu năng**: Scapy xử lý gói tin ở user-space, chậm hơn Snort (C, dùng
   libpcap trực tiếp) — phù hợp để demo, không phù hợp triển khai production
   traffic lớn. Đây là điểm có thể nêu trong phần "hạn chế & hướng phát triển".
3. **Phần OS**: việc tự sniff raw socket, tự quản lý tiến trình engine, và
   cần `cap_net_raw` để bắt gói tin mà không cần root — là các điểm bám sát
   yêu cầu OS của PBL4, mạnh hơn cả khi còn dùng Snort có sẵn.
