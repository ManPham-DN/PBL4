#!/usr/bin/env python3
"""
engine.py
Engine phát hiện xâm nhập tự viết (thay thế Snort) - hỗ trợ 5 giao thức:
IP, ICMP, ARP, TCP, UDP.

Kiến trúc tương đương Snort:
    Packet Sniffer (Scapy sniff) -> Protocol Parser (build_context)
    -> Detection Engine (DetectorManager) -> Alert Logger (AlertLogger)

Cách chạy (trên Ubuntu VM, cần quyền bắt gói tin):
    sudo python3 engine.py -i ens33 -l /var/log/mini_nids -r rules.json

Ghi chú OS-layer (map với phần OS của PBL4):
    - Bắt gói tin thô cần CAP_NET_RAW / CAP_NET_ADMIN (hoặc root).
      Có thể dùng: sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
      để KHÔNG cần chạy bằng root (giống hướng đã định cho Snort).
    - Có thể chạy như 1 service systemd riêng, giao tiếp với backend Node.js
      qua file log (hiện tại) hoặc nâng cấp lên Unix domain socket sau.
"""

import argparse
import time

from scapy.all import sniff, IP, ICMP, ARP, TCP, UDP

from alert_logger import AlertLogger
from detectors import DetectorManager
from blocker import BlockManager

_pkt_num = 0
_CLEANUP_EVERY_N_PKT = 200  # tần suất gọi cleanup_expired() để không tốn overhead mỗi gói


def build_context(pkt):
    """Protocol Parser: tách các trường cần thiết từ gói tin thô.
    Chỉ xử lý 5 giao thức mục tiêu: ARP, ICMP, TCP, UDP, và IP nói chung."""
    ctx = {
        "timestamp": time.time(),
        "pkt_len": len(pkt),
        "proto": None,
        "src_addr": None,
        "dst_addr": None,
        "src_port": None,
        "dst_port": None,
    }

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        ctx.update(
            proto="ARP",
            src_addr=arp.psrc,
            dst_addr=arp.pdst,
            src_mac=arp.hwsrc,
            dst_mac=arp.hwdst,
            arp_op=arp.op,  # 1 = request, 2 = reply
        )
        return ctx

    if pkt.haslayer(IP):
        ip = pkt[IP]
        ctx["src_addr"] = ip.src
        ctx["dst_addr"] = ip.dst

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            ctx.update(
                proto="TCP",
                src_port=tcp.sport,
                dst_port=tcp.dport,
                tcp_flags=str(tcp.flags),
            )
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            ctx.update(proto="UDP", src_port=udp.sport, dst_port=udp.dport)
        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            ctx.update(proto="ICMP", icmp_type=icmp.type, icmp_code=icmp.code)
        else:
            ctx["proto"] = f"IP_PROTO_{ip.proto}"  # các giao thức IP khác (không thuộc 5 loại chính)

    return ctx


def make_packet_handler(
    logger: AlertLogger,
    detector_mgr: DetectorManager,
    blocker: BlockManager,
    enable_block: bool,
    verbose: bool,
):
    def handle(pkt):
        global _pkt_num
        _pkt_num += 1

        ctx = build_context(pkt)
        if ctx["proto"] is None:
            return  # không thuộc phạm vi 5 giao thức mục tiêu -> bỏ qua

        ctx["pkt_num"] = _pkt_num

        for alert in detector_mgr.evaluate(ctx):
            line = logger.write_alert(ctx, alert)
            if verbose:
                print(f"[ALERT] {line}")

            if enable_block and alert["action"] == "block":
                src = ctx.get("src_addr")
                if blocker.block_ip(src):
                    print(f"[BLOCK] Đã chặn IP nguồn: {src} (rule sid={alert['sid']})")

        if _pkt_num % _CLEANUP_EVERY_N_PKT == 0:
            blocker.cleanup_expired()

    return handle


def main():
    parser = argparse.ArgumentParser(
        description="mini-NIDS: engine phát hiện xâm nhập tự viết (thay thế Snort)"
    )
    parser.add_argument("-i", "--interface", required=True, help="Interface bắt gói tin, vd: ens33")
    parser.add_argument("-l", "--logdir", default="/var/log/mini_nids", help="Thư mục ghi alert")
    parser.add_argument("-r", "--rules", default="rules.json", help="File định nghĩa luật (JSON)")
    parser.add_argument("-v", "--verbose", action="store_true", help="In alert ra console")
    parser.add_argument(
        "--enable-block", action="store_true",
        help="BẬT active response (tự chặn IP qua iptables) cho các rule có action=block. "
             "MẶC ĐỊNH TẮT để tránh tự khoá mạng khi demo/test.",
    )
    parser.add_argument(
        "--dry-run-block", action="store_true",
        help="Không chạy iptables thật, chỉ in ra log 'sẽ chặn IP nào' để kiểm tra an toàn.",
    )
    parser.add_argument(
        "--protected-ips", default="",
        help="Danh sách IP KHÔNG BAO GIỜ bị chặn, cách nhau bởi dấu phẩy "
             "(vd: gateway, IP dashboard, IP admin). Ví dụ: 192.168.1.1,192.168.1.10",
    )
    parser.add_argument(
        "--unblock-after", type=int, default=300,
        help="Số giây trước khi tự động gỡ chặn 1 IP (mặc định 300s = 5 phút).",
    )
    args = parser.parse_args()

    logger = AlertLogger(args.logdir)
    detector_mgr = DetectorManager(args.rules)
    protected = [ip.strip() for ip in args.protected_ips.split(",") if ip.strip()]
    blocker = BlockManager(
        protected_ips=protected,
        unblock_after=args.unblock_after,
        dry_run=args.dry_run_block,
    )

    print(f"[mini-nids] Lắng nghe trên interface '{args.interface}'...")
    print(f"[mini-nids] Ghi alert vào: {logger.path}")
    if args.enable_block:
        mode = "DRY-RUN (không chặn thật)" if args.dry_run_block else "THẬT (sẽ chạy iptables)"
        print(f"[mini-nids] Active response: BẬT — chế độ {mode}")
        print(f"[mini-nids] IP được bảo vệ (không bao giờ bị chặn): {protected or 'KHÔNG có — nên khai báo!'}")
    else:
        print("[mini-nids] Active response: TẮT (chỉ alert, không tự block)")
    print("[mini-nids] Nhấn Ctrl+C để dừng.\n")

    try:
        sniff(
            iface=args.interface,
            prn=make_packet_handler(logger, detector_mgr, blocker, args.enable_block, args.verbose),
            store=False,
        )
    except PermissionError:
        print("[mini-nids] Lỗi quyền truy cập. Hãy chạy với sudo hoặc cấp "
              "cap_net_raw,cap_net_admin cho python3.")
    except KeyboardInterrupt:
        print("\n[mini-nids] Đã dừng.")
    finally:
        if args.enable_block:
            blocker.unblock_all()
            print("[mini-nids] Đã gỡ toàn bộ IP bị chặn trước khi thoát.")


if __name__ == "__main__":
    main()
