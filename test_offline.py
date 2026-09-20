"""
test_offline.py
Kiểm thử engine mà KHÔNG cần quyền root / card mạng thật.
Tạo gói tin giả bằng Scapy, đẩy thẳng qua build_context() + DetectorManager
để xác nhận logic phát hiện port scan, flood, arp spoof, signature hoạt động đúng.
"""

import time
from scapy.all import IP, ICMP, ARP, TCP, UDP, Ether

from engine import build_context
from detectors import DetectorManager
from alert_logger import AlertLogger
from blocker import BlockManager

detector = DetectorManager("rules.json")
logger = AlertLogger("/tmp/mini_nids_test")
blocker = BlockManager(protected_ips=["10.0.0.1"], dry_run=True)  # dry_run: khong dung iptables that


def feed(pkt, label):
    ctx = build_context(pkt)
    if ctx["proto"] is None:
        return
    ctx["pkt_num"] = 0
    alerts = detector.evaluate(ctx)
    for a in alerts:
        print(f"  -> ALERT [{label}] sid={a['sid']} msg={a['msg']} action={a['action']}")
        if a["action"] == "block":
            blocker.block_ip(ctx.get("src_addr"))


print("== Test 1: TCP port scan (11 cong khac nhau tu 1 IP) ==")
for port in range(20, 31):
    pkt = IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=4444, dport=port, flags="S")
    feed(pkt, "port_scan")

print("\n== Test 2: ICMP flood (60 goi ping tu 1 IP) ==")
for _ in range(60):
    pkt = IP(src="10.0.0.6", dst="10.0.0.1") / ICMP(type=8)
    feed(pkt, "icmp_flood")

print("\n== Test 3: ARP spoofing (IP doi MAC) ==")
pkt1 = Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa")
pkt2 = Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="bb:bb:bb:bb:bb:bb")
feed(pkt1, "arp_baseline")
feed(pkt2, "arp_spoof")

print("\n== Test 4: Single ICMP echo (signature rule) ==")
pkt = IP(src="10.0.0.9", dst="10.0.0.1") / ICMP(type=8)
feed(pkt, "icmp_signature")

print("\n== Xong. Xem file alert: /tmp/mini_nids_test/alert_json.txt ==")
