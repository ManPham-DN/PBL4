"""
detectors.py
Bộ máy phát hiện (Detection Engine) của mini-NIDS.
Đóng vai trò tương đương "detection engine" của Snort, nhưng đơn giản hoá:
  - port_scan : phát hiện quét cổng (nhiều dst_port khác nhau từ 1 src trong khoảng thời gian)
  - flood     : phát hiện tấn công dạng lụt gói tin (ICMP/UDP/TCP-SYN flood)
  - arp_spoof : phát hiện giả mạo ARP (1 IP đổi MAC bất thường)
  - signature : so khớp trực tiếp 1 hoặc nhiều trường trong gói tin (giống rule Snort cơ bản)
"""

import json
from collections import defaultdict, deque


class DetectorManager:
    def __init__(self, rules_path):
        with open(rules_path) as f:
            self.rules = json.load(f)

        # State theo dõi cho từng loại detector (giữ trong RAM, tương tự flowbits của Snort)
        self._port_scan_state = defaultdict(deque)              # src_ip -> deque[(ts, dst_port)]
        self._flood_state = defaultdict(lambda: defaultdict(deque))  # proto -> src_ip -> deque[ts]
        self._arp_table = {}                                     # ip -> (mac, last_seen_ts)

    def evaluate(self, ctx):
        """Chạy toàn bộ rule đang bật với 1 gói tin (context) đã parse."""
        alerts = []
        for rule in self.rules:
            if not rule.get("enabled", True):
                continue
            rule_proto = rule.get("proto", "ANY")
            if rule_proto != "ANY" and rule_proto != ctx["proto"]:
                continue

            rtype = rule["type"]
            handler = {
                "port_scan": self._check_port_scan,
                "flood": self._check_flood,
                "arp_spoof": self._check_arp_spoof,
                "signature": self._check_signature,
            }.get(rtype)

            if handler is None:
                continue

            alert = handler(rule, ctx)
            if alert:
                alerts.append(alert)
        return alerts

    # ---------------------------------------------------------------
    # Port scan: đếm số cổng đích DUY NHẤT mà 1 src IP gửi SYN tới,
    # trong 1 cửa sổ thời gian trượt (sliding window).
    # ---------------------------------------------------------------
    def _check_port_scan(self, rule, ctx):
        if ctx["proto"] != "TCP" or "S" not in ctx.get("tcp_flags", ""):
            return None

        src = ctx["src_addr"]
        now = ctx["timestamp"]
        window = rule["window_seconds"]
        threshold = rule["unique_ports_threshold"]

        dq = self._port_scan_state[src]
        dq.append((now, ctx["dst_port"]))
        while dq and now - dq[0][0] > window:
            dq.popleft()

        unique_ports = {p for _, p in dq}
        if len(unique_ports) >= threshold:
            dq.clear()  # reset để tránh bắn alert liên tục cho cùng 1 đợt quét
            return self._build_alert(rule)
        return None

    # ---------------------------------------------------------------
    # Flood: đếm số gói cùng giao thức từ 1 src IP trong 1 cửa sổ thời gian.
    # Dùng chung cho ICMP flood, UDP flood, TCP SYN flood.
    # ---------------------------------------------------------------
    def _check_flood(self, rule, ctx):
        src = ctx["src_addr"]
        now = ctx["timestamp"]
        window = rule["window_seconds"]
        threshold = rule["packet_threshold"]

        # Rule TCP SYN flood chỉ tính gói có cờ SYN
        if rule["proto"] == "TCP" and rule.get("syn_only", True):
            if "S" not in ctx.get("tcp_flags", ""):
                return None

        dq = self._flood_state[rule["proto"]][src]
        dq.append(now)
        while dq and now - dq[0] > window:
            dq.popleft()

        if len(dq) >= threshold:
            dq.clear()
            return self._build_alert(rule)
        return None

    # ---------------------------------------------------------------
    # ARP spoofing: nếu 1 địa chỉ IP bất ngờ đổi sang MAC khác
    # (so với lần thấy trước đó) trong 1 gói ARP reply -> nghi vấn giả mạo.
    # ---------------------------------------------------------------
    def _check_arp_spoof(self, rule, ctx):
        if ctx["proto"] != "ARP" or ctx.get("arp_op") != 2:  # chỉ xét ARP reply
            return None

        ip = ctx["src_addr"]
        mac = ctx["src_mac"]
        prev = self._arp_table.get(ip)
        self._arp_table[ip] = (mac, ctx["timestamp"])

        if prev and prev[0] != mac:
            return self._build_alert(rule)
        return None

    # ---------------------------------------------------------------
    # Signature đơn giản: so khớp trực tiếp các field trong context,
    # ví dụ icmp_type == 8 (Echo Request).
    # ---------------------------------------------------------------
    def _check_signature(self, rule, ctx):
        for key, value in rule["condition"].items():
            if ctx.get(key) != value:
                return None
        return self._build_alert(rule)

    @staticmethod
    def _build_alert(rule):
        return {
            "sid": rule["sid"],
            "rev": rule.get("rev", 1),
            "msg": rule["msg"],
            "class": rule.get("class", "unknown"),
            "priority": rule.get("priority", 3),
            "action": rule.get("action", "alert"),
        }
