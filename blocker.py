"""
blocker.py
Module active response (giống tính năng "inline block" / IPS) - tự động chặn
IP nguồn tấn công bằng cách chèn rule DROP vào iptables (chain INPUT).

CẢNH BÁO QUAN TRỌNG - đọc kỹ trước khi bật block thật (không dry-run):
  - Cần chạy engine.py với quyền root (hoặc CAP_NET_ADMIN) vì thao tác iptables.
  - Nhiều loại gói tin (ICMP, UDP) RẤT DỄ bị giả mạo địa chỉ IP nguồn (IP spoofing),
    vì kẻ tấn công không cần nhận phản hồi. Nếu bật "action": "block" cho các rule
    flood dựa trên ICMP/UDP, kẻ tấn công có thể giả mạo IP của người khác (gateway,
    DNS nội bộ...) để khiến mini-NIDS tự chặn nhầm -> tự gây DoS cho chính hệ thống.
  - TCP port scan (nmap -sS) là loại AN TOÀN NHẤT để auto-block, vì kẻ quét bắt
    buộc phải dùng IP thật để nhận gói phản hồi (SYN-ACK/RST) mới xác định được
    trạng thái cổng.
  - TCP SYN flood VẪN có thể bị giả mạo IP nguồn (không cần hoàn tất handshake),
    nên mặc định KHÔNG bật auto-block cho rule này trong rules.json.
  - LUÔN khai báo protected_ips (gateway, DNS, IP server dashboard, IP admin).
  - Có cơ chế tự unblock sau unblock_after giây để tránh khoá IP vĩnh viễn do
    false positive.
"""

import subprocess
import time


class BlockManager:
    def __init__(self, protected_ips=None, unblock_after=300, dry_run=False):
        self.blocked = {}                       # ip -> thời điểm bị chặn
        self.protected_ips = set(protected_ips or [])
        self.unblock_after = unblock_after
        self.dry_run = dry_run                  # True: chỉ in log, không chạy iptables thật

    def block_ip(self, ip):
        if not ip or ip in self.protected_ips or ip in self.blocked:
            return False

        if self.dry_run:
            print(f"[blocker][DRY-RUN] Sẽ chặn IP: {ip}")
        else:
            try:
                subprocess.run(
                    ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True, capture_output=True,
                )
            except subprocess.CalledProcessError as e:
                print(f"[blocker] Lỗi khi chặn {ip}: {e.stderr.decode(errors='ignore')}")
                return False
            except FileNotFoundError:
                print("[blocker] Không tìm thấy iptables. Cài: sudo apt install iptables")
                return False

        self.blocked[ip] = time.time()
        return True

    def unblock_ip(self, ip):
        if self.dry_run:
            print(f"[blocker][DRY-RUN] Sẽ gỡ chặn IP: {ip}")
        else:
            try:
                subprocess.run(
                    ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True, capture_output=True,
                )
            except subprocess.CalledProcessError:
                pass  # rule có thể đã bị xoá thủ công từ trước
        self.blocked.pop(ip, None)

    def cleanup_expired(self):
        """Gọi định kỳ để tự động gỡ chặn các IP đã hết hạn (unblock_after)."""
        now = time.time()
        expired = [ip for ip, ts in self.blocked.items() if now - ts > self.unblock_after]
        for ip in expired:
            self.unblock_ip(ip)

    def unblock_all(self):
        """Gọi khi tắt engine, tránh để sót rule iptables mồ côi."""
        for ip in list(self.blocked.keys()):
            self.unblock_ip(ip)
