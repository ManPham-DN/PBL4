"""
alert_logger.py
Ghi alert ra file theo định dạng JSON Lines, cố tình giữ TÊN TRƯỜNG giống
với alert_json của Snort 3 (timestamp, pkt_num, proto, pkt_gen, pkt_len,
dir, src_ap, dst_ap, rule, action) + các trường mở rộng (msg, class,
priority, src_addr, src_port, dst_addr, dst_port) mà backend đã dùng.

=> watcher.js hiện tại (chokidar, byte-offset, usePolling) KHÔNG cần sửa gì,
   chỉ cần trỏ đường dẫn log sang file này.
"""

import json
import os
import time


class AlertLogger:
    def __init__(self, logdir, filename="alert_json.txt"):
        os.makedirs(logdir, exist_ok=True)
        self.path = os.path.join(logdir, filename)

    def write_alert(self, ctx, alert):
        record = {
            "timestamp": time.strftime(
                "%m/%d/%y-%H:%M:%S.000000", time.localtime(ctx["timestamp"])
            ),
            "pkt_num": ctx["pkt_num"],
            "proto": ctx["proto"],
            "pkt_gen": "mini_nids",     # đánh dấu nguồn sinh alert là engine tự viết
            "pkt_len": ctx["pkt_len"],
            "dir": "N/A",               # có thể nâng cấp sau: suy ra C2S/S2C qua flow tracking
            "src_ap": _addr_port(ctx.get("src_addr"), ctx.get("src_port")),
            "dst_ap": _addr_port(ctx.get("dst_addr"), ctx.get("dst_port")),
            "rule": f'1:{alert["sid"]}:{alert["rev"]}',   # giả lập gid:sid:rev
            "action": alert["action"],
            "msg": alert["msg"],
            "class": alert["class"],
            "priority": alert["priority"],
            "src_addr": ctx.get("src_addr"),
            "src_port": ctx.get("src_port"),
            "dst_addr": ctx.get("dst_addr"),
            "dst_port": ctx.get("dst_port"),
        }
        line = json.dumps(record, ensure_ascii=False)
        with open(self.path, "a") as f:
            f.write(line + "\n")
        return line


def _addr_port(addr, port):
    if addr is None:
        return None
    return f"{addr}:{port}" if port is not None else str(addr)
