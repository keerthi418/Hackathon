#!/usr/bin/env python3
"""
LabTrace LogLens — Test Log Generator

Writes fake failed/success login events into data/incoming/ (or sends
them via UDP syslog) so you can watch the Live Monitor and the R1/R2
detection rules fire in real time.

Examples:
  # normal traffic, one event every 3 s
  python tools/generate_test_logs.py

  # attack simulation: 5 failures then a success (triggers R1)
  python tools/generate_test_logs.py --mode attack --interval 2

  # after-hours logins (triggers R2)
  python tools/generate_test_logs.py --after-hours --mode attack

  # send via UDP syslog to 127.0.0.1:5140 instead of files
  python tools/generate_test_logs.py --udp --mode mixed

  # run for 60 seconds then stop
  python tools/generate_test_logs.py --duration 60
"""
import argparse
import csv
import os
import random
import socket
import sys
import time
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_FILE = os.path.join(BASE_DIR, "data", "incoming", "test_logs.csv")

DEFAULT_ACCOUNTS = ["a.raj", "v.hari", "r.devi", "guest_lab", "x.user",
                    "m.kumar", "s.priya"]
DEFAULT_COMPUTERS = ["PC-01", "PC-02", "PC-03", "PC-04", "PC-PRG-07"]
DEPARTMENTS = ["CSE", "ECE", "IT", "Common"]

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def now_str(after_hours=False):
    """Timestamp string for the generated event."""
    if after_hours:
        # today at 02:15 + a few minutes → outside 08:30-17:30 lab hours
        base = datetime.now().replace(hour=2, minute=15, second=0,
                                      microsecond=0)
        return (base + timedelta(seconds=random.randint(0, 300))).strftime(
            "%Y-%m-%d %H:%M:%S")
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def rfc3164_ts(after_hours=False):
    if after_hours:
        base = datetime.now().replace(hour=2, minute=15, second=0,
                                      microsecond=0)
        return (base + timedelta(seconds=random.randint(0, 300))).strftime(
            "%b %d %H:%M:%S")
    return datetime.now().strftime("%b %d %H:%M:%S")


class FileWriter:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.path = path
        self.counter = 0
        # write header only for a brand-new file
        if not os.path.exists(path):
            with open(path, "w", newline="", encoding="utf-8") as f:
                f.write("event_id,timestamp,account,computer,event,"
                        "department_case\n")

    def emit(self, account, computer, event, after_hours):
        self.counter += 1
        event_id = f"{int(time.time() * 1000)}-{self.counter}"
        ts = now_str(after_hours)
        with open(self.path, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([event_id, ts, account, computer, event,
                        random.choice(DEPARTMENTS)])
        return event_id, ts


class UdpSender:
    def __init__(self, host="127.0.0.1", port=5140):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.host = host
        self.port = port
        self.counter = 0

    def emit(self, account, computer, event, after_hours):
        self.counter += 1
        event_id = f"{int(time.time() * 1000)}-{self.counter}"
        ts = rfc3164_ts(after_hours)
        pri = 132 if event == "Failure" else 134  # auth.warning / auth.notice
        if event == "Failure":
            msg = (f"Failed password for invalid user {account} from "
                   f"10.0.0.{random.randint(2, 250)} port 22 ssh2")
        else:
            msg = (f"Accepted password for {account} from "
                   f"10.0.0.{random.randint(2, 250)} port 22 ssh2")
        line = f"<{pri}>{ts} {computer} sshd[{random.randint(100, 9999)}]: {msg}"
        self.sock.sendto(line.encode(), (self.host, self.port))
        return event_id, ts


def main():
    p = argparse.ArgumentParser(description="LabTrace LogLens test log generator")
    p.add_argument("--interval", type=float, default=3.0,
                   help="seconds between events/bursts (default 3)")
    p.add_argument("--accounts", default=",".join(DEFAULT_ACCOUNTS),
                   help="comma-separated account names")
    p.add_argument("--computers", default=",".join(DEFAULT_COMPUTERS),
                   help="comma-separated computer names")
    p.add_argument("--mode", choices=["normal", "attack", "mixed"],
                   default="normal",
                   help="normal=random logins, attack=burst then success "
                        "(R1), mixed=alternate")
    p.add_argument("--burst-size", type=int, default=5,
                   help="failures before a success in attack mode (default 5)")
    p.add_argument("--after-hours", action="store_true",
                   help="stamp events at 02:15 to trigger R2 (after-hours)")
    p.add_argument("--duration", type=float, default=0,
                   help="stop after N seconds (0 = run until Ctrl+C)")
    p.add_argument("--udp", action="store_true",
                   help="send via UDP syslog to 127.0.0.1:5140 instead of "
                        "writing a file")
    p.add_argument("--file", default=DEFAULT_FILE,
                   help=f"output file (default {DEFAULT_FILE})")
    args = p.parse_args()

    accounts = [a.strip() for a in args.accounts.split(",") if a.strip()]
    computers = [c.strip() for c in args.computers.split(",") if c.strip()]

    if args.udp:
        writer = UdpSender()
        target = "UDP 127.0.0.1:5140"
    else:
        writer = FileWriter(args.file)
        target = args.file

    print(f"LabTrace LogLens test generator")
    print(f"  target    : {target}")
    print(f"  mode      : {args.mode} (burst={args.burst_size})")
    print(f"  interval  : {args.interval}s")
    print(f"  after-hrs : {args.after_hours}")
    print(f"  duration  : {'until Ctrl+C' if args.duration <= 0 else str(args.duration) + 's'}")
    print(f"  accounts  : {', '.join(accounts)}")
    print("")
    print("  Watching the Live Monitor: http://127.0.0.1:5000/monitor")
    print("")

    cycle = 0
    start = time.time()
    try:
        while True:
            if args.duration > 0 and time.time() - start >= args.duration:
                print("  duration reached — stopping.")
                break

            account = random.choice(accounts)
            computer = random.choice(computers)
            mode = args.mode
            if mode == "mixed":
                mode = "attack" if cycle % 2 == 0 else "normal"

            if mode == "attack":
                # R1: N failures then a success within the window
                for i in range(args.burst_size):
                    eid, ts = writer.emit(account, computer, "Failure",
                                          args.after_hours)
                    print(f"  [{ts}] {account}@{computer} Failure  (#{eid})")
                    time.sleep(0.2)
                eid, ts = writer.emit(account, computer, "Success",
                                      args.after_hours)
                print(f"  [{ts}] {account}@{computer} Success  (#{eid})  <-- burst complete")
            else:
                event = "Success" if random.random() < 0.7 else "Failure"
                eid, ts = writer.emit(account, computer, event,
                                      args.after_hours)
                print(f"  [{ts}] {account}@{computer} {event}  (#{eid})")

            cycle += 1
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n  stopped.")


if __name__ == "__main__":
    main()
