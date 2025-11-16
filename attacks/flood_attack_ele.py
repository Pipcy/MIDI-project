#!/usr/bin/env python3
import socket, struct, time, hmac, hashlib, random

SERVER_IP   = "10.239.13.237"   # change if needed
SERVER_PORT = 5005
SECRET_KEY  = b't0ps3cr3tk3z' # correct key is y at the end

HDR_FMT = "!IqH"
ACK_FMT = "!Iq"

def build_packet(seq: int, payload: bytes) -> bytes:
    send_ts = int(time.time() * 1_000_000)          # µs
    hdr     = struct.pack(HDR_FMT, seq, send_ts, len(payload))
    msg     = hdr + payload
    mac     = hmac.new(SECRET_KEY, msg, hashlib.sha256).digest()
    return msg + mac

def massive_burst(total_packets: int, inter_pkt_sec: float):
    """
    Sends `total_packets` as fast as possible.
    `inter_pkt_sec` controls the gap between packets (use a very small value).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.00001)   # short timeout – we only care about ACKs that arrive

    sent, acked, silent_drop = 0, 0, 0

    for i in range(total_packets):
        # Random but valid MIDI Note On message: [status, note, velocity]
        status = random.choice([0x90, 0x80])    # Note On or Note Off on channel 0
        note = random.randint(60, 72)           # Middle C range
        velocity = random.randint(0, 127)

        payload = bytes([status, note, velocity])
        # payload = bytes([random.randint(0, 127)])   # dummy 1‑byte MIDI payload
        pkt = build_packet(i, payload)
        sock.sendto(pkt, (SERVER_IP, SERVER_PORT))
        sent += 1

        # Try to read an ACK; if none arrives we treat it as a silent drop
        try:
            data, _ = sock.recvfrom(1024)
            if len(data) == struct.calcsize(ACK_FMT):
                acked += 1
        except socket.timeout:
            silent_drop += 1

        # Sleep only a few hundred microseconds (or set to 0 for “as fast as possible”)
        if inter_pkt_sec > 0:
            time.sleep(inter_pkt_sec)

    print("\n=== Burst Summary ===")
    print(f"Sent packets          : {sent}")
    print(f"ACKs received         : {acked}")
    print(f"Silent drops (no ACK): {silent_drop}")
    print(f"Drop ratio            : {(sent-acked)/sent:.1%}")

if __name__ == "__main__":
    # -------------------------------------------------------------
    # 1️⃣ Very aggressive burst – 200 packets in <0.2 s
    # -------------------------------------------------------------
    print(">>> Running ultra‑fast burst (500000 pkts, 0.0000001 s gap)…")
    massive_burst(total_packets=500000, inter_pkt_sec=0.0000001)

    # -------------------------------------------------------------
    # 2️⃣ Slightly slower but still over the limit – 100 pkts @ 0.005 s
    # -------------------------------------------------------------
    # print("\n>>> Running moderate burst (100 pkts, 5 ms gap)…")
    # massive_burst(total_packets=100, inter_pkt_sec=0.005)
