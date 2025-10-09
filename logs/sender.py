import socket, struct, time, csv

DEST_IP = "127.0.0.1"   # loopback address
DEST_PORT = 5005
RATE_HZ = 1              # messages per second

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
seq = 0
start = time.monotonic()

with open("sender_log.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["seq", "send_ts_ns"])
    while True:
        seq += 1
        send_ts = time.time_ns()         # monotonic timestamp
        payload = struct.pack("!Iq", seq, send_ts)
        sock.sendto(payload, (DEST_IP, DEST_PORT))
        writer.writerow([seq, send_ts])
        f.flush()
        time.sleep(1 / RATE_HZ)

