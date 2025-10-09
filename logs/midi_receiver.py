# receiver_log_only.py
import socket, struct, time, csv

LISTEN_IP, LISTEN_PORT = "0.0.0.0", 5005
LOG_PATH = "receiver_log.csv"
HDR_FMT = "!IqH"
HDR_SIZE = struct.calcsize(HDR_FMT)

mono_ns = getattr(time, "monotonic_ns", lambda: int(time.monotonic()*1e9))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((LISTEN_IP, LISTEN_PORT))

with open(LOG_PATH, "w", newline="") as f:
    w = csv.writer(f); w.writerow(["seq","send_ts","recv_ts"])
    print(f"Listening on {LISTEN_IP}:{LISTEN_PORT} (logging only) → {LOG_PATH}")
    while True:
        data, _ = sock.recvfrom(2048)
        recv_ts = mono_ns() 
        recv_ts = recv_ts / 1_000_000.0
        if len(data) < HDR_SIZE: continue
        seq, send_ts, length = struct.unpack(HDR_FMT, data[:HDR_SIZE])
        send_ts = send_ts / 1_000_000.0
        # payload = data[HDR_SIZE:HDR_SIZE+length]  # not needed for logging
        w.writerow([seq, send_ts, recv_ts]); f.flush()
