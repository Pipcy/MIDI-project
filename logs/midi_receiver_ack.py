import socket, struct, time, csv

# ---------------- Configuration ----------------
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 5005
LOG_PATH = "receiver_log.csv"

HDR_FMT = "!IqH"       # seq:uint32, send_ts:int64, payload_len:uint16
HDR_SIZE = struct.calcsize(HDR_FMT)

ACK_FMT = "!Iq"        # seq:uint32, recv_ts:int64
ACK_SIZE = struct.calcsize(ACK_FMT)

mono_ns = getattr(time, "monotonic_ns", lambda: int(time.monotonic() * 1e9))

# ---------------- Setup ----------------
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((LISTEN_IP, LISTEN_PORT))
print(f"Receiver listening on {LISTEN_IP}:{LISTEN_PORT} → {LOG_PATH}")

with open(LOG_PATH, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["seq", "send_ts_ms", "recv_ts_ms"])

    while True:
        try:
            data, addr = sock.recvfrom(2048)
        except Exception as e:
            print("Receive error:", e)
            continue

        recv_ts = mono_ns()  # nanoseconds
        if len(data) < HDR_SIZE:
            continue

        # Unpack header
        seq, send_ts, length = struct.unpack(HDR_FMT, data[:HDR_SIZE])
        send_ts_ms = send_ts / 1_000_000
        recv_ts_ms = recv_ts / 1_000_000

        # Log to CSV
        writer.writerow([seq, send_ts_ms, recv_ts_ms])
        f.flush()

        # --------------- Send ACK ---------------
        try:
            ack = struct.pack(ACK_FMT, seq, recv_ts)
            sock.sendto(ack, addr)
            # Debug
            # print(f"Sent ACK for seq={seq} to {addr}")
        except Exception as e:
            print("ACK send error:", e)
