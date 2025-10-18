import socket, struct, time, csv, mido
import hmac, hashlib


# ---------------- Configuration ----------------
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 5005
LOG_PATH = "receiver_log.csv"

HDR_FMT = "!IqH"       # seq:uint32, send_ts:int64, payload_len:uint16
HDR_SIZE = struct.calcsize(HDR_FMT)

ACK_FMT = "!Iq"        # seq:uint32, recv_ts:int64
ACK_SIZE = struct.calcsize(ACK_FMT)

mono_ns = getattr(time, "monotonic_ns", lambda: int(time.monotonic() * 1e9))

SECRET_KEY = b't0ps3cr3tk3y'

# ---------------- MIDI Setup ----------------
print("Available MIDI output ports:")
for name in mido.get_output_names():
    print("   ", name)

# Choose the first available MIDI output port
out_name = mido.get_output_names()[0]
outport = mido.open_output(out_name)
print(f"Using MIDI output: {out_name}")

# ---------------- UDP Setup ----------------
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((LISTEN_IP, LISTEN_PORT))
print(f"Receiver listening on {LISTEN_IP}:{LISTEN_PORT} → {LOG_PATH}")

# ---------------- Main Loop ----------------
with open(LOG_PATH, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["seq", "send_ts_ms", "recv_ts_ms"])

    while True:
        try:
            data, addr = sock.recvfrom(2048)
            # check hmac
            msg = data[:-32] # msg is all but last 32 bytes
            mac_recv = data[-32:]# mac is only the last 32 bytes
            mac_calc = hmac.new(SECRET_KEY, msg, hashlib.sha256).digest()
            if not hmac.compare_digest(mac_calc, mac_recv):
                print("Uh oh!")
                continue

            # Debug
            # print(f"Received {len(data)} bytes from {addr}")
        except Exception as e:
            print("Receive error:", e)
            continue

        recv_ts = mono_ns()  # nanoseconds
        if len(data) < HDR_SIZE:
            continue

        # Unpack header
        seq, send_ts, length = struct.unpack(HDR_FMT, data[:HDR_SIZE])
        midi_bytes = data[HDR_SIZE:HDR_SIZE + length]
        send_ts_ms = send_ts / 1_000_000
        recv_ts_ms = recv_ts / 1_000_000

        # ---- Log to CSV ----
        writer.writerow([seq, send_ts_ms, recv_ts_ms])
        f.flush()

        # ---- MIDI Playback ----
        try:
            msg = mido.Message.from_bytes(midi_bytes)
            outport.send(msg)
            print("Played:", msg)
        except Exception as e:
            print("Invalid MIDI message:", e)

        # ---- Send ACK ----
        try:
            ack = struct.pack(ACK_FMT, seq, recv_ts)
            sock.sendto(ack, addr)
        except Exception as e:
            print("ACK send error:", e)
