import socket, struct, time, csv, mido, hmac, hashlib

# ---------------- Configuration ----------------
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 5005
LOG_PATH = "receiver_log.csv"

HDR_FMT = "!IqH"       # seq:uint32, send_ts:int64, payload_len:uint16
HDR_SIZE = struct.calcsize(HDR_FMT)

ACK_FMT = "!Iq"        # seq:uint32, recv_ts:int64
ACK_SIZE = struct.calcsize(ACK_FMT)

SECRET_KEY = b't0ps3cr3tk3y'

mono_ns = getattr(time, "monotonic_ns", lambda: int(time.monotonic() * 1e9))

# ---------------- Replay Protection ----------------
last_seq = -1          # highest sequence number seen so far
recent_seqs = set()    # remember all received seq numbers
WINDOW = 1000          # optional safety window for stale detection

# ---------------- MIDI Setup ----------------
print("Available MIDI output ports:")
for name in mido.get_output_names():
    print("   ", name)

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
        except Exception as e:
            print("Receive error:", e)
            continue

        # --- Verify HMAC ---
        if len(data) < HDR_SIZE + 32:
            continue  # too short to be valid

        msg = data[:-32]
        mac_recv = data[-32:]
        mac_calc = hmac.new(SECRET_KEY, msg, hashlib.sha256).digest()
        if not hmac.compare_digest(mac_calc, mac_recv):
            print("Uh oh!")
            continue

        recv_ts = mono_ns()
        seq, send_ts, length = struct.unpack(HDR_FMT, data[:HDR_SIZE])
        midi_bytes = data[HDR_SIZE:HDR_SIZE + length]

        # --- Replay protection ---
        if seq in recent_seqs:
            print(f"Replay detected! seq={seq} already processed")
            continue

        if seq < last_seq - WINDOW:
            print(f"Old/stale packet dropped (seq={seq}, last_seq={last_seq})")
            continue

        # Record as valid
        recent_seqs.add(seq)
        last_seq = max(last_seq, seq)

        # --- Log to CSV ---
        send_ts_ms = send_ts / 1_000_000
        recv_ts_ms = recv_ts / 1_000_000
        writer.writerow([seq, send_ts_ms, recv_ts_ms])
        f.flush()

        # --- MIDI Playback ---
        try:
            msg = mido.Message.from_bytes(midi_bytes)
            outport.send(msg)
            print(f"Played seq={seq}: {msg}")
        except Exception as e:
            print(f"Invalid MIDI message (seq={seq}):", e)
            continue

        # --- Send ACK ---
        try:
            ack = struct.pack(ACK_FMT, seq, recv_ts)
            sock.sendto(ack, addr)
        except Exception as e:
            print("ACK send error:", e)
