import socket, struct, time, csv, sys
import mido

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 5005
LOG_PATH = "receiver_log.csv"

HDR_FMT = "!IqH"
HDR_SIZE = struct.calcsize(HDR_FMT)

def monotonic_ns():
    try:
        return time.monotonic_ns()
    except AttributeError:
        return int(time.monotonic() * 1e9)

def pick_output_port():
    names = mido.get_output_names()
    if not names:
        print("uh oh: no MIDI output devices")
        sys.exit(1)
    return names[0]

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    out_name = pick_output_port()

    with mido.open_output(out_name) as outport, open(LOG_PATH, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["seq", "send_ts_ns", "recv_ts_ns"])
        print(f"Listening on {LISTEN_IP}:{LISTEN_PORT} | Logging to {LOG_PATH}")

        while True:
            data, _ = sock.recvfrom(2048)
            recv_ts = monotonic_ns()

            if len(data) < HDR_SIZE:
                continue
            seq, send_ts, length = struct.unpack(HDR_FMT, data[:HDR_SIZE])
            payload = data[HDR_SIZE:HDR_SIZE+length]
            if len(payload) != length:
                continue

            # Forward to local synth/output
            try:
                msg = mido.Message.from_bytes(payload)
                outport.send(msg)
            except Exception:
                # If multipart/packed messages arrive, you could parse bytes in a loop.
                pass

            # Log
            writer.writerow([seq, send_ts, recv_ts])
            f.flush()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nReceiver stopped.")

