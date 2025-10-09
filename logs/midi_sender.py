import socket, struct, time, csv, sys
import mido

DEST_IP = "10.239.69.112"
DEST_PORT = 5005
LOG_PATH = "sender_log.csv"

HDR_FMT = "!IqH"
seq = 0

def monotonic_ns():
    try:
        return time.monotonic_ns()
    except AttributeError:
        return int(time.monotonic() * 1e9)

def pick_input_port():
    names = mido.get_input_names()
    if not names:
        print("uh oh: no MIDI input devices")
        sys.exit(1)
    return names[0]

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    in_name = pick_input_port()

    with mido.open_input(in_name) as inport, open(LOG_PATH, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["seq", "send_ts_ns"])
        print(f"Sending to {DEST_IP}:{DEST_PORT} | Logging to {LOG_PATH}")
        for msg in inport:
            # convert MIDI message to raw bytes
            midi_bytes = bytes(msg.bytes())
            if not midi_bytes:
                continue

            global seq
            seq += 1
            send_ts = monotonic_ns()

            # build packet: header + payload
            header = struct.pack(HDR_FMT, seq, send_ts, len(midi_bytes))
            packet = header + midi_bytes

            # send and log
            sock.sendto(packet, (DEST_IP, DEST_PORT))
            writer.writerow([seq, send_ts])
            f.flush()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nSender stopped.")

