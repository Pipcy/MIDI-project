import socket, struct, time, csv, sys
import mido
from threading import Thread, Lock, Event
from queue import Queue, Empty
import hmac, hashlib

# ---------------- Configuration ----------------
DEST_IP = "10.193.68.64"
DEST_PORT = 5005
LOG_PATH = "sender_log.csv"

HDR_FMT = "!IqH"
HDR_SIZE = struct.calcsize(HDR_FMT)

ACK_FMT = "!Iq"
ACK_SIZE = struct.calcsize(ACK_FMT)

SECRET_KEY = b't0ps3cr3tk3y'

# ---------------- Globals ---------------------
seq = 0
acks = {}
acks_lock = Lock()
midi_queue = Queue()
log_queue = Queue()
stop_event = Event()

# Use NTP-synced wall-clock time
def now_ns():
    return time.time_ns()

def pick_input_port():
    names = mido.get_input_names()
    if not names:
        print("No MIDI input devices!")
        sys.exit(1)
    print("Available MIDI inputs:")
    for i, name in enumerate(names):
        print(f"{i}: {name}")
    return names[1]

# ---------------- Threads ----------------
def ack_listener(sock):
    while not stop_event.is_set():
        try:
            data, addr = sock.recvfrom(1024)
            if len(data) >= ACK_SIZE:
                ack_seq, recv_ts = struct.unpack(ACK_FMT, data)
                with acks_lock:
                    acks[ack_seq] = recv_ts
        except Exception:
            continue

def midi_poll_thread(inport):
    while not stop_event.is_set():
        msg = inport.poll()
        if msg:
            midi_queue.put(msg)
        time.sleep(0.001)

def sender_thread(sock):
    global seq
    while not stop_event.is_set():
        try:
            msg = midi_queue.get(timeout=0.05)
        except Empty:
            continue

        if isinstance(msg, mido.Message):
            midi_bytes = bytes(msg.bytes())
            if not midi_bytes:
                midi_queue.task_done()
                continue

            seq += 1
            send_ts = now_ns()

            header = struct.pack(HDR_FMT, seq, send_ts, len(midi_bytes))
            body = header + midi_bytes
            mac = hmac.new(SECRET_KEY, body, hashlib.sha256).digest()
            packet = body + mac

            sock.sendto(packet, (DEST_IP, DEST_PORT))
            print(f"Sent seq={seq}")

            log_queue.put((seq, send_ts))

        midi_queue.task_done()

def logger_thread(log_path):
    with open(log_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["seq", "send_ts_ms", "ack_ts_ms", "rtt_ms"])

        while not stop_event.is_set():
            try:
                seq_num, send_ts = log_queue.get(timeout=0.05)
            except Empty:
                continue

            ack_ts = None

            while ack_ts is None:
                with acks_lock:
                    if seq_num in acks:
                        ack_ts = acks.pop(seq_num)
                time.sleep(0.001)

            rtt_ms = (ack_ts - send_ts) / 1_000_000

            writer.writerow([
                seq_num,
                send_ts / 1_000_000,
                ack_ts / 1_000_000,
                rtt_ms
            ])
            f.flush()

            log_queue.task_done()

# ---------------- Main ----------------
def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))

    in_name = pick_input_port()

    with mido.open_input(in_name) as inport:
        threads = [
            Thread(target=ack_listener, args=(sock,), daemon=True),
            Thread(target=midi_poll_thread, args=(inport,), daemon=True),
            Thread(target=sender_thread, args=(sock,), daemon=True),
            Thread(target=logger_thread, args=(LOG_PATH,), daemon=True)
        ]

        for t in threads:
            t.start()

        print(f"Sending MIDI to {DEST_IP}:{DEST_PORT}")

        try:
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            stop_event.set()
            print("Stopping...")

if __name__ == "__main__":
    main()
