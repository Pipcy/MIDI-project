import socket, struct, time, csv, sys
import mido
from threading import Thread, Lock, Event
from queue import Queue, Empty

# ---------------- Configuration ----------------
DEST_IP = "10.239.166.92"  # Receiver IP
DEST_PORT = 5005
LOG_PATH = "sender_log.csv"

HDR_FMT = "!IqH"          # seq:uint32, send_ts:int64, payload_len:uint16
HDR_SIZE = struct.calcsize(HDR_FMT)

ACK_FMT = "!Iq"           # seq:uint32, recv_ts:int64
ACK_SIZE = struct.calcsize(ACK_FMT)

# ---------------- Globals ---------------------
seq = 0
acks = {}                 # seq -> recv_ts
acks_lock = Lock()
midi_queue = Queue()      # MIDI messages only
log_queue = Queue()       # (seq, send_ts) for logging
stop_event = Event()

# ---------------- Utility Functions ----------------
def mono_ns():
    try:
        return time.monotonic_ns()
    except AttributeError:
        return int(time.monotonic() * 1e9)

def pick_input_port():
    names = mido.get_input_names()
    if not names:
        print("No MIDI input devices found!")
        sys.exit(1)
    print("Available MIDI inputs:")
    for i, name in enumerate(names):
        print(f"{i}: {name}")
    return names[0]

# ---------------- Threads ----------------
def ack_listener(sock):
    """Continuously listens for ACKs from the receiver"""
    while not stop_event.is_set():
        try:
            data, addr = sock.recvfrom(1024)
            if len(data) >= ACK_SIZE:
                ack_seq, recv_ts = struct.unpack(ACK_FMT, data[:ACK_SIZE])
                with acks_lock:
                    acks[ack_seq] = recv_ts
        except Exception:
            continue

def midi_poll_thread(inport):
    """Poll MIDI input and push messages to queue"""
    while not stop_event.is_set():
        msg = inport.poll()
        if msg:
            midi_queue.put(msg)
        time.sleep(0.001)

def sender_thread(sock):
    """Send MIDI messages from queue to receiver"""
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
            send_ts = mono_ns()
            header = struct.pack(HDR_FMT, seq, send_ts, len(midi_bytes))
            packet = header + midi_bytes
            sock.sendto(packet, (DEST_IP, DEST_PORT))
            print(f"Sent seq={seq}, {len(midi_bytes)} bytes to {DEST_IP}:{DEST_PORT}")

            # push to log queue
            log_queue.put((seq, send_ts))

        midi_queue.task_done()

def logger_thread(log_path):
    """Log send_ts, RTT, estimated one-way latency"""
    with open(log_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["seq", "send_ts_ms", "rtt_ms", "est_oneway_ms"])

        while not stop_event.is_set():
            try:
                seq_num, send_ts = log_queue.get(timeout=0.05)
            except Empty:
                continue

            ack_received = False
            while not ack_received:
                with acks_lock:
                    if seq_num in acks:
                        recv_ts = acks.pop(seq_num)
                        now_ns = mono_ns()
                        rtt_ns = now_ns - send_ts
                        est_oneway_ns = rtt_ns // 2
                        ack_received = True
                        break
                time.sleep(0.001)

            writer.writerow([
                seq_num,
                send_ts / 1_000_000,
                rtt_ns / 1_000_000,
                est_oneway_ns / 1_000_000
            ])
            f.flush()
            log_queue.task_done()

# ---------------- Main ----------------
def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))  # ephemeral port for receiving ACKs
    sock.settimeout(0.05)

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

        print(f"Sending MIDI to {DEST_IP}:{DEST_PORT}, logging → {LOG_PATH}")
        try:
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            stop_event.set()
            print("\nStopping sender...")

if __name__ == "__main__":
    main()
