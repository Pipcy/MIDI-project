# midi_sender_dtls.py
# DTLS-PSK client that sends header+MIDI payloads, reads ACKs,
# and logs RTT / estimated one-way latency.

import socket
import struct
import time
import csv
import sys
import mido
from threading import Thread, Lock, Event
from queue import Queue, Empty

from mbedtls.tls import DTLSConfiguration, ClientContext, TLSWrappedSocket

# ---------------- Configuration ----------------
DEST_IP = "10.239.135.70"   # server IP (change as needed)
DEST_PORT = 5005
LOG_PATH = "sender_log.csv"

HDR_FMT = "!IqH"            # seq:uint32, send_ts:int64 (ns), payload_len:uint16
HDR_SIZE = struct.calcsize(HDR_FMT)

ACK_FMT = "!Iq"             # seq:uint32, recv_ts:int64 (ns)
ACK_SIZE = struct.calcsize(ACK_FMT)

# PSK identity and key MUST match the receiver
PSK_IDENTITY = b"midi-client"        # string
PSK_KEY = b"t0ps3cr3tk3y"           # bytes (same on server)

# ---------------- Globals ---------------------
seq = 0
acks = {}
acks_lock = Lock()
midi_queue = Queue()
log_queue = Queue()
stop_event = Event()

# ---------------- Utility ----------------
try:
    mono_ns = time.monotonic_ns
except AttributeError:
    mono_ns = lambda: int(time.monotonic() * 1e9)


def pick_input_port():
    names = mido.get_input_names()
    if not names:
        print("No MIDI input devices found!")
        sys.exit(1)
    print("Available MIDI inputs:")
    for i, name in enumerate(names):
        print(f"{i}: {name}")
    # You can change this to prompt if you want
    return names[0]  # pick first


# ---------------- DTLS client setup ----------------
conf = DTLSConfiguration(
    pre_shared_key=(PSK_IDENTITY, PSK_KEY),
    validate_certificates=False,
)

# Create client-side DTLS context and wrapped UDP socket
ctx = ClientContext(conf)
dtls_sock: TLSWrappedSocket = ctx.wrap_socket(
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
    server_hostname=None,
)

# Connect underlying DTLS socket to server and handshake
dtls_sock.connect((DEST_IP, DEST_PORT))
dtls_sock.do_handshake()
dtls_sock.settimeout(0.1)
print("DTLS handshake completed with", (DEST_IP, DEST_PORT))


# ---------------- Threads ----------------
def ack_reader():
    """Read ACKs from the DTLS socket (decrypted) and store them in `acks`."""
    while not stop_event.is_set():
        try:
            data = dtls_sock.recv(1024)
            if not data:
                continue
            if len(data) >= ACK_SIZE:
                ack_seq, recv_ts = struct.unpack(ACK_FMT, data[:ACK_SIZE])
                with acks_lock:
                    acks[ack_seq] = recv_ts
        except Exception:
            # timeout or other recoverable error
            time.sleep(0.001)
            continue


def midi_poll_thread(inport):
    while not stop_event.is_set():
        msg = inport.poll()
        if msg:
            midi_queue.put(msg)
        time.sleep(0.001)


def sender_thread():
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

            try:
                dtls_sock.send(packet)
            except Exception as e:
                print("DTLS send error:", e)
                midi_queue.task_done()
                continue

            log_queue.put((seq, send_ts))

        midi_queue.task_done()


def logger_thread(log_path):
    with open(log_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["seq", "send_ts_ms", "rtt_ms", "est_oneway_ms"])
        while not stop_event.is_set():
            try:
                seq_num, send_ts = log_queue.get(timeout=0.05)
            except Empty:
                continue

            ack_received = False
            rtt_ns = None
            est_oneway_ns = None

            wait_start = time.time()
            while not ack_received and time.time() - wait_start < 5.0:
                with acks_lock:
                    if seq_num in acks:
                        recv_ts = acks.pop(seq_num)
                        # We don't strictly need recv_ts for RTT,
                        # we just use local time.
                        now_ns = mono_ns()
                        rtt_ns = now_ns - send_ts
                        est_oneway_ns = rtt_ns // 2
                        ack_received = True
                        break
                time.sleep(0.001)

            if not ack_received:
                writer.writerow([seq_num, send_ts / 1_000_000, None, None])
            else:
                writer.writerow(
                    [
                        seq_num,
                        send_ts / 1_000_000,
                        rtt_ns / 1_000_000,
                        est_oneway_ns / 1_000_000,
                    ]
                )
            f.flush()
            log_queue.task_done()


# ---------------- Main ----------------
def main():
    in_name = pick_input_port()
    with mido.open_input(in_name) as inport:
        threads = [
            Thread(target=ack_reader, daemon=True),
            Thread(target=midi_poll_thread, args=(inport,), daemon=True),
            Thread(target=sender_thread, daemon=True),
            Thread(target=logger_thread, args=(LOG_PATH,), daemon=True),
        ]
        for t in threads:
            t.start()

        print(f"Sending MIDI to DTLS {DEST_IP}:{DEST_PORT}, logging → {LOG_PATH}")
        try:
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            stop_event.set()
            print("\nStopping sender...")
            dtls_sock.close()


if __name__ == "__main__":
    main()

