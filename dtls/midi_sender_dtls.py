# dtls_sender.py
# DTLS-PSK client that sends your existing header+midi payloads, reads ACKs over the DTLS channel,
# and logs RTT/one-way estimates.

import socket
import struct
import time
import csv
import sys
import mido
from threading import Thread, Lock, Event
from queue import Queue, Empty
from mbedtls.tls import DTLSConfiguration, DTLSClient, DTLSServer

# ---------------- Configuration ----------------
DEST_IP = "10.239.13.237"  # server IP (change)
DEST_PORT = 5005
LOG_PATH = "sender_log.csv"

HDR_FMT = "!IqH"          # seq:uint32, send_ts:int64 (ns), payload_len:uint16
HDR_SIZE = struct.calcsize(HDR_FMT)

ACK_FMT = "!Iq"           # seq:uint32, recv_ts:int64 (ns)
ACK_SIZE = struct.calcsize(ACK_FMT)

PSK_IDENTITY = b"midi-client"
PSK_KEY = b"t0ps3cr3tk3y"

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
    return names[0]  # pick first

# ---------------- DTLS client setup ----------------
psk_store = {PSK_IDENTITY: PSK_KEY}
conf = DTLSConfiguration(
    pre_shared_key_store=psk_store,
    validate_certificates=False,
)

# Underlying UDP socket
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_sock.bind(("0.0.0.0", 0))  # ephemeral local port
udp_sock.setblocking(False)

# Create client-side TLS context and a TLSWrappedSocket connected to the server
ctx = ClientContext(conf)
# TLSWrappedSocket(ctx, sock, server_side=False, server_hostname=None, peer_addr=(DEST_IP, DEST_PORT))
dtls_sock = TLSWrappedSocket(ctx, udp_sock, server_side=False, server_hostname=None, peer_addr=(DEST_IP, DEST_PORT))

# Perform handshake
dtls_sock.do_handshake()
print("DTLS handshake completed with", (DEST_IP, DEST_PORT))

# ---------------- Threads ----------------
def ack_reader():
    """Read ACKs from the DTLS socket (decrypted)"""
    while not stop_event.is_set():
        try:
            data = dtls_sock.recv(1024)  # blocking inside; you may want to set a timeout in your version
            if not data:
                continue
            if len(data) >= ACK_SIZE:
                ack_seq, recv_ts = struct.unpack(ACK_FMT, data[:ACK_SIZE])
                with acks_lock:
                    acks[ack_seq] = recv_ts
        except Exception:
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

            # send via DTLS
            try:
                dtls_sock.send(packet)
            except Exception as e:
                print("DTLS send error:", e)
                midi_queue.task_done()
                continue

            # push to log queue
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
            # Wait for ACK (with a timeout or retry policy)
            wait_start = time.time()
            while not ack_received and time.time() - wait_start < 5.0:
                with acks_lock:
                    if seq_num in acks:
                        recv_ts = acks.pop(seq_num)
                        now_ns = mono_ns()
                        rtt_ns = now_ns - send_ts
                        est_oneway_ns = rtt_ns // 2
                        ack_received = True
                        break
                time.sleep(0.001)

            if not ack_received:
                # mark with None or -1
                writer.writerow([seq_num, send_ts / 1_000_000, None, None])
            else:
                writer.writerow([seq_num, send_ts / 1_000_000, rtt_ns / 1_000_000, est_oneway_ns / 1_000_000])
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

if __name__ == "__main__":
    main()
