# midi_sender_dtls.py
import struct
import time
from threading import Thread, Lock, Event
from queue import Queue, Empty
import mido
from mbedtls.tls import DTLSConfiguration, ClientContext, TLSWrappedSocket

# ---------------- Configuration ----------------
DEST_IP = "10.239.135.70"  # server IP
DEST_PORT = 5005

HDR_FMT = "!IqH"
HDR_SIZE = struct.calcsize(HDR_FMT)

ACK_FMT = "!Iq"
ACK_SIZE = struct.calcsize(ACK_FMT)

PSK_IDENTITY = "midi-client"
PSK_KEY = b"t0ps3cr3tk3y"

seq = 0
acks = {}
acks_lock = Lock()
midi_queue = Queue()
stop_event = Event()

try:
    mono_ns = time.monotonic_ns
except AttributeError:
    mono_ns = lambda: int(time.monotonic() * 1e9)

# ---------------- MIDI input ----------------
def pick_input_port():
    names = mido.get_input_names()
    if not names:
        print("No MIDI input devices found!")
        exit(1)
    return names[0]

# ---------------- DTLS client ----------------
conf = DTLSConfiguration(pre_shared_key=(PSK_IDENTITY, PSK_KEY), validate_certificates=False)
ctx = ClientContext(conf)
dtls_sock: TLSWrappedSocket = ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), server_hostname=None)

# Connect and handshake
while True:
    try:
        dtls_sock.connect((DEST_IP, DEST_PORT))
        dtls_sock.do_handshake()
        dtls_sock.settimeout(0.1)
        break
    except Exception as e:
        print("Handshake retry:", e)
        time.sleep(0.1)

print("DTLS handshake completed with", (DEST_IP, DEST_PORT))

# ---------------- Threads ----------------
def ack_reader():
    while not stop_event.is_set():
        try:
            data = dtls_sock.recv(1024)
            if data and len(data) >= ACK_SIZE:
                ack_seq, _ = struct.unpack(ACK_FMT, data[:ACK_SIZE])
                with acks_lock:
                    acks[ack_seq] = True
        except Exception:
            time.sleep(0.001)

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
            print("Send error:", e)
        midi_queue.task_done()

# ---------------- Main ----------------
def main():
    in_name = pick_input_port()
    with mido.open_input(in_name) as inport:
        threads = [
            Thread(target=ack_reader, daemon=True),
            Thread(target=midi_poll_thread, args=(inport,), daemon=True),
            Thread(target=sender_thread, daemon=True),
        ]
        for t in threads:
            t.start()
        print(f"Sending MIDI to {DEST_IP}:{DEST_PORT}")
        try:
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            stop_event.set()
            dtls_sock.close()
            print("\nStopped.")

if __name__ == "__main__":
    main()
