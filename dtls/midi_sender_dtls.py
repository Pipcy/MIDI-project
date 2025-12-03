#!/usr/bin/env python3

import socket
import struct
import time
import csv
import sys
import mido
from threading import Thread, Lock, Event
from queue import Queue, Empty

from mbedtls.tls import DTLSConfiguration, ClientContext

DEST_IP = "10.239.135.70"
DEST_PORT = 5005
LOG_PATH = "sender_log.csv"

HDR_FMT = "!IqH"
HDR_SIZE = struct.calcsize(HDR_FMT)
ACK_FMT = "!Iq"
ACK_SIZE = struct.calcsize(ACK_FMT)

PSK_IDENTITY = "midi-client"
PSK_KEY = b"t0ps3cr3tk3y"

conf = DTLSConfiguration(
    pre_shared_key=(PSK_IDENTITY, PSK_KEY),
    validate_certificates=False,
)

mono_ns = getattr(time, "monotonic_ns", lambda: int(time.monotonic() * 1e9))

seq = 0
acks = {}
acks_lock = Lock()
midi_queue = Queue()
log_queue = Queue()
stop_event = Event()


def pick_input_port():
    ports = mido.get_input_names()
    if not ports:
        print("No MIDI input devices!")
        sys.exit(1)
    print("Using:", ports[0])
    return ports[0]


# /---- DTLS setup ----/
ctx = ClientContext(conf)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.connect((DEST_IP, DEST_PORT))

dtls_sock = ctx.wrap_socket(
    udp,
    server_hostname=None,
)

dtls_sock.do_handshake()
dtls_sock.settimeout(0.1)
print("DTLS handshake complete")


def ack_reader():
    while not stop_event.is_set():
        try:
            data = dtls_sock.recv(1024)
            if len(data) >= ACK_SIZE:
                ack_seq, recv_ts = struct.unpack(ACK_FMT, data)
                with acks_lock:
                    acks[ack_seq] = recv_ts
        except Exception:
            time.sleep(0.001)


def midi_poll(inport):
    while not stop_event.is_set():
        msg = inport.poll()
        if msg:
            midi_queue.put(msg)
        time.sleep(0.001)


def sender():
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
            continue

        log_queue.put((seq, send_ts))
        midi_queue.task_done()


def logger(path):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["seq", "send_ts_ms", "rtt_ms", "oneway_ms"])

        while not stop_event.is_set():
            try:
                seq_num, send_ts = log_queue.get(timeout=0.05)
            except Empty:
                continue

            start = time.time()
            got = False
            rtt_ns = None

            while time.time() - start < 5.0:
                with acks_lock:
                    if seq_num in acks:
                        recv_ts = acks.pop(seq_num)
                        now_ns = mono_ns()
                        rtt_ns = now_ns - send_ts
                        got = True
                        break
                time.sleep(0.001)

            if not got:
                w.writerow([seq_num, send_ts/1e6, None, None])
            else:
                w.writerow([seq_num, send_ts/1e6, rtt_ns/1e6, (rtt_ns/2)/1e6])
            f.flush()
            log_queue.task_done()


def main():
    inport = mido.open_input(pick_input_port())

    Thread(target=ack_reader, daemon=True).start()
    Thread(target=midi_poll, args=(inport,), daemon=True).start()
    Thread(target=sender, daemon=True).start()
    Thread(target=logger, args=(LOG_PATH,), daemon=True).start()

    print("Sender running, logging →", LOG_PATH)
    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        stop_event.set()
        dtls_sock.close()


if __name__ == "__main__":
    main()
