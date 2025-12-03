#!/usr/bin/env python3
import socket
import struct
import time
import mido
from threading import Thread, Lock, Event
from queue import Queue, Empty

from mbedtls.tls import DTLSConfiguration, ClientContext

# ---------------- Configuration ----------------
DEST_IP = "127.0.0.1"  # change to server IP
DEST_PORT = 5005

HDR_FMT = "!IqH"
HDR_SIZE = struct.calcsize(HDR_FMT)
ACK_FMT = "!Iq"
ACK_SIZE = struct.calcsize(ACK_FMT)

PSK_IDENTITY = "midi-client"
PSK_KEY = b"t0ps3cr3tk3y"

conf = DTLSConfiguration(pre_shared_key=(PSK_IDENTITY, PSK_KEY), validate_certificates=False)
print("Client PSK tuple:", conf.pre_shared_key)
print("PSK Identity type:", type(PSK_IDENTITY), "PSK Key type:", type(PSK_KEY))

mono_ns = getattr(time, "monotonic_ns", lambda: int(time.monotonic() * 1e9))

seq = 0
acks = {}
acks_lock = Lock()
midi_queue = Queue()
stop_event = Event()

# ---------------- MIDI ----------------
def pick_input_port():
    ports = mido.get_input_names()
    if not ports:
        print("No MIDI input devices found!")
        exit(1)
    print("Using MIDI input:", ports[0])
    return ports[0]

# ---------------- DTLS Setup ----------------
ctx = ClientContext(conf)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.connect((DEST_IP, DEST_PORT))

dtls_sock = ctx.wrap_socket(udp, server_hostname=None)
dtls_sock.do_handshake()
dtls_sock.settimeout(0.1)
print("DTLS handshake completed")


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
        packet =
