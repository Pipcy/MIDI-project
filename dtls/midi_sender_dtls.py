#!/usr/bin/env python3
import socket
import struct
import time
import mido
from mbedtls.tls import DTLSConfiguration, ClientContext

SERVER_ADDR = ("127.0.0.1", 5005)
PSK_IDENTITY = "midi-client"
PSK_KEY = b"t0ps3cr3tk3y"

HDR_FMT = "!IqH"
seq = 0
mono_ns = getattr(time, "monotonic_ns", lambda: int(time.monotonic() * 1e9))

# ---------------- MIDI Setup ----------------
inputs = mido.get_input_names()
if not inputs:
    print("No MIDI input devices found!")
    exit(1)

print("\nAvailable MIDI inputs:")
for i, name in enumerate(inputs):
    print(f"{i}: {name}")
idx = int(input("Select a MIDI input: "))
midi_name = inputs[idx]

midi_port = mido.open_input(midi_name)
print(f"Using MIDI input: {midi_name}")

# ---------------- DTLS Setup ----------------
conf = DTLSConfiguration(pre_shared_key=(PSK_IDENTITY, PSK_KEY))
ctx = ClientContext(conf)

udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dtls_sock = ctx.wrap_socket(udp_sock, server_hostname="localhost")  # required in recent versions
dtls_sock.connect(SERVER_ADDR)
print("Client: DTLS handshake completed")

# ---------------- Main Loop ----------------
try:
    while True:
        for msg in midi_port.iter_pending():
            data = msg.bytes()
            payload_len = len(data)
            send_ts = mono_ns()
            header = struct.pack(HDR_FMT, seq, send_ts, payload_len)
            packet = header + bytes(data)
            dtls_sock.send(packet)
            seq += 1
        time.sleep(0.001)
except KeyboardInterrupt:
    print("Exiting.")
finally:
    dtls_sock.close()
