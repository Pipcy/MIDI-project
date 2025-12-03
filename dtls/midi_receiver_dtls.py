#!/usr/bin/env python3
import socket
import struct
import time
from threading import Thread
import mido
from mbedtls.tls import DTLSConfiguration, ServerContext, TLSWrappedSocket

# ---------------- Configuration ----------------
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 5005

HDR_FMT = "!IqH"
HDR_SIZE = struct.calcsize(HDR_FMT)
ACK_FMT = "!Iq"

PSK_IDENTITY = "midi-client"   # must be str
PSK_KEY = b"t0ps3cr3tk3y"      # must be bytes

mono_ns = getattr(time, "monotonic_ns", lambda: int(time.monotonic() * 1e9))

# ---------------- MIDI Setup ----------------
names = mido.get_output_names()
if not names:
    print("No MIDI output devices found!")
    exit(1)
outport = mido.open_output(names[0])
print("Using MIDI output:", names[0])

# ---------------- DTLS Setup ----------------
conf = DTLSConfiguration(pre_shared_key=(PSK_IDENTITY, PSK_KEY))
ctx = ServerContext(conf)

srv_sock = ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))  # remove server_side
srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv_sock.bind((LISTEN_IP, LISTEN_PORT))
srv_sock.settimeout(1.0)
print(f"DTLS server listening on {LISTEN_IP}:{LISTEN_PORT}")


# ---------------- Client Handler ----------------
def handle_client(cli: TLSWrappedSocket, addr):
    print(f"[{addr}] Client handler started")
    while True:
        try:
            data = cli.recv(4096)
        except Exception:
            break
        if not data or len(data) < HDR_SIZE:
            continue

        seq, send_ts, payload_len = struct.unpack(HDR_FMT, data[:HDR_SIZE])
        midi_bytes = data[HDR_SIZE:HDR_SIZE+payload_len]
        recv_ts = mono_ns()

        # Play MIDI
        try:
            msg = mido.Message.from_bytes(midi_bytes)
            outport.send(msg)
            print(f"[{addr}] Played seq={seq}: {msg}")
        except Exception as e:
            print("Invalid MIDI:", e)

        # Send ACK
        ack = struct.pack(ACK_FMT, seq, recv_ts)
        try:
            cli.send(ack)
        except Exception:
            break
    print(f"[{addr}] Client disconnected")
    try:
        cli.close()
    except:
        pass


# ---------------- Main Loop ----------------
def accept_clients():
    while True:
        try:
            cli, addr = srv_sock.accept()
            print("DTLS handshake completed with", addr)
            Thread(target=handle_client, args=(cli, addr), daemon=True).start()
        except socket.timeout:
            continue
        except KeyboardInterrupt:
            print("Server shutting down")
            break


if __name__ == "__main__":
    accept_clients()
