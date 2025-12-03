#!/usr/bin/env python3

import socket
import struct
import time
from contextlib import suppress
from threading import Thread, Lock
import csv
import mido

from mbedtls.tls import (
    DTLSConfiguration,
    ServerContext,
    TLSWrappedSocket,
    HelloVerifyRequest,
)

# ---------------- Configuration ----------------
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 5005
LOG_PATH = "receiver_log.csv"

HDR_FMT = "!IqH"
HDR_SIZE = struct.calcsize(HDR_FMT)
ACK_FMT = "!Iq"
ACK_SIZE = struct.calcsize(ACK_FMT)

PSK_IDENTITY = "midi-client"
PSK_KEY = b"t0ps3cr3tk3y"

conf = DTLSConfiguration(
    pre_shared_key=(PSK_IDENTITY, PSK_KEY),  # tuple for 2.10.1
    validate_certificates=False,
)
ctx = ServerContext(conf)

mono_ns = getattr(time, "monotonic_ns", lambda: int(time.monotonic() * 1e9))

# ---------------- MIDI Setup ----------------
names = mido.get_output_names()
if not names:
    print("No MIDI output devices!")
    exit(1)
outport = mido.open_output(names[0])
print("Using MIDI output:", names[0])

# ---------------- DTLS Setup ----------------
ctx = ServerContext(conf)

srv: TLSWrappedSocket = ctx.wrap_socket(
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((LISTEN_IP, LISTEN_PORT))

print(f"DTLS server listening on {LISTEN_IP}:{LISTEN_PORT}")

csv_lock = Lock()
log_file = open(LOG_PATH, "w", newline="")
writer = csv.writer(log_file)
writer.writerow(["seq", "send_ts_ms", "recv_ts_ms"])
log_file.flush()


def accept_dtls(listen_sock: TLSWrappedSocket) -> TLSWrappedSocket:
    """Perform cookie + handshake as required by old python-mbedtls."""
    cli0, addr0 = listen_sock.accept()
    cli0.setcookieparam(addr0[0].encode())
    print("Initial DTLS client from", addr0)

    # First handshake attempt (may need cookie)
    with suppress(HelloVerifyRequest):
        cli0.do_handshake()

    # After cookie verification, the client retransmits, so accept again
    cli1, addr1 = cli0.accept()
    cli0.close()

    cli1.setcookieparam(addr1[0].encode())
    print("Verified DTLS client from", addr1)

    cli1.do_handshake()
    print("DTLS handshake completed with", addr1)

    cli1.settimeout(1.0)
    return cli1


def handle_client(cli: TLSWrappedSocket, addr):
    print(f"[{addr}] client handler started")

    while True:
        try:
            data = cli.recv(4096)
        except Exception:
            break

        if not data:
            continue

        if len(data) < HDR_SIZE:
            print("[short packet]", len(data))
            continue

        seq, send_ts, length = struct.unpack(HDR_FMT, data[:HDR_SIZE])
        midi_bytes = data[HDR_SIZE:HDR_SIZE + length]

        recv_ts = mono_ns()

        # Log
        with csv_lock:
            writer.writerow([seq, send_ts / 1e6, recv_ts / 1e6])
            log_file.flush()

        # Play MIDI
        try:
            msg = mido.Message.from_bytes(midi_bytes)
            outport.send(msg)
            print(f"[{addr}] played seq={seq} {msg}")
        except Exception as e:
            print("Invalid MIDI:", e)

        # ACK
        ack = struct.pack(ACK_FMT, seq, recv_ts)
        try:
            cli.send(ack)
        except Exception:
            break

    print(f"[{addr}] client disconnected")
    try: cli.close()
    except: pass


def main():
    while True:
        print("Waiting for DTLS client...")
        cli = accept_dtls(srv)
        addr = cli.getpeername()
        Thread(target=handle_client, args=(cli, addr), daemon=True).start()


if __name__ == "__main__":
    main()
