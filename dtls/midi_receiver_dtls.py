#!/usr/bin/env python3
import socket
import struct
import time
from contextlib import suppress
from threading import Thread
import mido

from mbedtls.tls import DTLSConfiguration, ServerContext, TLSWrappedSocket, HelloVerifyRequest

# ---------------- Configuration ----------------
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 5005

HDR_FMT = "!IqH"  # seq:uint32, send_ts:int64 (ns), payload_len:uint16
HDR_SIZE = struct.calcsize(HDR_FMT)
ACK_FMT = "!Iq"
ACK_SIZE = struct.calcsize(ACK_FMT)

PSK_IDENTITY = "midi-client"   # MUST match client exactly
PSK_KEY = b"t0ps3cr3tk3y"      # MUST match client exactly

conf = DTLSConfiguration(
    pre_shared_key=(PSK_IDENTITY, PSK_KEY),
    validate_certificates=False,
)

print("Server PSK tuple:", conf.pre_shared_key)
print("PSK Identity type:", type(PSK_IDENTITY), "PSK Key type:", type(PSK_KEY))

ctx = ServerContext(conf)

mono_ns = getattr(time, "monotonic_ns", lambda: int(time.monotonic() * 1e9))

# ---------------- MIDI Setup ----------------
names = mido.get_output_names()
if not names:
    print("No MIDI output devices found!")
    exit(1)
outport = mido.open_output(names[0])
print("Using MIDI output:", names[0])

# ---------------- DTLS Setup ----------------
srv_sock = ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv_sock.bind((LISTEN_IP, LISTEN_PORT))
print(f"DTLS server listening on {LISTEN_IP}:{LISTEN_PORT}")


def accept_dtls(listen_sock: TLSWrappedSocket) -> TLSWrappedSocket:
    cli0, addr0 = listen_sock.accept()
    cli0.setcookieparam(addr0[0].encode())
    print("Initial DTLS client from", addr0)

    # First handshake attempt (may require cookie)
    with suppress(HelloVerifyRequest):
        try:
            cli0.do_handshake()
        except Exception as e:
            print("Handshake attempt failed:", e)
            print("Client PSK identity (if available):", getattr(cli0, "psk_identity", None))
            raise

    # Accept again after cookie verification
    cli1, addr1 = cli0.accept()
    cli0.close()
    cli1.setcookieparam(addr1[0].encode())
    print("Verified DTLS client from", addr1)

    cli1.do_handshake()
    print("DTLS handshake completed with", addr1)
    cli1.settimeout(1.0)
    return cli1


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
    try: cli.close()
    except: pass


def main():
    while True:
        print("Waiting for DTLS client...")
        cli = accept_dtls(srv_sock)
        addr = cli.getpeername()
        Thread(target=handle_client, args=(cli, addr), daemon=True).start()


if __name__ == "__main__":
    main()
