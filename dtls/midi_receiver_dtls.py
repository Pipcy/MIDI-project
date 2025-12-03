# midi_receiver_dtls.py
# DTLS-PSK server that receives header+MIDI payloads and sends ACKs.

import socket
import struct
import time
from contextlib import suppress

from mbedtls.tls import (
    DTLSConfiguration,
    ServerContext,
    TLSWrappedSocket,
    HelloVerifyRequest,
)

# ---------------- Configuration ----------------
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 5005

HDR_FMT = "!IqH"            # seq:uint32, send_ts:int64 (ns), payload_len:uint16
HDR_SIZE = struct.calcsize(HDR_FMT)

ACK_FMT = "!Iq"             # seq:uint32, recv_ts:int64 (ns)
ACK_SIZE = struct.calcsize(ACK_FMT)

PSK_IDENTITY = "midi-client"        # must match sender
PSK_KEY = b"t0ps3cr3tk3y"           # must match sender

conf = DTLSConfiguration(
    pre_shared_key={PSK_IDENTITY: PSK_KEY},   # <-- THIS is the correct server format
    validate_certificates=False,
)

try:
    mono_ns = time.monotonic_ns
except AttributeError:
    mono_ns = lambda: int(time.monotonic() * 1e9)


# ---------------- DTLS server setup ----------------
conf = DTLSConfiguration(
    pre_shared_key=(PSK_IDENTITY, PSK_KEY),
    validate_certificates=False,
)

ctx = ServerContext(conf)
srv: TLSWrappedSocket = ctx.wrap_socket(
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((LISTEN_IP, LISTEN_PORT))

print(f"DTLS server listening on {LISTEN_IP}:{LISTEN_PORT}")


def accept_dtls_client(listen_sock: TLSWrappedSocket) -> TLSWrappedSocket:
    """
    Perform DTLS cookie + handshake as in python-mbedtls examples.
    Returns a connected TLSWrappedSocket for the client.
    """
    # First connection attempt (may raise HelloVerifyRequest)
    cli0, addr0 = listen_sock.accept()
    cli0.setcookieparam(addr0[0].encode("ascii"))
    print("Initial DTLS client from", addr0)

    with suppress(HelloVerifyRequest):
        cli0.do_handshake()

    # If HelloVerifyRequest happened, a second accept() is needed
    cli1, addr1 = cli0.accept()
    cli0.close()
    cli1.setcookieparam(addr1[0].encode("ascii"))
    print("Verified DTLS client from", addr1)

    cli1.do_handshake()
    print("DTLS handshake completed with", addr1)

    # Optionally set timeout so recv() doesn’t block forever
    cli1.settimeout(1.0)
    return cli1


def handle_client(cli: TLSWrappedSocket):
    """
    Receive packets, parse header + MIDI, and send ACKs.
    """
    while True:
        try:
            data = cli.recv(4096)
        except Exception:
            # timeout, or client closed; treat as end of session
            break

        if not data:
            continue

        if len(data) < HDR_SIZE:
            print("Received too-short packet:", len(data))
            continue

        seq, send_ts_ns, payload_len = struct.unpack(HDR_FMT, data[:HDR_SIZE])
        midi_payload = data[HDR_SIZE:HDR_SIZE + payload_len]

        # Timestamp when we received the packet (server-side)
        recv_ts_ns = mono_ns()

        print(
            f"Got seq={seq}, payload_len={payload_len}, "
            f"send_ts_ns={send_ts_ns}, recv_ts_ns={recv_ts_ns}"
        )
        print("MIDI bytes:", list(midi_payload))

        # Build and send ACK
        ack = struct.pack(ACK_FMT, seq, recv_ts_ns)
        try:
            cli.send(ack)
        except Exception as e:
            print("Error sending ACK:", e)
            break


def main():
    while True:
        try:
            print("Waiting for DTLS client...")
            cli = accept_dtls_client(srv)
            handle_client(cli)
            cli.close()
            print("Client disconnected")
        except KeyboardInterrupt:
            print("\nStopping server...")
            srv.close()
            break


if __name__ == "__main__":
    main()

