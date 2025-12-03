# midi_receiver_dtls.py
import socket
import struct
import time
from contextlib import suppress
from mbedtls.tls import DTLSConfiguration, ServerContext, TLSWrappedSocket, HelloVerifyRequest

# ---------------- Configuration ----------------
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 5005

HDR_FMT = "!IqH"  # seq:uint32, send_ts:int64, payload_len:uint16
HDR_SIZE = struct.calcsize(HDR_FMT)
ACK_FMT = "!Iq"   # seq:uint32, recv_ts:int64
ACK_SIZE = struct.calcsize(ACK_FMT)

PSK_IDENTITY = "midi-client"
PSK_KEY = b"t0ps3cr3tk3y"

try:
    mono_ns = time.monotonic_ns
except AttributeError:
    mono_ns = lambda: int(time.monotonic() * 1e9)

# ---------------- UDP + DTLS ----------------
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
udp_sock.bind((LISTEN_IP, LISTEN_PORT))

conf = DTLSConfiguration(pre_shared_key=(PSK_IDENTITY, PSK_KEY), validate_certificates=False)
ctx = ServerContext(conf)
srv_sock: TLSWrappedSocket = ctx.wrap_socket(udp_sock)

print(f"DTLS server listening on {LISTEN_IP}:{LISTEN_PORT}")

# ---------------- Accept client ----------------
def accept_dtls_client(sock: TLSWrappedSocket) -> TLSWrappedSocket:
    """
    Accept a DTLS client and complete handshake.
    Handles HelloVerifyRequest automatically.
    """
    cli, addr = sock.accept()
    print("Initial DTLS client from", addr)

    # First handshake attempt
    with suppress(HelloVerifyRequest):
        cli.do_handshake()

    # Sometimes HelloVerifyRequest occurs; retry handshake if needed
    try:
        cli.do_handshake()
    except HelloVerifyRequest:
        cli.do_handshake()

    cli.settimeout(1.0)
    print("DTLS handshake completed with", addr)
    return cli

# ---------------- Handle client ----------------
def handle_client(cli: TLSWrappedSocket):
    while True:
        try:
            data = cli.recv(4096)
        except Exception:
            break

        if not data or len(data) < HDR_SIZE:
            continue

        seq, send_ts_ns, payload_len = struct.unpack(HDR_FMT, data[:HDR_SIZE])
        midi_payload = data[HDR_SIZE:HDR_SIZE + payload_len]
        recv_ts_ns = mono_ns()

        print(f"Got seq={seq}, payload_len={payload_len}, send_ts={send_ts_ns}, recv_ts={recv_ts_ns}")
        print("MIDI bytes:", list(midi_payload))

        ack = struct.pack(ACK_FMT, seq, recv_ts_ns)
        try:
            cli.send(ack)
        except Exception as e:
            print("Error sending ACK:", e)
            break

# ---------------- Main loop ----------------
def main():
    while True:
        try:
            print("Waiting for DTLS client...")
            cli = accept_dtls_client(srv_sock)
            handle_client(cli)
            cli.close()
            print("Client disconnected")
        except KeyboardInterrupt:
            print("\nStopping server...")
            srv_sock.close()
            break
        except Exception as e:
            print("Client handshake/connection failed:", e)

if __name__ == "__main__":
    main()
