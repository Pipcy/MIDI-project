# dtls_receiver.py
# DTLS-PSK server that receives your existing header+midi payload,
# plays MIDI (mido) and replies with ACKs — all over DTLS.

import socket
import struct
import time
import csv
import sys
from mido import Message, get_output_names, open_output
from mbedtls.tls import DTLSConfiguration, ServerContext, TLSWrappedSocket
from typing import Dict

# ---------------- Configuration ----------------
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 5005
LOG_PATH = "receiver_log.csv"

HDR_FMT = "!IqH"       # seq:uint32, send_ts:int64 (ns), payload_len:uint16
HDR_SIZE = struct.calcsize(HDR_FMT)

ACK_FMT = "!Iq"        # seq:uint32, recv_ts:int64
ACK_SIZE = struct.calcsize(ACK_FMT)

# PSK credentials: identity -> key (both bytes)
PSK_IDENTITY = b"midi-client"
PSK_KEY = b"t0ps3cr3tk3y"   # replace with secure key in production

# ---------------- MIDI Setup ----------------
names = get_output_names()
if not names:
    print("No MIDI output ports found!")
    sys.exit(1)
out_name = names[0]
outport = open_output(out_name)
print(f"Using MIDI output: {out_name}")

# ---------------- DTLS Setup ----------------
# Build a DTLS configuration with a pre-shared key store
psk_store: Dict[bytes, bytes] = {PSK_IDENTITY: PSK_KEY}

conf = DTLSConfiguration(
    pre_shared_key_store=psk_store,
    validate_certificates=False,  # PSK mode; no cert validation
)

# We'll create a plain UDP socket and then wrap per-client with TLSWrappedSocket.
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((LISTEN_IP, LISTEN_PORT))
sock.setblocking(False)
print(f"Receiver listening {LISTEN_IP}:{LISTEN_PORT} (DTLS PSK) → {LOG_PATH}")

# Helper: nano-monotonic
try:
    mono_ns = time.monotonic_ns
except AttributeError:
    mono_ns = lambda: int(time.monotonic() * 1e9)

# We'll maintain DTLS-wrapped connections keyed by client addr
dtls_peers: Dict[tuple, TLSWrappedSocket] = {}

def make_dtls_for_peer(peer_addr):
    """
    Create a DTLS server-side wrapped socket object bound to this peer address.
    TLSWrappedSocket acts like a socket-like object that you can recv/send from.
    The TLSWrappedSocket will use the existing UDP socket for lower-level send/recv.
    """
    # ServerContext holds the DTLS config for server side
    srv_ctx = ServerContext(conf)
    # TLSWrappedSocket wraps the context and requires the underlying socket and peer address.
    # For python-mbedtls: TLSWrappedSocket(context, sock, server_side=True, server_hostname=None, peer_address=peer_addr)
    wrapped = TLSWrappedSocket(srv_ctx, sock, server_side=True, server_hostname=None, peer_addr=peer_addr)
    # perform handshake (non-blocking style); depending on your python-mbedtls version you may need to call .do_handshake()
    wrapped.do_handshake()   # may raise or block internally; in practice it will perform DTLS handshake over UDP
    return wrapped

# ---------------- Logging CSV ----------------
log_f = open(LOG_PATH, "w", newline="")
writer = csv.writer(log_f)
writer.writerow(["seq", "send_ts_ms", "recv_ts_ms"])

try:
    while True:
        # receive raw UDP datagrams
        try:
            data, addr = sock.recvfrom(8192)
        except BlockingIOError:
            # no data right now
            time.sleep(0.001)
            continue
        except Exception as e:
            print("Socket recv error:", e)
            continue

        # If we don't yet have a DTLS session for this addr, create/wrap one and feed the packet
        if addr not in dtls_peers:
            try:
                wrapped = make_dtls_for_peer(addr)
            except Exception as e:
                print("DTLS handshake/setup failed for", addr, ":", e)
                continue
            dtls_peers[addr] = wrapped
            print("DTLS session established for", addr)

        wrapped = dtls_peers[addr]

        # Now pass datagram bytes into the DTLS socket — TLSWrappedSocket will decrypt / reassemble records
        try:
            # Some versions offer a method to feed raw datagrams; other versions manage this internally.
            # But TLSWrappedSocket exposes recv() that returns application bytes after decryption.
            # So just call recv() to obtain application-layer data.
            appdata = wrapped.recv(4096)  # blocking; may raise if handshake incomplete
        except Exception as e:
            # If we can't read application data yet, skip
            # In practice you may need to feed the raw datagram into an API or call do_handshake first.
            print("DTLS recv error (peer):", e)
            continue

        recv_ts = mono_ns()

        if not appdata or len(appdata) < HDR_SIZE:
            continue

        seq, send_ts, length = struct.unpack(HDR_FMT, appdata[:HDR_SIZE])
        midi_bytes = appdata[HDR_SIZE:HDR_SIZE + length]
        send_ts_ms = send_ts / 1_000_000
        recv_ts_ms = recv_ts / 1_000_000

        # Log
        writer.writerow([seq, send_ts_ms, recv_ts_ms])
        log_f.flush()

        # MIDI playback
        try:
            msg = Message.from_bytes(midi_bytes)
            outport.send(msg)
            print(f"Played from {addr}: seq={seq}, msg={msg}")
        except Exception as e:
            print("Invalid MIDI message:", e)

        # Send ACK over the same DTLS-secured channel
        try:
            ack = struct.pack(ACK_FMT, seq, recv_ts)
            wrapped.send(ack)
        except Exception as e:
            print("ACK send error:", e)

except KeyboardInterrupt:
    print("Shutting down receiver...")
finally:
    log_f.close()
    for w in dtls_peers.values():
        try:
            w.close()
        except Exception:
            pass
    sock.close()
