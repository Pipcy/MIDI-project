#!/usr/bin/env python3
import socket, struct, time, hmac, hashlib, mido

# --- MUST match the receiver ---
DEST_IP = "10.239.135.70"     # same as midi_sender_ack_replay.py
DEST_PORT = 55666             # or whatever your receiver is bound to

HDR_FMT = "!IqH"
SECRET_KEY = b"t0ps3cr3tk3y"

def now_ns():
    return time.time_ns()

def make_packet(seq: int):
    # Same kind of MIDI payload as your sender
    msg = mido.Message("note_on", note=60, velocity=64)
    midi_bytes = bytes(msg.bytes())   # same as sender_thread

    send_ts = now_ns()
    header = struct.pack(HDR_FMT, seq, send_ts, len(midi_bytes))
    body = header + midi_bytes

    mac = hmac.new(SECRET_KEY, body, hashlib.sha256).digest()
    return body + mac

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Pick a seq that is NOT stale (see note below)
seq = 80
packet = make_packet(seq)

# First send – should be accepted & played
sock.sendto(packet, (DEST_IP, DEST_PORT))
time.sleep(0.2)

# Second send – identical replay – should trigger "Replay detected"
sock.sendto(packet, (DEST_IP, DEST_PORT))

print("Sent same packet twice with seq", seq)

