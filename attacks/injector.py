# injector.py
import socket, struct, time

DEST = ("10.239.166.92", 5005)   # receiver IP:port
HDR_FMT = "!IqH"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def send_note_on(seq, note=60, vel=100):
    # MIDI Note On: status 0x90 channel0, note, vel
    midi = bytes([0x90, note, vel])
    send_ts = int(time.monotonic() * 1e9)
    hdr = struct.pack(HDR_FMT, seq, send_ts, len(midi))
    sock.sendto(hdr + midi, DEST)

def send_note_off(seq, note=60):
    midi = bytes([0x80, note, 0])
    send_ts = int(time.monotonic() * 1e9)
    hdr = struct.pack(HDR_FMT, seq, send_ts, len(midi))
    sock.sendto(hdr + midi, DEST)

# simple demo: send rapid fake notes
for i in range(1, 21):
    send_note_on(i, note=60 + (i % 12))
    time.sleep(0.02)
    send_note_off(i, note=60 + (i % 12))

