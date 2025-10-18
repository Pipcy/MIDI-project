# flood.py
import socket, struct, time
DEST=("10.193.68.64",5005)
HDR="!IqH"
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

for i in range(10000):
    seq = i & 0xffffffff
    send_ts = int(time.monotonic()*1e9)
    midi = bytes([0x90, 60, 127])  # Note On
    pkt = struct.pack(HDR, seq, send_ts, len(midi)) + midi
    sock.sendto(pkt, DEST)

