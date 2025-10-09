import socket, struct, time, csv

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 5005

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((LISTEN_IP, LISTEN_PORT))

with open("receiver_log.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["seq", "send_ts_ns", "recv_ts_ns"])
    while True:
        data, _ = sock.recvfrom(1024)
        recv_ts = time.time_ns()
        seq, send_ts = struct.unpack("!Iq", data)
        writer.writerow([seq, send_ts, recv_ts])
        f.flush()

