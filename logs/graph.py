#!/usr/bin/env python3

import csv
import sys
import matplotlib.pyplot as plt
import statistics

WINDOW_SIZE = 100  # moving average window size (in samples)

# get input
if len(sys.argv) != 2:
    sys.stderr.write("oops, provide input file path, or - for stdin.\n")
    sys.exit(1)

input_path = sys.argv[1]

# open file
if input_path == "-":
    f = sys.stdin
else:
    try:
        f = open(input_path, newline="", encoding="utf-8")
    except OSError as e:
        sys.stderr.write(f"oops, cannot open '{input_path}': {e}\n")
        sys.exit(1)

# read file (collect only values <= 50 ms)
raw_seq, raw_rtt, raw_one_way = [], [], []

reader = csv.DictReader(f)
for row in reader:
    try:
        s = int(row["seq"])
        r = float(row["rtt_ms"])
        o = float(row["est_oneway_ms"])

        # filter out outliers > 50 ms
        if r <= 20:
            raw_seq.append(s)
            raw_rtt.append(r)
            raw_one_way.append(o)
    except (KeyError, ValueError):
        continue

# assign filtered lists
seq = raw_seq
rtt = raw_rtt
one_way = raw_one_way

# close file
if input_path != "-":
    f.close()

if not seq:
    sys.stderr.write("oops, no valid data found.\n")
    sys.exit(1)

# compute average RTT
avg_rtt = statistics.mean(rtt)
print(f"Average RTT: {avg_rtt:.3f} ms")

# moving average
ma_seq = []
ma_rtt = []
if len(rtt) >= WINDOW_SIZE:
    for i in range(WINDOW_SIZE - 1, len(rtt)):
        window = rtt[i - WINDOW_SIZE + 1 : i + 1]
        ma_rtt.append(sum(window) / WINDOW_SIZE)
        ma_seq.append(seq[i])

# plot
plt.figure(figsize=(8, 4))
plt.plot(seq, rtt,      label="RTT (ms)",      marker='o', markersize=3, linewidth=1)
plt.plot(seq, one_way,  label="One-way (ms)",  marker='x', markersize=3, linewidth=1)

if ma_seq:
    plt.plot(ma_seq, ma_rtt, label=f"RTT {WINDOW_SIZE}-pt MA", linewidth=2)

# fixed y-axis
plt.ylim(0, 50)

# horizontal average line
plt.axhline(avg_rtt, color='red', linestyle='--', linewidth=1,
            label=f"Avg RTT = {avg_rtt:.3f} ms")

plt.title("Network latency over packet sequence")
plt.xlabel("Sequence number")
plt.ylabel("Milliseconds")
plt.grid(True, which="both", linestyle="--", alpha=0.5)
plt.legend()
plt.tight_layout()
plt.show()
