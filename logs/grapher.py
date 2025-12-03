#!/usr/bin/env python3

import csv
import matplotlib.pyplot as plt

LOG_PATH = "../hmac1/sender_log.csv"

# Set to 0.0 to disable; e.g. 0.01 = drop top 1% RTT values as outliers
OUTLIER_FRACTION = 0.01

def main():
    seqs = []
    rtts = []
    oneways = []

    # Read CSV
    with open(LOG_PATH, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                seqs.append(int(row["seq"]))
                rtts.append(float(row["rtt_ms"]))
                oneways.append(float(row["est_oneway_ms"]))
            except (KeyError, ValueError):
                continue

    if not rtts:
        print("No data found in sender_log.csv")
        return

    print(f"Total samples (raw): {len(rtts)}")

    # ---- Simple outlier removal on RTT (trim top OUTLIER_FRACTION) ----
    if OUTLIER_FRACTION > 0.0 and len(rtts) > 10:
        sorted_rtts = sorted(rtts)
        cutoff_index = int(len(sorted_rtts) * (1.0 - OUTLIER_FRACTION))
        cutoff_index = min(max(cutoff_index, 0), len(sorted_rtts) - 1)
        cutoff = sorted_rtts[cutoff_index]

        filtered = [(s, r, o) for s, r, o in zip(seqs, rtts, oneways) if r <= cutoff]

        if filtered:
            seqs, rtts, oneways = map(list, zip(*filtered))
            print(f"Outlier filter: dropped RTT > {cutoff:.3f} ms")
        else:
            print("Outlier filter removed all samples; using raw data.")

    print(f"Samples used: {len(rtts)}")

    # Compute averages
    avg_rtt = sum(rtts) / len(rtts)
    avg_oneway = sum(oneways) / len(oneways)

    print(f"Average RTT (ms): {avg_rtt:.3f}")
    print(f"Average est. one-way latency (ms): {avg_oneway:.3f}")

    # Plot
    plt.figure()
    plt.plot(seqs, rtts, label="RTT (ms)")
    plt.plot(seqs, oneways, label="Est one-way (ms)")

    # Average lines
    plt.axhline(avg_rtt, linestyle="--", linewidth=1,
                label=f"Avg RTT ({avg_rtt:.2f} ms)")
    plt.axhline(avg_oneway, linestyle="--", linewidth=1,
                label=f"Avg one-way ({avg_oneway:.2f} ms)")

    plt.xlabel("Sequence number")
    plt.ylabel("Latency (ms)")
    plt.title("MIDI WiFi Latency")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    main()

