timestamps = []
with open("data/redteam.txt") as f:
    for line in f:
        parts = line.strip().split(",")
        timestamps.append(int(parts[0]))

buckets = {
    "150000-900000": sum(1 for t in timestamps if 150000 <= t <= 900000),
    "900000-1800000": sum(1 for t in timestamps if 900000 < t <= 1800000),
    "1800000+": sum(1 for t in timestamps if t > 1800000)
}
for k, v in buckets.items():
    print(f"{k}: {v} events")