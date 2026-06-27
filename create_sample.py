# create_sample.py
"""
Extract a focused sample around redteam timestamps.
"""

import gzip

# Redteam timestamp range: 150,000 - 160,000
TARGET_START = 150000
TARGET_END = 160000

print("Creating focused samples...")

# Sample auth.txt
with open('auth.txt', 'r') as infile, open('auth_sample.txt', 'w') as outfile:
    count = 0
    for line in infile:
        try:
            ts = int(line.split(',')[0])
            if TARGET_START <= ts <= TARGET_END:
                outfile.write(line)
                count += 1
        except:
            pass
    print(f"  auth_sample.txt: {count} lines")

# Sample proc.txt
with open('proc.txt', 'r') as infile, open('proc_sample.txt', 'w') as outfile:
    count = 0
    for line in infile:
        try:
            ts = int(line.split(',')[0])
            if TARGET_START <= ts <= TARGET_END:
                outfile.write(line)
                count += 1
        except:
            pass
    print(f"  proc_sample.txt: {count} lines")

# Sample flows.txt
with open('flows.txt', 'r') as infile, open('flows_sample.txt', 'w') as outfile:
    count = 0
    for line in infile:
        try:
            ts = int(line.split(',')[0])
            if TARGET_START <= ts <= TARGET_END:
                outfile.write(line)
                count += 1
        except:
            pass
    print(f"  flows_sample.txt: {count} lines")

print("Done!")
