# extract_redteam_window.py
"""
Extract auth events around redteam timestamps (100,000 - 200,000)
"""

START_TS = 100000
END_TS = 200000

output_file = 'auth_redteam_window.txt'
count = 0

print(f"Extracting auth events between {START_TS} and {END_TS}...")

with open('auth.txt', 'r') as infile, open(output_file, 'w') as outfile:
    for line in infile:
        try:
            ts = int(line.split(',')[0])
            if START_TS <= ts <= END_TS:
                outfile.write(line)
                count += 1
                if count % 100000 == 0:
                    print(f"  Extracted {count:,} events...")
        except:
            continue

print(f"Extracted {count:,} events to {output_file}")