# find_redteam_position.py
"""
Sample auth.txt at different offsets to find where timestamps reach ~150,000
"""

import os

def sample_at_position(filepath, byte_offset):
    with open(filepath, 'r') as f:
        f.seek(byte_offset)
        # Read first line at this position
        line = f.readline()
        if line:
            parts = line.split(',')
            timestamp = int(parts[0]) if parts else 0
            return timestamp
    return 0

filepath = 'auth.txt'
file_size = os.path.getsize(filepath)

# Sample at different percentages
for percent in [1, 5, 10, 20, 30, 40, 50]:
    offset = int(file_size * percent / 100)
    ts = sample_at_position(filepath, offset)
    print(f"{percent:2d}% offset {offset:,}: timestamp {ts}")