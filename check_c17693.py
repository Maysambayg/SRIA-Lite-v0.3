# check_c17693.py
import sys

print("Checking for C17693 in auth.txt...")
count = 0
with open('auth.txt', 'r') as f:
    for i, line in enumerate(f):
        if i >= 1000000:  # Check first 1M lines
            break
        if 'C17693' in line:
            count += 1
            if count <= 5:
                print(f"  Found: {line.strip()[:100]}")
print(f"\nTotal occurrences in first 1M lines: {count}")