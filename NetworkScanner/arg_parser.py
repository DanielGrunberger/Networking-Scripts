import sys
import os


def validate_input():
    if len(sys.argv) != 2:
        print("Usage: scan.py <ips_file>")
        exit(0)
    filename = sys.argv[1]
    if os.path.exists(filename):
        return True, filename
    return False, ""