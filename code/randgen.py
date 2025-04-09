import os
import sys

if len(sys.argv) == 2:
    nBytes = int(sys.argv[1])
else:
    nBytes = 16
a = os.urandom(nBytes)
print("".join([f"{int(byte):02x}" for byte in a]))
