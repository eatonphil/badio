import os

with open("test.txt", "w") as f:
    f.write("some great stuff")
    os.fsync(f.fileno())
