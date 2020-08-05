#!/usr/bin/env python
import socket

crash_id = 0

crashes = ["crash-2f7be03f0e3ce6f2d5b3efef4c8d3fec308c2493",
           "crash-cc7185217f7ddeeceafcff25f9ca2903df636f57",
           "crash-fe848819d3b52ed8d3683e784718057a004f497f"]

# Bug introduced in commit 39c8ccdb9152cf0f9dd6895f8a3f400de5f84d46

if __name__ == '__main__':
    crash_data = b''
    with open("input_chain/client_00065_hel.bin", "rb") as f:
        d = f.read()
        crash_data += d[:-4]

    with open("input_chain/opn.bin", "rb") as f:
        d = f.read()
        crash_data += d[:-4]

    with open(crashes[crash_id], "rb") as f:
        d = f.read()
        crash_data += d[:-4]

    print(crash_data)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 4840))
    s.send(crash_data)
    while data := s.recv(2048):
        print(data)
