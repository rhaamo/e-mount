#!/usr/bin/env python3
import base64
import binascii
import sys
import struct

class Message():
    def __init__(self, dir, raw, tstamp):
        self.som = None
        self.message_length = None
        self.message_class = None
        self.seq_number = None
        self.message_type = None
        self.message = None
        self.checksum = None
        self.eom = None
        self.garbage = None
        self.direction = dir
        self.timestamp = tstamp
        self.bytes = bytes.fromhex(raw)

    def parse(self):
        print(f"{self.direction} Parsing '{str.upper(self.bytes.hex())}'")
        print(f"bytes: {self.bytes}")
        self.som = str.upper(self.bytes[0:1].hex()) # byte 0
        self.message_length = struct.unpack("<H", self.bytes[1:3])[0] # byte 1,2; 16-bit length
        self.message_class = str.upper(self.bytes[3:4].hex()) # byte 3
        self.seq_number = str.upper(self.bytes[4:5].hex()) # byte 4
        self.message_type = str.upper(self.bytes[5:6].hex()) # byte 5
        self.message = str.upper(self.bytes[6:-3].hex()) # bytes
        self.message_bytes = self.bytes[6:-3]
        self.checksum = struct.unpack("<H", self.bytes[-3:-1])[0] # byte -2
        self.eom = str.upper(self.bytes[-1:].hex()) # byte -1
        self.computed_checksum = (self.bytes[self.message_length - 2] << 8) + self.bytes[self.message_length - 3]

    def validate(self):
        if self.som != 'F0':
            print(f"SOM '{self.som} != F0")
            return False
        if self.message_class not in ['01', '02', '03']:
            print(f"Unknown message class: '0x{self.message_class}'")
            return False
        if self.message_type not in ['03', '04', '05', '06', '1C', '1D', '1F', '22', '2F', '3C']:
            print(f"Unknown message type: '0x{self.message_type}'")
            return False
        if self.eom != '55':
            print(f"EOM {self.eom} != 55")
            return False

    def pp_message_type(self):
        if self.message_type == '03':
            return "03, aperture"
        elif self.message_type == '04':
            return "04, unknown"
        elif self.message_type == '05':
            return "05, aperture status"
        elif self.message_type == '06':
            return "06, focus position status"
        elif self.message_type == '1C':
            return "1C, stop af"
        elif self.message_type == '1D':
            return "1D, abs or rel motor movement"
        elif self.message_type == '1F':
            return "1F, af hunt"
        elif self.message_type == '22':
            return "22, abs motor movement"
        elif self.message_type == '2F':
            return "2F, echo request"
        elif self.message_type == '3C':
            return "3C, move at speed"
        else:
            return f"{self.message_type} UNKNOWN"

    def pp_message_class(self):
        if self.message_class == '01':
            return "01, normal"
        elif self.message_class == '02':
            return "02, init or shutdown"
        elif self.message_class == '03':
            return "03, UNKNOWN"
        else:
            return f"{self.message_class}, UNKNOWN TOO"

    def message_bruteforce(self):
        for i in range(0, len(self.message_bytes)):
            try:
                print(struct.unpack('<H', self.message_bytes[i:i+2])[0])
            except struct.error as e:
                print(f"quack: {e}")
                print(f"i: {i}, len: {len(self.message_bytes)}")

    def prettyprint(self):
        print(f"[{self.direction}] SOM: 0x{self.som}, length: {self.message_length} (ushortle), class: 0x{self.pp_message_class()}, seq: 0x{self.seq_number}, type: 0x{self.pp_message_type()}")
        print(f"  Message (hex): {self.message}")
        print(f"  Checksum: {self.checksum} (ushortle), EOM: 0x{self.eom}")
        print(f"  Valid checksum: {self.checksum == self.computed_checksum}")
        print(f"  Valid length: {self.message_length == len(self.bytes)}")
        self.message_bruteforce()


def pretty(line):
    l = line.split(" ")
    direction = l[0]
    raw = l[1]
    timestamp = l[2]
    message = Message(direction, raw, timestamp)
    message.parse()
    message.validate()
    message.prettyprint()

with open(sys.argv[1], 'r') as file:
    for line in file.readlines():
        if not line.startswith("#"):
            pretty(line)
            print("")
