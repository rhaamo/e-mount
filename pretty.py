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
        self.som = str.upper(self.bytes[0:1].hex()) # byte 0
        self.message_length = struct.unpack("<H", self.bytes[1:3])[0] # byte 1,2; 16-bit length
        self.message_class = str.upper(self.bytes[3:4].hex()) # byte 3
        self.seq_number = str.upper(self.bytes[4:5].hex()) # byte 4
        self.message_type = str.upper(self.bytes[5:6].hex()) # byte 5
        self.message = str.upper(self.bytes[6:-3].hex()) # bytes
        self.message_bytes = self.bytes[6:-3]
        self.checksum = struct.unpack("<H", self.bytes[-3:-1])[0] # byte -2
        self.eom = str.upper(self.bytes[-1:].hex()) # byte -1
        try:
            self.computed_checksum = (self.bytes[self.message_length - 2] << 8) + self.bytes[self.message_length - 3]
        except IndexError:
            self.computed_checksum = None

    def validate(self):
        if self.som != 'F0':
            print(f"SOM '{self.som} != F0")
            return False
        if self.message_class not in ['01', '02', '03']:
            print(f"Unknown message class: '0x{self.message_class}'")
            return False
        if self.message_type not in ['03', '04', '05', '06', '1C', '1D', '1F', '22', '2F', '3C', '28']:
            print(f"Unknown message type: '0x{self.message_type}'")
            return False
        if self.eom != '55':
            print(f"EOM {self.eom} != 55")
            return False

    def pp_message_type(self):
        if self.message_type == '03':
            return "03, aperture"
        elif self.message_type == '04':
            return "04, unknown (preceds an 0x05 aperture status message)"
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
        elif self.message_type == '28':
            return "28, take picture ?"
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
        print("=== bruteforcing message as lsb unsigned short")
        for i in range(0, len(self.message_bytes)):
            try:
                print(struct.unpack('<H', self.message_bytes[i:i+2])[0])
                #print(struct.unpack('<h', self.message_bytes[i:i+2])[0])
                #print(struct.unpack('<I', self.message_bytes[i:i+4])[0])
                #print(struct.unpack('<i', self.message_bytes[i:i+4])[0])
                #print(struct.unpack('<B', self.message_bytes[i:i+1])[0].split('\0', 1)[0])
            except struct.error as e:
                print(f"error: {e}; index: {i}, msg length: {len(self.message_bytes)}")
        print("=== bruteforcing end")

    def decode_message(self):
        if self.message_type == '06': # focus position status
            print(f"Limit flags: {self.message_bytes[0:1].hex()}")
            print(f"static?(00): {self.message_bytes[1:2].hex()}")
            if self.message_bytes[2:3] == '00':
                print(f"focus position (MAX): {self.message_bytes[2:3].hex()}")
            else:
                print(f"focus position: {self.message_bytes[2:3].hex()}")
            print(f"static?(10): {self.message_bytes[3:4].hex()}")
            print(f"static?(00): {self.message_bytes[4:5].hex()}")
            print(f"static?(00): {self.message_bytes[5:6].hex()}")
            print(f"static?(00): {self.message_bytes[6:7].hex()}")
            print(f"static?(00): {self.message_bytes[7:8].hex()}")
            print(f"static?(00): {self.message_bytes[8:9].hex()}")
            print(f"(3F): {self.message_bytes[9:10].hex()}")
            print(f"(10): {self.message_bytes[10:11].hex()}")
            print(f"(00): {self.message_bytes[11:12].hex()}")
            print(f"leftover?: {self.message_bytes[12:].hex()}")
        elif self.message_type == '05': # aperture status
            print(f"Focus ?: {self.message_bytes[20:22].hex()}")
            print(f"Focus pos: {self.message_bytes[23:24].hex()}")
            print(f"Aperture (00 brightest; 4AB darkest): {self.message_bytes[30:32].hex()}")
            print(f"Aperture??: {self.message_bytes[33:40].hex()}")
            print(f"Focus moving flag: {self.message_bytes[60:61].hex()} (00 no motion; 255/ff focus++; 01 focus--??; linked to 0x06 focus position status byte 2: position)")
            print(f"Target 1: {self.message_bytes[77:78].hex()}")
            print(f"Target 2: {self.message_bytes[78:79].hex()}")
            print(f"??: {self.message_bytes[81:82].hex()}")
            print(f"{self.message_bytes[84:85].hex()}")
        elif self.message_type == '03': # aperture
            print(f"Liveness? (00/01): {self.message_bytes[12:13].hex()}")
            print(f"Target 1? (15/17): {self.message_bytes[21:22].hex()}")
            print(f"Target 2? (15/17): {self.message_bytes[22:23].hex()}")


    def prettyprint(self):
        print(f"[{self.direction}] SOM: 0x{self.som}, length: {self.message_length} (ushortle), class: 0x{self.pp_message_class()}, seq: 0x{self.seq_number}, type: 0x{self.pp_message_type()}")
        print(f"  Message (hex): {self.message}")
        print(f"  Message (bytes): {self.bytes}")
        try:
            print(f"  Message (string): {self.bytes.decode('utf-8')}")
        except UnicodeDecodeError:
            pass
        print(f"  Checksum: {self.checksum} (ushortle), EOM: 0x{self.eom}")
        print(f"  Valid checksum: {self.checksum == self.computed_checksum}")
        print(f"  Valid length: {self.message_length == len(self.bytes)}")
        print()
        self.decode_message()
        #self.message_bruteforce()


def pretty(line):
    l = line.split(" ")
    direction = l[0]
    raw = l[1]
    timestamp = l[2]
    message = Message(direction, raw, timestamp)
    message.parse()
    message.validate()
    message.prettyprint()

if len(sys.argv) <= 1 or len(sys.argv) > 3:
    print(f"Usage: {sys.argv[0]} <trace file name.txt> [number of lines to process]")
    exit()

if len(sys.argv) == 2:
    process = None
else:
    process = int(sys.argv[2])

processed = 0
with open(sys.argv[1], 'r') as file:
    for line in file.readlines():
        if not line.startswith("#"):
            if process and processed >= process:
                break
            try:
                pretty(line)
                print("")
                processed += 1
            except IndexError:
                print(f"Invalid message: {line}")
