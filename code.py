#!/usr/bin/env python3
"""
UART Packet Tester for ATmega328P (fixed)

- Clears the buffer before each transmission
- Displays the calculated CRC for a valid packet
- Waits for exactly as many bytes as expected in response
"""

import sys
import time
import serial

SYNC = 0x5A

def crc8(data: bytes) -> int:
    """CRC 8 (poly=0x07, init=0x00)"""
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ 0x07) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc

def build_packet(payload: bytes,
                 bad_sync: bool = False,
                 bad_len: bool = False,
                 incomplete: bool = False) -> bytes:
    """
    Builds packet:
      [SYNC][LEN][DATA...][CRC]
    bad_* parameters simulate errors.
    """
    length = len(payload)
    hdr = bytearray()
    hdr.append(SYNC if not bad_sync else 0x00)
    hdr.append((length if not bad_len else length + 1) & 0xFF)
    pkt = hdr + payload
    if not incomplete:
        # CRC is calculated over LENGTH + DATA
        chk = crc8(bytes([hdr[1]]) + payload)
        pkt.append(chk)
    return bytes(pkt)

def send_and_recv(ser: serial.Serial, pkt: bytes, expected_len: int):
    """
    Clears input buffer, sends pkt and waits for exactly expected_len bytes.
    """
    print(f"\nSending: {pkt.hex(' ')}  (expecting {expected_len} bytes in response)")
    ser.reset_input_buffer()
    ser.write(pkt)
    resp = ser.read(expected_len)
    if resp:
        print("Response: ", resp.hex(' '))
    else:
        print("No response (no echo received)")

def main():
    if len(sys.argv) != 2:
        print("Usage: python client.py <COM-port>")
        sys.exit(1)

    port = sys.argv[1]
    ser = serial.Serial(
        port,
        baudrate=57600,
        parity=serial.PARITY_EVEN,
        stopbits=serial.STOPBITS_ONE,
        timeout=0.5
    )

    try:
        while True:
            print("\nSelect a case:")
            print(" 1) Valid packet")
            print(" 2) Incorrect length")
            print(" 3) Missing SYNC")
            print(" 4) Incomplete packet (not enough bytes)")
            print(" 0) Exit")
            choice = input("> ").strip()

            if choice == "0":
                break

            # example payload — two bytes
            payload = bytes([0x10, 0x20])

            if choice == "1":
                pkt = build_packet(payload)
                # calculate and display CRC separately
                length = pkt[1]
                data = pkt[2:-1]
                calc_crc = crc8(bytes([length]) + data)
                print(f"→ CRC calculated: 0x{calc_crc:02X}")
                expected = len(pkt)

            elif choice == "2":
                pkt = build_packet(payload, bad_len=True)
                expected = 0   # no echo expected

            elif choice == "3":
                pkt = build_packet(payload, bad_sync=True)
                expected = 0

            elif choice == "4":
                pkt = build_packet(payload, incomplete=True)
                expected = 0

            else:
                print("Invalid selection, please try again.")
                continue

            send_and_recv(ser, pkt, expected)

    finally:
        ser.close()

if __name__ == "__main__":
    main()
