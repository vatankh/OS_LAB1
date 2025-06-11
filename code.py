#!/usr/bin/env python3

import sys
import time
import serial

SYNC = 0x5A


def crc8(data: bytes) -> int:
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
    length = len(payload)
    hdr = bytearray()
    hdr.append(SYNC if not bad_sync else 0x00)
    hdr.append((length if not bad_len else length + 1) & 0xFF)
    pkt = hdr + payload

    if not incomplete:
        chk = crc8(bytes([hdr[1]]) + payload)
        pkt.append(chk)

    return bytes(pkt)


def send_and_recv(ser: serial.Serial, pkt: bytes, expected_len: int):
    print(f"\nSending: {pkt.hex(' ')}  (expecting {expected_len} bytes in response)")
    ser.reset_input_buffer()
    ser.write(pkt)
    resp = ser.read(expected_len)

    if resp:
        print("Response: ", resp.hex(' '))
    else:
        print("No response (no echo received)")


def read_packet(ser: serial.Serial):
    # Wait for SYNC byte
    while True:
        byte = ser.read(1)
        if not byte:
            return None
        if byte[0] == SYNC:
            break
    
    len_byte = ser.read(1)
    if not len_byte:
        return None
    length = len_byte[0]

    data = ser.read(length)
    if len(data) != length:
        return None

    crc_byte = ser.read(1)
    if not crc_byte:
        return None
    crc_val = crc_byte[0]

    crc_calc = crc8(bytes([length]) + data)
    if crc_calc != crc_val:
        print("CRC mismatch, skipping packet.")
        return None

    return data


def monitor_temperature(ser: serial.Serial):
    print("\n--- Monitoring temperature and humidity ---\n(Press CTRL+C to stop)\n")
    try:
        while True:
            pkt = read_packet(ser)
            if pkt and len(pkt) >= 2:
                temp = pkt[0]
                hum = pkt[1]
                print(f"Температура: {temp}°C  Влажность: {hum}%")
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")


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
            print(" 5) Periodic temperature and humidity monitor")
            print(" 0) Exit")
            
            choice = input("> ").strip()

            if choice == "0":
                break

            payload = bytes([0x10, 0x20])

            if choice == "1":
                pkt = build_packet(payload)
                length = pkt[1]
                data = pkt[2:-1]
                calc_crc = crc8(bytes([length]) + data)
                print(f"→ CRC calculated: 0x{calc_crc:02X}")
                expected = len(pkt)
                send_and_recv(ser, pkt, expected)

            elif choice == "2":
                pkt = build_packet(payload, bad_len=True)
                send_and_recv(ser, pkt, 0)

            elif choice == "3":
                pkt = build_packet(payload, bad_sync=True)
                send_and_recv(ser, pkt, 0)

            elif choice == "4":
                pkt = build_packet(payload, incomplete=True)
                send_and_recv(ser, pkt, 0)

            elif choice == "5":
                monitor_temperature(ser)

            else:
                print("Invalid selection, please try again.")

    finally:
        ser.close()

if __name__ == "__main__":
    main()
