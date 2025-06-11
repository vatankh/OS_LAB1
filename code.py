#!/usr/bin/env python3
"""
UART Packet Tester for ATmega328P (fixed)

- Сбрасывает буфер перед каждой отправкой
- Выводит рассчитанный CRC для корректного пакета
- Ждёт ровно столько байт, сколько должно прийти в ответ
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
    Собирает пакет:
      [SYNC][LEN][DATA...][CRC]
    Параметры bad_* позволяют симулировать ошибки.
    """
    length = len(payload)
    hdr = bytearray()
    hdr.append(SYNC if not bad_sync else 0x00)
    hdr.append((length if not bad_len else length + 1) & 0xFF)
    pkt = hdr + payload
    if not incomplete:
        # CRC считается по полю LENGTH + DATA
        chk = crc8(bytes([hdr[1]]) + payload)
        pkt.append(chk)
    return bytes(pkt)

def send_and_recv(ser: serial.Serial, pkt: bytes, expected_len: int):
    """
    Сбрасывает входной буфер, шлёт pkt и ждёт ровно expected_len байт.
    """
    print(f"\nОтправляю: {pkt.hex(' ')}  (ожидаю {expected_len} байт ответа)")
    ser.reset_input_buffer()
    ser.write(pkt)
    resp = ser.read(expected_len)
    if resp:
        print("Ответ:  ", resp.hex(' '))
    else:
        print("Нет ответа (эхо не пришло)")

def main():
    if len(sys.argv) != 2:
        print("Использование: python client.py <COM-порт>")
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
            print("\nВыберите кейс:")
            print(" 1) Корректный пакет")
            print(" 2) Неправильная длина")
            print(" 3) Отсутствие SYNC")
            print(" 4) Недостаточно байт (incomplete)")
            print(" 0) Выход")
            choice = input("> ").strip()

            if choice == "0":
                break

            # пример полезной нагрузки — два байта
            payload = bytes([0x10, 0x20])

            if choice == "1":
                pkt = build_packet(payload)
                # считаем CRC отдельно и выводим
                length = pkt[1]
                data = pkt[2:-1]
                calc_crc = crc8(bytes([length]) + data)
                print(f"→ CRC рассчитан: 0x{calc_crc:02X}")
                expected = len(pkt)

            elif choice == "2":
                pkt = build_packet(payload, bad_len=True)
                expected = 0   # эха не будет

            elif choice == "3":
                pkt = build_packet(payload, bad_sync=True)
                expected = 0

            elif choice == "4":
                pkt = build_packet(payload, incomplete=True)
                expected = 0

            else:
                print("Неверный выбор, повторите.")
                continue

            send_and_recv(ser, pkt, expected)

    finally:
        ser.close()

if __name__ == "__main__":
    main()
