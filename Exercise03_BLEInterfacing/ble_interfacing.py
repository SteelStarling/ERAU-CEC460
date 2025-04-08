#!/usr/bin/env python3

"""Code for BLE Interfacing exercise
Author: Taylor Hancock
Date:   03/25/2025
Class:  CEC460 - Telecom Systems
Assignment: EX03 - BLE Interfacing
"""

import asyncio
from bleak import BleakClient, BleakScanner
from struct import pack, unpack

SPEAKER_UUID = "00002beb-0000-1000-8000-00805f9b34fb"
BATTERY_UUID = "00002a19-0000-1000-8000-00805f9b34fb"
BUTTON_UUID  = "0000183b-0000-1000-8000-00805f9b34fb"

async def play_dot(client: BleakClient) -> None:
    """Plays a dot in morse"""
    await client.write_gatt_char(SPEAKER_UUID, bytearray([10]))
    await asyncio.sleep(0.4)

async def play_dash(client: BleakClient) -> None:
    """Plays a dash in morse"""
    await client.write_gatt_char(SPEAKER_UUID, bytearray([30]))
    await asyncio.sleep(0.4)

async def play_letter_spacing() -> None:
    """Waits the time for a letter in morse"""
    await asyncio.sleep(0.8)

async def play_word_spacing() -> None:
    """Waits the time for a word space in morse"""
    await asyncio.sleep(2.4)

async def play_morse_string(client: BleakClient, morse: str) -> None:
    """Plays a string converted from morse (space separates letters, comma separates words)"""
    for char in morse:
        if char == ".":
            await play_dot(client)
        elif char == "-":
            await play_dash(client)
        elif char == " ":
            await play_letter_spacing()
        elif char == ",":
            await play_word_spacing()
        else:
            print("Invalid character")


async def main() -> None:
    devices = await BleakScanner.discover()
    for device in devices:
        if device.name != "CEC460-ESP32-C6A":
            continue
        try:
            this_device = await BleakScanner.find_device_by_address(device.address,timeout=20)
            async with BleakClient(this_device) as client:

                data = await client.read_gatt_char(SPEAKER_UUID)

                data_int = int.from_bytes(data, byteorder="big")

                data_bytes = data_int.to_bytes(4, byteorder="little")

                battery_voltage = unpack(">f", data_bytes)[0]                

                print(f"Battery Voltage: {battery_voltage}")

                battery_level = await client.read_gatt_char(BATTERY_UUID)

                print(f"Battery Level: {battery_level[0]}")

                await play_morse_string(client, ".... . .-.. .-.. ---,.-- --- .-. .-.. -..")

        except Exception as e:
            print(f"Could not connect to device with info: {device}")
            print(f"Error: {e}")

asyncio.run(main())