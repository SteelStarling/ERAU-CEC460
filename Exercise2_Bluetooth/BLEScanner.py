# https://medium.com/@protobioengineering/how-to-make-a-detailed-bluetooth-le-scanner-with-a-macbook-and-python-8e2c7dccfd39

# Scan for nearby Bluetooth LE devices and their services

# Bash output color codes

GREEN = '\033[92m'
RED = '\033[91m'
CYAN = '\033[96m'
YELLOW = '\033[93m'
GOLD = '\033[33m'
BOLD = '\033[1m'
END = '\033[0m'

import asyncio
from bleak import BleakClient, BleakScanner

async def main():
    devices = await BleakScanner.discover()
    for device in devices:
        if device.name == None:
            continue
        print()
        print(f"Name: \033[92m{device.name}\033[0m")
        print(f"Address: {device.address}")
        print(f"Details: {device.details}")
        print(f"Metadata: {device.metadata}")
        print(f"RSSI: {device.rssi}")
        
    for device in devices:
        if device.name == None:
            continue
        try:
            this_device = await BleakScanner.find_device_by_address(device.address, timeout=20)
            async with BleakClient(this_device) as client:
                print(f'Services found for device')
                print(f'\tDevice address:{device.address}')
                print(f'\tDevice name:{device.name}')

                print('\tServices:')
                for service in client.services:
                    print()
                    print(f'\t\tDescription: {service.description}')
                    print(f'\t\tService: {service}')
                    
                    print('\t\tCharacteristics:')
                    for c in service.characteristics:
                        print()              
                        print(f'\t\t\tUUID: {c.uuid}'),
                        print(f'\t\t\tDescription: {c.description}')
                        print(f'\t\t\tHandle: {c.handle}'),
                        print(f'\t\t\tProperties: {c.properties}')                   
                        
                        print('\t\tDescriptors:')
                        for descrip in c.descriptors:
                            print(f'\t\t\t{descrip}')

        except Exception as e:
                print(f"Could not connect to device with info: {device}")
                print(f"Error: {e}")

asyncio.run(main())