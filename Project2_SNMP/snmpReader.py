#!/usr/bin/env python3

"""Code for SNMP homework for CEC460
Author: Taylor Hancock
Date:   03/03/2025
Class:  CEC460 - Telecom Systems
Assignment: HW02 - SNMP Reader

Write a program that uses SNMP to read the ink levels from the given printer and gives a readout in percentages for each value
"""

from asyncio import run
from pysnmp.hlapi.v3arch.asyncio import get_cmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity


async def get_value_from_oid(oid: str, ip: str) -> any:
    """Converts an OID and IP address into the output from a SNMP Get Request"""
    output = await get_cmd(SnmpEngine(),
                           CommunityData("public"),
                           await UdpTransportTarget.create((ip, 161)),
                           ContextData(),
                           ObjectType(ObjectIdentity(oid))
                           )

    return output[-1][-1][-1]


def get_percent(size: float, amount: float) -> float:
    """Converts a size and amount into what percent of the size an amount is"""
    return (amount * 100.0) / size


if __name__ == "__main__":
    # define IP
    PRINTER_IP = "172.19.172.24"

    # Toner OIDs
    cartridge_info_oids = {
        "C": {"size": "1.3.6.1.2.1.43.11.1.1.8.1.2", "fill": "1.3.6.1.2.1.43.11.1.1.9.1.2"},
        "M": {"size": "1.3.6.1.2.1.43.11.1.1.8.1.3", "fill": "1.3.6.1.2.1.43.11.1.1.9.1.3"},
        "Y": {"size": "1.3.6.1.2.1.43.11.1.1.8.1.4", "fill": "1.3.6.1.2.1.43.11.1.1.9.1.4"},
        "K": {"size": "1.3.6.1.2.1.43.11.1.1.8.1.1", "fill": "1.3.6.1.2.1.43.11.1.1.9.1.1"}
    }

    # Create empty dictionary
    cartridge_size = {}
    cartridge_fill = {}

    # Read cartridge data
    for color, oids in cartridge_info_oids.items():
        cartridge_size[color] = run(get_value_from_oid(oids["size"], PRINTER_IP))
        cartridge_fill[color] = run(get_value_from_oid(oids["fill"], PRINTER_IP))

    # Print data
    for color in cartridge_fill.keys():
        percent = get_percent(cartridge_size[color], cartridge_fill[color])
        print(f'{color}: {round(percent, 2)}%')
