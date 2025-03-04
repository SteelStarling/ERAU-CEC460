#!/usr/bin/env python3

"""Code for Port Scanning homework for CEC460
Author: Taylor Hancock
Date:   02/06/2025
Class:  CEC460 - Telecom Systems
Assignment: HW01 - Port Scanning
"""

import socket

def port_scanner(ip_address: str, port: int) -> bool:
    
    # open port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

        sock.settimeout(1)

        # handle exceptions if they still somehow happen
        try:
            # use ex_connect (much faster than connect, doesn't cause as many exceptions)
            response = sock.connect_ex((ip_address, port))
            if response == 0:
                return True
            return False
        except:
            return False


if __name__ == "__main__":
    # set ip to use
    system_ip = "127.0.0.1"

    # set ports to search
    port_min, port_max = 1, 10000

    with open("output.txt", "a") as f:

        print(f"Searching {system_ip}", file=f)

        for port in range(port_min, port_max):

            # only print open ports
            if port_scanner(system_ip, port):
                print(f'Port {port} is currently open!', file=f)

        print("Searching complete!", file=f)
