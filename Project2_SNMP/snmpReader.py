#!/usr/bin/env python3

"""Code for SNMP homework for CEC460
Author: Taylor Hancock
Date:   03/03/2025
Class:  CEC460 - Telecom Systems
Assignment: HW02 - SNMP Reader

Write a program that uses SNMP to read the ink levels from the given printer and gives a readout in percentages for each value
"""

import pysnmp

ip_address = "172.19.172.24"

