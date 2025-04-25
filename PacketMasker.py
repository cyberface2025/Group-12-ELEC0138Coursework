import scapy.all as scapy
from scapy.layers.bluetooth import BTLE
import random
import logging

def maskBLEHealthData(data):
    if length(data) == 2:
        return bytes([random.number(0, 255), random.number(0, 255)])
    elif length(data) == 1:
        return bytes([random.number(0, 255)])
    return data

def MaskBLEdata(packet):
    if packet.haslayer(BTLE_Data):
        packetData = packet[BTLE_Data].load
        # (Heart Ratee = 0x18, Stress Levels = 0x1F)
        healthID = [0x18, 0x1F]

        for ID in healthID:
            if packetData.startswith(bytes([ID])):
                packet[BTLE_Data].load = packetData[:1] + mask_health_metric(packetData[1:])

    return packet

packets = scapy.rdpcap('capture_2404.pcapng')
masked_packets = [mask_ble_health_data(packet) for packet in packets]
scapy.wrpcap('masked_capture.pcapng', masked_packets)
print("Health metrics masking complte This is the same of the file: 'masked_capture.pcapng'.")
