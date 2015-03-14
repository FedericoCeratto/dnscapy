# DNScapy #

**DNScapy** is a DNS tunneling tool. The code is very light and written in Python. It includes a server and a client. The server can handle multiple clients.

**DNScapy** creates a SSH tunnel through DNS packets. SSH connection, SCP and proxy socks (SSH -D) are supported. You can use CNAME records or TXT records for the tunnel. The default mode is RAND, which uses randomly both CNAME and TXT.

**DNScapy** uses Scapy (http://www.secdev.org/scapy) for DNS packet forging and for his network automaton API.

**DNScapy** is still under development. The current version is 0.99b and seems to work pretty well. Feel free to clone and test it !






## Software Requirements ##
  * Python >= 2.6
  * Scapy >= 2.1-dev (2.2 recommended)
  * Openssh
  * Linux (should work on Windows with some minor changes)

Note : once scapy is installed you have to patch a missing import.
  * Edit the file supersocket.py (located for example on /usr/local/lib/python2.6/dist-packages/scapy/supersocket.py)
  * Add the line: `from scapy.packet import Padding`

## Hardware Requirements ##
To make a _real_ DNS tunnel, you will need:
  * a client, typically a computer on a restricted network
  * a server, typically a computer with a full acces to Internet
  * a domain name (e.g. mydomain.com ) and an access on the configuration of its DNS server in order to delegate a zone (e.g. tunnel.mydomain.com) to your tunneling server

You can find further informations on how to delegate a DNS zone on websites like http://dnstunnel.de/

## Howto ##

Here is a very short guide:
```
# On the server:
sudo python dnscapy_server.py [DELEGATED_ZONE_NAME] [EXTERNAL_IP_ADDR]
```

```
# On the client:
ssh -o ProxyCommand="sudo python dnscapy_client.py [DELEGATED_ZONE_NAME] [IP_ADDR_OF_CLIENT_DNS]" yourlogin@localhost
```

```
# help and options:
./dnscapy_client.py -h
./dnscapy_server.py -h
```

It will not work if both client and server are on localhost. If you want to test it on the same computer I suggest to use a virtual machine.

## Why making a DNS tunnel ? ##

Because in most cases a security policy takes care of HTTP and forgets DNS.
Let's consider two common situations:
  * You are not able to access to a specific website because of a HTTP proxy.
  * You are not be able to connect to a Hotspot because of a firewall that redirects HTTP requests of non-authenticated users.

In general, nothing is done to control the DNS resolution. Therefore you can break the two previous restrictions by making a DNS tunnel.

**DISCLAIMER:** We are not responsible at all for misuse of DNScapy. Bypassing a security policy is forbidden. Please use DNScapy only for test purposes in order to detect potential security holes in your own network.

## Why a SSH tunnel through DNS ? ##

The idea of encapsulating SSH in DNS comes from OzymanDNS, a DNS tunneling tool written in Perl (http://dankaminsky.com/2004/07/29/51/)

The reasons of this choice are:
  * SSH encrypts the data. Whatever passed through the tunnel will remain secret.
  * You will be able to do whatever you want on the tunneling server (ie your remote computer)
  * Secured file transfer is provided by `scp`
  * You can surf on Internet with the connection of the tunneling server thanks to a proxy SOCKS provided by `ssh -D`

## Known bugs ##
  * When doing a `scp` the speed indicator is wrong
  * When the client ends the SSH connection, the DNS tunnel remains established few seconds and an error message appears (timeout)
  * A DNS packet contains only a tiny amount of data. Don't be surprised if the speed of the connection is _**VERY LOW**_

## Copyright and license ##
**DNScapy** is a free software protected by the GNU GPL v3 license.
**DNScapy** was created during a pedagogic project by:
  * Pierre Bienaimé <pbienaim -at- gmail.com>
  * Pascal Mazon <pascal.mazon -at- gmail.com>

Do not hesitate to ask questions on the Google Group (http://groups.google.com/group/dnscapy)


Enjoy.

**Pierre Bienaimé**
