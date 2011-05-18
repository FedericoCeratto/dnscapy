#!/usr/bin/env python2
#-*- coding:utf-8 -*-

### LICENCE ###
# This file is part of DNScapy.
# DNScapy is a free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# DNScapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details: <http://www.gnu.org/licenses/>

### ABOUT DNScapy ###
# DNScapy creates a SSH tunnel through DNS packets
# SSH connection, SCP and proxy socks (SSH -D) are supported
# See http://code.google.com/p/dnscapy/ for more informations
# Copyright (C) Pierre Bienaimé <pbienaim@gmail.com>
#               and Pascal Mazon <pascal.mazon@gmail.com>
# DNScapy uses Scapy, wrote by Philippe Biondi <phil@secdev.org>

### DISCLAMER ###
# We are not responsible for misuse of DNScapy
# Making a DNS tunnel to bypass a security policy may be forbidden
# Do it at your own risks

from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, Raw, send, Automaton, ATMT, StreamSocket, log_interactive
from random import randint
from threading import Thread
from optparse import OptionParser
from base64 import b64encode, b64decode
import socket, sys

CNAME = 5
TXT = 16

class Core(Automaton):
    dn = "" 
    def parse_qname(self, pkt):
        return pkt[DNSQR].qname.rsplit(self.dn, 1)[0].split(".")
        
    def master_filter(self, pkt):
        return (self.state.state == "WAITING" and
                IP in pkt and UDP in pkt and
                pkt[UDP].dport == 53 and DNS in pkt and
                pkt[DNS].qr == 0 and DNSQR in pkt and
                pkt[DNSQR].qname.endswith(self.dn + "."))

    def forge_packet(self, pkt, rdata="", rcode=0):
        d = pkt[IP].src 
        dp = pkt[UDP].sport
        id = pkt[DNS].id
        q = pkt[DNS].qd    
        t = pkt[DNSQR].qtype
        if t == TXT:
            for i in range(0, len(rdata), 0xff+1):
                rdata = rdata[:i] + chr(len(rdata[i:i+0xff])) + rdata[i:]     
        an = (None, DNSRR(rrname=self.dn, type=t, rdata=rdata, ttl=60))[rcode == 0]        
        ns = DNSRR(rrname=self.dn, type="NS", ttl=3600, rdata="ns."+self.dn)
        return IP(dst=d)/UDP(dport=dp)/DNS(id=id, qr=1, rd=1, ra=1, rcode=rcode, qd=q, an=an, ns=ns)


class Parent(Core):
    def parse_args(self, dn, ext_ip, debug=0, nb_clients=10, ssh_p=22):
        self.dn = dn
        self.ext_ip = ext_ip
        self.dbg = debug
        self.nb_clients = nb_clients
        self.ssh_p = ssh_p
        bpf = "udp port 53"
        Automaton.parse_args(self, filter=bpf, debug=debug)
     
    def master_filter(self, pkt):
        if Core.master_filter(self, pkt) and pkt[IP].src != self.ext_ip:
            self.qname = Core.parse_qname(self, pkt)                     
            return len(self.qname) >= 2
        else:
            return False
            
    def get_identifier(self):
        if len(self.empty_slots) >= 1:
            return self.empty_slots.pop()
        elif self.kill_children() >= 1:
            return self.empty_slots.pop()
        else:
            return None
            
    def kill_children(self):
        for k in self.childs.keys():
            if self.childs[k].state.state == "END":
                self.childs[k].stop()
                del(self.childs[k])
                self.empty_slots.add(k)
        return len(self.empty_slots)

    @ATMT.state(initial=True)
    def START(self):
        self.childs = {}
        self.empty_slots = set(range(1, self.nb_clients+1))
        raise self.WAITING()

    @ATMT.state()
    def WAITING(self):
        pass

    @ATMT.receive_condition(WAITING)
    def true_dns_request(self, pkt):
        if not self.qname[-2].isdigit():
            qtype = pkt[DNSQR].sprintf("%qtype%")
            raise self.WAITING().action_parameters(pkt, qtype)

    @ATMT.action(true_dns_request)
    def true_dns_reply(self, pkt, qtype):
        if qtype == "A":
            reply = Core.forge_packet(self, pkt, rdata=self.ext_ip)
        elif qtype == "SOA":
            reply = Core.forge_packet(self, pkt, rdata="ns.{0} root.{0} {1} 28800 14400 3600000 0".format(self.dn, randint(1, 65535)))
        elif qtype == "NS":
            reply = Core.forge_packet(self, pkt, rdata="ns."+self.dn)
        elif qtype == "MX":
            reply = Core.forge_packet(self, pkt, rdata="mail."+self.dn)
        elif qtype == "CNAME" or qtype == "TXT":
            reply = Core.forge_packet(self, pkt, rcode=3) 
        elif qtype == "AAAA" or qtype == "NULL":
            reply = Core.forge_packet(self, pkt, rcode=4)
        else:
            reply = Core.forge_packet(self, pkt, rcode=2)
        send(reply, verbose=0)

    @ATMT.receive_condition(WAITING)
    def connection_request(self, pkt):
        if len(self.qname) >=3 and self.qname[-3] == "0":
            raise self.WAITING().action_parameters(pkt)

    @ATMT.action(connection_request)
    def childbirth(self, pkt):
        i = self.get_identifier()
        if i is not None:
            thread = Child(self.dn, i, pkt, self.dbg, self.ssh_p)
            self.childs[i] = thread
            thread.runbg()


class Child(Core):
    def parse_args(self, dn, con_id, first_pkt, dbg=0, ssh_p=22):
        self.dn = dn
        self.con_id = str(con_id)
        self.first_pkt = first_pkt
        self.ssh_p = ssh_p
        Automaton.parse_args(self, debug=dbg)

    def master_filter(self, pkt):        
        if (Core.master_filter(self, pkt) and pkt[IP].src == self.ip_client):
            self.qname = Core.parse_qname(self, pkt)    
            if ( len(self.qname) >= 4 and self.qname[-2].isdigit() and self.qname[-3] == self.con_id):
                self.msg_type = self.qname[-4]
                return True
        else: 
            return False
    
    def calculate_limit_size(self, pkt):
        s = self.pkt_max_size - len(pkt[DNS]) - 2*len(DNSRR()) - 3*len(self.dn) - len("ns.") - 10
        if pkt[DNSQR].qtype == TXT:
            max_size = 512
            s -= len(str(s))
        else:
            max_size = self.qname_max_size
        return min((s, 1)[s<1], max_size) 

    def fragment_data(self, data, limit_size, qtype):
        if qtype == CNAME:
            qname = []
            rest = data
            while len(rest) > 0:
                d = rest[:limit_size]
                qname.append('.'.join([d[i:i+self.label_size] for i in range(0, len(d), self.label_size)]))
                rest = rest[limit_size:]
        elif qtype == TXT:
            qname = [data[i:i+limit_size] for i in range(0, len(data), limit_size)]
        return qname
          
    @ATMT.state(initial=True)
    def START(self):
        self.label_size = 63
        self.qname_max_size = 253
        self.pkt_max_size = 512
        self.recv_data = ""
        self.wanted = None
        self.last_wanted = None
        self.last_recv = None
        self.ip_client = self.first_pkt[IP].src
        self.is_first_wyw_pkt = True
        raise self.TICKLING()

    @ATMT.state()
    def TICKLING(self):
        s = socket.socket()
        s.connect(("127.0.0.1", self.ssh_p))
        self.stream = StreamSocket(s, Raw)
        ssh_msg = self.stream.recv()
        raise self.CON(ssh_msg.load)
        
    @ATMT.state()
    def CON(self, ssh_msg):
        if ssh_msg == "":
            raise self.TICKLING()
        s = self.calculate_limit_size(self.first_pkt)
        qtype = self.first_pkt[DNSQR].qtype 
        frag_msg = self.fragment_data(b64encode(ssh_msg), s, qtype)
        if len(frag_msg) == 1:
            pkt = Core.forge_packet(self, self.first_pkt, "0.{0}.0.{1}".format(self.con_id, frag_msg[0]))
        else:
            pkt = Core.forge_packet(self, self.first_pkt, "0.{0}.{1}".format(self.con_id, str(len(frag_msg)-1)))
        send(pkt, verbose=0)
        raise self.WAITING()

    @ATMT.state()
    def WAITING(self):
        pass
    
    @ATMT.timeout(WAITING, 600)
    def timeout_reached(self):
        raise self.END()

    @ATMT.receive_condition(WAITING)
    def data_pkt(self, pkt):
        if self.msg_type == "1":
            pkt_nb = self.qname[-5]
            if pkt_nb.isdigit():
                raise self.DATA_RECEPTION(pkt, int(pkt_nb))
                
    @ATMT.receive_condition(WAITING)
    def iwt_pkt(self, pkt):
        if self.msg_type == "2":
            raise self.IWT(pkt)

    @ATMT.receive_condition(WAITING)
    def ttm_pkt(self, pkt):
        if self.msg_type == "3":
            asked_pkt = self.qname[-5]
            if asked_pkt.isdigit():
                raise self.DATA_EMISSION(pkt, int(asked_pkt))

    @ATMT.receive_condition(WAITING)
    def done_pkt(self, pkt):
        if self.msg_type == "4":
            raise self.DONE(pkt)

    @ATMT.state()
    def DATA_RECEPTION(self, pkt, pkt_nb):
        if self.wanted is None:
            self.wanted = pkt_nb
        if pkt_nb == self.last_wanted:
            ack_pkt = Core.forge_packet(self, pkt, "1." + str(pkt_nb))
            send(ack_pkt, verbose=0)
        elif pkt_nb == self.wanted:
            self.recv_data += "".join(self.qname[:-5])
            self.last_recv = pkt_nb
            if self.wanted > 0:
                self.wanted -= 1
            ack_pkt = Core.forge_packet(self, pkt, "1." + str(pkt_nb))
            send(ack_pkt, verbose=0)
        raise self.WAITING()

    @ATMT.state()
    def IWT(self, pkt):
        """IWT (I Want This) state of the Child automaton.
        After receiving a WYW (What You Want) pkt from the client, the server
        says how many DNS pkts he needs to send the reply
        """
        self.wanted = None
        self.last_wanted = None
        if self.is_first_wyw_pkt:
            self.iwt_pkt = Core.forge_packet(self, pkt,"4")
            ssh_request = Raw(b64decode(self.recv_data))
            ssh_reply = self.stream.sr1(ssh_request, timeout=1, verbose=0)
            if ssh_reply is not None:
                qtype = pkt[DNSQR].qtype
                s = self.calculate_limit_size(pkt)
                self.frag_reply = self.fragment_data(b64encode(ssh_reply.load), s, qtype)
                self.iwt_pkt = Core.forge_packet(self, pkt,"2." + str(len(self.frag_reply)))
                self.is_first_wyw_pkt = False
            send(self.iwt_pkt, verbose=0)
            self.recv_data = ""
        else:
            send(self.iwt_pkt, verbose=0)
        raise self.WAITING()

    @ATMT.state()
    def DATA_EMISSION(self, pkt, asked_pkt):
        if asked_pkt <= len(self.frag_reply):
            data_pkt = Core.forge_packet(self, pkt, "3.{0}.{1}".format(str(asked_pkt), self.frag_reply[-(asked_pkt+1)]))
            send(data_pkt, verbose=0)
        raise self.WAITING()

    @ATMT.state()
    def DONE(self, pkt):
        self.is_first_wyw_pkt = True
        send(Core.forge_packet(self, pkt, "4"), verbose=0)
        raise self.WAITING()
 
    @ATMT.state(final=True)
    def END(self):
        pass

        
if __name__ == "__main__":
    v = "%prog 0.1 - 2011"
    u = "usage: %prog [options]  DOMAIN_NAME  EXTERNAL_IP  [options]"
    parser = OptionParser(usage=u, version=v)
    parser.add_option("-g", "--graph", dest="graph", action="store_true", help="Generate the graph of the automaton, save it to /tmp and exit. You will need some extra packages. Refer to www.secdev.org/projects/scapy/portability.html. In short: apt-get install graphviz imagemagick python-gnuplot python-pyx", default=False)
    parser.add_option("-d", "--debug-lvl", dest="debug", type="int", help="Set the debug level, where D is an integer between 0 (quiet) and 5 (very verbose). Default is 0", metavar="D", default=0)
    parser.add_option("-p", "--ssh-port", dest="port", type="int", help="P is the listening port of your SSH server. Default is 22.", metavar="P", default=22)
    parser.add_option("-c", "--clients", dest="nb_clients", type="int", help="C is the max number of simultaneous clients your server will handle with. Max is 1000. Default is 10.", metavar="C", default=10)
    (opt, args) = parser.parse_args()
    if opt.graph:
        Parent.graph(target="> /tmp/dnscapy_server_parent.pdf")
        Child.graph(target="> /tmp/dnscapy_server_child.pdf")
        sys.exit(0)
    if opt.nb_clients > 1000:
        parser.error("the max number of simultaneous clients is 1000")
    if len(args) != 2:
        parser.error("incorrect number of arguments. Please give the domain name to use and the external IP address of the server")
    dn = args[0]
    ext_ip = args[1]
    log_interactive.setLevel(1)
    dnscapy = Parent(dn, ext_ip, debug=opt.debug, nb_clients=opt.nb_clients, ssh_p=opt.port)
    dnscapy.run()

