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
from base64 import b64encode, b64decode
from random import randint
from threading import Thread
import socket, sys

class Core(Automaton):
    domain_name = "" 
    def parse_qname(self, pkt):
        return pkt[DNSQR].qname.rsplit(self.domain_name, 1)[0].split(".")
        
    def master_filter(self, pkt):
        return (self.state.state == "WAITING" and
                IP in pkt and UDP in pkt and
                pkt[UDP].dport == 53 and DNS in pkt and
                pkt[DNS].qr == 0 and DNSQR in pkt and
                pkt[DNSQR].qname.endswith(self.domain_name + "."))

    def forge_packet(self, pkt, rdata="", rcode=0):
        d = pkt[IP].src 
        dp = pkt[UDP].sport
        i = pkt[DNS].id
        q = pkt[DNS].qd    
        t = pkt[DNSQR].qtype
        qn = pkt[DNSQR].qname
        an = (None, DNSRR(rrname=qn, type=t, rdata=rdata, ttl=60))[rcode == 0]        
        ns = DNSRR(rrname=self.domain_name, type="NS", ttl=3600, rdata="ns."+self.domain_name)
        return IP(dst=d)/UDP(dport=dp)/DNS(id=i, qr=1, rd=1, ra=1, rcode=rcode, qd=q, an=an, ns=ns)


class DNScapyServerFather(Core):
    def parse_args(self, domain_name, ext_ip, max_clients=10, **kargs):
        if max_clients >= 255:
            print >> sys.stderr, "Bad arguments. Nb max of clients is 255"
        self.domain_name = domain_name
        self.ext_ip = ext_ip
        self.max_clients = max_clients
        bpf = "udp port 53"
        Automaton.parse_args(self, filter=bpf, **kargs)
     
    def master_filter(self, pkt):
        if Core.master_filter(self, pkt) and pkt[IP].src != self.ext_ip:
            self.qname = Core.parse_qname(self, pkt)                     
            return len(self.qname) >= 2
        else:
            return False
            
    def get_identifier(self):
        if len(self.available_slots) >= 1:
            return self.available_slots.pop()
        elif self.clean_child_threads() >= 1:
            return self.available_slots.pop()
        else:
            return None
            
    def clean_child_threads(self):
        for key in self.instances.keys():
            if self.instances[key].state.state == "END":
                self.instances[key].stop()
                del(self.instances[key])
                self.available_slots.add(key)
        return len(self.available_slots)

    @ATMT.state(initial=True)
    def START(self):
        self.instances = {}
        self.available_slots = set(range(1, self.max_clients+1))
        raise self.WAITING()

    @ATMT.state()
    def WAITING(self):
        pass

    @ATMT.receive_condition(WAITING)
    def got_a_true_dns_request(self, pkt):
        if not self.qname[-2].isdigit():
            qtype = pkt[DNSQR].sprintf("%qtype%")
            raise self.WAITING().action_parameters(pkt, qtype)

    @ATMT.action(got_a_true_dns_request)
    def create_fake_dns_reply(self, pkt, qtype):
        if qtype == "A":
            reply = Core.forge_packet(self, pkt, rdata=self.ext_ip)
        elif qtype == "SOA":
            reply = Core.forge_packet(self, pkt, rdata="ns.{0} root.{0} {1} 28800 14400 3600000 0".format(self.domain_name, randint(1, 65535)))
        elif qtype == "NS":
            reply = Core.forge_packet(self, pkt, rdata="ns."+self.domain_name)
        elif qtype == "MX":
            reply = Core.forge_packet(self, pkt, rdata="mail."+self.domain_name)
        elif qtype == "CNAME" or qtype == "TXT":
            reply = Core.forge_packet(self, pkt, rcode=3) 
        elif qtype == "AAAA" or qtype == "NULL":
            reply = Core.forge_packet(self, pkt, rcode=4)
        else:
            reply = Core.forge_packet(self, pkt, rcode=2)
        send(reply, verbose=0)

    @ATMT.receive_condition(WAITING)
    def got_a_connection_request(self, pkt):
        if len(self.qname) >=3 and self.qname[-3] == "0":
            raise self.WAITING().action_parameters(pkt)

    @ATMT.action(got_a_connection_request)
    def start_server_thread(self, pkt):
        i = self.get_identifier()
        if i is not None:
            thread = DNScapyServerChild(self.domain_name, i, pkt, debug=self.debug_level)
            self.instances[i] = thread
            thread.runbg()


class DNScapyServerChild(Core):
    def parse_args(self, domain_name, con_id, initial_pkt, **kargs):
        self.domain_name = domain_name
        self.con_id = str(con_id)
        self.initial_pkt = initial_pkt
        Automaton.parse_args(self, **kargs)

    def master_filter(self, pkt):        
        if (Core.master_filter(self, pkt) and pkt[IP].src == self.ip_client):
            self.qname = Core.parse_qname(self, pkt)    
            if ( len(self.qname) >= 4 and
                    self.qname[-2].isdigit() and 
                    self.qname[-3] == self.con_id):
                self.msg_type = self.qname[-4]
                return True
        else: 
            return False
    
    def calculate_limit_size(self, pkt):
        s = self.pkt_max_size - len(pkt[DNS]) - 2*len(DNSRR()) - len(pkt[DNS].qd.qname) - 2*len(self.domain_name) - len("ns.")
        return min((s, 1)[s<1], 253) 

    def fragment_data(self, b64_data, limit_size):
        first_frag = b64_data[:limit_size]
        rest = b64_data[limit_size:]
        rdata = '.'.join([first_frag[i:i+self.subdomain_max_size] for i in range(0, len(first_frag), self.subdomain_max_size)])
        if rest:
             return "{0} {1}".format(rdata, self.fragment_data(rest, limit_size))                
        else:
            return rdata            
    
    @ATMT.state(initial=True)
    def START(self):
        self.nonce_bytes_size = 2
        self.nonce_max_value = 2**(8*self.nonce_bytes_size) - 1
        self.nonce_real_size = len(str(self.nonce_max_value))
        self.subdomain_max_size = 63
        self.qname_max_size = 253
        self.pkt_max_size = 512
        self.received_data = ""
        self.wanted_pkt_nb = None
        self.last_wanted_pkt_nb = None
        self.last_received_pkt_nb = None
        self.ip_client = self.initial_pkt[IP].src
        self.is_first_wyw_pkt = True
        raise self.TICKLING()

    @ATMT.state()
    def TICKLING(self):
        s = socket.socket()
        s.connect(("127.0.0.1", 22))
        self.stream = StreamSocket(s, Raw)
        ssh_server_msg = self.stream.recv()
        raise self.CON(ssh_server_msg.load)
        
    @ATMT.state()
    def CON(self, ssh_server_msg):
        if ssh_server_msg == "":
            raise self.TICKLING()
        s = self.calculate_limit_size(self.initial_pkt)
        fragmented_msg = self.fragment_data(b64encode(ssh_server_msg), s).split(" ")
        if len(fragmented_msg) == 1:
            connection_reply_pkt = Core.forge_packet(self, self.initial_pkt, "0.{0}.0.{1}".format(self.con_id, fragmented_msg[0]))
        else:
            connection_reply_pkt = Core.forge_packet(self, self.initial_pkt, "0.{0}.{1}".format(self.con_id, str(len(fragmented_msg)-1)))
        send(connection_reply_pkt, verbose=0)
        raise self.WAITING()

    @ATMT.state()
    def WAITING(self):
        pass
    
    @ATMT.timeout(WAITING, 600)
    def timeout_reached(self):
        raise self.END()

    @ATMT.receive_condition(WAITING)
    def got_a_data_pkt(self, pkt):
        if self.msg_type == "1":
            pkt_nb = self.qname[-5]
            if pkt_nb.isdigit():
                raise self.DATA_RECEPTION(pkt, int(pkt_nb))
                
    @ATMT.receive_condition(WAITING)
    def got_an_enquiry_pkt(self, pkt):
        if self.msg_type == "2":
            raise self.IWT(pkt)

    @ATMT.receive_condition(WAITING)
    def got_a_ttm_pkt(self, pkt):
        if self.msg_type == "3":
            asked_pkt = self.qname[-5]
            if asked_pkt.isdigit():
                raise self.DATA_EMISSION(pkt, int(asked_pkt))

    @ATMT.receive_condition(WAITING)
    def got_a_done_pkt(self, pkt):
        if self.msg_type == "4":
            raise self.DONE(pkt)

    @ATMT.state()
    def DATA_RECEPTION(self, pkt, pkt_nb):
        if self.wanted_pkt_nb is None:
            self.wanted_pkt_nb = pkt_nb
        if pkt_nb == self.last_wanted_pkt_nb:
            ack_pkt = Core.forge_packet(self, pkt, "1." + str(pkt_nb))
            send(ack_pkt, verbose=0)
        elif pkt_nb == self.wanted_pkt_nb:
            self.received_data += "".join(self.qname[:-5])
            self.last_received_pkt_nb = pkt_nb
            if self.wanted_pkt_nb > 0:
                self.wanted_pkt_nb -= 1
            ack_pkt = Core.forge_packet(self, pkt, "1." + str(pkt_nb))
            send(ack_pkt, verbose=0)
        raise self.WAITING()

    @ATMT.state()
    def IWT(self, pkt):
        """IWT (I Want This) state of the Child automaton.
        After receiving a WYW (What You Want) pkt from the client, the server
        says how many DNS pkts he needs to send the reply
        """
        self.wanted_pkt_nb = None #Reset the variable for data reception
        self.last_wanted_pkt_nb = None
        if self.is_first_wyw_pkt:
            self.iwt_pkt_to_send = Core.forge_packet(self, pkt,"4")
            msg_for_ssh_server = Raw(b64decode(self.received_data))
            reply_from_ssh_server = self.stream.sr1(msg_for_ssh_server, timeout=1, verbose=0)
            if reply_from_ssh_server is not None:
                self.fragmented_answer = self.fragment_data(b64encode(reply_from_ssh_server.load), self.calculate_limit_size(pkt)).split(" ")
                self.iwt_pkt_to_send = Core.forge_packet(self, pkt,"2." + str(len(self.fragmented_answer)))
                self.is_first_wyw_pkt = False
            send(self.iwt_pkt_to_send, verbose=0)
            self.received_data = ""
        else:
            send(self.iwt_pkt_to_send, verbose=0)
        raise self.WAITING()

    @ATMT.state()
    def DATA_EMISSION(self, pkt, asked_pkt):
        if asked_pkt <= len(self.fragmented_answer):
            data_pkt = Core.forge_packet(self, pkt, "3.{0}.{1}".format(str(asked_pkt), self.fragmented_answer[-(asked_pkt+1)]))
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

        
def main(argv):
    try:
        domain_name = argv[1]
        ext_ip = argv[2]
    except IndexError:
        print >> sys.stderr, "Bad arguments. Usage: domain_name external_ip [debug_level]"
        sys.exit(0)
    try:
        debug_level = int(argv[3])
    except IndexError:
        debug_level = 0
    except ValueError:
        print >> sys.stderr, "Bad arguments. debug_level must be an int"
        sys.exit(0)
    log_interactive.setLevel(1)
    DNScapy = DNScapyServerFather(domain_name, ext_ip, debug=debug_level)
    #DNScapyServerFather.graph(target="> /tmp/DNScapy_server_father.pdf")
    #DNScapyServerChild.graph(target="> /tmp/DNScapy_server_child.pdf")
    DNScapy.run()

if __name__ == "__main__":
    main(sys.argv)
