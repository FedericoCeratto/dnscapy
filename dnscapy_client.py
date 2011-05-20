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

### DISCLAIMER ###
# We are not responsible for misuse of DNScapy
# Making a DNS tunnel to bypass a security policy may be forbidden
# Do it at your own risks

from scapy.all import IP, UDP, DNS, DNSQR, send, Automaton, ATMT, log_interactive
from math import ceil
from random import randint, choice
from datetime import datetime
from optparse import OptionParser
from base64 import b64encode, b64decode
import os, sys, time, select

_CON = "a"
_DATA = "b"
_WYW = "c"
_TTM = "d"
_DONE = "e"
_FAST = "f"

class Client(Automaton):
    def parse_args(self, dn, ip_dns, debug=0, keep_alive=5, timeout=3, retry=3, mode="CNAME"):
        Automaton.parse_args(self, debug)
        self.dn = dn
        self.ip_dns = ip_dns
        self.keep_alive = keep_alive
        self.timeout = timeout
        self.retry = retry
        self.mode = mode
        
    def master_filter(self, pkt):
        if ( self.state.state == "SR1" and
                IP in pkt and pkt[IP].src == self.ip_dns and
                UDP in pkt and pkt[UDP].sport == 53 and 
                DNS in pkt and pkt[DNS].qr == 1 and
                pkt[DNS].rcode == 0 and
                DNSQR in pkt and DNSRR in pkt[DNS].an and
                pkt[UDP].dport in [ p[UDP].sport for p in self.sr1_pkts ] and
                pkt[DNS].id in [ p[DNS].id for p in self.sr1_pkts ] and
                pkt[DNSQR].qname in [ p[DNSQR].qname for p in self.sr1_pkts ] and
                pkt[DNS].an.type in [ p[DNS].an.type for p in self.sr1_pkts ] ):
            rdata = pkt[DNS].an.rdata
            if pkt[DNS].an.sprintf("%type%") == "TXT":
                for i in range(0, len(rdata), 0xff):
                    rdata = rdata[:i] + rdata[i+1:]
            self.rdata = rdata.split(".")
            self.msg_type = self.rdata[0]
            self.retry_token = self.token
            return True
        return False

    def forge_packet(self, qname, is_connection = False, rand = False):
        sp = randint(10000,50000)
        i = randint(1, 65535)
        n = randint(0, self.n_max)
        if is_connection:
            con_id = ""
        else:
            con_id = self.con_id + "."
        if self.mode == "RAND":
            if rand or self.qtype is None:
                self.qtype = choice(["TXT","CNAME"])
            qtype = self.qtype
        else:
            qtype = self.mode
        q = DNSQR(qtype=qtype, qname="{0}.{1}{2}.{3}".format(qname, con_id, str(n), self.dn))
        return IP(dst=self.ip_dns)/UDP(sport=sp)/DNS(id=i, rd=1, qd=q)

    def calculate_limit_size(self):
        temp = self.qname_max_size - len(self.dn) - self.n_size - 5 - 10 - len(self.con_id) - 1
        limit_size = int(temp - ceil(float(temp)/(self.label_size+1)))
        return limit_size

    def fragment_data(self, data, limit_size):
        data_dict = {}
        rest = data
        i = 0
        while len(rest) > 0:
            d = rest[:limit_size]
            data_dict[i] = ('.'.join([d[j:j+self.label_size] for j in range(0, len(d), self.label_size)]))
            rest = rest[limit_size:]
            i += 1
        return data_dict
    
    def decompress(s):
        """ '0-6.8.12-14.19' => [0,1,2,3,4,5,6,8,12,13,14,19] """
        l = s.split(".")
        result = []
        for i in l:
            if i.isdigit():
                result.append(int(i))
            else:
                r = i.split("-")
                if len(r) >= 2:
                    if r[0].isdigit() and r[1].isdigit():
                        result += range(int(r[0]),int(r[1])+1)
        return result             

    @ATMT.state(initial=True)
    def START(self):
        self.n_bytes = 2
        self.n_max = 2**(8*self.n_bytes) - 1
        self.n_size = len(str(self.n_max))
        self.label_size = 63
        self.qname_max_size = 253
        self.recv_data = ""
        self.wyw_token = 0
        self.qtype = None
        self.data_to_send = {}
        self.sr1_pkts = []
        self.retry_token = self.retry
        con_request_pkt = self.forge_packet(_CON, is_connection=True, rand=True)
        raise self.SR1(con_request_pkt)

    @ATMT.state()
    def SR1(self, pkt):
        if type(pkt) != type([]):
            pkt = [ pkt ]
        self.sr1_pkts = pkt
        send(self.sr1_pkts, verbose=0)
    
    @ATMT.timeout(SR1, 3)
    def retry_or_exit(self):
        if self.retry_token > 0:
            self.retry_token -= 1
            raise self.SR1(self.sr1_pkts)
        else:
            raise self.ERROR("Timeout !")
        
    @ATMT.receive_condition(SR1)
    def con_pkt(self, pkt):
        if self.msg_type == _CON:
            r = self.rdata
            l = len(r)
            if l > 2:
                if r[1].isdigit() and r[2].isdigit():
                    con_iwt = int(r[2])
                    data = None
                    if l > 3:
                        data = "".join(r[3:])
                    if (con_iwt == 0 and data is not None) or con_iwt > 0:
                        self.con_id = int(r[1])                    
                        raise self.CON(con_iwt, data)
    
    @ATMT.receive_condition(SR1)
    def data_pkt(self, pkt):
        if self.msg_type == _DATA:
            r = self.rdata
            l = len(r)
            if l > 1:
                if r[1].isdigit():
                    raise self.DATA(int(r[1]))
                    
    @ATMT.receive_condition(SR1)
    def fast_pkt(self, pkt):
        if self.msg_type == _FAST:
            if len(self.rdata) > 1:
                ack_range = self.rdata[1:]
                raise self.FAST(ack_range) 
    
    @ATMT.receive_condition(SR1)
    def wyw_pkt(self, pkt): 
        if self.msg_type == _WYW:
            r = self.rdata
            l = len(r) 
            if l > 1:
                if r[1].isdigit():
                    nb_pkts = int(r[1]) - 1
                    raise self.TTM(nb_pkts)
                    
    @ATMT.receive_condition(SR1)
    def ttm_pkt(self, pkt): 
         if self.msg_type == _TTM:
            r = self.rdata
            l = len(r)
            if l > 2 and r[1].isdigit():
                pkt_nb = int(r[1])
                data = "".join(r[2:])
                raise self.TTM(data, pkt_nb)  
    
    @ATMT.receive_condition(SR1)
    def done_pkt(self, pkt): 
        if self.wyw_token > 0:
            self.wyw_token -= 1
            raise self.WYW()
        else:
            raise self.STDIN_LISTENING()
            
    @ATMT.state()
    def CON(self, con_iwt, data):
        self.wyw_token = 2
        if con_iwt == 0:
            msg = b64decode(data)
            sys.stdout.write(msg)
            sys.stdout.flush()
            done_pkt = self.forge_packet("{0}.{1}".format(_TTM, _DONE), rand=True)
            raise self.SR1(done_pkt)
        else:
            first_ttm_pkt = self.forge_packet("{0}.{1}".format(con_iwt, _TTM))
            raise self.SR1(first_ttm_pkt)

    @ATMT.state()
    def TTM(self, data, pkt_nb=None):
        """TTM (Talk To Me) state of the automaton.
        Sending empty packets to receive data from the server.
        """
        self.wyw_token = 1
        if self.msg_type == _WYW:
            first_ttm_pkt = self.forge_packet("{0}.{1}".format(data, _TTM))
            raise self.SR1(first_ttm_pkt)
        elif self.msg_type == _TTM:
            self.recv_data += data
            if pkt_nb == 0:
                msg = b64decode(self.recv_data)
                self.recv_data = ""
                sys.stdout.write(msg)
                sys.stdout.flush()
                done_pkt = self.forge_packet("{0}.{1}".format(_TTM, _DONE), rand=True)
                raise self.SR1(done_pkt)
            else:
                ttm_pkt = self.forge_packet("{0}.{1}".format(pkt_nb-1, _TTM))
            raise self.SR1(ttm_pkt)
        else:
            raise self.ERROR("Error: Internal Error. Please insult developers.")

    @ATMT.state()
    def DATA(self, ack_nb=None):
        self.wyw_token = 3
        if ack_nb is not None:
            if self.data_to_send.has_key(ack_nb):
                del(self.data_to_send[ack_nb])
            if len(self.data_to_send) == 0:
                done_pkt = self.forge_packet("{0}.{1}".format(_DATA, _DONE), rand=True)
                raise self.SR1(done_pkt)
        k = self.data_to_send.keys()[0]
        pkt_of_data = self.forge_packet("{0}.{1}.{2}".format(self.data_to_send[k], k, _DATA))
        raise self.SR1(pkt_of_data)
            
    @ATMT.state()
    def FAST(self, ack_range=None): 
        self.wyw_token = 3 
        if ack_range is not None:
            print sys.stderr , "ack-range:" + repr(ack_range)
            ack_list = self.decompress(ack_range)
            for a in ack_list:
                if self.data_to_send.has_key(a):
                    del(self.data_to_send[a])
                if len(self.data_to_send) == 0:
                    done_pkt = self.forge_packet("{0}.{1}".format(_DATA, _DONE), rand=True)
                    raise self.SR1(done_pkt)
        if len(self.data_to_send) < 5:
            raise self.DATA()
        pkts = []
        for i in self.data_to_send.iteritems():
            pkt = self.forge_packet("{0}.{1}.{2}".format(i[1], i[0], _FAST))
            pkts.append(pkt)
        raise self.SR1(pkts)
        
    @ATMT.state()
    def WYW(self):
        """WYW (What do You Want) state of the automaton.
        Asking if the server wants to say something
        """
        wyw_pkt = self.forge_packet(_WYW, rand=True)
        raise self.SR1(wyw_pkt)

    @ATMT.state()
    def STDIN_LISTENING(self):
        a,b,c = select.select([sys.stdin],[],[],self.keep_alive)
        if len(a) > 0:
            input_msg = os.read(a[0].fileno(),20000)
            self.data_to_send = self.fragment_data(b64encode(input_msg), self.calculate_limit_size())
            if len(self.data_to_send) < 5:
                raise self.DATA()
            raise self.FAST()
        raise self.WYW()

    @ATMT.state(error=True)
    def ERROR(self, error_msg):
        print >> sys.stderr, "Error message: ", error_msg
        
if __name__ == "__main__":
    v = "%prog 0.2 - 2011"
    u = "usage: %prog [options]  DOMAIN_NAME  IP_INTERNAL_DNS  [options]"
    parser = OptionParser(usage=u, version=v)
    parser.add_option("-m", "--mode", dest="mode", help="Set the DNS field use for the tunneling. Possible values are CNAME, TXT and RAND. TXT offers better speed but CNAME offers better compatibility. RAND mean that both TXT and CNAME are randomly used. Default is CNAME.", default="CNAME")
    parser.add_option("-g", "--graph", dest="graph", action="store_true", help="Generate the graph of the automaton, save it to /tmp and exit. You will need some extra packages. Refer to www.secdev.org/projects/scapy/portability.html. In short: apt-get install graphviz imagemagick python-gnuplot python-pyx", default=False)
    parser.add_option("-d", "--debug-lvl", dest="debug", type="int", help="Set the debug level, where D is an integer between 0 (quiet) and 5 (very verbose). Default is 0", metavar="D", default=0)
    parser.add_option("-k", "--keep-alive", dest="keep_alive", type="int", help="After waiting during K seconds, the client sends a keep-alive packet. Default is 5.", metavar="K", default=5)
    parser.add_option("-t", "--timeout", dest="timeout", type="int", help="After sending a packet to the server, the client waits for the reply up to T seconds. If there is no reply the packet is re-sent. Default is 3.", metavar="T", default=3)
    parser.add_option("-r", "--retry", dest="retry", type="int", help="After R retries without response, the connection with the server is considered broken. Default is 3.", metavar="R", default=3)
    (opt, args) = parser.parse_args()
    if opt.graph:
        Client.graph(target="> /tmp/dnscapy_client.pdf")
        sys.exit(0)
    if opt.mode not in ["CNAME", "TXT", "RAND"]:
        parser.error("incorrect mode. Possible values are CNAME, TXT and RAND. Default is CNAME.")
    if len(args) != 2:
        parser.error("incorrect number of arguments. Please give the domain name to use and the IP address of the client's internal DNS server")
    dn = args[0]
    ip_dns = args[1]
    log_interactive.setLevel(1)
    dnscapy = Client(dn=dn, ip_dns=ip_dns, debug=opt.debug, keep_alive=opt.keep_alive, timeout=opt.timeout, retry=opt.retry, mode=opt.mode)
    dnscapy.run()

