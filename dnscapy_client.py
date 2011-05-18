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

from scapy.all import IP, UDP, DNS, DNSQR, sr1, Automaton, ATMT, log_interactive
from math import ceil
from random import randint, choice
from datetime import datetime
from optparse import OptionParser
from base64 import b64encode, b64decode
import os, sys, fcntl, time

class Client(Automaton):
    def parse_args(self, dn, ip_dns, debug=0, keep_alive=30, timeout=3, retry=3, mode="CNAME"):
        Automaton.parse_args(self, debug)
        self.dn = dn
        self.ip_dns = ip_dns
        self.keep_alive = keep_alive
        self.timeout = timeout
        self.retry = retry
        self.mode = mode

    def forge_packet(self, qname, is_connection = False, rand = True):
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
        qname = []
        rest = data
        while len(rest) > 0:
            d = rest[:limit_size]
            qname.append('.'.join([d[j:j+self.label_size] for j in range(0, len(d), self.label_size)]))
            rest = rest[limit_size:]
        return qname

    @ATMT.state(initial=True)
    def START(self):
        self.n_bytes = 2
        self.n_max = 2**(8*self.n_bytes) - 1
        self.n_size = len(str(self.n_max))
        self.label_size = 63
        self.qname_max_size = 253
        self.recv_data = ""
        self.was_in_data = False
        self.qtype = None
        con_request_pkt = self.forge_packet("0", True)
        raise self.SR1(con_request_pkt)

    @ATMT.state()
    def SR1(self, pkt):
        rcode = None
        nb_retry = 0
        while rcode != 0:
            rep = sr1(pkt, filter="udp port 53", timeout=self.timeout, retry=self.retry, verbose=0)
            if rep is None or nb_retry >= 3:
                raise self.ERROR("Timeout Error : No response after 3 requests")
            rcode = rep[DNS].rcode
            nb_retry += 1
        try:
            rdata = rep[DNS].an.rdata
        except AttributeError:
            raise self.ERROR("Error: Answer received is not a correct DNS answer (no rdata)")
        if rep[DNS].an.sprintf("%type%") == "TXT":
            for i in range(0, len(rdata), 0xff):
                rdata = rdata[:i] + rdata[i+1:]
        rdata = rdata.split(".")
        msg_type = rdata[0]
        if msg_type == "0":
            con_id = rdata[1]
            nb_msg_needed = rdata[2]
            recv_data = None
            if nb_msg_needed == "0":
                recv_data = "".join(rdata[3:])
            raise self.CON(con_id, nb_msg_needed, recv_data)
        elif msg_type == "1":
            pkt_nb_ack = rdata[1]
            raise self.DATA(pkt_nb_ack)
        elif msg_type == "2":
            nb_pkts = rdata[1]
            raise self.TTM(msg_type, str(int(nb_pkts)-1))
        elif msg_type == "3":
            pkt_received_nb = rdata[1]
            recv_data = "".join(rdata[2:])
            raise self.TTM(msg_type, recv_data, pkt_received_nb)
        elif msg_type == "4":
            raise self.DONE()
        else:
            raise self.ERROR("Error: Unknown message type")

    @ATMT.state()
    def CON(self, con_id, nb_msg_needed, recv_data):
        self.con_id = con_id
        if nb_msg_needed == "0":
            self.recv_data = recv_data
            done_pkt = self.forge_packet("4")
            raise self.SR1(done_pkt)
        else:
            first_ttm_pkt = self.forge_packet("{0}.3".format(nb_msg_needed))
            raise self.SR1(first_ttm_pkt)

    @ATMT.state()
    def TTM(self, msg_type, data, msg_num=None):
        """TTM (Talk To Me) state of the automaton.
        Sending empty packets to receive data from the server.
        """
        self.was_in_data = True
        if msg_type == "2":
            nb_of_pkts = data
            first_ttm_pkt = self.forge_packet("{0}.3".format(nb_of_pkts), rand=False)
            raise self.SR1(first_ttm_pkt)
        elif msg_type == "3":
            self.recv_data += data
            if msg_num == "0":
                done_pkt = self.forge_packet("4", rand=False)
                raise self.SR1(done_pkt)
            else:
                ttm_pkt = self.forge_packet("{0}.3".format(str(int(msg_num)-1)), rand=False)
            raise self.SR1(ttm_pkt)
        else:
            raise self.ERROR("Error: Internal Error. Please insult developers.")

    @ATMT.state()
    def DATA(self, ack_nb=None):
        self.was_in_data = True
        if ack_nb is None:
            first_pkt_of_data = self.forge_packet("{0}.{1}.1".format(self.data_to_send[0], str(len(self.data_to_send) - 1)))
            raise self.SR1(first_pkt_of_data)
        elif ack_nb == "0":
            self.data_to_send = []
            raise self.WYW()
        elif ack_nb == str(len(self.data_to_send) - 1):
            self.data_to_send = self.data_to_send[1:]
            pkt_of_data = self.forge_packet("{0}.{1}.1".format(self.data_to_send[0], str(len(self.data_to_send) - 1)))
            raise self.SR1(pkt_of_data)
        else:
            pkt_of_data = self.forge_packet(self.data_to_send[0])
            raise self.SR1(pkt_of_data)

    @ATMT.state()
    def WYW(self):
        """WYW (What do You Want) state of the automaton.
        Asking if the server wants to say something
        """
        wyw_pkt = self.forge_packet("2")
        raise self.SR1(wyw_pkt)

    @ATMT.state()
    def DONE(self):
        msg = b64decode(self.recv_data)
        self.recv_data = ""
        sys.stdout.write(msg)
        sys.stdout.flush()
        if self.was_in_data:
            self.was_in_data = False    
            raise self.WYW()
        raise self.STDIN_LISTENING()

    @ATMT.state()
    def STDIN_LISTENING(self):
        file_descriptor = sys.stdin.fileno()
        filel = fcntl.fcntl(file_descriptor, fcntl.F_GETFL)
        fcntl.fcntl(file_descriptor, fcntl.F_SETFL, filel | os.O_NONBLOCK)

        input_msg = ""
        timeout = 0
        sleep_time = 0.1
        while input_msg == "":
            try:
                input_msg = sys.stdin.read()
            except:
                time.sleep(sleep_time)
                timeout += sleep_time
                if timeout >= self.keep_alive:
                    raise self.WYW()
        self.data_to_send = self.fragment_data(b64encode(input_msg), self.calculate_limit_size())
        raise self.DATA()

    @ATMT.state(error=True)
    def ERROR(self, error_msg):
        print >> sys.stderr, "Error message: ", error_msg
        
if __name__ == "__main__":
    v = "%prog 0.1 - 2011"
    u = "usage: %prog [options]  DOMAIN_NAME  IP_INTERNAL_DNS  [options]"
    parser = OptionParser(usage=u, version=v)
    parser.add_option("-m", "--mode", dest="mode", help="Set the DNS field use for the tunneling. Possible values are CNAME, TXT and RAND. TXT offers better speed but CNAME offers better compatibility. RAND mean that both TXT and CNAME are randomly used. Default is CNAME.", default="CNAME")
    parser.add_option("-g", "--graph", dest="graph", action="store_true", help="Generate the graph of the automaton, save it to /tmp and exit. You will need some extra packages. Refer to www.secdev.org/projects/scapy/portability.html. In short: apt-get install graphviz imagemagick python-gnuplot python-pyx", default=False)
    parser.add_option("-d", "--debug-lvl", dest="debug", type="int", help="Set the debug level, where D is an integer between 0 (quiet) and 5 (very verbose). Default is 0", metavar="D", default=0)
    parser.add_option("-k", "--keep-alive", dest="keep_alive", type="int", help="After waiting during K seconds, the client sends a keep-alive packet. Default is 30.", metavar="K", default=30)
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
    automaton = Client(dn=dn, ip_dns=ip_dns, debug=opt.debug, keep_alive=opt.keep_alive, timeout=opt.timeout, retry=opt.retry, mode=opt.mode)
    automaton.run()

