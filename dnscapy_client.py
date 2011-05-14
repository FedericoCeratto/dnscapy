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
from base64 import b64encode, b64decode
from math import ceil
from random import randint
from datetime import datetime
import os, sys, fcntl, time

class DNScapyClient(Automaton):
    def parse_args(self, domain_name, ip_internal_dns, **kargs):
        Automaton.parse_args(self, **kargs)
        self.domain_name = domain_name
        self.ip_dns = ip_internal_dns

    def forge_packet(self, qname, is_connection = False):
        sp = randint(10000,50000)
        i = randint(1, 65535)
        nonce = randint(0, self.nonce_max_value)
        #con_id = ("", self.con_id + ".")[not is_connection]
        if is_connection:
            con_id = ""
        else:
            con_id = self.con_id + "."
        q = DNSQR(qtype='CNAME', qname="{0}.{1}{2}.{3}".format(qname, con_id, str(nonce), self.domain_name))
        return IP(dst=self.ip_dns)/UDP(sport=sp)/DNS(id=i, rd=1, qd=q)

    def calculate_limit_size(self):
        qname_max_size = 253
        con_id_size = 1
        temp = qname_max_size - len(self.domain_name) - self.nonce_real_size - 5 - 10 - con_id_size - 1
        limit_size = int(temp - ceil(float(temp)/(self.subdomain_max_size+1)))
        return limit_size

    def fragment_data(self, data, limit_size):
        qname = ""
        rest = data
        while len(rest) > 0:
            d = rest[:limit_size]
            qname += '.'.join([d[j:j+self.subdomain_max_size] for j in range(0, len(d), self.subdomain_max_size)])
            rest = rest[limit_size:]
            if len(rest) > 0:
                qname += " " 
        return qname

    @ATMT.state(initial=True)
    def START(self):
        self.nonce_bytes_size = 2
        self.nonce_max_value = 2**(8*self.nonce_bytes_size) - 1
        self.nonce_real_size = len(str(self.nonce_max_value))
        self.subdomain_max_size = 63
        self.recv_data = ""
        self.was_in_data = False
        connection_request_pkt = self.forge_packet("0", True)
        raise self.SR1(connection_request_pkt)

    @ATMT.state()
    def SR1(self, pkt):
        rcode = None
        nb_retry = 0
        while rcode != 0:
            rep = sr1(pkt, filter="udp port 53", timeout=3, retry=3, verbose=0)
            if rep is None or nb_retry >= 3:
                raise self.ERROR("Error : No response, or multiple server failure")
            rcode = rep[DNS].rcode
            nb_retry += 1
        try:
            rdata = rep[DNS].an.rdata.split('.')
        except AttributeError:
            raise self.ERROR("Error: Answer received is not a correct DNS answer (no rdata)")
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
        if msg_type == "2":
            nb_of_pkts = data
            first_ttm_pkt = self.forge_packet("{0}.3".format(nb_of_pkts))
            raise self.SR1(first_ttm_pkt)
        elif msg_type == "3":
            self.recv_data += data
            if msg_num == "0":
                done_pkt = self.forge_packet("4")
                raise self.SR1(done_pkt)
            else:
                ttm_pkt = self.forge_packet("{0}.3".format(str(int(msg_num)-1)))
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
                if timeout >= 10:
                    raise self.WYW()
        fragmented_input_msg = self.fragment_data(b64encode(input_msg), self.calculate_limit_size())
        self.data_to_send = fragmented_input_msg.split(" ")
        raise self.DATA()

    @ATMT.state(error=True)
    def ERROR(self, error_msg):
        print >> sys.stderr, "Error message: ", error_msg
        open_file = open("/tmp/DNScapy_client_error.log", "a")
        open_file.write(str(datetime.today()) + ":: " + error_msg + "")
        open_file.close()

def main(argv):
    try:
        domain_name = argv[1]
        ip_internal_dns = argv[2]
    except IndexError:
        print >> sys.stderr, "Bad arguments. Usage: domain_name ip_internal_dns [debug_level]"
        sys.exit(0)
    try:
        debug_level = int(argv[3])
    except IndexError:
        debug_level = 0
    except ValueError:
        print >> sys.stderr, "Bad arguments. debug_level mut be an int"
        sys.exit(0)
    log_interactive.setLevel(1)
    automaton = DNScapyClient(domain_name=domain_name, ip_internal_dns=ip_internal_dns, debug=debug_level)
    #DNScapyClient.graph(target="> /tmp/DNScapy_client.pdf")
    automaton.run()

if __name__ == "__main__":
    main(sys.argv)
