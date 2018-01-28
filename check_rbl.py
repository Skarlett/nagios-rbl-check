#! /usr/bin/env python
#
# This is a multi-threaded RBL lookup check for Icinga / Nagios.
# Copyright (C) 2012 Frode Egeland <egeland[at]gmail.com>
#
# Modified by Kumina bv in 2013. We only added an option to use an
# address instead of a hostname.
#
# Modified by Guillaume Subiron (Sysnove) in 2015 : mainly PEP8.
#
# Modified by Steve Jenkins (SteveJenkins.com) in 2017. Added a number
# of additional DNSRBLs and made 100% PEP8 compliant.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

# Import Modules
import sys
import socket
if sys.version_info[0] == 3:
    import queue as Queue
else:
    import Queue
import threading


# Python version check
rv = (2, 6)
if rv >= sys.version_info:
    print("ERROR: Requires Python 2.6 or greater")
    sys.exit(3)

class DNSBL():
    servers =\
    set(['0spam.fusionzero.com', 'access.redhawk.org', 'all.rbl.webiron.net', 'all.s5h.net',
     'bad.psky.me', 'bhnc.njabl.org', 'bl.blocklist.de', 'bl.deadbeef.com', 'bl.emailbasura.org', 'bl.mailspike.net',
     'bl.spamcannibal.org', 'bl.spamcop.net', 'bl.spameatingmonkey.net', 'bl.technovision.dk',
     'blackholes.five-ten-sg.com', 'blackholes.mail-abuse.org', 'blacklist.sci.kun.nl', 'blacklist.woody.ch',
     'bogons.cymru.com', 'cbl.abuseat.org', 'cdl.anti-spam.org.cn', 'cidr.bl.mcafee.com', 'combined.abuse.ch',
     'combined.rbl.msrbl.net', 'db.wpbl.info', 'dnsbl-1.uceprotect.net', 'dnsbl-2.uceprotect.net',
     'dnsbl-3.uceprotect.net', 'dnsbl.anticaptcha.net', 'dnsbl.cobion.com', 'dnsbl.cyberlogic.net', 'dnsbl.dronebl.org',
     'dnsbl.inps.de', 'dnsbl.kempt.net', 'dnsbl.njabl.org', 'dnsbl.solid.net', 'dnsbl.sorbs.net', 'dnsrbl.org',
     'drone.abuse.ch', 'duinv.aupads.org', 'dul.dnsbl.sorbs.net', 'dul.ru', 'dyna.spamrats.com', 'dynip.rothen.com',
     'forbidden.icm.edu.pl', 'hostkarma.junkemailfilter.com', 'hil.habeas.com', 'images.rbl.msrbl.net',
     'ips.backscatterer.org', 'ix.dnsbl.manitu.net', 'korea.services.net', 'mail-abuse.blacklist.jippg.org',
     'no-more-funn.moensted.dk', 'noptr.spamrats.com', 'ohps.dnsbl.net.au', 'omrs.dnsbl.net.au', 'orvedb.aupads.org',
     'osps.dnsbl.net.au', 'osrs.dnsbl.net.au', 'owfs.dnsbl.net.au', 'owps.dnsbl.net.au', 'phishing.rbl.msrbl.net',
     'probes.dnsbl.net.au', 'proxy.bl.gweep.ca', 'proxy.block.transip.nl', 'psbl.surriel.com', 'rbl.abuse.ro',
     'rbl.interserver.net', 'rbl.megarbl.net', 'rbl.orbitrbl.com', 'rbl.realtimeblacklist.com', 'rbl.schulte.org',
     'rdts.dnsbl.net.au', 'relays.bl.gweep.ca', 'relays.bl.kundenserver.de', 'relays.nether.net',
     'residential.block.transip.nl', 'ricn.dnsbl.net.au', 'rmst.dnsbl.net.au', 'short.rbl.jp', 'singular.ttk.pte.hu',
     'spam.abuse.ch', 'spam.dnsbl.sorbs.net', 'spam.rbl.msrbl.net', 'spam.spamrats.com', 'spamguard.leadmon.net',
     'spamlist.or.kr', 'spamrbl.imp.ch', 'spamsources.fabel.dk', 'spamtrap.drbl.drand.net', 'srnblack.surgate.net',
     't3direct.dnsbl.net.au', 'tor.dnsbl.sectoor.de', 'torserver.tor.dnsbl.sectoor.de', 'truncate.gbudb.net',
     'ubl.lashback.com', 'ubl.unsubscore.com', 'virbl.dnsbl.bit.nl', 'virus.rbl.jp', 'virus.rbl.msrbl.net',
     'wormrbl.imp.ch', 'zen.spamhaus.org', 'b.barracudacentral.org','all.rbl.jp', 'all.spamrats.com',
     'bl.mailspike.org', 'bl.score.senderscore.com', 'cblplus.anti-spam.org.cn', 'combined.njabl.org', 'dnsbl.burnt-tech.com',
     'dnsbl.justspam.org', 'dnsbl.rv-soft.info', 'dnsbl.tornevall.org', 'dnsbl.webequipped.com', 'dnsrbl.swinog.ch',
     'fnrbl.fast.net', 'ip.v4bl.org', 'l2.apews.org', 'l2.bbfh.ext.sorbs.net', 'list.blogspambl.com', 'rbl2.triumf.ca',
     'rbl.choon.net', 'rbl.dns-servicios.com', 'rbl.efnetrbl.org', 'rbl.polarcomm.net', 'singlebl.spamgrouper.com',
     'spam.pedantic.org', 'st.technovision.dk', 'tor.dan.me.uk', 'work.drbl.gremlin.ru'])

    def __init__(self):
      self.queue = Queue.Queue()
      self.workers = set()
      self._reverse_ip = lambda ip: '.'.join(ip.split('.')[::-1])
      self._results = {}
      
      
    def _worker(self, query):
      while self.queue.not_empty:
        hostname, root_name = self.queue.get()
        check_host = "%s.%s" % (hostname, root_name)
        try:
          r = socket.gethostbyname(check_host)
        except socket.error:
          r = None
        if not r:
          self._results[query].append((check_host, r))
        self.queue.task_done()
        
    
    def query(self, ip):
      query = len(self._results)
      self._results[query] = []
      if not len(self.workers) == 10:
        more_workers = 10-len(self.workers)
        if more_workers >= 0:
          for _ in range(more_workers):
            self.workers.add(threading._start_new_thread(self._worker, (query,)))
          
      for blhost in self.servers:
        self.queue.put((self._reverse_ip(ip), blhost))
      
      for d in self.workers:
        d.setDaemon(True)
        d.start()
      
      self.queue.join()
      return self._results.pop(query)
    
