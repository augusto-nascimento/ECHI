#!/usr/bin/python

#    Copyright 2014 Michael Herman
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import struct
import binascii
import time
import os
import os.path
import sys,argparse
import time

parser = argparse.ArgumentParser(description='Find calls in spi.log files')
parser.add_argument("-f", "--file", action="store", dest="file", help="source file" )

args = parser.parse_args()

chrfile = args.file
#print chrfile
chrcsv = chrfile + ".csv"
echdata = open(chrfile, "rb")

headerblock = echdata.read(8)
header_seq = struct.unpack('<I', headerblock[4:8])
# print header_seq

blocksize = 617
record = []
filedata = []
totalsize = os.path.getsize(chrfile)
# print totalsize



# echdata.seek(1)


#print echdata.tell()
block = "0"
#block = echdata.read(blocksize)

print
print "Starting parsing for file: " + chrfile

while block <> "" :
	record = []
	# print echdata.tell()
	block=echdata.read(blocksize)

	callid = struct.unpack('<I', block[0:4])
	#print callid
	acwtime = struct.unpack('<I', block[4:8])
	#print acwtime
	ansholdtime = struct.unpack('<I', block[8:12])
	#print ansholdtime
	# record = callid, acwtime, ansholdtime
	consulttime = struct.unpack('<I', block[12:16])
	#print consulttime
	disptime = struct.unpack('<I', block[16:20])
	#print disptime
	duration = struct.unpack('<I', block[20:24])
	#print duration
	segstart = struct.unpack('<I', block[24:28])
	# print segstart
	f_segstart = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(float(segstart[0])))
	segstart_utc = struct.unpack('<I', block[28:32])
	f_segstart_utc = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(float(segstart_utc[0])))
	segstop = struct.unpack('<I', block[32:36])
	f_segstop = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(float(segstop[0])))
	segstop_utc = struct.unpack('<I', block[36:40])
	f_segstop_utc = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(float(segstop_utc[0])))
	talktime = struct.unpack('<I', block[40:44])
	#print talktime
	netintime = struct.unpack('<I', block[44:48])
	#print netintime
	origholdtime = struct.unpack('<I', block[48:52])
	#print origholdtime
	queuetime = struct.unpack('<I', block[52:56])
	#print queuetime
	ringtime = struct.unpack('<I', block[56:60])
	#print ringtime
	dispivector = struct.unpack('<H', block[60:62])
	#print dispivector
	dispsplit = struct.unpack('<h', block[62:64])
	#print dispsplit
	firstvector = struct.unpack('<H', block[64:66])
	#print firstvector
	split1 = struct.unpack('<h', block[66:68])
	#print split1
	split2 = struct.unpack('<h', block[68:70])
	#print split2
	split3 = struct.unpack('<h', block[70:72])
	#print split3
	tkgrp = struct.unpack('<H', block[72:74])
	#print tkgrp
	eq_locid = struct.unpack('<H', block[74:76])
	#print eq_locid
	orig_locid = struct.unpack('<H', block[76:78])
	#print orig_locid
	ans_locid = struct.unpack('<H', block[78:80])
	#print ans_locid
	obs_locid = struct.unpack('<H', block[80:82])
	#print obs_locid
	uui_len = struct.unpack('<H', block[82:84])
	#print uui_len

	agentreleased = struct.unpack('<B', block[85])
	acd = struct.unpack('<B', block[86])
	#print "ACD: " + str(acd)
	call_disp = struct.unpack('<B', block[87])
	#print call_disp
	disppriority = struct.unpack('<B', block[88])
	#print disppriority
	held = struct.unpack('<B', block[89])
	#print held
	segment = struct.unpack('<B', block[90])
	#print segment
	ansreason = struct.unpack('<B', block[91])
	#print ansreason
	origreason = struct.unpack('<B', block[92])
	#print origreason
	dispsklevel = struct.unpack('<B', block[93])
	#print dispsklevel
	event1 = struct.unpack('<B', block[94])
	#print event1
	event2 = struct.unpack('<B', block[95])
	#print event2
	event3 = struct.unpack('<B', block[96])
	#print event3
	event4 = struct.unpack('<B', block[97])
	#print event4
	event5 = struct.unpack('<B', block[98])
	#print event5
	event6 = struct.unpack('<B', block[99])
	#print event6
	event7 = struct.unpack('<B', block[100])
	#print event7
	event8 = struct.unpack('<B', block[101])
	#print event8
	event9 = struct.unpack('<B', block[102])
	#print event9
	ucid = str(struct.unpack('21s', block[103:124])[0]).strip(' \t\r\n\0')
	# print str(ucid[0]).rstrip(' \t\r\n\0')
	# print ucid
	dispvdn = str(struct.unpack('16s', block[124:140])[0]).strip(' \t\r\n\0')
	#print str(dispvdn[0]).rstrip(' \t\r\n\0')
	eqloc = str(struct.unpack('10s', block[140:150])[0]).strip(' \t\r\n\0')
	#print eqloc
	firstvdn = str(struct.unpack('16s', block[150:166])[0]).strip(' \t\r\n\0')
	#print firstvdn
	origlogin = str(struct.unpack('16s', block[166:182])[0]).strip(' \t\r\n\0')
	#print origlogin
	anslogin = str(struct.unpack('16s', block[182:198])[0]).strip(' \t\r\n\0')
	#print anslogin
	lastobserver = str(struct.unpack('16s', block[198:214])[0]).strip(' \t\r\n\0')
	#print lastobserver
	dialed_num = str(struct.unpack('25s', block[214:239])[0]).strip(' \t\r\n\0')
	#print dialed_num
	calling_pty = str(struct.unpack('25s', block[239:264])[0]).strip(' \t\r\n\0')
	#print calling_pty
	lastdigits = str(struct.unpack('17s', block[264:281])[0]).strip(' \t\r\n\0')
	#print lastdigits
	lastcwc = str(struct.unpack('17s', block[281:298])[0]).strip(' \t\r\n\0')
	#print lastcwc
	calling_II = str(struct.unpack('3s', block[298:301])[0]).strip(' \t\r\n\0')
	#print calling_II
	cwc1 = str(struct.unpack('17s', block[301:318])[0]).strip(' \t\r\n\0')
	cwc2 = str(struct.unpack('17s', block[318:335])[0]).strip(' \t\r\n\0')
	cwc3 = str(struct.unpack('17s', block[335:352])[0]).strip(' \t\r\n\0')
	cwc4 = str(struct.unpack('17s', block[352:369])[0]).strip(' \t\r\n\0')
	cwc5 = str(struct.unpack('17s', block[369:386])[0]).strip(' \t\r\n\0')
	vdn2 = str(struct.unpack('16s', block[386:402])[0]).strip(' \t\r\n\0')
	#print str(vdn2[0]).strip(' \t\r\n\0')
	vdn3 = str(struct.unpack('16s', block[402:418])[0]).strip(' \t\r\n\0')
	#print str(vdn3[0]).strip(' \t\r\n\0')
	vdn4 = str(struct.unpack('16s', block[418:434])[0]).strip(' \t\r\n\0')
	#print str(vdn4[0]).strip(' \t\r\n\0')
	vdn5 = str(struct.unpack('16s', block[434:450])[0]).strip(' \t\r\n\0')
	#print str(vdn5[0]).strip(' \t\r\n\0')
	vdn6 = str(struct.unpack('16s', block[450:466])[0]).strip(' \t\r\n\0')
	#print str(vdn6[0]).strip(' \t\r\n\0')
	vdn7 = str(struct.unpack('16s', block[466:482])[0]).strip(' \t\r\n\0')
	#print str(vdn7[0]).strip(' \t\r\n\0')
	vdn8 = str(struct.unpack('16s', block[482:498])[0]).strip(' \t\r\n\0')
	#print str(vdn8[0]).strip(' \t\r\n\0')
	vdn9 = str(struct.unpack('16s', block[498:514])[0]).strip(' \t\r\n\0')
	#print vdn9
	asai_uui = struct.unpack('<B', block[514])
	interruptdel = struct.unpack('<B', block[515])
	#print interruptdel
	agentsurplus = struct.unpack('<B', block[516])
	#print agentsurplus
	agentskilllevel = struct.unpack('<B', block[517])
	#print agentskilllevel
	prefskilllevel = struct.unpack('<B', block[518])
	#print prefskilllevel
	icrresent = struct.unpack('<B', block[519])
	#print icrresent
	icrpullreason = struct.unpack('<B', block[520])
	#print icrpullreason

	call_bits = block[84]
	call_bits = ord(call_bits)
	call_bits = bin(call_bits)[2:].zfill(8)
	# print call_bits
	assist = call_bits[7]
	audio = call_bits[6]
	conference = call_bits[5]
	da_queued = call_bits[4]
	holdabn = call_bits[3]
	malicious = call_bits[2]
	observingcall = call_bits[1]
	transferred = call_bits[0]
	record.append(callid[0])
	record.append(acwtime[0])
	record.append(ansholdtime[0])
	record.append(consulttime[0])
	record.append(disptime[0])
	record.append(duration[0])
	record.append(f_segstart)
	record.append(f_segstart_utc)
	record.append(f_segstop)
	record.append(f_segstop_utc)
	record.append(talktime[0])
	record.append(netintime[0])
	record.append(origholdtime[0])
	record.append(queuetime[0])
	record.append(ringtime[0])
	record.append(dispivector[0])
	record.append(dispsplit[0])
	record.append(firstvector[0])
	record.append(split1[0])
	record.append(split2[0])
	record.append(split3[0])
	record.append(tkgrp[0])
	record.append(eq_locid[0])
	record.append(orig_locid[0])
	record.append(ans_locid[0])
	record.append(obs_locid[0])
	record.append(uui_len[0])
	record.append(assist)
	record.append(audio)
	record.append(conference)
	record.append(da_queued)
	record.append(holdabn)
	record.append(malicious)
	record.append(observingcall)
	record.append(transferred)
	record.append(agentreleased[0])
	record.append(acd[0])
	record.append(call_disp[0])
	record.append(disppriority[0])
	record.append(held[0])
	record.append(segment[0])
	record.append(ansreason[0])
	record.append(origreason[0])
	record.append(dispsklevel[0])
	record.append(event1[0])
	record.append(event2[0])
	record.append(event3[0])
	record.append(event4[0])
	record.append(event5[0])
	record.append(event6[0])
	record.append(event7[0])
	record.append(event8[0])
	record.append(event9[0])
	record.append(ucid)
	record.append(dispvdn)
	record.append(eqloc)
	record.append(firstvdn)
	record.append(origlogin)
	record.append(anslogin)
	record.append(lastobserver)
	record.append(dialed_num)
	record.append(calling_pty)
	record.append(lastdigits)
	record.append(lastcwc)
	record.append(calling_II)
	record.append(cwc1)
	record.append(cwc2)
	record.append(cwc3)
	record.append(cwc4)
	record.append(cwc5)
	record.append(vdn2)
	record.append(vdn3)
	record.append(vdn4)
	record.append(vdn5)
	record.append(vdn6)
	record.append(vdn7)
	record.append(vdn8)
	record.append(vdn9)
	record.append(asai_uui[0])
	record.append(interruptdel[0])
	record.append(agentsurplus[0])
	record.append(agentskilllevel[0])
	record.append(prefskilllevel[0])
	record.append(icrresent[0])
	record.append(icrpullreason[0])
	record.append(header_seq[0])


	filedata.append(record)
	currentbyte = echdata.tell()
	if currentbyte == totalsize :
		break

	# print str(ucid[0]).rstrip(' \t\r\n\0')
	blockstart = echdata.tell()

output = open (chrcsv, "w")
for recordrow in filedata :
	output.write( '%s\n' % ','.join(map(str, recordrow)))
	# print ('%s\n' % ','.join(map(str, record)) )
	# print record

echdata.close()
output.close()
print
print "CSV file created for: " + chrfile
print;

	# block = block + 505
# return self.get_bin(chars).decode('ASCII')