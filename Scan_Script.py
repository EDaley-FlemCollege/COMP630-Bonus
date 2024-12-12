#!/usr/bin/env python

from threading import Thread
import time,sys,subprocess,os
from scapy.all import Dot11, Dot11Deauth, Dot11Disas, RadioTap, Dot11Elt, sendp, sniff, conf, EAPOL, Dot11EltRSN

hmac = '5A:6D:67:AC:90:90'
COUNT = 0

if len(sys.argv) > 2:
	hmac = sys.argv[2]
if len(sys.argv) < 2:
	chan = input('Enter Channel: ')
else :
	chan=sys.argv[1]

subprocess.run("sudo airmon-ng check kill > /dev/null", shell=True, executable="/bin/bash")
subprocess.run("sudo airmon-ng start wlan0 > /dev/null", shell=True, executable="/bin/bash")
change_channel="sudo iwconfig wlan0 channel "+chan
subprocess.run(change_channel, shell=True, executable="/bin/bash")

def Process_Frame(packet):
	if packet.type == 0:
		null = 0

def counter():
	global COUNT
	while True:
		time.sleep(1)
		COUNT += 1
		subprocess.run("clear", shell=True, executable="/bin/bash")
		print(f"Count: {COUNT}")

counter_thread = Thread(target=counter)
counter_thread.daemon = True
counter_thread.start()

sniff(iface='wlan0',prn=Process_Frame,lfilter=lambda pkt: pkt.haslayer(Dot11), store=0)
