#!/usr/bin/python

"""
RAPS - Rogue AP Scanner(Suite)

author: bi0dr0ned at gmail

General TODO:

- Use threading for things because parallelisation
- Implement attack methods once an AP is found
    - Reaver
    - Honeypot
- Use curses or some form of GUI to display log file to terminal
- Add an install option
- Have a DB of known default SSIDs for quick detection
- Fix mongo DBs because currently everything is going towards the known APs DB,
    need to go to unknown if not in known as known will be preconfigured (or possibly set up on first run?)
- Have a point that the user can see the contents of the unknown DB and pick whether to add to known or rogue

"""

import os
from os import walk
import subprocess
import threading
import sys
import time
import argparse
import socket
from subprocess import Popen, PIPE, call
from signal import SIGINT, SIGTERM
import pymongo
import datetime
import csv

ipath = "/opt/raps"

def main(argv):
    global ipath

    parser = argparse.ArgumentParser(usage='Find rogue Access Points within scanning range')
    parser.add_argument('-t', '--temp', action='store_true', help='Real basic temp stuffs')
    parser.add_argument('-a', '--auto', action='store_true', help='Run in auto mode (assumes --fightback)',)
    parser.add_argument('-f', '--fightback', action='store_true', help='Fights back against Rogue AP with Reaver and Honey Pot')
    parser.add_argument('-s', '--snmp', action='store_true', help='For SNMP-only testing before integration into --auto')
    parser.add_argument('-i', '--interface', help='Interface to scan on')
    # parser.add_argument('-si', '--switchIP', help='IP Address of core switch(es) or file containing IP addresses')
    # parser.add_argument('-sc', '--snmpCommunity', help='SNMP Community of switches to be polled')
    # parser.add_argument('-sp', '--snmpPort', help='Port that SNMP operates on')

    #TODO: add arg for db location (or have a default location of /opt/raps)
    #TODO: have a flag to init the mongodb with a file or a list of MACs
    args = parser.parse_args()

    # if args.install: #TODO: eventually make this a function triggered if the dir doesn't exist each run
    #     print 'Installing...'
    #     ud = Popen(["apt-get update"])
    #     ins = Popen(["apt-get install aircrack-ng scapy build-essential python-dev -y"])
    #     #TODO: do pip install stuff here
    #     #TODO: add logic to figure out if RAPS is already installed
    #     call(["mkdir", "/opt/raps"])
    #     call(['chmod', '775', "/opt/raps"])
    #     #connect to MongoDB
    #     try:
    #         conn=pymongo.MongoClient()
    #         print "Connected successfully!!!"
    #     except pymongo.errors.ConnectionFailure, e:
    #         print "Could not connect to MongoDB: %s" % e
    #
    #     db = conn.aps
    #     collk = db.known_aps
    #     collu = db.unknown_apps
    #     ap = {"SSID":"kawaii-fi", "BSSID":"DE:AD:BE:EF:CO:FE"}
    #     g = Popen(["git clone https://github.com/biodrone/FYP /opt/RAPS/"]) #change this after project

    if args.auto: #TODO: Spawn a thread based on this
        print 'Running RAPS in auto mode'
        try:
            conn=pymongo.MongoClient()
            print "Connected successfully!!!"
        except pymongo.errors.ConnectionFailure, e:
            print "Could not connect to MongoDB: %s" % e
            sys.exit()

        #TODO: do some logic here to determine if a db exists already
        db = conn.aps
        collk = db.known_aps
        collu = db.unknown_aps
        collr = db.rogue_aps
        #collk.remove({}) #remove all documents from collection
        #collu.remove({})
        utc = datetime.datetime.utcnow()
        ssid = "kawaii-fi"
        bssid = "DE:AD:BE:EF:CO:FF"
        channel = "1"
        #ap2 = {"BSSID":"DE:AD:BE:EF:CO:FF", "SSID":ssid + "bawlz", "CHANNEL":channel, "SEEN":utc}
        apFound = 0 #var to control whether the AP was found in the database
        #TODO: search db for BSSID in case it's already there
        if collk.count({'SSID':ssid}) > 0: #check if there's actually any APs in the db
            for a in collk.find({'SSID':ssid}, {'SSID':1, 'BSSID':1, '_id':0}): #check for matches with SSID
                if str(a[u'BSSID']) == bssid: #check for matches with BSSID
                    print "Expected AP %s as all elements match." % str(a[u'SSID'])
                    apFound = 1 #have this become a breakout from the loop eventually
                else: #if BSSID doesn't match
                    apFound = 1
                    ap = {"BSSID":bssid, "SSID":ssid, "CHANNEL":channel, "SEEN":utc}
                    collr.insert(ap)
                    print "BSSID: " + bssid + " with SSID: " + ssid + " added to Rogue AP DB."
                    snmpAsk() #find out if the rogue is on the LAN
            if apFound == 0:
                ap = {"BSSID":bssid, "SSID":ssid, "CHANNEL":channel, "SEEN":utc}
                collu.insert(ap)
                print "BSSID: " + bssid + " with SSID: " + ssid + " added to Unkown AP DB."
        else: #in case there's nothing in the db
            print "There is nothing in the known database, please run RAPS with the install flag set."
            sys.exit()

    if args.snmp:
        snmpAsk()

    if args.temp:
        #scanner()
        readDump()

def scanner(scanint):
    global ipath

    tmp0 = open("/opt/raps/tmp.txt", 'w')
    Popen('ifconfig', stdin=PIPE, stdout=tmp0, stderr=PIPE, shell=True)
    tmp0.close() #maybe try doing this in the same file...?
    tmp1 = open("/opt/raps/tmp.txt", 'r')
    if tmp1.read().find("mon") == -1:
        call(['airmon-ng', 'start', scanint]) #add logic to determine which interface to put in mon
        time.sleep(10)
    tmp1.close()
    monint = 'mon0'
    aircom = "airodump-ng --output-format csv --write %s/rapsdump %s" % (ipath, monint)
    p = Popen([aircom], stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
    time.sleep(10)
    os.kill(p.pid, SIGTERM)
    call(['airmon-ng', 'stop', monint]) #make more intelligent for different OSes?

def readDump():
    global ipath
    f = []
    for (dirpath, dirnames, filenames) in walk(ipath):
        f.extend(filenames)
        break
    print f
    fpath = "%s/rapsdump-01.csv" % ipath

    with open(fpath, 'rb') as f1:
        r = csv.reader(f1, delimiter='\n')
        l1 = list(r)

    for x in l1:
		print x

def snmpAsk():
    mArr = [] #array to hold MAC addresses from the MIB
    f1 = open("/opt/raps/mib.txt", 'w')
    Popen('snmpwalk -v 2c -c fyp 192.168.1.4 1.3.6.1.2.1.17.4.3.1.1', stdin=PIPE, stdout=f1, stderr=PIPE, shell=True)
    time.sleep(5)
    f1.close() #maybe try doing this in the same file...?

def snmpRead():
    f2 = open("/opt/raps/mib.txt", 'r')
    for line in f2:
        line = line.split(': ')
        line = line[1]
        mArr.append(line[0:17])
    f2.close()

def mongoTests():
    print "collk has %s records." % collk.count()
    print "collu has %s records." % collu.count()
    print "collr has %s records." % collr.count()
    for a in collk.find(): #loops over the collection and prints each document
        print a
    print collk.find_one()

if __name__ == "__main__":
    main(sys.argv)
