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
from snmp_helper import snmp_get_oid, snmp_extract

ipath = "/opt/raps"

def main(argv):
    global ipath

    parser = argparse.ArgumentParser(usage='Find rogue Access Points within scanning range')
    #parser.add_argument('-i', '--install', action='store_true', help='Install RAPS')
    parser.add_argument('-a', '--auto', action='store_true', help='Run in auto mode (assumes --fightback)',)
    parser.add_argument('-f', '--fightback', action='store_true', help='Fights back against Rogue AP with Reaver and Honey Pot')
    parser.add_argument('-s', '--snmp', action='store_true', help='For SNMP-only testing before integration into --auto')
    parser.add_argument('-i', '--interface', help='Interface to scan on')
    parser.add_argument('-si', '--switchip', help='IP Address of core switch(es) or file containing IP addresses')
    parser.add_argument('-sc', '--snmpCommunity', help='SNMP Community of switches to be polled')
    parser.add_argument('-sp', '--snmpPort', help='Port that SNMP operates on')

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
                    snmpAsk(args.switchIP, args.snmpCommunity, args.snmpPort) #find out if the rogue is on the LAN
            if apFound == 0:
                ap = {"BSSID":bssid, "SSID":ssid, "CHANNEL":channel, "SEEN":utc}
                collu.insert(ap)
                print "BSSID: " + bssid + " with SSID: " + ssid + " added to Unkown AP DB."
        else: #in case there's nothing in the db
            print "There is nothing in the known database, please run RAPS with the install flag set."
            sys.exit()


        # print "collk has %s records." % collk.count()
        # print "collu has %s records." % collu.count()
        # print "collr has %s records." % collr.count()
        for a in collk.find(): #loops over the collection and prints each document
            print a
        #print collk.find_one()

        scanint = args.interface #eventually make this a cmd flag
        aircom = "airodump-ng --output-format csv --write %s/rapsdump %s" % (ipath, scanint + 'mon')
        fo = open("/proc/net/dev", 'rb')
        if fo.read().find("mon0") == -1:
            call(['airmon-ng', 'start', scanint]) #add logic to determine which interface to put in mon
            time.sleep(10)
        p = Popen([aircom], stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
        time.sleep(10)
        os.kill(p.pid, SIGTERM)
        call(['airmon-ng', 'stop', 'mon0'])

    if args.snmp:
        snmpAsk(args.switchIP, args.snmpCommunity, args.snmpPort)

def readdump(): #TODO: actually start this...
    global ipath
    fpath = "%s/rapsdump-01.csv" % ipath

    while True: #maybe add thread.stopped check here
        of = open(ipath, 'rb')
        print of.read()
        of.close()
        time.sleep(2) #wait for 2 seconds because reasons
        #add a check here for thread.stopped
        #so that the thread can terminate

def snmpAsk(sIP, sComm, sPort):
    oid = '1.3.6.1.2.1.17.4.3.1.1' #gets all unicast address on the LAN (from Mib)
    device = (sIP, sComm, sPort)
    data = snmp_get_oid(device, oid=oid, display_errors=False)
    output = snmp_extract(data)
    print output #output should be raw output of MIB
    print type(output) #need to find out how to process this i. e. can i use for loop or no?

if __name__ == "__main__":
    main(sys.argv)
