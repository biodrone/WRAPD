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
    x = 0

    parser = argparse.ArgumentParser(usage='Find Rogue Access Points within scanning range')
    parser.add_argument('-t', '--temp', action='store_true', help='Real basic temp stuffs')
    parser.add_argument('-a', '--auto', action='store_true', help='Run in Auto Mode',) #maybe make this the default without flags?
    parser.add_argument('-c', '--clean', dest='cleandb', help='Clean Databases, Accepts k/r/u')
    parser.add_argument('-u', '--unknown', action='store_true', help='View the Unknown database',)
    parser.add_argument('-i', '--interface', help='Interface to Scan on')
    # parser.add_argument('-si', '--switchIP', help='IP Address of core switch(es) or file containing IP addresses')
    # parser.add_argument('-sc', '--snmpCommunity', help='SNMP Community of switches to be polled')
    # parser.add_argument('-sp', '--snmpPort', help='Port that SNMP operates on')

    #TODO: add arg for db location (or have a default location of /opt/raps)
    args = parser.parse_args()

    try:
        conn=pymongo.MongoClient()
        print "Connected successfully!!!"
    except pymongo.errors.ConnectionFailure, e:
        print "Could not connect to MongoDB: %s" % e
        sys.exit()

    #TODO: do some logic here to determine if a db exists already
    #define mongo DBs
    db = conn.aps
    collk = db.known_aps
    collu = db.unknown_aps
    collr = db.rogue_aps

    if args.unknown:
        if collu.count({}) > 0: #check if there's actually any APs in the db
            print "The Unknown Database has %s Records" % collu.count()
            if raw_input("Do you want to organise the Unkown DB into Known and Rogue? [y/N]").find("y") != -1:
                for u in collu.find({}, {'SSID':1, 'BSSID':1, 'LANMAC':1, '_id':0}): #might need to delete the first bracket entirely
                    print u
                    ap = {"SSID":str(u[u'SSID']), "BSSID":str(u[u'BSSID']), "LANMAC":str(u[u'LANMAC'])}
                    print ap
                    if raw_input("Which Database Would You Like to Add This to? [k/R]") == "k":
                        collk.insert(ap)
                    else:
                        collr.insert(ap)
                    collu.remove({"SSID":str(u[u'SSID']), "BSSID":str(u[u'BSSID']), "LANMAC":str(u[u'LANMAC'])})
            else:
                for u in collu.find():
                    print u
        else:
            print "The Unknown Database is Empty."

    if args.cleandb:
        #print "Cleaning %s Database(s)" % args.cleandb
        if args.cleandb.find('k') != -1:
            print "Cleaning Known DB"
            collk.remove({})
        if args.cleandb.find('r') != -1:
            print "Cleaning Rogue DB"
            collr.remove({})
        if args.cleandb.find('u') != -1:
            print "Cleaning Unknown DB"
            collu.remove({})

    if args.temp:
        for k in collk.find({}, {'SSID':1, 'BSSID':1, 'LANMAC':1, '_id':0}): #might need to delete the first bracket entirely
            print k
        for u in collu.find({}, {'SSID':1, 'BSSID':1, 'LANMAC':1, '_id':0}): #might need to delete the first bracket entirely
            print u
        for r in collr.find({}, {'SSID':1, 'BSSID':1, 'LANMAC':1, '_id':0}): #might need to delete the first bracket entirely
            print r
        #print findLanMac("C4:E9:84:F8:28:73")

    if args.auto: #TODO: Spawn a thread based on this
        print 'Running RAPS in auto mode'

        scanWifi(args.interface)
        macs, ssids = readDump()
        #mongoTests(db, collk, collu, collr)

        for m in macs:
            doTheMongo(db, collk, collu, collr, ssids[x], macs[x])
            x = x + 1

def mongoInit(db, collk, collu, collr, ssid, bssid, lanmac):
    ap = {"SSID":ssid, "BSSID":bssid, "LANMAC":lanmac}
    collk.insert(ap)
    for k in collk.find({}, {'SSID':1, 'BSSID':1, 'LANMAC':1, '_id':0}): #might need to delete the first bracket entirely
        print k
    collu.insert(ap)
    for u in collu.find({}, {'SSID':1, 'BSSID':1, 'LANMAC':1, '_id':0}): #might need to delete the first bracket entirely
        print u
    collr.insert(ap)
    for r in collr.find({}, {'SSID':1, 'BSSID':1, 'LANMAC':1, '_id':0}): #might need to delete the first bracket entirely
        print r

def scanWifi(scanint):
    global ipath

    #put ifconfig stats into a temp file to find monitor interfaces
    tmp0 = open("/opt/raps/tmp.txt", 'w')
    Popen('ifconfig', stdin=PIPE, stdout=tmp0, stderr=PIPE, shell=True)
    tmp0.close() #maybe try doing this in the same file...?
    #read the temp file to see if monitor mode int exists
    tmp1 = open("/opt/raps/tmp.txt", 'r')
    if tmp1.read().find("mon") == -1:
        call(['airmon-ng', 'start', scanint])
        time.sleep(10)
    tmp1.close()
    monint = 'mon0' #TODO: Grab this from ifconfig file
    aircom = "airodump-ng --output-format csv --write %s/rapsdump %s" % (ipath, monint)
    p = Popen([aircom], stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
    time.sleep(10)
    os.kill(p.pid, SIGTERM)
    call(['airmon-ng', 'stop', monint]) #TODO: make more intelligent for different OSes?

def readDump(): #parse the wifi dump .csv for MACs and SSIDs
    global ipath
    f = []
    macs = []
    ssids = []

    #TODO: use this to get the latest file
    #get files in dir (for when there's multiple files)
    for (dirpath, dirnames, filenames) in walk(ipath):
        f.extend(filenames)
        break
    #print f
    fpath = "%s/rapsdump-01.csv" % ipath

    #parse .csv into a list for detail grabbing
    with open(fpath, 'rb') as f1:
        r = csv.reader(f1, delimiter='\n')
        l1 = list(r)

    for x in l1:
        if str(x).find("Station MAC") != -1: #filter out station macs
            break
        if str.find(str(x), ":") != -1: #only get macs in final list
            macs.append(str.strip(str.split(str(x), ',')[0], "[ '")) #split to only get MAC and then remove first 2 chars ([')
            ssids.append(str.strip(str.split(str(x), ',')[13])) #split to only get SSID and then remove whitespace
    #return the 2 lists
    return macs, ssids

def doTheMongo(db, collk, collu, collr, ssid, bssid):
    """
    Return codes:
        -1 - Not on LAN
        -2 - Multiple matching MACs on LAN
         1 - Matched Known AP
         2 - Matched Rogue AP
         3 - Added AP to Unkown DB
    """
    #if lanman doesn't find anything, automatically add the AP to collu as it's not on the LAN
    lanmac = findLanMac(bssid)
    if lanmac == 0:
        print "AP with SSID %s, BSSID %s is not on the LAN." % (ssid, bssid)
        ap = {"SSID":ssid, "BSSID":bssid, "LANMAC":lanmac}
        collu.insert(ap)
        return -1
    elif lanmac == 1:
        #multiple MACs found, do something with this later
        print "Multiple MACs found, please search for the device manually!"
        return -2

    if collk.count({}) > 0: #check if there's actually any APs in the db
        for k in collk.find({'SSID':ssid}, {'SSID':1, 'BSSID':1, 'LANMAC':1, '_id':0}):
            if str(k[u'SSID']) == ssid: #check ssid match
                if str(k[u'BSSID']) == bssid:
                    if str(k[u'LANMAC']) == lanmac:
                        #if a RAP has all these, there would be switching errors
                        #which will be more obvious to network managers
                        print "Expected SSID %s, all elements match." % ssid
                        return 1
                    else:
                        print "Did you forget to add an AP to the known database?:\n%s, %s, %s\nChecking Rogue for Safety." % (ssid, bssid, lanmac)
                        if checkRogue(db, collk, collu, collr, ssid, bssid, lanmac) != 1:
                            print "Not in Rogue DB, checking Unknown DB."
                            #launch unknown func here
                            return 3
                        else:
                            print "AP already in Rogue DB, please find and eliminate the following:\n%s, %s, %s." % (ssid, bssid, lanmac)
                            return 2
                else:
                    if str(k[u'LANMAC']) == lanmac:
                        #print "Adding to Rogue DB:\n%s, %s, %s\nRAP Match on SSID and LANMAC." % ssid, bssid, lanmac
                        #ap = {"SSID":ssid, "BSSID":bssid, "LANMAC":lanmac}
                        #collr.insert(ap)
                        print "Did you forget to add an AP to the known database?:\n%s, %s, %s\nChecking Rogue for Safety." % (ssid, bssid, lanmac)
                        if checkRogue(db, collk, collu, collr, ssid, bssid, lanmac) != 1:
                            print "Not in Rogue DB, checking Unknown DB."
                            if checkUnknown(db, collk, collu, collr, ssid, bssid, lanmac) != 1:
                                print "Not in Unknown DB, Adding %s, %s, %s." % (ssid, bssid, lanmac)
                                ap = {"SSID":ssid, "BSSID":bssid, "LANMAC":lanmac}
                                collu.insert(ap)
                            else:
                                print "Already in Unknown DB, please launch with -u flag to review."
                            return 3
                        else:
                            print "AP already in Rogue DB, please find and eliminate the following:\n%s, %s, %s." % (ssid, bssid, lanmac)
                            return 2
                    else:
                        print "Only matched on SSID %s, checking against the Rogue DB." % ssid
                        if checkRogue(db, collk, collu, collr, ssid, bssid, lanmac) != 1:
                            print "Not in Rogue DB, checking Unknown DB."
                            if checkUnknown(db, collk, collu, collr, ssid, bssid, lanmac) != 1:
                                print "Not in Unknown DB, Adding %s, %s, %s." % (ssid, bssid, lanmac)
                                ap = {"SSID":ssid, "BSSID":bssid, "LANMAC":lanmac}
                                collu.insert(ap)
                            else:
                                print "Already in Unknown DB, please launch with -u flag to review."
                            return 3
                        else:
                            print "AP already in Rogue DB, please find and eliminate the following:\n%s, %s, %s." % (ssid, bssid, lanmac)
                            return 2
            else:
                print "No SSID match on %s, checking Rogue DB." % ssid
                if checkRogue(db, collk, collu, collr, ssid, bssid, lanmac) != 1:
                    print "Not in Rogue DB, checking Unknown DB."
                    if checkUnknown(db, collk, collu, collr, ssid, bssid, lanmac) != 1:
                        print "Not in Unknown DB, Adding %s, %s, %s." % (ssid, bssid, lanmac)
                        ap = {"SSID":ssid, "BSSID":bssid, "LANMAC":lanmac}
                        collu.insert(ap)
                    else:
                        print "Already in Unknown DB, please launch with -u flag to review."
                    return 3
                else:
                    print "AP already in Rogue DB, please find and eliminate the following:\n%s, %s, %s." % (ssid, bssid, lanmac)
                    return 2

    else: #in case there's nothing in the db
        print "There is nothing in the known database, running init function."
        mongoInit(db, collk, collu, collr, "Init", "DE:AD:BE:EF:CO:FE", "DE:AD:BE:EF:CO:FE")
        print "Being recursive with SSID: %s & BSSID: %s & LANMAC: %s" % (ssid, bssid, lanmac)
        doTheMongo(db, collk, collu, collr, ssid, bssid)

def checkRogue(db, collk, collu, collr, ssid, bssid, lanmac):
    for r in collr.find({'SSID':ssid}, {'SSID':1, 'BSSID':1, 'LANMAC':1, '_id':0}):
        if str(r[u'SSID']) == ssid: #check ssid match
            if str(r[u'BSSID']) == bssid:
                if str(r[u'LANMAC']) == lanmac:
                    print "Full RAP Match:\n%s, %s, %s." % (ssid, bssid, lanmac)
                    return 1
                else:
                    print "Match on Rogue DB:\n%s, %s, %s\nRAP Match on SSID and BSSID." % (ssid, bssid, lanmac)
                    return 1
            else:
                if str(r[u'LANMAC']) == lanmac:
                    print "Match on Rogue DB:\n%s, %s, %s\nRAP Match on SSID and LANMAC." % (ssid, bssid, lanmac)
                    return 1
                else:
                    print "Match on Rogue DB:\n%s, %s, %s\nRAP Match on SSID." % (ssid, bssid, lanmac)
                    return 1
        else:
            if str(r[u'BSSID']) == bssid:
                if str(r[u'LANMAC']) == lanmac:
                    print "Match on Rogue DB:\n%s, %s, %s\nRAP Match on BSSID and LANMAC." % (ssid, bssid, lanmac)
                    return 1
                else:
                    print "Match on Rogue DB:\n%s, %s, %s\nRAP Match on BSSID." % (ssid, bssid, lanmac)
                    return 1
            else:
                if str(a[u'LANMAC']) == lanmac:
                    print "Match on Rogue DB:\n%s, %s, %s\nRAP Match on LANMAC." % (ssid, bssid, lanmac)
                    return 1

def checkUnknown(db, collk, collu, collr, ssid, bssid, lanmac):
    for u in collu.find({'SSID':ssid}, {'SSID':1, 'BSSID':1, 'LANMAC':1, '_id':0}):
        if str(u[u'SSID']) == ssid: #check ssid match
            if str(u[u'BSSID']) == bssid:
                if str(u[u'LANMAC']) == lanmac:
                    print "Full Unknown Match:\n%s, %s, %s." % (ssid, bssid, lanmac)
                    return 1
                else:
                    print "Match on Unknown DB:\n%s, %s, %s\nUnknown Match on SSID and BSSID." % (ssid, bssid, lanmac)
                    return 1
            else:
                if str(u[u'LANMAC']) == lanmac:
                    print "Match on Unknown DB:\n%s, %s, %s\nUnknown Match on SSID and LANMAC." % (ssid, bssid, lanmac)
                    return 1
                else:
                    print "Match on Unknown DB:\n%s, %s, %s\nUnknown Match on SSID." % (ssid, bssid, lanmac)
                    return 1
        else:
            if str(u[u'BSSID']) == bssid:
                if str(u[u'LANMAC']) == lanmac:
                    print "Match on Unknown DB:\n%s, %s, %s\nUnknown Match on BSSID and LANMAC." % (ssid, bssid, lanmac)
                    return 1
                else:
                    print "Match on Unknown DB:\n%s, %s, %s\nUnknown Match on BSSID." % (ssid, bssid, lanmac)
                    return 1
            else:
                if str(u[u'LANMAC']) == lanmac:
                    print "Match on Unknown DB:\n%s, %s, %s\nUnknown Match on LANMAC." % (ssid, bssid, lanmac)
                    return 1

def findLanMac(bssid): #takes the bssid and finds the lan mac of the AP

#Returns:
#XX:XX:XX:XX:XX:XX - Found MAC
#0                 - Not Found
#1                 - Found Multiple MACs that match
    found = 0
    vendor = bssid[:8]
    matchMe = bssid[:-1]

    while len(matchMe) > 8:
        if matchMe[len(matchMe) - 1] == ":":
            matchMe = matchMe[:-1]

        snmpAsk() #enable this in live environment to run a fresh snmp capture
        snmp = snmpRead()
        for s in snmp:
            s = s.replace(" ", ":")
            if s.find(matchMe) != -1:
                #print "LAN MAC found! %s" % s
                found = found + 1
        if found == 1:
            return s
            break
        elif found > 1:
            print "Multiple matching MACs found, do something else with this later!"
            return 1
        matchMe = matchMe[:-1]
        #do something like check the arp on the pi here just in case the above fails
        arp = ""
        matchMe = bssid[:-1]
        while matchMe < 8:
            Popen("/usr/sbin/arp -n | grep %s | awk '{print $3}'" % matchMe, stdin=PIPE, stdout=arp, stderror=PIPE, shell=True)
            if len(arp) > 0:
                print "MAC FOUND IN ARP!!1!11!!1: \n%s" % arp
                return arp
                break
        return 0

def snmpAsk():
    f1 = open("/opt/raps/mib.txt", 'w')
    Popen('snmpwalk -v 2c -c fyp 192.168.1.4 1.3.6.1.2.1.17.4.3.1.1', stdin=PIPE, stdout=f1, stderr=PIPE, shell=True)
    time.sleep(5)
    f1.close() #maybe try doing this in the same file...?

def snmpRead():
    mArr = []
    f2 = open("/opt/raps/mib.txt", 'r')
    for line in f2:
        line = line.split(': ')
        line = line[1]
        mArr.append(line[0:17])
    f2.close()
    return mArr

def mongoTests(db, collk, collu, collr):
    print "collk has %s records." % collk.count()
    for a in collk.find(): #loops over the collection and prints each document
        print a
    print collk.find_one()
    print "collu has %s records." % collu.count()
    for a in collu.find(): #loops over the collection and prints each document
        print a
    print collu.find_one()
    print "collr has %s records." % collr.count()
    for a in collr.find(): #loops over the collection and prints each document
        print a
    print collr.find_one()
    #collk.delete_many({}) #remove all documents from collection
    #collu.delete_many({})
    #collr.delete_many({})

if __name__ == "__main__":
    main(sys.argv)
