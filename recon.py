#!/usr/bin/python3
#
# Vulnerabilty Scanner using NMAP and the Vulscan file suite to assess current Network security footprint.
# Download http://www.computec.ch/projekte/vulscan/?s=download and place vulscan directory files in the /usr/share/nmap/scripts location
# Below are the locations of the vulnerability scanning scripts that we will use.
#
# https://github.com/scipag/vulscan scipag_vulscan
# https://github.com/vulnersCom/nmap-vulners.git
#

import subprocess
import sys
import datetime
import time
import os
from _ast import List

working_dir = os.path.expanduser('~/vulscanner/')
if not os.path.exists(working_dir):
    os.makedirs(working_dir)

# Let's clear the screen before running the script
# by using this subprocess. We will call it later
# If running this on a Unix system, clear will be called
# If running this on a Windows system, cls will be called
#
from subprocess import call
from time import sleep
def screen_clear():
   _ = call('clear' if os.name =='posix' else 'cls')

subnet_list = working_dir + 'subnet_list.txt'
vulscan_results = working_dir + 'vulscan_results_'

# If the file subnet_list does not exist in the working_dir location, the user will be prompted
# to create one before the script will run. The file will need to be located in the path
# working_dir
#
if not os.path.isfile(subnet_list):
    print ("Please create subnet list called subnet_list.txt with one subnet/host per line in: " + working_dir)
    exit()

# If the file vulscan.nse does not exist in the working_dir location, the user will be prompted
# to create one before the script will run. The file will need to be located in the path
# /usr/share/nmap/scripts/vulscan/
#
if not os.path.isfile("/usr/share/nmap/scripts/vulscan/vulscan.nse"):
    print ("Please be sure nmap is installed and you have the vulscan files in /usr/share/nmap/scripts/vulscan dir")
    exit()

# Make a choice using the menu structure and place code under each choice
#
loop = 1
while loop == 1:

    # Make sure that they proper files and folders exists
    #
    dns_results = working_dir + 'dns_results_'
    rev_results = working_dir + 'rev_results_'
    scan_results = working_dir + 'scan_results_'

    # now call the clear screen function we defined above
    screen_clear()

    print("##################################################")
    print("#                                                #")
    print("#  ####      #####    ####      ####      ####   #")
    print("#  #   #    #        #    #    #    #    #    #  #")
    print("#  #   #    #        #         #    #    #    #  #")
    print("#  ####      ####    #         #    #    #    #  #")
    print("#  #   #    #        #         #    #    #    #  #")
    print("#  #    #   #        #    #    #    #    #    #  #")
    print("#  #    #    #####    ####      ####     #    #  #")
    print("#                                                #")
    print("##################################################")
    print()

    # Display simple menu with scanning options and use choice to select option
    #
    print("Welcome to Recon")
    print("Your All In One Vulnerability Scanning and Testing Script")
    print()
    print("1) DNS Lookup of Hostname")
    print("2) Reverse DNS Lookup of Hostname")
    print("3) Network Port Scan")
    print("4) Search IP Services and Versions")
    print("5) Service Vulnerability Scan")
    print("6) Wordpress Vulnerability Scan")
    print("7) List Host Based Firewall and Port Status ")
    print("8) Exit")
    print()

    # Define a function to open file and read in subnets file producing a space delimited list.
    # Format: One host or subnet per line.
    #
    choice = input("Choose An Option: ")
    choice = int(choice)

    # This function will issue a DNS Lookup for a given Hostname
    # THe user will enter a hostname when prompted.
    #
    if choice == 1:
        print("DNS Lookup of Hostname")
        hostname = input("Type the Hostname of Lookup: ")
        hostname = str(hostname)
        print("Scanning for DNS Results: " + hostname)
        ts = time.time()
        fn_timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d_%H%M%S')
        dns_results += fn_timestamp

        with open(dns_results, 'w') as outfile:
            subprocess.call(['dig', 'ANY', hostname], stdout=outfile)
        print("DNS Lookup complete, check results file: " + dns_results)
        outfile.close()
        print()

    # This function will issue a DNS reverser lookup for a given IP Address
    # The user will enter an IP address when prompted
    # I need to clean up the results for this one as it shows all data that
    # has been pulled from the dig command
    #
    elif choice == 2:
        print("Reverse DNS Lookup of Hostname")
        ip_addr = input("Type the IP Address of Lookup: ")
        ip_addr = str(ip_addr)
        print("Scanning for Reverse DNS Results: " + ip_addr)
        ts = time.time()
        fn_timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d_%H%M%S')
        rev_results += fn_timestamp

        with open(rev_results, 'w') as outfile:
            subprocess.call(['dig', '-x', ip_addr], stdout=outfile)
        print("Reverse Lookup Complete, check results file: " + rev_results)
        outfile.close()
        print()

    elif choice == 3:
        print("Network Port Scan")
        ip = input("Type the IP Address of Host to Scan: ")
        ip = str(ip)
        print("Scanning for Open Ports for IP Address: " + ip)
        ts = time.time()
        fn_timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d_%H%M%S')
        scan_results += fn_timestamp

        with open(scan_results, 'w') as outfile:
            subprocess.call(['nmap', '-sT', '-p', ip] + List(subnet_list), stdout=outfile)
        print("Scan complete, check results file: " + scan_results)
        outfile.close()
        print()

    elif choice == 4:
        print("Multiple subnet/hosts port scan in progress...")

        ts = time.time()
        fn_timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d_%H%M%S')
        scan_results += fn_timestamp

        with open(scan_results, 'w') as outfile:
            subprocess.call(['nmap', '-sT', '-iL', subnet_list], stdout=outfile)
        print("Scan Complete, check results file: " + scan_results)
        outfile.close()

    elif choice == 5:
        print("Multiple subnet vulnerability scan in progress...")
        print()

        ts = time.time()
        fn_timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d_%H%M%S')
        vulscan_results += fn_timestamp

        with open(vulscan_results, 'w') as outfile:
            subprocess.call(['nmap', '-sV', '-script=vulscan/vulscan.nse', '-iL', subnet_list], stdout=outfile)
        print("Scan Complete, check results file: " + vulscan_results)
        outfile.close()

    # Exit the script when the use hits the correct key
    #
    elif choice == 8:
        loop = 0

    else:
        print("Please enter a choice from the menu: ")
