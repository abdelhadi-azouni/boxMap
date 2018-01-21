#!usr/bin/env python

import os, sys
import socket
import subprocess


def main(arg):

    plnodes=open(arg[1], "r")

    # open all servers


    for node in plnodes.readlines():
        print node
        print '\n\n\n'
        try:
            print "sending files to "+node.strip()
            subprocess.Popen("sudo ./send_test_files_to_VP.sh "+node.strip(), shell=True)
            print 'next'

        except Exception as e:
            print'fuck it '+e.message


    print 'done! \n'




if __name__ == "__main__":
    main(sys.argv)