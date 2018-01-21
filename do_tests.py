#!usr/bin/env python

import os, sys
import socket
import subprocess


def main(arg):

    plnodes=open(arg[1], "r")

    # open all servers
    server_command="\'sudo python boxMap.py 0\'"

    """
    for node in plnodes.readlines():
        print node
        print '\n\n\n'
        try:
            print "sudo /usr/bin/ssh -oBatchMode=yes -l uwaterloo_boxMap -i ~/id_rsa "+node.strip()+" "+server_command
            subprocess.Popen("sudo /usr/bin/ssh -oBatchMode=yes -l uwaterloo_boxMap -i ~/id_rsa "+node.strip()+" "+server_command, shell=True)
            print 'next'

        except Exception as e:
            print'fuck it '+e.message


    print 'done! \n'
    """


    # probe all servers from plink


    #"""
    for node in plnodes.readlines():

        print '\n\n\n'
        try:
            server_ip = socket.gethostbyname(node.strip())




            client_command="sudo python boxMap.py "+server_ip
            try:
                ssh_command="sudo ssh -oBatchMode=yes -l uwaterloo_boxMap -i ~/id_rsa plink.cs.uwaterloo.ca "+client_command
                print "sudo python boxMap.py "+server_ip
                os.system("sudo python boxMap.py "+server_ip)
                #subprocess.Popen(client_command, shell=True)
                print 'next'

            except Exception, e:
                print'fuck it'+e.message

        except Exception, e:
            print'Somethin went wrong ' + e.message

    print 'done! \n'
    #"""



if __name__ == "__main__":
    main(sys.argv)