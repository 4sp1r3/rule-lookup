from argparse import ArgumentParser
import getpass
import paramiko
import requests
import re
import sys


class RuleLookup(object):
    def __init__(self):
        self.allrules_url = None
        self.sensorhostname = ""
        self.rulesdirectory = ""
        self.allrules_location = ""
        self.allrules = True
        self.flowbits = []
        self.credentials = None


    def command(self, command):
        if not self.credentials:
            self.username = raw_input("Username: ")
            self.password = getpass.getpass()
            self.credentials = True

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
                    self.sensorhostname,
                    username=self.username,
                    password=self.password
                   )
        stdin, stdout, stderr = ssh.exec_command(command)
        
        return stdout.read()


    def rulelookup_html(self, sid):
        self.sid = sid
        req = requests.get(self.allrules_url)

        for line in req.content.splitlines():
            if self.sid in line:
                self.rule = line

        if "flowbits:isset" in self.rule:
            reg = re.search("flowbits:isset,([a-zA-Z0-9\.]+)", self.rule)
            flowbitgroup = reg.group(1)

        for line in req.content.splitlines():
            if "flowbits:set,{};".format(flowbitgroup) in line:
                self.flowbits.append(line)


    def rulelookup_ssh_password(self, sid):

        if self.allrules:
            foundrule = self.command("grep {} {}".format(sid, self.allrules_location))
            
            if foundrule:
                pass
            else:
                print "[-] sid not found"

            if foundrule and ("flowbits:isset" in foundrule):
                reg = re.search("flowbits:isset,([a-zA-Z0-9\.]+)", foundrule)
                flowbitgroup = reg.group(1)
                foundbits = self.command("grep \"flowbits:set,{};\" {}".format(flowbitgroup, self.allrules_location))
                print "\n==============\nsid {}\n==============\n\n{}".format(sid, foundrule)
                print "==============\nFlowbits\n==============\n\n{}".format(foundbits)


p = ArgumentParser()
p.add_argument("-w", "--web", help="Get rule from an HTML page", action="store_true")
p.add_argument("-p", "--password", help="SSH and password authentication", action="store_true")
p.add_argument("-c", "--certificate", help="SSH and certificate authentication", action="store_true")
p.add_argument("sid", help="Rule sid")
args = p.parse_args()

if args.password:
    r = RuleLookup()
    r.rulelookup_ssh_password(args.sid)