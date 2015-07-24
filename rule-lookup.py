from argparse import ArgumentParser
import getpass
import paramiko
import requests
import re
import sys


class RuleLookup(object):
    def __init__(self):
        self.sensorhostname = ""
        self.allrules_location = ""
        self.password_protected_key = False
        self.allrules_url = None
        self.allrules = True
        self.credentials = None


    def command(self, auth_type, command):

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        

        if auth_type == "certificate":
            if not self.credentials:
                self.username = raw_input("Username: ")
                self.credentials = True

            try:
                ssh.connect(
                        self.sensorhostname,
                        username=self.username,
                           )

            except paramiko.AuthenticationException:
                sys.exit("[-] Authentication failed")

        if auth_type == "password":

            if not self.credentials:
                self.username = raw_input("Username: ")
                self.password = getpass.getpass()
                self.credentials = True

            try:
                ssh.connect(
                        self.sensorhostname,
                        allow_agent=False
                        look_for_keys=False,
                        username=self.username,
                        password=self.password,
                           )
            except paramiko.AuthenticationException:
                sys.exit("[-] Authentication failed")

        stdin, stdout, stderr = ssh.exec_command(command)

        return stdout.read()


    def rulelookup_html(self, sid):
        flowbits = []

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


    def rulelookup_ssh(self, auth_type, sid):

        findsid = "grep {} {}".format(sid, self.allrules_location)

        foundrule = self.command(auth_type, findsid)

        if not foundrule:
            print "[-] sid not found"
            sys.exit()

        elif foundrule and ("flowbits:isset" in foundrule):
            reg = re.search("flowbits:isset,([a-zA-Z0-9\.]+)", foundrule)
            flowbitgroup = reg.group(1)
            findflowbits = "grep \"flowbits:set,%s;\" %s" % (flowbitgroup, self.allrules_location)
            foundrule = foundrule
            foundbits = self.command(auth_type, findflowbits)

            print "\n==============\nsid {}\n==============\n\n{}".format(sid, foundrule)
            print "==============\nFlowbits\n==============\n\n{}".format(foundbits)

        else:
            print "\n==============\nsid {}\n==============\n\n{}".format(sid, foundrule)

        


p = ArgumentParser()
p.add_argument("-w", "--web", help="Get rule from an HTML page", action="store_true")
p.add_argument("-p", "--password", help="SSH and password authentication", action="store_true")
p.add_argument("-c", "--certificate", help="SSH and certificate authentication", action="store_true")
p.add_argument("sid", help="Rule sid")
args = p.parse_args()

if args.password:
    r = RuleLookup()
    r.rulelookup_ssh("password", args.sid)

elif args.certificate:
    r = RuleLookup()
    r.rulelookup_ssh("certificate", args.sid)
else:
    print "[-] No arguments provided. Use -h for assistance"