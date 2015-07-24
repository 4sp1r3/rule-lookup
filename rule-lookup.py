from argparse import ArgumentParser
import getpass
import paramiko
import requests
import re
import sys


class RuleLookup(object):

    def __init__(self):
        self.sensor = ""
        self.rulesfile_type = "single/multiple"
        self.rules_location = "/"
        self.sid = None

        self.credentials = False
        self.password_protected_key = False
        self.keypassword = False

        self.allrules_url = None


    def command(self, search_string):

        if self.rulesfile_type == "single":
            command = "grep '{}' {}".format(search_string, self.rules_location)

        elif self.rulesfile_type == mutliple:
            command = "for file in $(ls {})" \
                      "do grep {} $file; done".format(self.rules_location, search_string)
        else:
            sys.exit("[-] Set the rulesfile_type variable.\nExiting..")

        return command


    def ssh_auth_password(self, command):

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if not self.credentials:
            self.username = raw_input("Username: ")
            self.password = getpass.getpass()
            self.credentials = True

        try:
            ssh.connect(
                    self.sensor,
                    allow_agent=False,
                    look_for_keys=False,
                    username=self.username,
                    password=self.password,
                       )

        except paramiko.AuthenticationException:
            sys.exit("[-] Authentication failed")

        stdin, stdout, stderr = ssh.exec_command(command)

        return stdout.read()


    def ssh_auth_key(self, command):

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        

        if not self.credentials:
            self.username = raw_input("Username: ")
            self.credentials = True

        try:
            ssh.connect(
                    self.sensor,
                    username=self.username,
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


    def ssh_results(self, results, sid):
        
        if not results:
            sys.exit("[-] sid not found")

        elif results and ("flowbits:isset" in results):
            reg = re.search("flowbits:isset,([a-zA-Z0-9\.]+)", results)
            flowbitgroup = reg.group(1)
            findbits_command = self.command("flowbits:set,%s;" % (flowbitgroup))
            foundbits = self.ssh_auth_key(findbits_command)

            print "\n==============\nsid {}\n==============\n\n{}".format(sid, results)
            print "==============\nFlowbits\n==============\n\n{}".format(foundbits)

        else:
            print "\n==============\nsid {}\n==============\n\n{}".format(sid, foundrule)


p = ArgumentParser()
p.add_argument("-w", "--web", help="Get rule from an HTML page", action="store_true")
p.add_argument("-p", "--password", help="SSH and password authentication", action="store_true")
p.add_argument("-c", "--certificate", help="SSH and certificate authentication", action="store_true")
p.add_argument("sid", help="Rule sid")
args = p.parse_args()

if args.certificate:
    r = RuleLookup()
    command = r.command(args.sid)
    results = r.ssh_auth_key(command)
    r.ssh_results(results, args.sid)

elif args.password:
    r = RuleLookup()
    command = r.command(args.sid)
    results = r.ssh_auth_password(command)
    r.ssh_results(results, args.sid)
else:
    print "[-] No arguments provided. Use -h for assistance"