from argparse import ArgumentParser
import getpass
import paramiko
import requests
import re
import sys


class RuleLookup(object):

    def __init__(self):

        # Configuration settings, to be selected by the User
        # Sensor can be IP or hostname
        # rulesfile_type identifies a single rules file or multiple
        # rules_location is either a full directory path containing-
        # multiple rules files, or the full path to one rules file
        self.sensor = "IP address / hostname"
        self.rulesfile_type = "single / multiple"
        # If using multiple rules files, set the below variable to-
        # be the directory holding the ruleset
        self.rules_location = "/rules directory/ or allrules file path (full)"
        self.username = None

        # The two settings below are not to be touched by the User,
        # they pseudo track state and authentication types to
        # prevent Paramiko from prompting for authentication during 
        # second connection to check for flowbits 
        self.auth_type = None
        self.credentials = False

        # If hosting the content of an allrules file on a web server,
        # the allRules URL is to be set below:
        self.allrules_url = None


    def command(self, search_string):

        if self.rulesfile_type == "single":
            command = "grep '{}' {}".format(search_string, self.rules_location)

        elif self.rulesfile_type == "multiple":
            command = "for file in $(ls {0});" \
            "do grep '{1}' {0}$file; done".format(self.rules_location, search_string)

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
            reg = re.search("flowbits:isset,([a-zA-Z0-9_\.]+)", self.rule)
            flowbitgroup = reg.group(1)

        for line in req.content.splitlines():
            if "flowbits:set,{};".format(flowbitgroup) in line:
                self.flowbits.append(line)

    def get_flowbits(self, sidresults):

        reg = re.search("flowbits:isset,([a-zA-Z0-9_\.]+)", sidresults)
        flowbitgroup = reg.group(1)
        findbits_command = r.command("flowbits:set,%s;" % (flowbitgroup))

        if self.auth_type == "key":
            flowbits = self.ssh_auth_key(findbits_command)

        elif self.auth_type == "password":
            flowbits = self.ssh_auth_password(findbits_command)

        return flowbits

    def pretty_print(self, results):

        if not results:
            print "[-] sid not found"
            sys.exit()
    
        else:
            print "\n============\nRule Logic\n============\n"
            print results

        if "flowbits:isset" in results:
            print "============\nFlowbit(s)\n============\n"

            flowbits = self.get_flowbits(results)
            
            for item in flowbits.splitlines():
                print item + "\n"



p = ArgumentParser()
p.add_argument("-w", "--web", help="Get rule from an HTML page", action="store_true")
p.add_argument("-p", "--password", help="SSH and password authentication", action="store_true")
p.add_argument("-k", "--key", help="SSH and key-based authentication", action="store_true")
p.add_argument("sid", help="Rule sid")
args = p.parse_args()

if args.key:
    r = RuleLookup()
    r.auth_type = "key"
    sidcommand = r.command("sid:" + args.sid + ";")
    sidresults = r.ssh_auth_key(sidcommand)
    r.pretty_print(sidresults)

elif args.password:
    r = RuleLookup()
    r.auth_type = "password"
    sidcommand = r.command("sid:" + args.sid + ";")
    sidresults = r.ssh_auth_password(sidcommand)
    r.pretty_print(sidresults)

else:
    print "[-] No arguments provided. Use -h for assistance"



