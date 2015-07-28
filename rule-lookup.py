from argparse import ArgumentParser
import getpass
import paramiko
import requests
import re
import sys


class RuleLookup(object):

    def __init__(self):

        # SSH ONLY: Configuration settings, to be selected by the User
        # Sensor can be IP or hostname
        # rulesfile_type identifies a single rules file or multiple rules files
        self.sensor = "IP address / hostname"
        self.rulesfile_type = "single / multiple"
        #
        # SSH ONLY: If using multiple rules files, set the below variable 
        # to the /directory/ holding your rules files. Otherwise, it 
        # should be the full path of you allrules file
        self.rules_location = "/etc/snort/rules/allRules.rules"
        #
        # If hosting the content of an allrules file on a web server,
        # the allRules URL is to be set below:
        self.allrules_url = "<url>"
        #
        # The two settings below are not to be touched by the User,
        # they pseudo track state and authentication types to
        # prevent Paramiko from prompting for authentication during 
        # second connection to check for flowbits 
        self.auth_type = None
        self.credentials = False


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
            if sid in line:
                print "\n============\nRule Logic\n============\n"
                rule = line
                print rule

        if "flowbits:isset" in rule:
            reg = re.search("flowbits:isset,([a-zA-Z0-9_\.]+)", rule)
            flowbitgroup = reg.group(1)
            print "\n============\nFlowbits\n============\n"

            for line in req.content.splitlines():
                if "flowbits:set,{};".format(flowbitgroup) in line:
                    flowbits.append(line)

            for item in flowbits:
                print item

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
p.add_argument("-p", "--password", help="Get rule using SSH + password auth", action="store_true")
p.add_argument("-k", "--key", help="Get rule SSH using key-based auth", action="store_true")
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

elif args.web:
    r = RuleLookup()
    r.rulelookup_html("sid:" + args.sid + ";")

else:
    print "[-] No arguments provided. Use -h for assistance"



