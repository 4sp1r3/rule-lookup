#rule-lookup

##Description (short)

Given a Snort / Suricata rule sid, rule-lookup.py will query a given sensor or web page for its rule logic. Additionally, rule-lookup will resolve flowbits dependencies to offer a more complete view of what happened when a rule fired.

##Description (long)

Once an IDS is up and running, two of the most important things to have are:

* A copy of the traffic which caused a given rule to fire
* A way to access current and accurate rule logic for the rules which do fire

Often times (in my experience), Analyts are left to Google the sid for rules that fire, so proper analysis can be completed. The problem with this strategy is that rules contain revisions. Depending on how often (or not often) a security group updates the ruleset(s), an Analyst may be guessing as to which rule revision is running in memory on their sensors at a given moment.
Some tools have built-in support to query for local ruleset logic (ie Snorby, though its development has ceased). Other tools defer to hard-coded online resources, and still other tools provide no support for this at all; specifically SIEM solutions which aggregate data from various security devices. Even the tools with built-in support only provide half of the story. Consider the scenario below, in which sid 2018234 fired into an Analysts view:

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO JAR Sent Claiming To Be Text Content - Likely Exploit Kit"; flow:established,to_client; flowbits:isset,ET.http.javaclient; content:"Content-Type|3A| text/"; http_header; content:"|0d 0a 0d 0a|PK"; content:".class"; fast_pattern; distance:10; within:500; classtype:bad-unknown; sid:2018234; rev:3;)

This is a fairly straight-forward rule to interpret at first glance. This rule is looking for a Java Archive being served to a user-agent while claiming to contain text data. What you'll also notice below, is the 'flowbits' piece. In order for this rule to fire, another rule from a previous network interaction had to "set" a bit in memory for the group "ET.http.javaclient". So even before this rule fired, detection mechanisms were hard at paly - we should try to understand those other mechanisms as well. Here is the logic which sets the ET.http.javaclient bit in memory:

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET POLICY Java Client HTTP Request"; flow:established,to_server; content:" Java/1."; http_header; flowbits:set,ET.http.javaclient; flowbits:noalert; classtype:misc-activity; sid:2013035; rev:2;)

Before firing the initial rule (sid 2018234), Suricata first takes steps to verify that this is a Java client making a connection to the internet with a Java user-agent by utilizing sid 2013035. That being said, sid 2013035 will never fire - the "flowbits:noalert" piece guarantees that. That being said, understanding the full scope of an alert and surrounding events can be extremely valuable. 

More on flowbits can be found here: http://manual.snort.org/node470.html

##Example / Output:

```
rule-lookup.py -p 2018234
<enter username>
<enter password>

============
Rule Logic
============

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO JAR Sent Claiming To Be Text Content - Likely Exploit Kit"; flow:established,to_client; flowbits:isset,ET.http.javaclient; content:"Content-Type|3A| text/"; http_header; content:"|0d 0a 0d 0a|PK"; content:".class"; fast_pattern; distance:10; within:500; classtype:bad-unknown; sid:2018234; rev:3;)

============
Flowbit(s)
============

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET POLICY Java Client HTTP Request"; flow:established,to_server; content:" Java/1."; http_header; flowbits:set,ET.http.javaclient; flowbits:noalert; classtype:misc-activity; sid:2013035; rev:2;)
```

##Usage

```
poorbillionaire@pb:~/git/rule-lookup$ python rule-lookup.py -h
usage: rule-lookup.py [-h] [-w] [-p] [-k] sid

positional arguments:
  sid             Rule sid

optional arguments:
  -h, --help      show this help message and exit
  -w, --web       Get rule from an HTML page
  -p, --password  SSH and password authentication
  -k, --key       SSH and key-based authentication
```

##Requirements

* You have a way to get rule sids when alerts fire. Unified2 logging and Barnyard2 accomplish this well.
* You have at least one sensor or webpage to point this script at, which contains all rules in the environment
* You update all rulesets in all locations around the same time. Having different rule versions running on different sensors defeats the goal of obtaining accurate data
* If querying the sensor and not a web page, your IDS sensor must be "Unix-like"
* If querying the sensor and not a web page, your IDS sensor's default shell supports bash style 'for' loops
* If querying the sensor and not a web page, your sensor is running a modern version of Grep

##Support scope

* Rule-lookup supports both password and key-based SSH authentication
* Rules can be copied to a web server and rule-lookup contains support for querying a web page. Useful for environments when not all Analysts have access to the IDS infrastructure
* Rule-lookup supports an "allrules" file, or multiple rules files when querying a local sensor
* If querying a web server, all rules must be on the same web page

##Configuration

A small amount of configuration of this script is required. This is accomplished by modifying the values under __init__ in the RuleLookup class. You will need to know the following:

* How do you want to access the rule logic? Will rule-lookup query the sensor directly, or query a web page which contains a copy of the full rulset(s)?
* When querying a sensor directly, where are the rules located?
* When querying a web page, what is the URL?

#Example Configuration (SSH authentication)

        # Configuration settings, to be selected by the User
        # Sensor can be IP or hostname
        # rulesfile_type identifies a single rules file or multiple
        # rules_location is either a full directory path containing-
        # multiple rules files, or the full path to one rules file
        self.sensor = "sensor1"
        self.rulesfile_type = "single"
        #
        # If using multiple rules files, set the below variable to-
        # be the directory holding the ruleset
        self.rules_location = "/etc/snort/rules/allRules.rules"
        #
        # The two settings below are not to be touched by the User,
        # they pseudo track state and authentication types to
        # prevent Paramiko from prompting for authentication during 
        # second connection to check for flowbits 
        self.auth_type = None
        self.credentials = False
        #
        # If hosting the content of an allrules file on a web server,
        # the allRules URL is to be set below:
        self.allrules_url = "<url>"
        
        
