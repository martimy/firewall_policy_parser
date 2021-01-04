"""
Copyright 2016-2021 Maen Artimy

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from pyparsing import *
import sys

# This app will be able to parse ASA policies like the following example:
# See https://www.cisco.com/c/en/us/td/docs/security/asa/asa914/configuration/firewall/asa-914-firewall-config.html

cfg = r"""\
access-list abc extended permit icmp any any echo
access-list abc extended permit icmp any any object-group obj_icmp
access-list xyz line 10 extended permit icmp any any echo-reply
access-list xyz line 20 extended permit tcp 0.0.0.0 255.255.255.0 eq 3389 host 192.168.20.53 eq 3389 log
access-list xyz line 30 extended permit tcp any eq https host 192.168.30.54 eq https
access-list xyz line 40 extended permit tcp any eq https host 192.168.30.55 eq https
access-list xyz line 50 extended permit tcp any eq https host 192.168.30.56 eq https
access-list xyz line 60 extended permit tcp any eq https host 192.168.30.57 eq https
access-list uvw extended permit ip interface inside 192.168.20.64 255.255.255.240
access-list uvw extended permit ip 192.168.20.0 255.255.255.0 192.168.20.64 255.255.255.240
access-list uvw extended permit ip 192.168.30.0 255.255.255.0 192.168.20.64 255.255.255.240
access-list uvw extended permit ip 192.168.40.0 255.255.255.0 192.168.20.64 255.255.255.240
access-list uvw extended permit ip 192.168.50.0 255.255.255.0 192.168.20.64 255.255.255.240
access-list uvw extended permit ip 10.5.5.0 255.255.255.0 192.168.20.64 255.255.255.240
"""

outfilename = "out.csv"
NOT_PARSED = "**Unable to parse this policy**"

# Cisco ACL Parsing Definitions
POLICY_START_MARKER = LineStart() + Keyword("access-list").suppress()
POLICY_END_MARKER = LineEnd().suppress()

# General Parsing Definitions
SEPERATOR = Word("-_.", max=1)
LBRACE, RBRACE, SEMI, QUOTE, COMMA = map(Suppress, '{};",')
#ip4Address = Combine(Word(nums, max=3) + ('.' + Word(nums, max=3))*3)


def policyParser(text):
    """
    Parse individual firewall policies.
    """

    icmp = Literal("icmp")
    transport = oneOf("tcp udp sctp")
    action = oneOf("deny permit")
    objName = Combine(Word(alphanums) +
                      ZeroOrMore(SEPERATOR + Word(alphanums)))
    ip4Address = objName
    lineNum = Keyword("line").suppress() + Word(nums)("line")
    protocol_argument = Keyword(
        "object-group") + objName | Keyword("object") + objName | ~icmp + Word(alphas)

    address_argument = Literal(
        "any") | Keyword("host") + ip4Address | ip4Address + ip4Address | Keyword("interface") + objName | Keyword("object-group") + objName | Keyword("object") + objName
    address_argument_st = Literal("any") | Keyword(
        "host") + ip4Address | ip4Address + ip4Address
    user_argument = Keyword("object-group-user") + objName | Keyword(
        "user") + Keyword(printables) | Keyword("user-gorup") + Keyword(printables)
    port_argument = oneOf(
        "lt gt eq neq") + Word(alphanums) | Keyword("range") + Word(alphanums) + Word(alphanums)
    icmp_argument = Keyword("object-group") + \
        objName | objName + Optional(Word(alphanums))

    # Extended ACLs
    # FQDN matching:
    # access-list access_list_name [line line_number] extended {deny | permit} protocol_argument source_address_argument dest_address_argument [log [[level] [interval secs] | disable | default]] [time-range time_range_name] [inactive]
    # Port-Based Matching:
    # access-list access_list_name [line line_number] extended {deny | permit} {tcp | udp | sctp} source_address_argument [port_argument] dest_address_argument [port_argument] [log [[level] [interval secs] | disable | default] [time-range time-range-name] [inactive]
    # ICMP-Based Matching:
    # access-list access_list_name [line line_number] extended {deny | permit} {icmp | icmp6} source_address_argument dest_address_argument [icmp_argument] [log [[level] [interval secs] | disable | default]] [time-range time_range_name] [inactive]
    # User-Based Matching
    # access-list access_list_name [line line_number] extended {deny | permit} protocol_argument [user_argument] source_address_argument [port_argument] dest_address_argument [port_argument] [log [[level] [interval secs] | disable | default]] [time-range time_range_name] [inactive]

    extendedHeader = objName(
        "name") + Optional(lineNum) + Keyword("extended") + action("action")
    fqdnPolicy = extendedHeader + protocol_argument.setParseAction(' '.join)("protocol") + \
        address_argument.setParseAction(' '.join)(
            "srcaddr") + address_argument.setParseAction(' '.join)("dstaddr")
    portPolicy = extendedHeader + transport("protocol") + address_argument.setParseAction(' '.join)("srcaddr") + \
        Optional(port_argument).setParseAction(' '.join)("srcport") + \
        address_argument.setParseAction(' '.join)(
            "dstaddr") + Optional(port_argument).setParseAction(' '.join)("srcport")
    icmpPolicy = extendedHeader + icmp("protocol") + address_argument.setParseAction(' '.join)("srcaddr") + \
        address_argument.setParseAction(' '.join)(
            "dstaddr") + Optional(icmp_argument).setParseAction(' '.join)("icmp_opt")
    userPolicy = extendedHeader + protocol_argument.setParseAction(' '.join)("protocol") + \
        Optional(user_argument)("user") + address_argument.setParseAction(' '.join)("srcaddr") + \
        Optional(port_argument).setParseAction(' '.join)("srcport") + \
        address_argument.setParseAction(' '.join)(
            "dstaddr") + Optional(port_argument).setParseAction(':'.join)("dstport")

    # Standard ACLs
    # access-list access_list_name standard {deny | permit} {any4 | host ip_address | ip_address mask }

    standardPolicy = objName("name") + \
        Keyword("standard") + action("action") + \
        address_argument_st.setParseAction(' '.join)("srcaddr")

    remarkPolicy = objName("name") + \
        Optional(lineNum) + Keyword("remark") + \
        OneOrMore(Word(printables)).setParseAction(' '.join)("remark")

    policyDef = fqdnPolicy | portPolicy | icmpPolicy | userPolicy | remarkPolicy | standardPolicy

    return policyDef.searchString(text)


def policyFinder(text):
    """
    Finds individual firewall policies by locating the keywords 'access-list'.
    It is used to verify the number of policies parsed correctly.
    """

    policyDef = POLICY_START_MARKER + SkipTo(LineEnd())

    return policyDef.searchString(text)


def fieldNames(policies):
    """
    Extract field names from parsed policies
    """

    fields = set()
    for sec in policies:
        for obj in sec:
            fields.update(obj.asDict().keys())
    return list(fields)


def verifyParsing(num, text):
    """
    Generate report for debugging.
    """

    count = text.count(NOT_PARSED)
    return f"Found {num} and parsed {num - count} policies.\n"


def policyToCSV(columns, policies):
    """
    Returns a list of strings. 
    Each string represents a comma-seperated table of a single firewall policy section.
    """

    st = ','.join(columns) + "\n"
    for sec in policies:
        if sec:
            row = [sec[0].get(att, '') for att in columns]
            st += ",".join(row) + "\n"
        else:
            st += NOT_PARSED + "\n"

    # print(f"Policies not parsed {count}")
    return st


if __name__ == "__main__":
    # Read command line arguments
    if len(sys.argv) > 2:
        outfilename = sys.argv[2].split('.')[0] + ".csv"
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as fgfile:
            cfg = fgfile.read()
    else:
        print("Input file name is required! An example is used for now.")

    # Parse firewall policies
    policylines = [p[0] for p in policyFinder(cfg)]
    policies = [policyParser(policy) for policy in policylines]

    # Get field names from parsed policies and insert order field
    columns = fieldNames(policies)
    #columns = ['name','line','action','protocol','srcaddr','srcport','dstaddr','dstport','icmp_opt','remark']

    # Convert parsed policies to CSV and save to file
    text = ""
    with open(outfilename, 'w') as outfile:
        for s in policyToCSV(columns, policies):
            text += s
            outfile.write(s)

    # Print report
    print(verifyParsing(len(policylines), text), file=sys.stderr)
