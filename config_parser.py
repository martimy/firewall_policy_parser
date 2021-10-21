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

import pyparsing as pp

# Field names
F_NAME = 'name'
F_ACTION = 'action'
F_PROTOCOL = 'protocol'
F_SRCIP = 'srcip'
F_SRCPORT = 'srcport'
F_DSTIP = 'dstip'
F_DSTPORT = 'dstport'
F_NOTES = 'notes'

# General Parsing Definitions
SEPERATOR = pp.Word("-_.", max=1)
LBRACE, RBRACE, SEMI, QUOTE, COMMA = map(pp.Suppress, '{};",')

DECBYTE = pp.Word(pp.nums, max=3)
IP4ADDRESS = pp.Combine(DECBYTE + ('.' + DECBYTE)*3)
WILEDCARD = pp.Combine(DECBYTE + ('.' + DECBYTE)*3)

# Cisco ACL Parsing Definitions
POLICY_START_MARKER = pp.LineStart() + pp.Keyword("access-list").suppress()
POLICY_END_MARKER = pp.LineEnd().suppress()
STD_NUM = pp.Word(pp.nums, max=2, asKeyword=True)
EXD_NUM = pp.Word(pp.nums, min=3, asKeyword=True)
ACL_NUM = STD_NUM | EXD_NUM
REMARK = pp.Keyword('remark').suppress()
ANY = pp.Keyword("any")
HOST = pp.Keyword("host").suppress()
ONE_PORT_MATCH = pp.Keyword('eq').suppress() | pp.oneOf('gt lt neq')
PORT_RNAGE = pp.Keyword('range').suppress()
PORTKEY = pp.Word(pp.alphas, asKeyword=True)
PORTNUM = pp.Word(pp.nums, asKeyword=True)
PORTID = PORTKEY | PORTNUM
ACTION = pp.oneOf("deny permit")
PROTOCOL = pp.Word(pp.alphanums)

ADDRESS = ANY | HOST + IP4ADDRESS | IP4ADDRESS + WILEDCARD
PORT = ONE_PORT_MATCH + PORTID | PORT_RNAGE + PORTNUM + PORTNUM

PORT_OR_ANY = pp.Optional(PORT, 'any')
REMAINDER = pp.SkipTo(pp.LineEnd())


def ios_policy_parser(text):
    """
    Parse individual firewall policies.
    """

    remarkPolicy = ACL_NUM(F_NAME) + REMARK + REMAINDER(F_NOTES)

    standardPolicy = STD_NUM(F_NAME) + ACTION(F_ACTION) + PROTOCOL(F_PROTOCOL)\
        + ADDRESS.setParseAction(' '.join)(F_SRCIP)\
        + PORT_OR_ANY.setParseAction(' '.join)(F_SRCPORT)\
        + REMAINDER(F_NOTES)

    extendedPolicy = EXD_NUM(F_NAME) + ACTION(F_ACTION) + PROTOCOL(F_PROTOCOL)\
        + ADDRESS.setParseAction('/'.join)(F_SRCIP)\
        + PORT_OR_ANY.setParseAction('-'.join)(F_SRCPORT)\
        + ADDRESS.setParseAction('/'.join)(F_DSTIP)\
        + PORT_OR_ANY.setParseAction('-'.join)(F_DSTPORT)\
        + REMAINDER(F_NOTES)

    policyDef = remarkPolicy ^ extendedPolicy ^ standardPolicy
    return policyDef.searchString(text)

def field_names(policies):
    """
    Extract field names from parsed policies
    """

    fields = set()
    for p in policies:
        fields.update(p.keys())
    return list(fields)
