"""
Copyright 2016-2020 Maen Artimy

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

# This app will be able to parse FG policies like the following example:

example = r"""\
config firewall policy
    edit 93
        set uuid 3509d226-cff8-51e5-aa5c-35c83c70e195
        set srcintf "internal-lan"
        set dstintf "outside"
        set srcaddr "WEB_SERVER-2"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set nat enable
        set comments "Example Policy"
    next
end
"""

# Constants
FW_POLICY_SECTION = "config firewall policy\n"

# General Definitions
SEPERATOR = Word("-_. ", max=1)
LBRACE, RBRACE, SEMI, QUOTE, COMMA = map(Suppress, '{};",')


def policySectionParser(text):
    """
    Returns the firewall policy section in the configuration. Thers is one section per VDOM.
    """

    ENDMARK = Suppress("end\n")
    sectionDef = Literal(FW_POLICY_SECTION) + \
        SkipTo(ENDMARK).setResultsName("content")
    return sectionDef.searchString(text)


def policyParser(text):
    """
    Parse individual firewall policy.
    """

    NEXTMARK = Suppress(Keyword("next"))
    fieldName = Combine(Word(alphas) + ZeroOrMore('-' + Word(alphas)))
    objName = Combine(Word(alphanums) +
                      ZeroOrMore(SEPERATOR + Word(alphanums)))
    objList = OneOrMore(QUOTE + objName + QUOTE).setParseAction(';'.join)

    policyNum = Literal("edit").suppress() + Word(nums).setResultsName("num")
    policyParam = objName | objList | quotedString | SkipTo("\n")
    policyStatement = Literal("set").suppress() + \
        Group(fieldName + policyParam)
    policyDef = policyNum + \
        Dict(OneOrMore(policyStatement)) + NEXTMARK.suppress()

    return policyDef.searchString(text)


def fieldNames(policy_sections):
    """
    Extract field names from parsed policies
    """

    fields = set()
    for section in policy_sections:
        if section.content:
            for obj in policyParser(section.content):
                fields.update(obj.asDict().keys())
    return list(fields)


def policyToString(columns, policy_sections):
    """
    Returns a list of strings. Each string represent a command-seperated table of firewall policies.
    """

    sections = []
    for section in policy_sections:
        if section.content:
            order = 0
            st = ','.join(columns) + "\n"
            for obj in policyParser(section.content):
                order += 1
                row = [obj.get(att, '') for att in columns]
                row[0] = str(order)
                st += ",".join(row) + "\n"
            sections.append(st)
    return sections


if __name__ == "__main__":
    # Read a Fortinet configuration file or exit
    if(len(sys.argv) > 1):
        fgfile = open(sys.argv[1].strip(), 'r')
        cfg = fgfile.read()
    else:
        print("Input file name is required!")
        print("An example is used for now.")
        cfg = example

    # Parse firewall policies
    policySections = policySectionParser(cfg)

    # Get field names from parsed policies
    columns = sorted(fieldNames(policySections))
    columns.insert(0, "order")

    # Convert parsed policies to tables
    sections = policyToString(columns, policySections)
    for s in sections:
        print(s)
