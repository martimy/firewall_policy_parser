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

cfg = r"""\
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

outfilename = "out.csv"
FW_POLICY_SECTION = "config firewall policy\n"

# General Parsing Definitions
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
    Parse individual firewall policies.
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
    policyDef = policyNum + Dict(OneOrMore(policyStatement)) + NEXTMARK

    return policyDef.searchString(text)


def policyFinder(text):
    """
    Finds individual firewall policies by locating the keywords 'edit' and 'next'.
    It is used to verify the number of policies parsed correctly.
    """

    policyNum = Literal("edit").suppress() + Word(nums)
    policyDef = policyNum + SkipTo("next").suppress()

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


def verifyParsing(policyNums, policies):
    """
    Generate report for debugging.
    """

    num = len(policyNums)
    st = f"Found {num} firewall policy section(s).\n"

    for x in range(num):
        st += f"Found {len(policyNums[x])} and parsed {len(policies[x])} policies in section {x}.\n"

    # for x in range(num):
    #     st += f"Policy numbers found in section { x } (in order):\n"
    #     st += ",".join([item[0] for item in policyNums[x]]) + "\n"

    for x in range(num):
        notparsed = set([ item[0] for item in policyNums[x]]) - set([ item[0] for item in policies[x]])
        if notparsed:
            st += f"Policies not parsed in section { x }: "
            st += ",".join(list(notparsed)) + "\n"

    return st


def policyToCSV(columns, policies):
    """
    Returns a list of strings. 
    Each string represents a comma-seperated table of a single firewall policy section.
    """

    sections = []
    for sec in policies:
        # order = 0
        st = ','.join(columns) + "\n"
        for obj in sec:
            # order += 1
            row = [obj.get(att, '') for att in columns]
            # row[0] = str(order)
            st += ",".join(row) + "\n"
        sections.append(st)
    return sections


if __name__ == "__main__":
    # Read command line arguments
    if len(sys.argv) > 2:
        outfilename = sys.argv[2].split('.')[0] + ".csv"
    if len(sys.argv) > 1:
        fgfile = open(sys.argv[1], 'r')
        cfg = fgfile.read()
    else:
        print("Input file name is required! An example is used for now.")

    # Parse firewall policies
    policySections = policySectionParser(cfg)
    policyNums = [policyFinder(section) for section in policySections]
    policies = [policyParser(section.content) for section in policySections]

    # Get field names from parsed policies and insert order field
    columns = sorted(fieldNames(policies))
    # columns.insert(0, "order")

    # Convert parsed policies to CSV and save to file
    with open(outfilename, 'w') as outfile:
        for s in policyToCSV(columns, policies):
            outfile.write(s)
        
    # Print report
    print(verifyParsing(policyNums, policies), file=sys.stderr)
