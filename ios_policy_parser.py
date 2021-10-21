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


import sys
import csv

# Literal: will match the given string, even if it is just the start of a larger string.
# Word: will match a word group of characters consisting of the letters in its constructor string.
# Keyword: will only match the given string if it is not part of a larger word (followed by space, or by a non-word character)

# This app will be able to parse ASA policies like the following example:

cfg = r"""\
access-list 141 remark We start with a remark
access-list 141 permit icmp host 172.16.130.88 10.0.0.0 0.255.255.255
access-list 141 permit tcp host 172.16.130.89 eq 734 10.0.0.0 0.255.255.255 range 10000 10010
access-list 141 permit udp host 172.16.130.90 10.0.0.0 0.255.255.255 eq tftp
access-list 141 deny ip 172.16.130.0 0.0.0.255 host 192.168.10.118
access-list 141 permit ip any any
access-list 101 permit tcp 192.168.13.0 0.0.0.255 host 172.16.40.2 eq telnet
access-list 101 permit icmp 192.168.13.0 0.0.0.255 host 172.16.40.2 echo
access-list 101 deny   ip 192.168.13.0 0.0.0.255 172.16.40.0 0.0.0.255
access-list 101 permit ip 192.168.13.0 0.0.0.255 any
access-list 101 permit udp any any eq rip
access-list 101 deny   ip any any
access-list 111 permit udp any any eq rip
access-list 111 deny   ip any any
access-list 121 permit tcp 150.1.14.0 0.0.0.255 172.16.40.0 0.0.0.255 eq www
access-list 121 permit tcp 150.1.14.0 0.0.0.255 172.16.40.0 0.0.0.255 eq ftp
access-list 121 permit tcp 150.1.14.0 0.0.0.255 172.16.40.0 0.0.0.255 eq smtp
access-list 121 permit icmp 150.1.14.0 0.0.0.255 172.16.40.0 0.0.0.255 echo
access-list 121 permit udp any any eq rip
access-list 121 deny   ip any any
access-list 13 deny ip any
"""

from config_parser import ios_policy_parser, field_names
import yaml

outfilename = "out.csv"


if __name__ == "__main__":
    # Read command line arguments
    if len(sys.argv) > 2:
        outfilename = sys.argv[2].split('.')[0] + ".csv"
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as fgfile:
            cfg = fgfile.read()
    else:
        print("Input file name is required! An example is used for now.")

    # Parse ACL policies
    policies = ios_policy_parser(cfg)
    
    # Get field names from parsed policies and insert order field
    columns = field_names(policies)

    # Write to yaml
    policy_list = [p.asDict() for p in policies if p]
    with open('out.yml', 'w') as file:
        yaml.dump({'acl': policy_list}, file)

    # Write to csv         
    with open(outfilename, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, lineterminator='\n', fieldnames=columns)
        writer.writeheader()
        for data in policy_list:
            writer.writerow(data)