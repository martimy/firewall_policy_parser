# -*- coding: utf-8 -*-
"""
Created on Sat Oct  2 11:55:33 2021

"""

import csv
import sys
from policyanalyzer import Policy, PolicyAnalyzer, Packet

# Read csv file conatining policies but remove header
reader = []

# Read command line arguments
if len(sys.argv) > 2:
    outfilename = sys.argv[2].split('.')[0] + ".csv"
if len(sys.argv) > 1:
    with open(sys.argv[1], 'r') as csvfile:
        reader = list(csv.reader(csvfile))[1:]
else:
    print("Input file name is required!")

# HEADER = "protocol,src,s_port,dest,d_port,action"
        


print("=" * 50)
print("Policies:")
policies = [Policy(*r) for r in reader]
for n, p in enumerate(policies):
    print(f"{n:3}: {p}")

analyzer = PolicyAnalyzer(policies)
rule_relations = analyzer.get_relations()

print("=" * 50)
print("Anomalies:")
anom = analyzer.get_anomalies()
for i in anom:
    print(f"{i:3}: {anom[i]}")    

print("=" * 50)
print("Matches:")
packet = Packet('tcp', '140.192.37.0/24', 'any', '0.0.0.0/0', '80')
packet = Packet('tcp', '0.0.0.0/0', 'any', '161.120.33.40', '80')
packet = Packet('tcp', '140.192.37.0/24', 'any', '161.120.33.40', '80')
result = analyzer.get_first_match(packet)
print(result)
