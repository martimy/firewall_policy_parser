# Firewall Policy Parser
A Python application that parses a firewall configuration and converts firewall policies into table format for easy reading and analysis.
Currently, the parser works with [Fortinet](https://www.fortinet.com/)'s Forigate configuration (FortiOS) only.

## Requirements

```
pip3 install pyparsing
```

or

```
python3 -m pip install pyparsing
```

## How to Use

```
python3 fg_policy_parser_lite.py Example.conf > out.csv
```

## Example output

order|name|srcintf|srcaddr|dstintf|dstaddr|groups|nat|schedule|service|status|utm-status|action|logtraffic|comments
---|---|---|---|---|---|---|---|---|---|---|---|---|---|---
1|VPN_Policy|ssl.root|all|internal|Local_LAN|VPNUsers|enable|always|ALL|disable||accept||
2|Inbound_Access|wan1|US Region|internal|WebAccess|||always|ALL_TCP|disable|enable|accept||
3|Block Private IP|internal|Local_LAN|wan1|Private_RFC1918|||always|ALL||||all|
4|IoT_Night|internal|IoT Device Addresses|wan1|all|||IoT_Night|ALL||||all|IoT night policy
5|IoT_Day|internal|IoT Devices Addresses|wan1|all||enable|IoT_Day|ALL||enable|accept||IoT daytime policy
6|Main|internal|Local_LAN|wan1|all||enable|always|ALL||enable|accept|all|
