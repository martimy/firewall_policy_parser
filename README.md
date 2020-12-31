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

Which produces a table like this:

![Firewall policies](images/picture1.png)
