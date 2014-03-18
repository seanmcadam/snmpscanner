snmpscanner
===========

Tool for performing SNMP scanning accross wide swaths of IP ranges

Provide two files for input: list of SNMP strings, and a list of CIDRs to scan
The script will:
    import the list of SNMP strings
    import the list of CIDRs and generate the IPs to check
    ping each IP first, and skip if no response
    Start to scan the IP with V2 first going though the SNMP strings until one responds
    Gather System Name, Location, and contact info
    Loop until all IPs have been checked
    print out a CSV of the data

