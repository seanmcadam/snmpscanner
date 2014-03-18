snmpscanner
===========

Tool for performing SNMP scanning accross wide swaths of IP ranges<BR>
<BR>
Provide two files for input: 
    list of SNMP strings<BR> 
    and a list of CIDRs to scan<BR>
    <BR>
The script will:<BR>
    import the list of SNMP strings<BR>
    import the list of CIDRs and generate the IPs to check<BR>
    ping each IP first, and skip if no response<BR>
    Start to scan the IP with V2 first going though the SNMP strings until one responds<BR>
    Gather System Name, Location, and contact info<BR>
    Loop until all IPs have been checked<BR>
    print out a CSV of the data<BR>

