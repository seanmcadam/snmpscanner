#!/usr/bin/perl
#
# Author: Sean McAdam
# Website: https://github.com/seanmcadam/snmpscanner
# License: GPL v2
#
#
# Purpose:
# Tool for scanning SNMP devices accross wide swaths of IP ranges
#
#

use Carp;
use Data::Dumper;
use Getopt::Std;
use Net::Netmask;
use Net::Ping;
use Net::SNMP;
use Readonly;
use strict;

sub print_usage;
sub ping_target($);
sub get_ips_from_block($);
sub get_snmp_oid($$);
sub open_snmp_session($$$);

Readonly our $COUNT              => 'COUNT';
Readonly our $SNMPV1             => 'snmpv1';
Readonly our $SNMPV2             => 'snmpv2';
Readonly our $SYSNAME            => 'SYSNAME';
Readonly our $SYSCONT            => 'SYSCONTACT';
Readonly our $SYSLOC             => 'SYSLOCATION';
Readonly our $SYSUPTIME          => 'SYSUPTIME';
Readonly our $SNMPVER            => 'SNMPVERSION';
Readonly our $SNMPSTRING         => 'SNMPSTRING';
Readonly our $SNMPREADY          => 'SNMPREADY';
Readonly our $SNMP_OID_SYSUPTIME => '.1.3.6.1.2.1.1.3.0';
Readonly our $SNMP_OID_SYSCONT   => '.1.3.6.1.2.1.1.4.0';
Readonly our $SNMP_OID_SYSNAME   => '.1.3.6.1.2.1.1.5.0';
Readonly our $SNMP_OID_SYSLOC    => '.1.3.6.1.2.1.1.6.0';

my $VERSION   = "0.9.1";
my $DEBUG     = 0;
my $DRYRUN    = 0;
my $VERBOSE   = 0;
my $progname  = ( split( /\//, $0 ) )[-1];
my $file_CIDR = '';
my $file_SNMP = '';
my %SCANIP    = ();
my @SNMP      = ();
my @SNMPVER   = ( $SNMPV2, $SNMPV1 );

our $opt_C = 0;
our $opt_d = 0;
our $opt_h = 0;
our $opt_n = 0;
our $opt_S = 0;
our $opt_v = 0;
our $opt_V = 0;

getopts('C:dhnS:vV');

if ($opt_d) {
    $DEBUG = 1;
}

if ($opt_h) {
    print_usage();
}

if ($opt_n) {
    $DRYRUN = 1;
}

if ($opt_v) {
    $VERBOSE = 1;
}

if ($opt_V) {
    print "$progname: $VERSION\n";
    exit;
}

if ( !$opt_S ) {
    print "Missing SNMP String input file\n";
    print_usage();
}

if ( !$opt_C ) {
    print "Missing CIDR Input file\n";
    print_usage();
}

$file_SNMP = $opt_S;
$file_CIDR = $opt_C;

# ----------------------
# Open SNMP File
#
# ----------------------
print "Open SNMP\n";
open( SNMP, $file_SNMP ) || die "Unable to open SNMP File: '$file_SNMP'\n";
while (<SNMP>) {
    chop;
    my $snmp = $_;
    push( @SNMP, $snmp );

    # print "Adding SNMP String: '$snmp'\n" if $DEBUG;

}
close SNMP;

# ----------------------
# Open CIDR File
#
# ----------------------
print "Open CIDR\n";
open( CIDR, $file_CIDR ) || die "Unable to open CIDR File: '$file_CIDR'\n";
while (<CIDR>) {
    chop;
    my $cidr = $_;

    # print "Adding CIDR Block: '$cidr'\n" if $DEBUG;

    foreach my $ip ( get_ips_from_block($cidr) ) {

        # print "\t$ip\n" if $DEBUG;

        if ( !defined $SCANIP{$ip} ) {
            my %h;
            $h{$COUNT}++;
            $SCANIP{$ip} = \%h;

        }
        else {
            $SCANIP{$ip}->{$COUNT}++;
            print "$ip added $COUNT times\n" if $DEBUG;
        }

    }
}
close CIDR;

foreach my $ip ( sort( keys(%SCANIP) ) ) {
    my $snmp_ver;
    my $snmp_string;
    my $ipref = $SCANIP{$ip};

    if ( !ping_target($ip) ) {
        print "SKIP $ip\n" if $DEBUG;
        next;
    }
    else {
        print "PINGABLE $ip, continue\n" if $DEBUG;
    }

    foreach my $v (@SNMPVER) {
        $snmp_ver = $v;

        foreach my $s (@SNMP) {
            my $session;
            my $sysname;
            my $sysloc;
            my $syscont;
            my $sysuptime;
            $snmp_string = $s;

            if ( defined( $session = open_snmp_session( $ip, $snmp_string, $snmp_ver ) ) ) {
                my $result_ref;

                #
                # IF THE FIRST QUERY MISSES, SKIP THE REST AND GO TO THE NEXT STRING
                #
                if ( !( $result_ref = get_snmp_oid( $session, $SNMP_OID_SYSNAME ) ) ) {
                    print "SYSNAME: Unknown\n" if $DEBUG;
                    next;
                }
                $sysname = $result_ref->{$SNMP_OID_SYSNAME};

                if ( !( $result_ref = get_snmp_oid( $session, $SNMP_OID_SYSLOC ) ) ) {
                    print "LOCATION: Unknown\n" if $DEBUG;
                    $sysloc = 'none found';
                }
                $sysloc = $result_ref->{$SNMP_OID_SYSLOC};

                if ( !( $result_ref = get_snmp_oid( $session, $SNMP_OID_SYSCONT ) ) ) {
                    print "CONTACT: Unknown\n" if $DEBUG;
                    $syscont = 'none found';
                }
                $syscont = $result_ref->{$SNMP_OID_SYSCONT};

                if ( !( $result_ref = get_snmp_oid( $session, $SNMP_OID_SYSUPTIME ) ) ) {
                    print "SYSUPTIME: Unknown\n" if $DEBUG;
                    $sysuptime = 'none found';
                }
                $sysuptime = $result_ref->{$SNMP_OID_SYSUPTIME};

                $ipref->{$SYSNAME}    = $sysname;
                $ipref->{$SYSLOC}     = $sysloc;
                $ipref->{$SYSCONT}    = $syscont;
                $ipref->{$SYSUPTIME}  = $sysuptime;
                $ipref->{$SNMPVER}    = $snmp_ver;
                $ipref->{$SNMPSTRING} = $snmp_string;
                $ipref->{$SNMPREADY}  = 1;

                print "SYSNAME: '$sysname'\n"       if $DEBUG;
                print "SYSLOC: '$sysloc'\n"         if $DEBUG;
                print "SYSCONT: '$syscont'\n"       if $DEBUG;
                print "SYSUPTIME: '$sysuptime'\n"   if $DEBUG;
                print "SYSVER: '$snmp_ver'\n"       if $DEBUG;
                print "SYSSTRING: '$snmp_string'\n" if $DEBUG;

                goto SNMP_NEXT;
            }
            else {
                print "Cannot open session: $ip, $snmp_string, $snmp_ver\n" if $DEBUG;
            }
        }
      SNMP_NEXT:
    }
}

foreach my $ip ( sort { $a <=> $b } ( keys(%SCANIP) ) ) {
    if ( $SCANIP{$ip}->{$SNMPREADY} ) {
        my $ipref       = $SCANIP{$ip};
        my $sysname     = $ipref->{$SYSNAME};
        my $sysloc      = $ipref->{$SYSLOC};
        my $syscont     = $ipref->{$SYSCONT};
        my $sysuptime   = $ipref->{$SYSUPTIME};
        my $snmp_ver    = $ipref->{$SNMPVER};
        my $snmp_string = $ipref->{$SNMPSTRING};
        print "$ip,$snmp_ver,$snmp_string,$sysname,$sysloc,$syscont\n";
    }
}

#----------------------------------------------------------------
#
# Returns result = \{ oid => 'value' }
#
#----------------------------------------------------------------
sub get_snmp_oid($$) {
    my ( $session, $oid ) = @_;

    my $result = $session->get_request( -varbindlist => [$oid], );
    if ( !defined $result ) {
        print "get_snmp_oid() NO Result for $oid\n" if $DEBUG;
    }

    $result;
}

#----------------------------------------------------------------
sub open_snmp_session($$$) {
    my ( $ip, $comm, $ver ) = @_;

    my ( $session, $error ) = Net::SNMP->session(
        -hostname  => $ip,
        -community => $comm,
        -version   => $ver
    );

    if ($error) {
        print( "Failed to Open SNMP Session with $ip: " . $error ) if $DEBUG;
    }

    $session;
}

#----------------------------------------------------------------
sub get_ips_from_block($) {
    my ($cidr) = @_;
    my $block  = new Net::Netmask($cidr);
    my @ips    = $block->enumerate();
    @ips;
}

#----------------------------------------------------------------
sub ping_target($) {
    my ($target) = @_;
    my $P        = Net::Ping->new("icmp");
    my $ret      = 0;

    # LOG( LOG_DEBUG, "CHECK LINK $TARGET" );

    if ( $P->ping($target) ) {
        $ret = 1;

        # LOG( LOG_DEBUG, "LINK UP" );
    }
    else {
        $ret = 0;

        # LOG( LOG_DEBUG, "LINK DOWN: $target" );
    }
    $ret;
}

#----------------------------------------------------------------
sub print_usage {
    print "$progname [options]\n";
    print "\tOptions:\n";
    print "\t-C File of CIDRs to scan\n";
    print "\t-S File of SNMP Strings to use\n";
    print "\t-V print version info\n";
    print "\t-h print this message\n";
    print "\t-n Dry Run, dont do anything\n";
    print "\t-d Turn on DEBUG\n";
    exit;
}

