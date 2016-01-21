#!/usr/bin/perl
# Script allowing to display every x secondes the most bandwidth consuming IP talkers on Cisco router.
# Netflow must have been enabled.

use strict;
use Net::SNMP;
use Data::Dumper;
use DateTime;
use DateTime::Format::Strptime;
use threads;
use threads::shared;

my $count_args = scalar(@ARGV);
my $start_dt = DateTime->now(time_zone  => "local");
my $start_formatted_dt = $start_dt->strftime('%d-%m-%Y %H:%M:%S');
my $community;
my $interval;
my $help;
my $timeout;
my $hostname = $ARGV[0];
my $cisco = 1;
my @todisplay       : shared;
my $token       : shared = 0;
my $token_buffer : shared = 0;
my %buffer       : shared;
my $dt_cache       : shared;
$token = 0;
$token_buffer = 0;
my $datapath;
my $parser = DateTime::Format::Strptime->new(
  pattern => '%d-%m-%Y %H:%M:%S',
  on_error => 'croak',
);

if(defined($ENV{"HOME"}))
{
    $datapath = $ENV{"HOME"}.'/';
}
else
{
	$datapath = '/tmp/';
}

print "All reports will be placed in $datapath\n";

# Ctrl-c to stop the script, a summary csv is generated
$SIG{INT} = sub {end()};

for(my $i = 1; $i < $count_args; $i++)
{
	usage() if($ARGV[$i] eq '-h');
	$community = $ARGV[++$i] if($ARGV[$i] eq '-c');
	$interval = $ARGV[++$i] if($ARGV[$i] eq '-i');
	$timeout = $ARGV[++$i] if($ARGV[$i] eq '-t');
}

usage() unless(defined($hostname) and defined($community) and $hostname ne 'h' and $hostname ne '-h' and $hostname ne '--help');
$interval = 20 unless(defined($interval));
$timeout = 2 unless(defined($timeout));

die('Interval too short (must be >= 5 sec)') if($interval < 5);

my $OID_ifDescr = '1.3.6.1.2.1.2.2.1.2';

my ($snmp, $snmperror);
($snmp, $snmperror) = Net::SNMP->session(
  -hostname => $hostname,
  -version => "snmpv2",
  -community => $community,
  -timeout => $timeout
);

die("Error while opening the SNMP session to $hostname") unless(defined($snmp));

my $result = $snmp->get_entries(-columns => [$OID_ifDescr],
                                -maxrepetitions => 3);

die("Error while opening the SNMP session to $hostname") unless(defined($result));

# Thread
my $request = sub {
	my $snmp = shift;
	getTop($snmp);
};

my $display_serv = sub 
{
	open(FILEHANLDER, '>'.$datapath.'logs_'.$hostname);
	close(FILEHANLDER);
    while (1)
    {
        while (@todisplay)
        {
            my $content = shift(@todisplay);
            print $content."\n\n";
            open(FILEHANLDER, '>>'.$datapath.'logs_'.$hostname);
            print FILEHANLDER $content."\n\n";
            close(FILEHANLDER);
            sleep(1);
        }
    }
};

my $thread1 = threads->create($display_serv);

my $temp_dt = DateTime->now();
$dt_cache = $temp_dt->strftime('%d-%m-%Y %H:%M:%S');

while(1)
{
	sleep($interval);
	# Create thread because the calculations to sort IP couples can be longer than expected
	threads->create($request, $snmp);
}

sub getTop
{
	my $snmp = shift;
	my $result_get_entries;
	my $dt = DateTime->now(time_zone  => "local");
	my $formatted_dt = $dt->strftime('%H:%M:%S');
	my $content = "$formatted_dt\nIp Source\t\tIp Destination\t\tPort Source\tPort Dest\tTotal\n";
	my $topCountOid = '1.3.6.1.4.1.9.9.387.1.7.2.0';
	my $cacheTimeoutOid = '1.3.6.1.4.1.9.9.387.1.7.7.0';
	my $ipSrcOid = '1.3.6.1.4.1.9.9.387.1.7.8.1.3';
	my $ipDstOid = '1.3.6.1.4.1.9.9.387.1.7.8.1.6';
	my $prtSrcOid = '1.3.6.1.4.1.9.9.387.1.7.8.1.10';
	my $prtDstOid = '1.3.6.1.4.1.9.9.387.1.7.8.1.11';
	my $bytesOid = '1.3.6.1.4.1.9.9.387.1.7.8.1.24';
	my @top;
	my $wait = 0;
	my $max_wait = 3;

	# Check if we can display infos
	while($token == 1)
	{
		if($wait > $max_wait)
		{
			push(@todisplay, "Wait for SNMP request too long at ".$formatted_dt);
			return;
		}
		sleep(2);
		$wait++;
	}
	$token = 1;

    $result_get_entries = $snmp->get_request(
                          -varbindlist      => [$topCountOid],
                       );
	my $topCount = $result_get_entries->{$topCountOid};

    $result_get_entries = $snmp->get_request(
                          -varbindlist      => [$cacheTimeoutOid],
                       );

	my $cacheTimeout = $result_get_entries->{$cacheTimeoutOid} / 1000;

	$result_get_entries = $snmp->get_entries(-columns => [$ipSrcOid, $ipDstOid, $prtSrcOid, $prtDstOid, $bytesOid],
                                             -maxrepetitions => 3);

	$token = 0;

	for my $i (1..$topCount)
	{
		my $entry;
		$entry->{'src'} = $result_get_entries->{$ipSrcOid.'.'.$i};
		$entry->{'dest'} = $result_get_entries->{$ipDstOid.'.'.$i};
		$entry->{'prtsrc'} = $result_get_entries->{$prtSrcOid.'.'.$i};
		$entry->{'prtdst'} = $result_get_entries->{$prtDstOid.'.'.$i};
		$entry->{'bytes'} = $result_get_entries->{$bytesOid.'.'.$i};

		# If port in hex format
		$entry->{'prtsrc'} = hex($entry->{'prtsrc'}) if($entry->{'prtsrc'} =~ m/^0x/);
		$entry->{'prtdst'} = hex($entry->{'prtdst'}) if($entry->{'prtdst'} =~ m/^0x/);

		# if @IP in hex format
		$entry->{'src'} = getIpFromHex($entry->{'src'}) if($entry->{'src'} =~ m/^0x/);
		$entry->{'dest'} = getIpFromHex($entry->{'dest'}) if($entry->{'dest'} =~ m/^0x/);

		# Check the consistency, because the mib is bugged sometimes...
		$entry->{'prtsrc'} = 'No info (MIB)' if($entry->{'prtsrc'} !~ m/^[0-9]+$/ or $entry->{'prtsrc'} < 0 or $entry->{'prtsrc'} > 65536);
		$entry->{'prtdst'} = 'No info (MIB)' if($entry->{'prtdst'} !~ m/^[0-9]+$/ or $entry->{'prtdst'} < 0 or $entry->{'prtdst'} > 65536);
		$entry->{'src'} = 'No info (MIB)' unless($entry->{'src'} =~ m/^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/);
		$entry->{'dest'} = 'No info (MIB)' unless($entry->{'dest'} =~ m/^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/);

		push(@top, $entry);
	}

	foreach my $result_ip_acco (@top)
	{
		$content .= ${$result_ip_acco}{'src'}."\t\t".${$result_ip_acco}{'dest'}."\t\t".${$result_ip_acco}{'prtsrc'}."\t\t".${$result_ip_acco}{'prtdst'}."\t\t".formatValue(${$result_ip_acco}{'bytes'})."\n" if(defined(${$result_ip_acco}{'src'}));
	}
	push (@todisplay,$content);

	$wait = 0;

	# Try to display if the token is available
	while($token_buffer == 1)
	{
		if($wait > $max_wait)
		{
			push(@todisplay, "Wait for buffer was too long at ".$formatted_dt);
			return;
		}
		sleep(2);
		$wait++;
	}
	$token_buffer = 1;

	my $dt_test = DateTime->now();
	my $temp_dt = $parser->parse_datetime($dt_cache);

	if($temp_dt < $dt_test)
	{
		foreach my $result_ip_acco (@top)
		{
			$buffer{${$result_ip_acco}{'src'}.'#'.${$result_ip_acco}{'dest'}.'#'.${$result_ip_acco}{'prtsrc'}.'#'.${$result_ip_acco}{'prtdst'}} += ${$result_ip_acco}{'bytes'};
		}

		$temp_dt = DateTime->now();
		$temp_dt->add(seconds => $cacheTimeout);
		$dt_cache = $temp_dt->strftime('%d-%m-%Y %H:%M:%S');
	}

	$token_buffer = 0;
}

# Format to have a more readable output
sub formatValue
{
	my $value = shift;
	my $return_value = '';
	
	if($value >= 1000000000)
	{
		$return_value = $value / 1000000000;
		$return_value = sprintf("%.2f", $return_value);
		$return_value .= ' Gb';
	}
	elsif($value >= 1000000)
	{
		$return_value = $value / 1000000;
		$return_value = sprintf("%.2f", $return_value);
		$return_value .= ' Mb';
	}
	elsif($value >= 1000)
	{
		$return_value = $value / 1000;
		$return_value = sprintf("%.2f", $return_value);
		$return_value .= ' Kb';
	}
	else
	{
		$return_value = $value.' b';
	}

	return $return_value;
}

sub end
{
	push(@todisplay, "Wait while creating a CSV file with a result compilation");
	my $dt = DateTime->now(time_zone  => "local");
	my $formatted_dt = $dt->strftime('%d-%m-%Y %H:%M:%S');
	my $total = 0;

	open(RESULT, '>'.$datapath.'recap_'.$hostname.'.csv');
	print RESULT 'Recapitulatif Netflow '.$hostname.';Debut : '.$start_formatted_dt.';Fin : '.$formatted_dt."\n";
	print RESULT "Ip Source;Ip Destination;Port Source;Port Dest;Total\n";

    foreach my $entry (reverse sort {$buffer{$a} <=> $buffer{$b}} keys %buffer) 
    {
    	my @data = split(/#/, $entry);
    	print RESULT $data[0].';'.$data[1].';'.$data[2].';'.$data[3].';'.formatValue($buffer{$entry})."\n";
    	$total += $buffer{$entry};
    }

	print RESULT ";;;Total;".formatValue($total);
	close(RESULT);
	exit(0);
}

# Return an @IP from hex format
sub getIpFromHex
{
	my $ipHex = shift;
	$ipHex =~ s/^0x//;
	my $ip = '';

	for my $i (0..3)
	{
		$ip .= hex(substr($ipHex, $i * 2, 2)).'.';
	}
	chop($ip);

	return $ip;
}

sub usage
{
	print <<EOF;
	./$0 <hostname> -c <snmp community string> (-i <refresh interval in sec>) (-t <snmp timeout interval in sec>) (-h)
	<hostname> : Hostname of the router      (Mandatory)
	-c : SNMP Community string of the router (Mandatory)
	-i : Refresh interval in sec             (Optionnal, default 20)
	-t : SNMP timeout interval in sec        (Optionnal, default 2)
	-h : display this brief help
EOF
	exit(1);
}