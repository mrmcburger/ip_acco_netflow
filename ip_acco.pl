#!/usr/bin/perl
# Script allowing to display every x secondes the most bandwidth consuming IP couples on Cisco or a OneAccess router.
# Ip accounting must have been enabled.

use strict;
use Net::SNMP;
use Data::Dumper;
use DateTime;
use threads;
use threads::shared;

my $count_args = scalar(@ARGV);
my $start_dt = DateTime->now(time_zone  => "local");
my $start_formatted_dt = $start_dt->strftime('%d-%m-%Y %H:%M:%S');
my $community;
my $interval;
my $help;
my $timeout;
my $max;
my $hostname = $ARGV[0];
my $cisco = 1;
my @todisplay       : shared;
my $token       : shared;
$token = 0;
my $datapath;

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
	$max = $ARGV[++$i] if($ARGV[$i] eq '-m');
}

usage() unless(defined($hostname) and defined($community) and $hostname ne 'h' and $hostname ne '-h' and $hostname ne '--help');
$interval = 20 unless(defined($interval));
$timeout = 2 unless(defined($timeout));
$max = 10 unless(defined($max));

die('Interval too short (must be >= 5 sec)') if($interval < 5);
die('Invalid value 0 for max (must be > 0') if($max <= 0);

my $OID_ifDescr = '1.3.6.1.2.1.2.2.1.2';
my @reset_ip_acco_OID = ('1.3.6.1.4.1.9.2.4.11.0');
my @reset_ip_acco_OA_OID = ('.1.3.6.1.4.1.13191.10.3.1.2.3.10.0');

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

# Check if the router is a cisco or an OA
my $rq = $snmp->get_request(-varbindlist => \@reset_ip_acco_OID);
$cisco = (defined($rq->{$reset_ip_acco_OID[0]}) and $rq->{$reset_ip_acco_OID[0]} ne 'noSuchObject') ? 1 : 0;

if($cisco)
{
	$snmp->set_request($reset_ip_acco_OID[0], INTEGER, $rq->{$reset_ip_acco_OID[0]} );
}
else
{
	$snmp->set_request($reset_ip_acco_OA_OID[0], INTEGER, 1);
}

# Thread
my $request = sub {
	my $snmp = shift;
	my $max = shift;
	getTop($snmp, $max);
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

while(1)
{
	sleep($interval);
	# Create thread because the calculations to sort IP couples can be longer than expected
	threads->create($request, $snmp, $max);
}

sub getTop
{
	my $snmp = shift;
	my $max = shift;
	my $ip_acco_OID = '1.3.6.1.4.1.9.2.4.7.1.4';
	my @data;
	my @sorted;
	my @top;
	my $result_get_entries;
	my $dt = DateTime->now(time_zone  => "local");
	my $formatted_dt = $dt->strftime('%H:%M:%S');
	my $content = "$formatted_dt\nIp Source\t\tIp Destination\t\tTotal\n";
	my $start_max = $max;
	my $wait = 0;
	my $max_wait = 3;
	$max_wait = 150 if($max == 0);

	if($cisco)
	{
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
		$result_get_entries = $snmp->get_entries(-columns => [$ip_acco_OID],
                                           		-maxrepetitions => 3);

		$token = 0;
		unless(defined($result_get_entries))
		{
			push(@todisplay, "Ip accounting does not seem to be enabled on $hostname");
			return;
		}

		if(defined($result_get_entries))
		{
			foreach my $entry (keys(%$result_get_entries))
			{
				push(@data, { src => $entry , bty => $result_get_entries->{$entry} });
			}

		    # Decreasing sort
		    @sorted =  sort { $b->{bty} <=> $a->{bty} } @data;

		    $max = scalar(@sorted) if($max == 0);

		    # Index the array in a hash
		    for my $i ( 0 .. ($max - 1)) 
		    {
		    	my %entry;
		    	for my $key(keys(%{$sorted[$i]}) )
		    	{
			        if ($key eq 'src')
			        {
			           my ($oid,$valeur)=split(/1.3.6.1.4.1.9.2.4.7.1.4./,$sorted[$i]{$key});
			           if($valeur=~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/)
			           {
			         		$entry{'src'} = $1;
			         		$entry{'dest'} = $2;
			           }
			        }
			        if($key eq 'bty')
			        {
			        	$entry{'bytes'} = $sorted[$i]{$key};
		        	}
		    	}
		    	push(@top, \%entry);
		    }
		}
	}
	else
	{
		# OA
		$ip_acco_OID = '1.3.6.1.4.1.13191.10.3.1.2.3.2.1.4';
		my $ip_acco_src_OID = '1.3.6.1.4.1.13191.10.3.1.2.3.2.1.1';
		my $ip_acco_dst_OID = '1.3.6.1.4.1.13191.10.3.1.2.3.2.1.2';
		
		while($token == 1)
		{
			if($wait > $max_wait)
			{
				push (@todisplay, "Wait for SNMP request too long at ".$dt->strftime('%H:%M:%S')."\n");
				return;
			}
			sleep(2);
			$wait++;
		}
		$token = 1;

		my $result_get_entries = $snmp->get_entries(-columns => [$ip_acco_OID],
                                           		-maxrepetitions => 3);

		my $result_get_src_entries = $snmp->get_entries(-columns => [$ip_acco_src_OID],
                                           		-maxrepetitions => 3);

		my $result_get_dst_entries = $snmp->get_entries(-columns => [$ip_acco_dst_OID],
                                           		-maxrepetitions => 3);

		$token = 0;

		unless(defined($result_get_entries))
		{
			push(@todisplay, "Ip accounting does not seem to be enabled on $hostname");
			return;
		}

		foreach my $entry (keys(%$result_get_entries))
		{
			push(@data, { src => $entry , bty => $result_get_entries->{$entry} });
		}

		@sorted =  sort { $b->{bty} <=> $a->{bty} } @data;

		$max = scalar(@sorted) if($max == 0);

 		# Indexing in a hash
	    for my $i ( 0 .. ($max -1)) 
	    {
	    	my %entry;
	    	for my $key(keys(%{$sorted[$i]}) )
	    	{
		        if ($key eq 'src')
		        {
		           my ($oid,$valeur)=split(/1.3.6.1.4.1.13191.10.3.1.2.3.2.1.4./,$sorted[$i]{$key});
		           if($valeur=~ /^([0-9]+\.[0-9]+)$/)
		           {
		           		# Get the source and destination in the appropriate MIB
		           		if(defined($result_get_src_entries->{$ip_acco_src_OID.'.'.$valeur}) and defined($result_get_dst_entries->{$ip_acco_dst_OID.'.'.$valeur}))
		           		{
			         		$entry{'src'} = $result_get_src_entries->{$ip_acco_src_OID.'.'.$valeur};
			         		$entry{'dest'} = $result_get_dst_entries->{$ip_acco_dst_OID.'.'.$valeur};
		           		}
		           		else
		           		{
		           			next;
		           		}
		           }
		        }
		        if($key eq 'bty')
		        {
		        	$entry{'bytes'} = $sorted[$i]{$key};
	        	}
	    	}

	    	push(@top, \%entry);
	    }
	}

	return \@top unless($start_max);

	foreach my $result_ip_acco (@top)
	{
			$content .= ${$result_ip_acco}{'src'}."\t\t".${$result_ip_acco}{'dest'}."\t\t".formatValue(${$result_ip_acco}{'bytes'})."\n" if(defined(${$result_ip_acco}{'src'}));
	}
	push (@todisplay,$content);
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
	my $top_res = getTop($snmp, 0);
	my $total = 0;
	open(RESULT, '>'.$datapath.'recap_'.$hostname.'.csv');
	print RESULT 'Recapitulatif ip accounting '.$hostname.';Debut : '.$start_formatted_dt.';Fin : '.$formatted_dt."\n";
	print RESULT "IP Source;Ip Destination;Total\n";
	foreach my $result_ip_acco (@$top_res)
	{
		$total += ${$result_ip_acco}{'bytes'};
		print RESULT ${$result_ip_acco}{'src'}.";".${$result_ip_acco}{'dest'}.";".formatValue(${$result_ip_acco}{'bytes'})."\n" if(defined(${$result_ip_acco}{'src'}));
	}
	print RESULT ";Total;".formatValue($total);
	close(RESULT);
	exit(0);
}

sub usage
{
	print <<EOF;
	./$0 <hostname> -c <snmp community string> (-i <refresh interval in sec>) (-t <snmp timeout interval in sec>) (-h) -m <number of displayed \@ips>
	<hostname> : Hostname of the router      (Mandatory)
	-c : SNMP Community string of the router (Mandatory)
	-i : Refresh interval in sec             (Optionnal, default 20)
	-t : SNMP timeout interval in sec        (Optionnal, default 2)
	-m : number of displayed \@IPs           (Optionnal, default 10)
	-h : display this brief help
EOF
	exit(1);
}
