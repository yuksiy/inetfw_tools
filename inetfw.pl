#!/usr/bin/perl

# ==============================================================================
#   機能
#     Windows Firewall の設定
#   構文
#     USAGE 参照
#
#   Copyright (c) 2010-2017 Yukio Shiiya
#
#   This software is released under the MIT License.
#   https://opensource.org/licenses/MIT
# ==============================================================================

######################################################################
# 基本設定
######################################################################
use strict;
use warnings;

use utf8;

use Encode;
use Getopt::Long qw(GetOptionsFromArray :config gnu_getopt no_ignore_case);
use Text::ParseWords;
use Win32::API;
use Win32::Console;
use Win32::OLE;
use Win32::OLE::Const;

my $s_err = "";
$SIG{__DIE__} = $SIG{__WARN__} = sub { $s_err = $_[0]; };

$SIG{WINCH} = "IGNORE";
$SIG{HUP} = $SIG{INT} = $SIG{TERM} = sub { POST_PROCESS();exit 1; };

my ($cp, $ENCODING_LOCALE, $ENCODING_CONSOLE_IN);
Win32::API::More->Import("kernel32", "UINT GetACP()");
$cp = GetACP();
$ENCODING_LOCALE = ( ($cp eq "") ? "" : "cp$cp");

$cp = Win32::Console::InputCP();
$ENCODING_CONSOLE_IN = ( ($cp eq "") ? "" : "cp$cp");

######################################################################
# 変数定義
######################################################################
my %param = (
	rule => [ qw(name description enable dir profile group localip remoteip protocol type_code localport remoteport edge program service interfacetype rmtcomputergrp rmtusrgrp security action) ],
);

my $remark = <<EOF;
REMARKS:
Also see the restrictions on adding a rule described in the Remarks section of
the netsh help page obtained by executing the following command.
  netsh advfirewall firewall add rule ?
EOF

my $command = "";
my $mode = "";

my %DEBUG = ();
my $DEBUG_OPT;
my $SCRIPT_FILE = "";
my $result = 0;

my ($exec_success_count, $exec_failure_count);
my $line;
my @arg;
my $arg;
my $rc;

# cf. https://msdn.microsoft.com/en-us/library/aa378137.aspx
my $S_OK = 0x00000000;

# cf. Microsoft SDKs/Windows/v7.0A/Include/icftypes.h
my $NET_FW_EDGE_TRAVERSAL_TYPE_DENY = 0;
my $NET_FW_EDGE_TRAVERSAL_TYPE_ALLOW = $NET_FW_EDGE_TRAVERSAL_TYPE_DENY + 1;
my $NET_FW_EDGE_TRAVERSAL_TYPE_DEFER_TO_APP = $NET_FW_EDGE_TRAVERSAL_TYPE_ALLOW + 1;
my $NET_FW_EDGE_TRAVERSAL_TYPE_DEFER_TO_USER = $NET_FW_EDGE_TRAVERSAL_TYPE_DEFER_TO_APP + 1;

# cf. Microsoft SDKs/Windows/v7.0A/Include/WTypes.h
my $VARIANT_TRUE = -1;
my $VARIANT_FALSE = 0;

######################################################################
# 関数定義
######################################################################
sub PRE_PROCESS {
}

sub POST_PROCESS {
}

sub USAGE {
	my $command = $_[0];

	if ( $command eq "" ) {
		print STDOUT <<EOF;
Usage:
  Syntax1.
    inetfw.pl [OPTIONS ...] COMMAND
  Syntax2.
    inetfw.pl [OPTIONS ...] -f SCRIPT_FILE

COMMAND:
    add rule

OPTIONS:
    -f SCRIPT_FILE
       Specify a script file.
    -d DEBUG_OPT[,...]
       DEBUG_OPT : {PROP_SET}
    --help
       Display this help and exit.
EOF

	} elsif ( $command eq "add rule" ) {
		print STDOUT <<EOF;
Usage:
    inetfw.pl $command OPTIONS ...

OPTIONS:
    name=<string>
    [description=<string>]
    [enable=yes|no]
    dir=in|out
    [profile=public|private|domain|any[,...]]
    [group=<string>]
    [localip=any|<IPv4 address>|<IPv6 address>|<subnet>|<range>|<list>]
    [remoteip=any|localsubnet|dns|dhcp|wins|defaultgateway|<IPv4 address>|<IPv6 address>|<subnet>|<range>|<list>]
    [protocol=0-255|icmpv4|icmpv6|tcp|udp|any]
    [type_code=type:code[,...]]
    [localport=0-65535|<port range>[,...]|RPC|RPC-EPMap|IPHTTPS(NOT IMPLEMENTED!)|Ply2Disc|mDNS|any]
    [remoteport=0-65535|<port range>[,...]|any]
    [edge=yes|deferapp|deferuser|no]
    [program=<program path>]
    [service=<service short name>|any]
    [interfacetype=wireless|lan|ras|any]
    (NOT IMPLEMENTED!) [rmtcomputergrp=<SDDL string>]
    (NOT IMPLEMENTED!) [rmtusrgrp=<SDDL string>]
    (NOT IMPLEMENTED!) [security=authenticate|authenc|authdynenc|authnoencap|notrequired]
    action=allow|block|bypass(NOT IMPLEMENTED!)

$remark
EOF
	}
}

# コマンドの実行
sub EXEC_COMMAND {
	my @arg = @_;
	my @opt_not_implemented = ();
	my @opt_required = ();
	my $arg;
	my ($opt, $optarg);
	my %opt = ();

	# コマンドのチェック
	if ( not defined($arg[0]) ) {
		print STDERR "-E Missing COMMAND\n";
		USAGE();return 1;
	} else {
		if ( "$arg[0] $arg[1]" eq "add rule" ) {
			$command = "add rule";
			$mode = "rule";
			splice @arg, 0, 2;
		} else {
			print STDERR "-E Invalid COMMAND -- \"" . $arg[0] . ( ($arg[1] eq "") ? "" : " $arg[1]" ) . "\"\n";
			USAGE();return 1;
		}
	}

	# オプションのチェック
	if ( $command eq "add rule" ) {
		@opt_not_implemented = qw(rmtcomputergrp rmtusrgrp security);
		@opt_required = qw(name dir action);
	}
	foreach $arg (@arg) {
		($opt, $optarg) = split(/=/, $arg, 2);
		if ( (grep {m#^$opt$#} @{ $param{$mode} }) == 0 ) {
			print STDERR "-E Invalid option -- \"$opt\"\n";
			USAGE($command);return 1;
		}
		if ( (grep {m#^$opt$#} @opt_not_implemented) == 1 ) {
			print STDERR "-E Option not implemented -- \"$opt\"\n";
			USAGE($command);return 1;
		}
		if ( $optarg eq "" ) {
			print STDERR "-E Argument to \"$opt\" is missing\n";
			USAGE($command);return 1;
		}
		$opt{$opt} = $optarg;
	}
	foreach $opt (@opt_required) {
		if ( not defined($opt{$opt}) ) {
			print STDERR "-E Missing \"$opt\" option\n";
			USAGE($command);return 1;
		}
	}

	# コマンドの実行
	if ( $command eq "add rule" ) {
		return ADD_RULE(%opt);
	}
}

# ルールの追加
sub ADD_RULE {
	my %opt = @_;
	my $FwPolicy2;
	my $Rules;
	my $FWRule;
	my ($opt, $optarg);
	my ($prop, $propval);
	my $hresult;

	$FwPolicy2 = Win32::OLE->new("HNetCfg.FwPolicy2");
	if ( not defined($FwPolicy2) ) {
		print STDERR "-E Cannot start new instance -- \"HNetCfg.FwPolicy2\": $!\n";
		return 1;
	}
	$Rules = $FwPolicy2->{Rules};
	if ( not defined($Rules) ) {
		print STDERR "-E Cannot get property -- \"FwPolicy2::Rules\": $!\n";
		return 1;
	}
	$FWRule = Win32::OLE->new("HNetCfg.FWRule");
	if ( not defined($FWRule) ) {
		print STDERR "-E Cannot start new instance -- \"HNetCfg.FWRule\": $!\n";
		return 1;
	}
	foreach $opt (@{ $param{$mode} }) {
		if ( defined($opt{$opt}) ) {
			$optarg = $opt{$opt};
			($prop, $propval) = opt2prop($opt, $optarg);
			if ( $propval eq "" ) {
				print STDERR "-E Argument to \"$opt\" is invalid -- \"$optarg\"\n";
				USAGE($command);return 1;
			}
			print "$. DEBUG(PROP_SET) FWRule->{$prop} = $propval\n" if $DEBUG{PROP_SET};
			$FWRule->{$prop} = $propval;
			$hresult = Win32::OLE->LastError;
			if ( $hresult != $S_OK ) {
				print STDERR "-E Cannot set property -- \"FwRule::$prop = $propval\": $!\n";
				print STDERR "$hresult\n";
				return 1;
			}
		}
	}
	$Rules->Add($FWRule);
	$hresult = Win32::OLE->LastError;
	if ( $hresult != $S_OK ) {
		print STDERR "-E Add rule failed.\n";
		print STDERR "$hresult\n";
		print STDERR "\n$remark";
		return 1;
	} else {
		print "-I Add rule succeeded.\n";
		return 0;
	}
}

# オプションのプロパティ形式変換
sub opt2prop {
	my $opt = $_[0];
	my $optarg = $_[1];
	my $netfw;
	my ($prop, $propval) = ("", "");
	my $optarg_tmp;
	my @propval_tmp;
	my $rc;
	my ($type, $code);

	$netfw = Win32::OLE::Const->Load("NetFwTypeLib");
	if ( not defined($netfw) ) {
		print STDERR "-E Load constant definition failed -- \"NetFwTypeLib\": $!\n";
		return 1;
	}
	if ( $command eq "add rule" ) {
		if ( $opt eq "name" ) {
			$prop = "Name";
			$propval = $optarg;
		} elsif ( $opt eq "description" ) {
			$prop = "Description";
			$propval = $optarg;
		} elsif ( $opt eq "enable" ) {
			$prop = "Enabled";
			if ( $optarg eq "yes" ) {
				$propval = $VARIANT_TRUE;
			} elsif ( $optarg eq "no" ) {
				$propval = $VARIANT_FALSE;
			} else {
				$propval = "";
			}
		} elsif ( $opt eq "dir" ) {
			$prop = "Direction";
			if ( $optarg eq "in" ) {
				$propval = $netfw->{NET_FW_RULE_DIR_IN};
			} elsif ( $optarg eq "out" ) {
				$propval = $netfw->{NET_FW_RULE_DIR_OUT};
			} else {
				$propval = "";
			}
		} elsif ( $opt eq "profile" ) {
			$prop = "Profiles";
			$propval = 0;
			foreach $optarg_tmp (split(/,/, $optarg, -1)) {
				if ( $optarg_tmp eq "public" ) {
					$propval = $propval | $netfw->{NET_FW_PROFILE2_PUBLIC};
				} elsif ( $optarg_tmp eq "private" ) {
					$propval = $propval | $netfw->{NET_FW_PROFILE2_PRIVATE};
				} elsif ( $optarg_tmp eq "domain" ) {
					$propval = $propval | $netfw->{NET_FW_PROFILE2_DOMAIN};
				} elsif ( $optarg_tmp eq "any" ) {
					$propval = $propval | $netfw->{NET_FW_PROFILE2_ALL};
				}
			}
			if ( $propval == (
				$netfw->{NET_FW_PROFILE2_PUBLIC} |
				$netfw->{NET_FW_PROFILE2_PRIVATE} |
				$netfw->{NET_FW_PROFILE2_DOMAIN}
			) ) {
				$propval = $netfw->{NET_FW_PROFILE2_ALL};
			} elsif ( $propval == 0 ) {
				$propval = "";
			}
		} elsif ( $opt eq "group" ) {
			$prop = "Grouping";
			$propval = $optarg;
		} elsif ( $opt eq "localip" ) {
			$prop = "LocalAddresses";
			@propval_tmp = ();
			foreach $optarg_tmp (split(/,/, $optarg, -1)) {
				if ( $optarg_tmp eq "any" ) {
					push @propval_tmp, "*";
				} else {
					push @propval_tmp, $optarg_tmp;
				}
			}
			$propval = join ",", @propval_tmp;
		} elsif ( $opt eq "remoteip" ) {
			$prop = "RemoteAddresses";
			@propval_tmp = ();
			foreach $optarg_tmp (split(/,/, $optarg, -1)) {
				if ( $optarg_tmp eq "any" ) {
					push @propval_tmp, "*";
				} elsif ( $optarg_tmp eq "localsubnet" ) {
					push @propval_tmp, "LocalSubnet";
				} elsif ( $optarg_tmp eq "dns" ) {
					push @propval_tmp, "DNS";
				} elsif ( $optarg_tmp eq "dhcp" ) {
					push @propval_tmp, "DHCP";
				} elsif ( $optarg_tmp eq "wins" ) {
					push @propval_tmp, "WINS";
				} elsif ( $optarg_tmp eq "defaultgateway" ) {
					push @propval_tmp, "Defaultgateway";
				} else {
					push @propval_tmp, $optarg_tmp;
				}
			}
			$propval = join ",", @propval_tmp;
		} elsif ( $opt eq "protocol" ) {
			$prop = "Protocol";
			if ( $optarg eq "icmpv4" ) {
				$propval = 1;
			} elsif ( $optarg eq "icmpv6" ) {
				$propval = 58;
			} elsif ( $optarg eq "tcp" ) {
				$propval = 6;
			} elsif ( $optarg eq "udp" ) {
				$propval = 17;
			} elsif ( $optarg eq "any" ) {
				$propval = $netfw->{NET_FW_IP_PROTOCOL_ANY};
			} else {
				$rc = IS_NUMERIC($optarg);
				if ( $rc == 0 ) {
					$propval = $optarg;
				} else {
					$propval = "";
				}
			}
		} elsif ( $opt eq "type_code" ) {
			$prop = "IcmpTypesAndCodes";
			@propval_tmp = ();
			foreach $optarg_tmp (split(/,/, $optarg, -1)) {
				($type, $code) = split(/:/, $optarg_tmp, 2);
				$type =~ s#^any$#*#;
				$code =~ s#^any$#*#;
				push @propval_tmp, ($type . ":" . $code);
			}
			$propval = join ",", @propval_tmp;
		} elsif ( $opt eq "localport" ) {
			$prop = "LocalPorts";
			@propval_tmp = ();
			foreach $optarg_tmp (split(/,/, $optarg, -1)) {
				if ( $optarg_tmp eq "any" ) {
					push @propval_tmp, "*";
				} else {
					push @propval_tmp, $optarg_tmp;
				}
			}
			# 「@propval_tmp」に「IPHTTPS」が含まれている場合
			if ((grep {m#^(?:IPHTTPS)$#} @propval_tmp) >= 1) {
				@propval_tmp = ();
			}
			$propval = join ",", @propval_tmp;
		} elsif ( $opt eq "remoteport" ) {
			$prop = "RemotePorts";
			@propval_tmp = ();
			foreach $optarg_tmp (split(/,/, $optarg, -1)) {
				if ( $optarg_tmp eq "any" ) {
					push @propval_tmp, "*";
				} else {
					push @propval_tmp, $optarg_tmp;
				}
			}
			# 「@propval_tmp」に「RPC|RPC-EPMap|IPHTTPS」が含まれている場合
			if ((grep {m#^(?:RPC|RPC-EPMap|IPHTTPS)$#} @propval_tmp) >= 1) {
				@propval_tmp = ();
			}
			$propval = join ",", @propval_tmp;
		} elsif ( $opt eq "edge" ) {
			$prop = "EdgeTraversalOptions";
			if ( $optarg eq "yes" ) {
				$propval = $NET_FW_EDGE_TRAVERSAL_TYPE_ALLOW;
			} elsif ( $optarg eq "deferapp" ) {
				$propval = $NET_FW_EDGE_TRAVERSAL_TYPE_DEFER_TO_APP;
			} elsif ( $optarg eq "deferuser" ) {
				$propval = $NET_FW_EDGE_TRAVERSAL_TYPE_DEFER_TO_USER;
			} elsif ( $optarg eq "no" ) {
				$propval = $NET_FW_EDGE_TRAVERSAL_TYPE_DENY;
			} else {
				$propval = "";
			}
		} elsif ( $opt eq "program" ) {
			$prop = "ApplicationName";
			$propval = $optarg;
		} elsif ( $opt eq "service" ) {
			$prop = "ServiceName";
			if ( $optarg eq "any" ) {
				$propval = "*";
			} else {
				$propval = $optarg;
			}
		} elsif ( $opt eq "interfacetype" ) {
			$prop = "InterfaceTypes";
			@propval_tmp = ();
			foreach $optarg_tmp (split(/,/, $optarg, -1)) {
				if ( $optarg_tmp eq "wireless" ) {
					push @propval_tmp, "Wireless";
				} elsif ( $optarg_tmp eq "lan" ) {
					push @propval_tmp, "Lan";
				} elsif ( $optarg_tmp eq "ras" ) {
					push @propval_tmp, "RemoteAccess";
				} elsif ( $optarg_tmp eq "any" ) {
					push @propval_tmp, "All";
				} else {
					push @propval_tmp, $optarg_tmp;
				}
			}
			$propval = join ",", @propval_tmp;
		} elsif ( $opt eq "rmtcomputergrp" ) {
			#(NOT IMPLEMENTED!)#$prop = "";
			#(NOT IMPLEMENTED!)#$propval = $optarg;
		} elsif ( $opt eq "rmtusrgrp" ) {
			#(NOT IMPLEMENTED!)#$prop = "";
			#(NOT IMPLEMENTED!)#$propval = $optarg;
		} elsif ( $opt eq "security" ) {
			#(NOT IMPLEMENTED!)#$prop = "";
			#(NOT IMPLEMENTED!)#if ( $optarg eq "authenticate" ) {
			#(NOT IMPLEMENTED!)#	$propval = "";
			#(NOT IMPLEMENTED!)#} elsif ( $optarg eq "authenc" ) {
			#(NOT IMPLEMENTED!)#	$propval = "";
			#(NOT IMPLEMENTED!)#} elsif ( $optarg eq "authdynenc" ) {
			#(NOT IMPLEMENTED!)#	$propval = "";
			#(NOT IMPLEMENTED!)#} elsif ( $optarg eq "authnoencap" ) {
			#(NOT IMPLEMENTED!)#	$propval = "";
			#(NOT IMPLEMENTED!)#} elsif ( $optarg eq "notrequired" ) {
			#(NOT IMPLEMENTED!)#	$propval = "";
			#(NOT IMPLEMENTED!)#} else {
			#(NOT IMPLEMENTED!)#	$propval = "";
			#(NOT IMPLEMENTED!)#}
		} elsif ( $opt eq "action" ) {
			$prop = "Action";
			if ( $optarg eq "allow" ) {
				$propval = $netfw->{NET_FW_ACTION_ALLOW};
			} elsif ( $optarg eq "block" ) {
				$propval = $netfw->{NET_FW_ACTION_BLOCK};
			#(NOT IMPLEMENTED!)#} elsif ( $optarg eq "bypass" ) {
			#(NOT IMPLEMENTED!)#	$propval = "";
			} else {
				$propval = "";
			}
		}
	}
	$propval = encode($ENCODING_LOCALE, $propval);
	return ($prop, $propval);
}

use Common_pl::Is_numeric;

######################################################################
# メインルーチン
######################################################################

# オプションのチェック
if ( not eval { GetOptionsFromArray( \@ARGV,
	"f=s" => sub {
		$SCRIPT_FILE = $_[1];
		# スクリプトファイルのチェック
		if ( not -f $SCRIPT_FILE ) {
			print STDERR "-E SCRIPT_FILE not a file -- \"$SCRIPT_FILE\"\n";
			USAGE();exit 1;
		}
	},
	"d=s" => sub {
		if ( $_[1] ne "" ) {
			foreach $DEBUG_OPT (split(/,/, $_[1], -1)) {
				if ( $DEBUG_OPT =~ m#^(?:PROP_SET)$# ) {
					$DEBUG{$DEBUG_OPT} = 1;
				} else {
					print STDERR "-E \"DEBUG_OPT\" parameter in argument to \"-d\" is invalid -- \"$DEBUG_OPT\"\n";
					USAGE();exit 1;
				}
			}
		} else {
			print STDERR "-E argument to \"-d\" is missing\n";
			USAGE();exit 1;
		}
	},
	"help" => sub {
		USAGE();exit 0;
	},
) } ) {
	print STDERR "-E $s_err\n";
	USAGE();exit 1;
}

# オプションの整合性チェック
# SCRIPT_FILE オプションとCOMMAND 引数のうち、両方とも指定された場合
if ( ($SCRIPT_FILE ne "") and (@ARGV != 0) ) {
	print STDERR "-E Specify only one of \"COMMAND\" argument and \"SCRIPT_FILE\" option\n";
	USAGE();exit 1;
}

# 作業開始前処理
PRE_PROCESS();

#####################
# メインループ 開始 #
#####################
$exec_success_count = 0;
$exec_failure_count = 0;

# スクリプトファイルオプションが指定されている場合
if ( $SCRIPT_FILE ne "" ) {
	if ( not defined(open(SCRIPT_FILE, '<', $SCRIPT_FILE)) ) {
		print STDERR "-E SCRIPT_FILE cannot open -- \"$SCRIPT_FILE\": $!\n";
		POST_PROCESS();exit 1;
	}
	binmode(SCRIPT_FILE, ":encoding(utf8)");
	# スクリプトファイルから1行読み込み
	$line = <SCRIPT_FILE>;
# スクリプトファイルオプションが指定されていない場合
} else {
	@arg = ();
	foreach $arg (@ARGV) {
		push @arg, decode($ENCODING_CONSOLE_IN, $arg);
	}
	$line = join " ", @arg;
}

while ( $line ) {
	if ( ($line !~ m/^#/) and ($line !~ m/^$/) ) {
		# スクリプトファイルオプションが指定されている場合
		if ( $SCRIPT_FILE ne "" ) {
			chomp $line;
			@arg = quotewords('\s+', 0, $line);
			# 行番号の表示
			print "(Line:$.) ";
		}
		# コマンドの実行
		$rc = EXEC_COMMAND(@arg);
		if ( $rc != 0 ) {
			$result = 1;
			$exec_failure_count += 1;
		} else {
			$exec_success_count += 1;
		}
	}
	# スクリプトファイルオプションが指定されている場合
	if ( $SCRIPT_FILE ne "" ) {
		# スクリプトファイルから1行読み込み
		$line = <SCRIPT_FILE>;
	# スクリプトファイルオプションが指定されていない場合
	} else {
		$line = undef;
	}
}

# スクリプトファイルオプションが指定されている場合
if ( $SCRIPT_FILE ne "" ) {
	close(SCRIPT_FILE);
}

#####################
# メインループ 終了 #
#####################

# 処理終了メッセージの表示
print "\n";
print "Succeeded commands: $exec_success_count; Failed commands: $exec_failure_count\n";

# 作業終了後処理
POST_PROCESS();exit $result;

