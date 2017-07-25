#!/usr/bin/perl

# ==============================================================================
#   機能
#     netsh advfirewall の出力結果ファイルをフォーマット変換する
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
binmode(STDOUT, ":encoding(utf8)");
binmode(STDERR, ":encoding(utf8)");

use Config::IniFiles;
use Encode;
use Fcntl qw(:seek);
use Getopt::Long qw(GetOptionsFromArray :config gnu_getopt no_ignore_case);
use IO::Handle;
use NetAddr::IP;

autoflush STDOUT;flush STDOUT;
autoflush STDERR;flush STDERR;

my $s_err = "";
$SIG{__DIE__} = $SIG{__WARN__} = sub { $s_err = $_[0]; };

$SIG{WINCH} = "IGNORE";
$SIG{HUP} = $SIG{INT} = $SIG{TERM} = sub { POST_PROCESS();exit 1; };

######################################################################
# 変数定義
######################################################################
# ユーザ変数

# Windows 依存変数
my $REGKEY_FirewallRules = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\FirewallRules';

# プログラム内部変数
my %DEBUG = ();
my $DEBUG_OPT;
my $INPUT_FILE = "";
my $INPUT_MODE = "rule";
my $OUTPUT_FORMAT = "tsv";
my $REG_FILE = "";						#初期状態が「空文字」でなければならない変数
my %REG_FILE;
my %REG_FILE_tmp;

my @mode = qw(rule profile);
my $mode;

my %param = ();
my $param;

# (「INPUT_MODE=rule」である場合)
#   「chcp 437 & netsh advfirewall firewall show rule name=規則名 verbose」を
#   実行した時に表示されるフィールド名のうち、
#   「netsh advfirewall firewall set rule /?」を実行した時に表示されるパラメータに
#   (1)関連付けられるもの
#      前者の値を格納するハッシュの添え字として後者のパラメータ名を採用し、ここに列挙する。
#        name description enable dir profile group localip remoteip protocol localport remoteport edge program service interfacetype rmtcomputergrp rmtusrgrp security action
#
#   (2)関連付けられないもの
#      前者の値を格納するハッシュの添え字として、前者のフィールド名を
#      以下の規則で文字列変換した結果を採用し、ここに列挙する。
#        ・英大文字は英小文字に変換
#        ・空白文字は「_」に変換
#        rule_source
#
#   (3)上記以外のもの
#        type_code
#
#   上記(1)(2)(3)のハッシュの添え字を配列として宣言
#     ただし、記載順序は以下の順とする。
#       ・TSV形式で出力する際の列方向の順
# (「INPUT_MODE=profile」である場合)
#   「chcp 437 & netsh advfirewall show allprofiles」を
#   実行した時に表示されるフィールド名のうち、
#   「netsh advfirewall set allprofiles /?」を実行した時に表示されるパラメータに
#   (1)関連付けられるもの
#      前者の値を格納するハッシュの添え字として後者のパラメータ名を採用し、ここに列挙する。
#        state firewallpolicy localfirewallrules localconsecrules inboundusernotification remotemanagement unicastresponsetomulticast allowedconnections droppedconnections filename maxfilesize
#
#   (2)関連付けられないもの
#      name
#
#   上記(1)(2)のハッシュの添え字を配列として宣言
#     ただし、記載順序は以下の順とする。
#       ・TSV形式で出力する際の列方向の順
%param = (
	rule    => [ qw(name description enable dir profile group localip remoteip protocol type_code localport remoteport edge program service interfacetype rmtcomputergrp rmtusrgrp security rule_source action) ],
	profile => [ qw(name state firewallpolicy localfirewallrules localconsecrules inboundusernotification remotemanagement unicastresponsetomulticast allowedconnections droppedconnections filename maxfilesize) ],
);

# パラメータ引数区切り文字を格納するハッシュの宣言・初期化
my %sep = ();
%sep = (
	type_code => {
		orig => [ (";", ",") ],
		cmd  => [ (",", ":") ],
	},
);

# 「chcp 437 & netsh advfirewall show allprofiles」を
# 実行した時に表示されるプロファイル名のうち、
# 「netsh advfirewall set /?」を実行した時に表示されるパラメータに
# (1)関連付けられるもの
#    前者のプロファイル名を格納するハッシュの添え字として後者のパラメータ名を採用し、ここに列挙する。
#      domainprofile privateprofile publicprofile
#
# 上記(1)のハッシュの添え字を配列として宣言
#   ただし、記載順序は以下の順とする。
#     ・「netsh advfirewall show allprofiles」で出力される順
my @profile = qw(domainprofile privateprofile publicprofile);
my $profile;

# 入力ファイルとして入力可能な言語を表すハッシュの添え字を配列として宣言
#   ただし、記載順序は「en その他の言語... tsvcmd」の順とする。
#   上記の「en」を含めその他の言語を表す添え字は2文字の固定値とする。
#   上記の6文字の固定値「tsvcmd」は、「OUTPUT_FORMAT=tsvcmd」である場合に出力する
#   ヘッダ文字列を「%header」に格納する際に使用する添え字を表す。
my @lang = qw(en ja tsvcmd);
my $lang;

# 下方で「%field」「%header」を初期化する元となる文字列群を配列として宣言
#   ただし、記載順序は以下の順とする。
#   (「INPUT_MODE=rule」である場合)
#     ・「chcp 437 & netsh advfirewall firewall show rule name=規則名 verbose」
#        を実行した時に表示されるフィールド名 (「@{ $param{rule} }」の順)
#     ・「chcp その他の言語のコードページ番号 & netsh advfirewall firewall show rule name=規則名 verbose」
#        を実行した時に表示されるフィールド名 (「@{ $param{rule} }」の順)
#         :
#     ・「OUTPUT_FORMAT=tsvcmd」である場合に出力するヘッダ文字列
#       (「@{ $param{rule} }」の順)
#   (「INPUT_MODE=profile」である場合)
#     ・「chcp 437 & netsh advfirewall show allprofiles」
#        を実行した時に表示されるフィールド名 (「@{ $param{profile} }」の順)
#     ・「chcp その他の言語のコードページ番号 & netsh advfirewall show allprofiles」
#        を実行した時に表示されるフィールド名 (「@{ $param{profile} }」の順)
#         :
#     ・「OUTPUT_FORMAT=tsvcmd」である場合に出力するヘッダ文字列
#       (「@{ $param{profile} }」の順)
my %field_all = ();
%field_all = (
	rule => [ 
		"Rule Name","Description","Enabled","Direction","Profiles"    ,"Grouping","LocalIP"    ,"RemoteIP"   ,"Protocol"  ,"Type@{$sep{type_code}{orig}}[1]Code[@{$sep{type_code}{orig}}[0]...]","LocalPort"      ,"RemotePort"     ,"Edge traversal"     ,"Program"   ,"Service" ,"InterfaceTypes"        ,"RemoteComputerGroup"             ,"RemoteUserGroup"           ,"Security"    ,"Rule source"  ,"Action",
		"規則名"   ,"説明"       ,"有効"   ,"方向"     ,"プロファイル","グループ","ローカル IP","リモート IP","プロトコル","Type@{$sep{type_code}{orig}}[1]Code[@{$sep{type_code}{orig}}[0]...]","ローカル ポート","リモート ポート","エッジ トラバーサル","プログラム","サービス","インターフェイスの種類","リモート コンピューター グループ","リモート ユーザー グループ","セキュリティ","規則のソース" ,"操作",
		"name"     ,"description","enable" ,"dir"      ,"profile"     ,"group"   ,"localip"    ,"remoteip"   ,"protocol"  ,"type@{$sep{type_code}{cmd}}[1]code[@{$sep{type_code}{cmd}}[0]...]"  ,"localport"      ,"remoteport"     ,"edge"               ,"program"   ,"service" ,"interfacetype"         ,"rmtcomputergrp"                  ,"rmtusrgrp"                 ,"security"    ,"(rule_source)","action",
	],
	profile => [ 
		"Profile Name"  ,"State","Firewall Policy","LocalFirewallRules","LocalConSecRules","InboundUserNotification","RemoteManagement","UnicastResponseToMulticast","LogAllowedConnections","LogDroppedConnections","FileName","MaxFileSize",
		"プロファイル名","State","Firewall Policy","LocalFirewallRules","LocalConSecRules","InboundUserNotification","RemoteManagement","UnicastResponseToMulticast","LogAllowedConnections","LogDroppedConnections","FileName","MaxFileSize",
		"(name)"        ,"state","firewallpolicy" ,"localfirewallrules","localconsecrules","inboundusernotification","remotemanagement","unicastresponsetomulticast","allowedconnections"   ,"droppedconnections"   ,"filename","maxfilesize",
	],
);
my @field_tmp;

# 下方で「%profile」を初期化する元となる文字列群を配列として宣言
#   ただし、記載順序は以下の順とする。
#     ・「chcp 437 & netsh advfirewall show allprofiles」
#        を実行した時に表示されるプロファイル名 (「@profile」の順)
#     ・「chcp その他の言語のコードページ番号 & netsh advfirewall show allprofiles」
#        を実行した時に表示されるプロファイル名 (「@profile」の順)
my @profile_all = (
	"Domain Profile Settings"   ,"Private Profile Settings"      ,"Public Profile Settings",
	"ドメイン プロファイル 設定","プライベート プロファイル 設定","パブリック プロファイル 設定",
);
my @profile_tmp;

# 入力ファイル終端文字列を格納するハッシュの宣言・初期化
#   ただし、記載順序は以下の順とする。
#     ・「chcp 437 & netsh advfirewall firewall show rule name=規則名 verbose」、および
#       「chcp 437 & netsh advfirewall show allprofiles」
#        を実行した時に表示される入力ファイル終端文字列
#     ・「chcp その他の言語のコードページ番号 & netsh advfirewall firewall show rule name=規則名 verbose」、および
#       「chcp その他の言語のコードページ番号 & netsh advfirewall show allprofiles」
#        を実行した時に表示される入力ファイル終端文字列
#         :
my @eof_all = (
	"Ok.",
	"OK" ,
);
my @eof_tmp;

my %field = ();
my %header = ();
my %profile = ();
my %eof = ();

my $input_lang;
my $line;
my ($field, $value);
my $value_tmp;
my ($reg_key, $reg_val);
my %reg;
my ($input_file_line_count, $name_line);
my %value;
my $field_sentinel;
my ($icmp_sentinel, $pos_save);
my ($type, $code);
my $type_cmd;
my $code_cmd;
my ($record_reg_key, $record_reg_key_sentinel);
my @value_addr;
my @reg_addr;
my $value_addr;
my $reg_addr;
my ($value_addr_from, $value_addr_to);
my ($reg_addr_from, $reg_addr_to);
my ($value_ip_from, $value_ip_to);
my ($reg_ip_from, $reg_ip_to);
my @record;
my @record_reason;
my $record_reason;

######################################################################
# サブルーチン定義
######################################################################
sub PRE_PROCESS {
}

sub POST_PROCESS {
}

sub USAGE {
	print STDOUT <<EOF;
Usage:
    inetfw_netsh.pl [OPTIONS ...] INPUT_FILE

    INPUT_FILE:
      Specify an input file obtained by executing the following command.
        Case of "INPUT_MODE=rule":
          chcp CODE_PAGE_NUMBER
          netsh advfirewall firewall show rule name=all verbose 2>&1 | iconv -f ENCODING -t UTF-8 2>&1 | dos2unix > INPUT_FILE
        Case of "INPUT_MODE=profile":
          chcp CODE_PAGE_NUMBER
          netsh advfirewall show allprofiles                    2>&1 | iconv -f ENCODING -t UTF-8 2>&1 | dos2unix > INPUT_FILE

OPTIONS:
    -t INPUT_MODE
       INPUT_MODE : {rule|profile}
       (default: $INPUT_MODE)
    -f OUTPUT_FORMAT
       OUTPUT_FORMAT : {tsv|tsvcmd|cmd}
       "OUTPUT_FORMAT=cmd" is supported only when "INPUT_MODE=rule".
       (default: $OUTPUT_FORMAT)
    -r REG_FILE
       Specify a registry file obtained by executing the following command.
         reg export "$REGKEY_FirewallRules" REG_FILE_TMP
         cat REG_FILE_TMP | iconv -f UTF-16LE -t UTF-8 2>&1 | dos2unix | sed "1s/^/#/" > REG_FILE
         del /f REG_FILE_TMP
       This option is supported only when "INPUT_MODE=rule".
       If this option is specified, the following routines are performed by
       using REG_FILE.
         * The value of the program field in firewall rule which is variable-
           expanded by netsh command is restored to the original value.
    -d DEBUG_OPT[,...]
       DEBUG_OPT : {REG_MATCH}
    --help
       Display this help and exit.
EOF
}

# フィールド・値の分割
sub SPLIT_FIELD_VALUE_COLON {
	my $line = $_[0];
	my ($field, $value);

	($field, $value) = split(/: {1,}/, $line, 2);
	if ( not defined($field) ) {
		$field = "";
	}
	if ( not defined($value) ) {
		$value = "";
	}
	return ($field, $value);
}
sub SPLIT_FIELD_VALUE_SPACE {
	my $line = $_[0];
	my ($field, $value);

	($field, $value) = split(/ {2,}/, $line, 2);
	if ( not defined($field) ) {
		$field = "";
	}
	if ( not defined($value) ) {
		$value = "";
	}
	return ($field, $value);
}

# 2つの値の分割
sub SPLIT_2_VALUES {
	my $line = $_[0];
	my ($value1, $value2);

	if ($line =~ m#^\s+#) {
		$line =~ s#^\s+([^\s]+)\s+([^\s]+).*$#$1\t$2#;
		($value1, $value2) = split(/\t/, $line, 2);
		if ( not defined($value1) ) {
			$value1 = "";
		}
		if ( not defined($value2) ) {
			$value2 = "";
		}
		return ($value1, $value2);
	} else {
		return ();
	}
}

# フィールドのエスケープ
sub ESCAPE_FIELD {
	my $field = $_[0];

	# フィールドに含まれる内部情報の隠蔽
	# 何もしない (「OUTPUT_FORMAT=tsvcmd」または「OUTPUT_FORMAT=cmd」である場合の出力が不完全になるため)
	# フィールドに含まれるダブルクォートを2つ並べてエスケープ
	$field =~ s#"#""#g;
	# フィールドをダブルクォートで囲む
	$field = '"' . $field . '"';
	return $field;
}

# コマンドラインのエスケープ
sub ESCAPE_CMD {
	my $cmd = $_[0];
	# DOS/Win のファイル名として使用できない文字
	my $chars_unusable_as_filename_of_doswin = '\\\|\/\:\?\"\*\<\>';

	# $cmd が複数のダブルクォート・「%環境変数名%」・空白文字を含む場合
	# (例1(「"」を含む場合)：
	#    a "b b" c)
	# (例2(「%環境変数名%」以外で始まり「%環境変数名%」以外で終わる場合)：
	#    a%VAR1%\b%VAR2%b\cc d%VAR3%d.exe)
	# (例3(「%環境変数名%」で始まり「%環境変数名%」で終わる場合)：
	#    %VAR1%\b%VAR2%b\cc d%VAR3%)
	# 全ての「\」を「\\」でエスケープ
	# 全てのダブルクォートを「\」でエスケープ
	# 「%環境変数名%」以外の全ての部分をダブルクォートで囲む
	# #中止#「%環境変数名%」を「^%環境変数名^%」に変換
	# (例1："a \\"b b\\" c")
	# (例2："a"%VAR1%"\\b"%VAR2%"b\\cc d"%VAR3%"d.exe")
	# (例3：""%VAR1%"\\b"%VAR2%"b\\cc d"%VAR3%"")
	$cmd =~ s#\\#\\\\#g;
	$cmd =~ s#"#\\"#g;
	$cmd = '"' . $cmd . '"';
	$cmd =~ s#%([^%\Q$chars_unusable_as_filename_of_doswin\E]+)%#"%$1%"#g;
	# $cmd が「""」でない場合、全ての「""」を削除
	if ($cmd ne '""') {
		$cmd =~ s#""##g;
	}
	return $cmd;
}

# 値のコマンド形式変換
sub VALUE2CMD {
	my $field = $_[0];
	my $value = $_[1];

	if ($INPUT_MODE eq "rule") {
		if ($field eq "description") {
			$value_tmp = INDIRECT_STR_LOAD($value);
			if ( $value_tmp !~ m#^-E Load indirect string failed# ) {
				$value = $value_tmp;
			}
		} elsif ($field eq "enable") {
			$value =~ s#^(?:Yes|はい)$#yes#;
			$value =~ s#^(?:No|いいえ)$#no#;
		} elsif ($field eq "dir") {
			$value =~ s#^(?:In|入力)$#in#;
			$value =~ s#^(?:Out|出力)$#out#;
		} elsif ($field eq "profile") {
			$value =~ s#(?:Public|パブリック)#public#g;
			$value =~ s#(?:Private|プライベート)#private#g;
			$value =~ s#(?:Domain|ドメイン)#domain#g;
			#使用中止#$value =~ s#^(?:domain,private,public)$#any#;
		} elsif ($field eq "group") {
			$value_tmp = INDIRECT_STR_LOAD($value);
			if ( $value_tmp !~ m#^-E Load indirect string failed# ) {
				$value = $value_tmp;
			}
		} elsif ($field eq "localip") {
			$value =~ s#(?:Any|任意)#any#;
		} elsif ($field eq "remoteip") {
			$value =~ s#(?:Any|任意)#any#;
			$value =~ s#(?:LocalSubnet)#localsubnet#;
			$value =~ s#(?:DNS)#dns#;
			$value =~ s#(?:DHCP)#dhcp#;
			$value =~ s#(?:WINS)#wins#;
			$value =~ s#(?:DefaultGateway)#defaultgateway#;
		} elsif ($field eq "protocol") {
			$value =~ s#(?:ICMPv4)#icmpv4#;
			$value =~ s#(?:ICMPv6)#icmpv6#;
			$value =~ s#(?:TCP)#tcp#;
			$value =~ s#(?:UDP)#udp#;
			$value =~ s#(?:Any|任意)#any#;
		} elsif ($field eq "type_code") {
			$value =~ s#^(?:Type)$#type#;
			$value =~ s#^(?:Code)$#code#;
			$value =~ s#^(?:Any|任意)$#any#;
		} elsif ($field eq "localport") {
			$value =~ s#(?:RPC)#RPC#;
			$value =~ s#(?:RPC-EPMap)#RPC-EPMap#;
			$value =~ s#(?:IPHTTPS)#IPHTTPS#;
			$value =~ s#(?:Ply2Disc)#Ply2Disc#;
			$value =~ s#(?:mDNS)#mDNS#;
			$value =~ s#(?:Any|任意)#any#;
		} elsif ($field eq "remoteport") {
			$value =~ s#(?:Any|任意)#any#;
		} elsif ($field eq "edge") {
			$value =~ s#^(?:Yes|はい)$#yes#;
			$value =~ s#^(?:Defer to application|アプリケーションに従う)$#deferapp#;
			$value =~ s#^(?:Defer to user|ユーザーに従う)$#deferuser#;
			$value =~ s#^(?:No|いいえ)$#no#;
		} elsif ($field eq "program") {
		} elsif ($field eq "service") {
			$value =~ s#^(?:Any|任意)$#any#;
		} elsif ($field eq "interfacetype") {
			$value =~ s#(?:Wireless|ワイヤレス)#wireless#;
			$value =~ s#(?:LAN)#lan#;
			$value =~ s#(?:RAS)#ras#;
			$value =~ s#(?:Any|任意)#any#;
		} elsif ($field eq "rmtcomputergrp") {
		} elsif ($field eq "rmtusrgrp") {
		} elsif ($field eq "security") {
			$value =~ s#^(?:Authenticate)$#authenticate#;
			$value =~ s#^(?:AuthEnc)$#authenc#;
			$value =~ s#^(?:AuthDynEnc)$#authdynenc#;
			$value =~ s#^(?:AuthNoEncap)$#authnoencap#;
			$value =~ s#^(?:NotRequired)$#notrequired#;
		} elsif ($field eq "rule_source") {
			$value =~ s#^(?:Local Setting|ローカル設定)$#local_setting#;
		} elsif ($field eq "action") {
			$value =~ s#^(?:Allow|許可)$#allow#;
			$value =~ s#^(?:Block|ブロック)$#block#;
			$value =~ s#^(?:Bypass|バイパス)$#bypass#;
		}
	} elsif ($INPUT_MODE eq "profile") {
		if ($field eq "state") {
			$value =~ s#^(?:ON|オン)$#on#;
			$value =~ s#^(?:OFF|オフ)$#off#;
		} elsif ($field eq "firewallpolicy") {
			$value =~ s#^BlockInbound,#blockinbound,#;
			$value =~ s#^BlockInboundAlways,#blockinboundalways,#;
			$value =~ s#^AllowInbound,#allowinbound,#;
			$value =~ s#,AllowOutbound$#,allowoutbound#;
			$value =~ s#,BlockOutbound$#,blockoutbound#;
		} elsif ($field eq "localfirewallrules") {
		} elsif ($field eq "localconsecrules") {
		} elsif ( ($field eq "inboundusernotification") or
			($field eq "remotemanagement") or
			($field eq "unicastresponsetomulticast") or
			($field eq "allowedconnections") or
			($field eq "droppedconnections") ) {
			$value =~ s#^(?:Enable|有効)$#enable#;
			$value =~ s#^(?:Disable|無効)$#disable#;
		} elsif ($field eq "filename") {
		} elsif ($field eq "maxfilesize") {
		}
	}
	return $value;
}

# レジストリ値のコマンド形式変換
sub REGVAL2CMD {
	my $regval = $_[0];
	my @regval_expr;
	my $regval_expr;
	my ($field, $value);
	my @field;
	my %value;
	my %reg_val;
	my $reg_val;
	my %reg;

	@regval_expr = split(/\|/, $regval, 0);
	%reg_val = ();
	foreach $regval_expr (@regval_expr) {
		($field, $value) = split(/=/, $regval_expr, 2);
		if ( defined($value) ) {
			push @{ $reg_val{$field} }, $value;
		} else {
			push @{ $reg_val{$field} }, "";
		}
	}
	%reg = ();
	if ($INPUT_MODE eq "rule") {
		$field = "Name";
		if ( defined($reg_val{$field}) ) {
			$value = @{ $reg_val{$field} }[0];
			$value_tmp = INDIRECT_STR_LOAD($value);
			if ( $value_tmp !~ m#^-E Load indirect string failed# ) {
				$reg{name} = $value_tmp;
			} else {
				$reg{name} = $value;
			}
		}

		$field = "Desc";
		if ( defined($reg_val{$field}) ) {
			$value = @{ $reg_val{$field} }[0];
			$value_tmp = INDIRECT_STR_LOAD($value);
			if ( $value_tmp !~ m#^-E Load indirect string failed# ) {
				$reg{description} = $value_tmp;
			} else {
				$reg{description} = $value;
			}
		}

		$field = "Active";
		if ( defined($reg_val{$field}) ) {
			$value = @{ $reg_val{$field} }[0];
			$value =~ s#^(?:TRUE)$#yes#;
			$value =~ s#^(?:FALSE)$#no#;
			$reg{enable} = $value;
		}

		$field = "Dir";
		if ( defined($reg_val{$field}) ) {
			$value = @{ $reg_val{$field} }[0];
			$value =~ s#^(?:In)$#in#;
			$value =~ s#^(?:Out)$#out#;
			$reg{dir} = $value;
		}

		$field = "Profile";
		if ( defined($reg_val{$field}) ) {
			$value = "";
			foreach $reg_val (@{ $reg_val{$field} }) {
				$reg_val =~ s#^(?:Public)$#public#;
				$reg_val =~ s#^(?:Private)$#private#;
				$reg_val =~ s#^(?:Domain)$#domain#;
				$value .= ",$reg_val";
			}
			$value =~ s#^,##;
			$reg{profile} = $value;
		} else {
			$reg{profile} = "domain,private,public";
		}

		$field = "EmbedCtxt";
		if ( defined($reg_val{$field}) ) {
			$value = @{ $reg_val{$field} }[0];
			$value_tmp = INDIRECT_STR_LOAD($value);
			if ( $value_tmp !~ m#^-E Load indirect string failed# ) {
				$reg{group} = $value_tmp;
			} else {
				$reg{group} = $value;
			}
		}

		@field = qw(LA4 LA6);
		undef $value;
		foreach $field (@field) {
			if ( defined($reg_val{$field}) ) {
				foreach $reg_val (@{ $reg_val{$field} }) {
					$value .= ",$reg_val";
				}
			}
		}
		if ( defined($value) ) {
			$value =~ s#^,##;
			$reg{localip} = $value;
		} else {
			$reg{localip} = "any";
		}

		@field = qw(RA4 RA6);
		undef $value;
		%value = ();
		foreach $field (@field) {
			if ( defined($reg_val{$field}) ) {
				foreach $reg_val (@{ $reg_val{$field} }) {
					$reg_val =~ s#^(?:LocalSubnet)$#localsubnet#;
					$reg_val =~ s#^(?:DNS)$#dns#;
					$reg_val =~ s#^(?:DHCP)$#dhcp#;
					$reg_val =~ s#^(?:WINS)$#wins#;
					$reg_val =~ s#^(?:DefaultGateway)$#defaultgateway#;
					if ($reg_val =~ m#^(?:localsubnet|dns|dhcp|wins|defaultgateway)$#) {
						$value{$field}{$reg_val} = 1;
					} else {
						$value .= ",$reg_val";
					}
				}
			}
		}
		@field = qw(localsubnet dns dhcp wins defaultgateway);
		foreach $field (@field) {
			if ( (defined($value{RA4}{$field})) or
				(defined($value{RA6}{$field})) ) {
				$value .= ",$field";
			}
		}
		if ( defined($value) ) {
			$value =~ s#^,##;
			$reg{remoteip} = $value;
		} else {
			$reg{remoteip} = "any";
		}

		$field = "Protocol";
		if ( defined($reg_val{$field}) ) {
			$value = @{ $reg_val{$field} }[0];
			$value =~ s#^(?:1)$#icmpv4#;
			$value =~ s#^(?:58)$#icmpv6#;
			$value =~ s#^(?:6)$#tcp#;
			$value =~ s#^(?:17)$#udp#;
			$reg{protocol} = $value;
		} else {
			$reg{protocol} = "any";
		}

		if ( ($reg{protocol} eq "icmpv4") or
			($reg{protocol} eq "icmpv6") ) {
			if ($reg{protocol} eq "icmpv4") {
				$field = "ICMP4";
			} elsif ($reg{protocol} eq "icmpv6") {
				$field = "ICMP6";
			}
			undef $value;
			if ( defined($reg_val{$field}) ) {
				foreach $reg_val (@{ $reg_val{$field} }) {
					$reg_val =~ s#\*#any#g;
					$value .= "@{$sep{type_code}{cmd}}[0]$reg_val";
				}
			}
			if ( defined($value) ) {
				$value =~ s#^@{$sep{type_code}{cmd}}[0]##;
				$reg{type_code} = $value;
			} else {
				$reg{type_code} = "any@{$sep{type_code}{cmd}}[1]any";
			}
		}

		if ( ($reg{protocol} eq "tcp") or
			($reg{protocol} eq "udp") ) {
			@field = qw(LPort LPort2_10 LPort2_20 LPort2_24);
			undef $value;
			%value = ();
			foreach $field (@field) {
				if ( defined($reg_val{$field}) ) {
					foreach $reg_val (@{ $reg_val{$field} }) {
						if ($reg_val =~ m#^(?:RPC|RPC-EPMap|IPHTTPSIn|IPTLSIn|Ply2Disc|mDNS)$#) {
							$value{$field}{$reg_val} = 1;
						} else {
							$value .= ",$reg_val";
						}
					}
				}
			}
			if ( defined($value{LPort}{"RPC"}) ) {
				$value .= ",RPC";
			}
			if ( defined($value{LPort}{"RPC-EPMap"}) ) {
				$value .= ",RPC-EPMap";
			}
			if ( (defined($value{LPort2_10}{"IPHTTPSIn"})) and
				(defined($value{LPort2_10}{"IPTLSIn"})) ) {
				$value .= ",IPHTTPS";
			}
			if ( defined($value{LPort2_20}{"Ply2Disc"}) ) {
				$value .= ",Ply2Disc";
			}
			if ( defined($value{LPort2_24}{"mDNS"}) ) {
				$value .= ",mDNS";
			}
			if ( defined($value) ) {
				$value =~ s#^,##;
				$reg{localport} = $value;
			} else {
				$reg{localport} = "any";
			}
		}

		if ( ($reg{protocol} eq "tcp") or
			($reg{protocol} eq "udp") ) {
			@field = qw(RPort RPort2_10);
			undef $value;
			%value = ();
			foreach $field (@field) {
				if ( defined($reg_val{$field}) ) {
					foreach $reg_val (@{ $reg_val{$field} }) {
						if ($reg_val =~ m#^(?:IPHTTPSOut|IPTLSOut)$#) {
							$value{$field}{$reg_val} = 1;
						} else {
							$value .= ",$reg_val";
						}
					}
				}
			}
			if ( (defined($value{RPort2_10}{"IPHTTPSOut"})) and
				(defined($value{RPort2_10}{"IPTLSOut"})) ) {
				$value .= ",IPHTTPS";
			}
			if ( defined($value) ) {
				$value =~ s#^,##;
				$reg{remoteport} = $value;
			} else {
				$reg{remoteport} = "any";
			}
		}

		@field = qw(Edge Defer);
		undef $value;
		%value = ();
		foreach $field (@field) {
			if ( defined($reg_val{$field}) ) {
				foreach $reg_val (@{ $reg_val{$field} }) {
					$value{$field} = $reg_val;
				}
			}
		}
		if ($value{Edge} eq "TRUE") {
			if ($value{Defer} eq "App") {
				$value = "deferapp";
			} else {
				$value = "yes";
			}
		} else {
			if ($value{Defer} eq "User") {
				$value = "deferuser";
			} else {
				$value = "no";
			}
		}
		if ( defined($value) ) {
			$reg{edge} = $value;
		}

		$field = "App";
		if ( defined($reg_val{$field}) ) {
			$value = @{ $reg_val{$field} }[0];
			$reg{program} = $value;
		}

		$field = "Svc";
		if ( defined($reg_val{$field}) ) {
			$value = @{ $reg_val{$field} }[0];
			$value =~ s#^(?:\*)$#any#;
			$reg{service} = $value;
		}

		$field = "IFType";
		if ( defined($reg_val{$field}) ) {
			$value = "";
			foreach $reg_val (@{ $reg_val{$field} }) {
				$reg_val =~ s#^(?:Wireless)$#wireless#;
				$reg_val =~ s#^(?:LAN)$#lan#;
				$reg_val =~ s#^(?:RemoteAccess)$#ras#;
				$value .= ",$reg_val";
			}
			$value =~ s#^,##;
			$reg{interfacetype} = $value;
		} else {
			$reg{interfacetype} = "any";
		}

		$field = "RMauth";
		if ( defined($reg_val{$field}) ) {
			$value = @{ $reg_val{$field} }[0];
			$reg{rmtcomputergrp} = $value;
		}

		$field = "RUAuth";
		if ( defined($reg_val{$field}) ) {
			$value = @{ $reg_val{$field} }[0];
			$reg{rmtusrgrp} = $value;
		}

		@field = qw(Security Security2 Security2_9);
		undef $value;
		%value = ();
		foreach $field (@field) {
			if ( defined($reg_val{$field}) ) {
				foreach $reg_val (@{ $reg_val{$field} }) {
					$value{$field} = $reg_val;
				}
			}
		}
		if ($value{Security} eq "Authenticate") {
			if ($value{Security2_9} eq "An-NoEncap") {
				$value = "authnoencap";
			} else {
				$value = "authenticate";
			}
		} elsif ($value{Security} eq "AuthenticateEncrypt") {
			if ($value{Security2} eq "AnE-Nego") {
				$value = "authdynenc";
			} else {
				$value = "authenc";
			}
		}
		if ( defined($value) ) {
			$reg{security} = $value;
		} else {
			$reg{security} = "notrequired";
		}

		$field = "Action";
		if ( defined($reg_val{$field}) ) {
			$value = @{ $reg_val{$field} }[0];
			$value =~ s#^(?:Allow)$#allow#;
			$value =~ s#^(?:Block)$#block#;
			$value =~ s#^(?:Bypass)$#bypass#;
			$reg{action} = $value;
		}
	} elsif ($INPUT_MODE eq "profile") {
	}
	return \%reg;
}

use Common_pl::Win32::API::Indirect_str_load;

######################################################################
# メインルーチン
######################################################################

# オプションのチェック
if ( not eval { GetOptionsFromArray( \@ARGV,
	"t=s" => sub {
		if ( $_[1] =~ m#^(?:rule|profile)$# ) {
			$INPUT_MODE = $_[1];
		} else {
			print STDERR "-E Argument to \"-$_[0]\" is invalid -- \"$_[1]\"\n";
			USAGE();exit 1;
		}
	},
	"f=s" => sub {
		if ( $_[1] =~ m#^(?:tsv|tsvcmd|cmd)$# ) {
			$OUTPUT_FORMAT = $_[1];
		} else {
			print STDERR "-E Argument to \"-$_[0]\" is invalid -- \"$_[1]\"\n";
			USAGE();exit 1;
		}
	},
	"r=s" => sub {
		$REG_FILE = $_[1];
		# レジストリファイルのチェック
		if ( not -f $REG_FILE ) {
			print STDERR "-E REG_FILE not a file -- \"$REG_FILE\"\n";
			USAGE();exit 1;
		}
	},
	"d=s" => sub {
		if ( $_[1] ne "" ) {
			foreach $DEBUG_OPT (split(/,/, $_[1], -1)) {
				if ( $DEBUG_OPT =~ m#^(?:REG_MATCH)$# ) {
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
# 「OUTPUT_FORMAT=cmd」である場合、かつ「INPUT_MODE=rule」でない場合
if ( ($OUTPUT_FORMAT eq "cmd") and ($INPUT_MODE ne "rule") ) {
	print STDERR "-E \"OUTPUT_FORMAT=cmd\" is supported only when \"INPUT_MODE=rule\"\n";
	USAGE();exit 1;
}
# REG_FILE オプションが指定されている場合、かつ「INPUT_MODE=rule」でない場合
if ( ($REG_FILE ne "") and ($INPUT_MODE ne "rule") ) {
	print STDERR "-E REG_FILE option is supported only when \"INPUT_MODE=rule\"\n";
	USAGE();exit 1;
}

# 第1引数のチェック
if ( not defined($ARGV[0]) ) {
	print STDERR "-E Missing INPUT_FILE argument\n";
	USAGE();exit 1;
} else {
	$INPUT_FILE = $ARGV[0];
	# 入力ファイルのチェック
	if ( not -f "$INPUT_FILE" ) {
		print STDERR "-E INPUT_FILE not a file -- \"$INPUT_FILE\"\n";
		USAGE();exit 1;
	}
}

# フィールド文字列を格納するハッシュの初期化
foreach $mode (@mode) {
	@field_tmp = @{ $field_all{$mode} };
	foreach $lang (grep {not m#^(?:tsvcmd)$#} @lang) {
		foreach $param (@{ $param{$mode} }) {
			if (@field_tmp != 0) {
				$field{$mode}{$lang}{$param} = shift @field_tmp;
			} else {
				print STDERR "-E Initialize \%field failed\n";
				exit 1;
			}
		}
	}
}

# ヘッダ文字列を格納するハッシュの初期化
foreach $mode (@mode) {
	@field_tmp = @{ $field_all{$mode} };
	foreach $lang (@lang) {
		foreach $param (@{ $param{$mode} }) {
			if (@field_tmp != 0) {
				$header{$mode}{$lang}{$param} = shift @field_tmp;
			} else {
				print STDERR "-E Initialize \%header failed\n";
				exit 1;
			}
		}
	}
}

# プロファイル名を格納するハッシュの初期化
@profile_tmp = @profile_all;
foreach $lang (grep {not m#^(?:tsvcmd)$#} @lang) {
	foreach $profile (@profile) {
		if (@profile_tmp != 0) {
			$profile{$lang}{$profile} = shift @profile_tmp;
		} else {
			print STDERR "-E Initialize \%profile failed\n";
			exit 1;
		}
	}
}

# 入力ファイル終端文字列を格納するハッシュの初期化
@eof_tmp = @eof_all;
foreach $lang (grep {not m#^(?:tsvcmd)$#} @lang) {
	if (@eof_tmp != 0) {
		$eof{$lang} = shift @eof_tmp;
	} else {
		print STDERR "-E Initialize \%eof failed\n";
		exit 1;
	}
}

# 作業開始前処理
PRE_PROCESS();

#####################
# メインループ 開始 #
#####################
if ( not defined(open(INPUT_FILE, '<', "$INPUT_FILE")) ) {
	print STDERR "-E INPUT_FILE cannot open -- \"$INPUT_FILE\": $!\n";
	POST_PROCESS();exit 1;
}
binmode(INPUT_FILE, ":encoding(utf8)");
# 入力ファイルの言語判定
$input_lang = "";
GUESS_LANG_INPUT_FILE: while ($line = <INPUT_FILE>) {
	chomp $line;
	($field, $value) = SPLIT_FIELD_VALUE_COLON($line);
	GUESS_LANG_LANG: foreach $lang (grep {not m#^(?:tsvcmd)$#} @lang) {
		if ( ($field eq $field{$INPUT_MODE}{$lang}{name}) or
			($field eq $profile{$lang}{domainprofile}) or
			($field eq $profile{$lang}{privateprofile}) or
			($field eq $profile{$lang}{publicprofile}) ) {
			$input_lang = $lang;
			last GUESS_LANG_LANG;
		}
	}
	if ($input_lang ne "") {
		last GUESS_LANG_INPUT_FILE;
	}
}
if ($input_lang eq "") {
	print STDERR "-E Cannot guess language of INPUT_FILE -- \"$INPUT_FILE\"\n";
	POST_PROCESS();exit 1;
}
# INPUT_FILE の現在行をファイルの先頭に戻す
seek(INPUT_FILE, 0, SEEK_SET);
# 「OUTPUT_FORMAT=tsv」または「OUTPUT_FORMAT=tsvcmd」である場合
if ( ($OUTPUT_FORMAT eq "tsv") or ($OUTPUT_FORMAT eq "tsvcmd") ) {
	# ヘッダの連結
	@record = ();
	CONCAT_HEADER_PARAM: foreach $param (@{ $param{$INPUT_MODE} }) {
		# 「OUTPUT_FORMAT=tsv」である場合
		if ($OUTPUT_FORMAT eq "tsv") {
			push @record, ESCAPE_FIELD($header{$INPUT_MODE}{$input_lang}{$param});
		# 「OUTPUT_FORMAT=tsvcmd」である場合
		} elsif ($OUTPUT_FORMAT eq "tsvcmd") {
			push @record, ESCAPE_FIELD($header{$INPUT_MODE}{tsvcmd}{$param});
		}
	}
	# ヘッダの出力
	print join "\t", @record;
	print "\n";
} elsif ($OUTPUT_FORMAT eq "cmd") {
	# ヘッダの出力
	print STDOUT <<EOF;
###
### inetfw.pl スクリプトファイル
###

##############################################################################
# ・このファイルは、inetfw.pl のスクリプトファイルです。
#   netsh のスクリプトファイルとしては使用できません。
# ・このファイルはUTF-8 コードで作成されています。
#   文字コードを変更しないでください。
# ・このファイルはUNIX 形式改行コードで作成されています。
#   改行コードを変更しないでください。
# ・「#」で始まる行はコメント行扱いされます。
# ・空行は無視されます。
# ・下方で「#Disabled by the reason: XXX[,...]#」で始まる行は、以下に示す
#   いくつかの理由により、コマンドをそのままでは実行できないため、無効化されて
#   いることを示しています。
#   該当行の内容に近いルールの追加・修正等を実行するには、自力で該当行を実行で
#   きる形に修正するか、あるいは「Windows Firewall with Advanced Security」の
#   MMC スナップインを使うなどしてルールの追加・修正等を実行してください。
#   理由一覧:
#     localport
#       入力ファイルでは「LocalPort」に特定の値「IPHTTPS」が指定されていたが、
#       現状のinetfw.pl を使ってそれを指定したルールを追加・修正することはでき
#       ません。
#     remoteport
#       入力ファイルでは「RemotePort」に特定の値「RPC|RPC-EPMap|IPHTTPS」が指定
#       されていたが、現状のinetfw.pl を使ってそれを指定したルールを追加・修正
#       することはできません。
#     rmtcomputergrp rmtusrgrp security
#       入力ファイルでは「RemoteComputerGroup」「RemoteUserGroup」「Security」
#       に任意の値が指定されていたが、現状のinetfw.pl を使ってそれを指定した
#       ルールを追加・修正することはできません。
#     rule_source
#       入力ファイルで「Rule source」に現状のnetsh を使ってルールを追加・修正
#       することができない値が指定されています。
#       (例：「Rule source」で「Local Setting」以外の値が指定されている場合等)
#     action
#       入力ファイルでは「Action」に特定の値「Bypass」が指定されていたが、現状
#       のinetfw.pl を使ってそれを指定したルールを追加・修正することはできませ
#       ん。
##############################################################################

# header_end
EOF
}
# REG_FILE オプションが指定されている場合
if ($REG_FILE ne "") {
	# レジストリファイルのハッシュへの結びつけ
	tie %REG_FILE, "Config::IniFiles", (-file => $REG_FILE, -nocase => 0);
	# レジストリファイルのハッシュへの読み込み
	%REG_FILE_tmp = %{ $REG_FILE{$REGKEY_FirewallRules} };
	READ_REG_REG_KEY: while ( ($reg_key, $reg_val) = each %REG_FILE_tmp ) {
		$reg_key = decode("UTF-8", $reg_key);
		$reg_val = decode("UTF-8", $reg_val);
		$reg_key =~ s#^"##; $reg_key =~ s#"$##; $reg_key =~ s#\\"#"#g;
		$reg_val =~ s#^"##; $reg_val =~ s#"$##; $reg_val =~ s#\\"#"#g;
		$reg{$input_lang}{$reg_key} = REGVAL2CMD($reg_val);
	}
	# レジストリファイルのハッシュへの結びつけ解除
	untie %REG_FILE;
}
# レコード名のループ
$input_file_line_count = 0;
RECORD_NAME_LINE: while ($line = <INPUT_FILE>) {
	chomp $line;
	$input_file_line_count += 1;
	($field, $value) = SPLIT_FIELD_VALUE_COLON($line);
	if ( ($field eq $field{$INPUT_MODE}{$input_lang}{name}) or
		($field eq $profile{$input_lang}{domainprofile}) or
		($field eq $profile{$input_lang}{privateprofile}) or
		($field eq $profile{$input_lang}{publicprofile}) ) {
		$name_line = $input_file_line_count;
		%value = ();
		if ($INPUT_MODE eq "rule") {
			$value_tmp = INDIRECT_STR_LOAD($value);
			if ( $value_tmp !~ m#^-E Load indirect string failed# ) {
				$value = $value_tmp;
			}
			$value{$input_lang}{name}{orig} = $value;
			$value{$input_lang}{name}{cmd} = $value;
		} elsif ($INPUT_MODE eq "profile") {
			$value{$input_lang}{name}{orig} = $field;
			$value{$input_lang}{name}{cmd} = "";
			RECORD_NAME_PROFILE: foreach $profile (@profile) {
				if ($field eq $profile{$input_lang}{$profile}) {
					$value{$input_lang}{name}{cmd} = $profile;
					last RECORD_NAME_PROFILE;
				}
			}
		}
		# レコード本体のループ
		RECORD_BODY_LINE: while ($line = <INPUT_FILE>) {
			chomp $line;
			$input_file_line_count += 1;
			if ($INPUT_MODE eq "rule") {
				($field, $value) = SPLIT_FIELD_VALUE_COLON($line);
				if ($field eq "") {
					last RECORD_BODY_LINE;
				}
			} elsif ($INPUT_MODE eq "profile") {
				($field, $value) = SPLIT_FIELD_VALUE_SPACE($line);
				if ($field eq "") {
					$line = <INPUT_FILE>;
					chomp $line;
					$input_file_line_count += 1;
					($field, $value) = SPLIT_FIELD_VALUE_COLON($line);
					if ($field =~ m#^(?:Logging|ログ):$#) {
						next RECORD_BODY_LINE;
					} else {
						last RECORD_BODY_LINE;
					}
				}
			}
			if ($field =~ m#^-+$#) {
				next RECORD_BODY_LINE;
			}
			if ($field eq $eof{$input_lang}) {
				last RECORD_BODY_LINE;
			}
			# フィールド値のハッシュへの読み込み
			$field_sentinel = 0;
			READ_VALUE_PARAM: foreach $param (@{ $param{$INPUT_MODE} }) {
				if ($field eq $field{$INPUT_MODE}{$input_lang}{$param}) {
					$value{$input_lang}{$param}{orig} = $value;
					$value{$input_lang}{$param}{cmd} = VALUE2CMD($param, $value);
					if ($INPUT_MODE eq "rule") {
						if ($param eq "protocol") {
							if ( ($value{$input_lang}{$param}{cmd} eq "icmpv4") or
								($value{$input_lang}{$param}{cmd} eq "icmpv6") ) {
								$value{$input_lang}{type_code}{orig} = "";
								$value{$input_lang}{type_code}{cmd} = "";
								$icmp_sentinel = 0;
								READ_VALUE_ICMP: while ( ($pos_save = tell(INPUT_FILE)) and ($line = <INPUT_FILE>) ) {
									chomp $line;
									$input_file_line_count += 1;
									($type, $code) = SPLIT_2_VALUES($line);
									$type_cmd = VALUE2CMD("type_code", $type);
									$code_cmd = VALUE2CMD("type_code", $code);
									if ($type_cmd eq "type") {
										$icmp_sentinel = 1;
										next READ_VALUE_ICMP;
									} else {
										if ($type_cmd eq "") {
											# INPUT_FILE の現在行を1行手前に戻す
											seek(INPUT_FILE, $pos_save, SEEK_SET);
											$input_file_line_count -= 1;
											last READ_VALUE_ICMP;
										} else {
											if ($icmp_sentinel == 0) {
												next READ_VALUE_ICMP;
											} else {
												$value{$input_lang}{type_code}{orig} = "@{$sep{type_code}{orig}}[0]$type@{$sep{type_code}{orig}}[1]$code";
												$value{$input_lang}{type_code}{cmd} = "@{$sep{type_code}{cmd}}[0]$type_cmd@{$sep{type_code}{cmd}}[1]$code_cmd";
											}
										}
									}
								}
								$value{$input_lang}{type_code}{orig} =~ s#^@{$sep{type_code}{orig}}[0]##;
								$value{$input_lang}{type_code}{cmd} =~ s#^@{$sep{type_code}{cmd}}[0]##;
							}
						}
					}
					$field_sentinel = 1;
					last READ_VALUE_PARAM;
				}
			}
			if ($field_sentinel == 0) {
				print STDERR "-W Unknown field exists, skipped\n";
				print STDERR "     Line: $name_line\n";
				print STDERR "     Name: $value{$input_lang}{name}{orig}\n";
				print STDERR "     $line\n";
			}
		}
		# REG_FILE オプションが指定されている場合
		if ($REG_FILE ne "") {
			# レコードとレジストリ値の対応付け
			$record_reg_key = "";
			MATCH_RECORD_REG_KEY: foreach $reg_key (keys %{ $reg{$input_lang} }) {
				$record_reg_key_sentinel = 1;
				MATCH_RECORD_REG_PARAM: foreach $param (grep {not m#^(?:program|rule_source)$#} @{ $param{$INPUT_MODE} }) {
					print "$name_line DEBUG(REG_MATCH) $reg_key $param\n" if $DEBUG{REG_MATCH};
					print "$name_line DEBUG(REG_MATCH) $reg_key $value{$input_lang}{$param}{cmd}\n" if $DEBUG{REG_MATCH};
					print "$name_line DEBUG(REG_MATCH) $reg_key $reg{$input_lang}{$reg_key}{$param}\n" if $DEBUG{REG_MATCH};
					if ( ($param eq "localip") or ($param eq "remoteip") ) {
						# 複数アドレス(「,」区切り)の分割・並び替え
						@value_addr = sort(split(/,/, $value{$input_lang}{$param}{cmd}, -1));
						@reg_addr = sort(split(/,/, $reg{$input_lang}{$reg_key}{$param}, -1));
						# @value_addr・@reg_addr のループ
						MATCH_RECORD_REG_ADDR: while ( (@value_addr > 0) and (@reg_addr > 0) ) {
							$value_addr = shift @value_addr;
							$reg_addr = shift @reg_addr;
							# アドレス範囲(「-」区切り)の左辺と右辺が同じ場合、右辺を切り捨てる ($value_addr のみ)
							$value_addr =~ s#^([^-]+)-([^-]+)$#if($1 eq $2) {sprintf("%s",$1)} else {sprintf("%s-%s",$1,$2)}#e;
							# アドレス範囲(「-」区切り)の分割
							($value_addr_from, $value_addr_to) = split(/-/, $value_addr, 2);
							($reg_addr_from, $reg_addr_to) = split(/-/, $reg_addr, 2);
							if ( ($value_addr_from !~ m#^(?:any|localsubnet|dns|dhcp|wins|defaultgateway)$#) and
								($value_addr_to !~ m#^(?:any|localsubnet|dns|dhcp|wins|defaultgateway)$#) and
								($reg_addr_from !~ m#^(?:any|localsubnet|dns|dhcp|wins|defaultgateway)$#) and
								($reg_addr_to !~ m#^(?:any|localsubnet|dns|dhcp|wins|defaultgateway)$#) ) {
								$value_ip_from = NetAddr::IP->new($value_addr_from);
								$value_ip_to = NetAddr::IP->new($value_addr_to);
								$reg_ip_from = NetAddr::IP->new($reg_addr_from);
								$reg_ip_to = NetAddr::IP->new($reg_addr_to);
								if ( ($value_ip_from ne "") and ($reg_ip_from ne "") ) {
									if ($value_ip_from ne $reg_ip_from) {
										$record_reg_key_sentinel = 0;
										print "$name_line DEBUG(REG_MATCH) $reg_key ne\n" if $DEBUG{REG_MATCH};
										last MATCH_RECORD_REG_PARAM;
									}
								} else {
									if ($value_addr_from ne $reg_addr_from) {
										$record_reg_key_sentinel = 0;
										print "$name_line DEBUG(REG_MATCH) $reg_key ne\n" if $DEBUG{REG_MATCH};
										last MATCH_RECORD_REG_PARAM;
									}
								}
								if ( ($value_ip_to ne "") and ($reg_ip_to ne "") ) {
									if ($value_ip_to ne $reg_ip_to) {
										$record_reg_key_sentinel = 0;
										print "$name_line DEBUG(REG_MATCH) $reg_key ne\n" if $DEBUG{REG_MATCH};
										last MATCH_RECORD_REG_PARAM;
									}
								} else {
									if ($value_addr_to ne $reg_addr_to) {
										$record_reg_key_sentinel = 0;
										print "$name_line DEBUG(REG_MATCH) $reg_key ne\n" if $DEBUG{REG_MATCH};
										last MATCH_RECORD_REG_PARAM;
									}
								}
							} else {
								if ($value_addr_from ne $reg_addr_from) {
									$record_reg_key_sentinel = 0;
									print "$name_line DEBUG(REG_MATCH) $reg_key ne\n" if $DEBUG{REG_MATCH};
									last MATCH_RECORD_REG_PARAM;
								}
								if ($value_addr_to ne $reg_addr_to) {
									$record_reg_key_sentinel = 0;
									print "$name_line DEBUG(REG_MATCH) $reg_key ne\n" if $DEBUG{REG_MATCH};
									last MATCH_RECORD_REG_PARAM;
								}
							}
						}
						# @value_addr・@reg_addr のループ後、いずれかの配列に要素が残っていた場合
						if ( (@value_addr != 0) or (@reg_addr != 0) ) {
							$record_reg_key_sentinel = 0;
							print "$name_line DEBUG(REG_MATCH) $reg_key ne\n" if $DEBUG{REG_MATCH};
							last MATCH_RECORD_REG_PARAM;
						}
					} else {
						if ($value{$input_lang}{$param}{cmd} ne $reg{$input_lang}{$reg_key}{$param}) {
							$record_reg_key_sentinel = 0;
							print "$name_line DEBUG(REG_MATCH) $reg_key ne\n" if $DEBUG{REG_MATCH};
							last MATCH_RECORD_REG_PARAM;
						}
					}
					print "$name_line DEBUG(REG_MATCH) $reg_key eq\n" if $DEBUG{REG_MATCH};
				}
				if ($record_reg_key_sentinel == 1) {
					$record_reg_key = $reg_key;
					last MATCH_RECORD_REG_KEY;
				}
			}
			# レコードとレジストリ値の対応付けに成功した場合
			if ($record_reg_key ne "") {
				# フィールド文字列の修正 (program)
				$value = $reg{$input_lang}{$record_reg_key}{program};
				$value =~ s#\\\\#\\#g;
				$value =~ s#%([^%]+)%#$ENV{$1} || $ENV{uc($1)} || "%$1%"#eg;
				if ($value{$input_lang}{program}{cmd} eq $value) {
					$value{$input_lang}{program}{cmd} = $reg{$input_lang}{$record_reg_key}{program};
					$value{$input_lang}{program}{cmd} =~ s#\\\\#\\#g;
					$value{$input_lang}{program}{orig} = $value{$input_lang}{program}{cmd};
				}
				# レジストリハッシュから対応付けに成功したキーと値を削除
				delete $reg{$input_lang}{$record_reg_key};
			# レコードとレジストリ値の対応付けに失敗した場合
			} else {
				print STDERR "-W Matching record with registry key failed, routines described in \"Usage\" are skipped\n";
				print STDERR "     Line: $name_line\n";
				print STDERR "     Name: $value{$input_lang}{name}{orig}\n";
			}
		}
		# レコードの連結
		@record = ();
		CONCAT_RECORD_PARAM: foreach $param (@{ $param{$INPUT_MODE} }) {
			# 「OUTPUT_FORMAT=tsv」である場合
			if ($OUTPUT_FORMAT eq "tsv") {
				push @record, ESCAPE_FIELD($value{$input_lang}{$param}{orig});
			# 「OUTPUT_FORMAT=tsvcmd」である場合
			} elsif ($OUTPUT_FORMAT eq "tsvcmd") {
				push @record, ESCAPE_FIELD(ESCAPE_CMD($value{$input_lang}{$param}{cmd}));
			# 「OUTPUT_FORMAT=cmd」である場合
			} elsif ($OUTPUT_FORMAT eq "cmd") {
				push @record, $param . "=" . ESCAPE_CMD($value{$input_lang}{$param}{cmd});
			}
		}
		# レコードの出力
		# 「OUTPUT_FORMAT=tsv」または「OUTPUT_FORMAT=tsvcmd」である場合
		if ( ($OUTPUT_FORMAT eq "tsv") or ($OUTPUT_FORMAT eq "tsvcmd") ) {
			print join "\t", @record;
			print "\n";
		# 「OUTPUT_FORMAT=cmd」である場合
		} elsif ($OUTPUT_FORMAT eq "cmd") {
			if ($INPUT_MODE eq "rule") {
				# 「@record」中の「任意オプション=""」を削除
				@record = grep {not m#^[^=]+=""$#} @record;
				# 「@record」中の「security="notrequired"」を削除
				@record = grep {not m#^security="notrequired"$#} @record;
				# 「@record」中の「rule_source="local_setting"」を削除
				@record = grep {not m#^rule_source="local_setting"$#} @record;
				# 「@record_reason」の初期化
				@record_reason = ();
				# 「@record」に「localport="*IPHTTPS*"」が含まれている場合
				if ((grep {m#^localport="[^"]*(?:IPHTTPS)[^"]*"$#} @record) >= 1) {
					push @record_reason, "localport";
				}
				# 「@record」に「remoteport="*RPC|RPC-EPMap|IPHTTPS*"」が含まれている場合
				if ((grep {m#^remoteport="[^"]*(?:RPC|RPC-EPMap|IPHTTPS)[^"]*"$#} @record) >= 1) {
					push @record_reason, "remoteport";
				}
				# 「@record」に「rmtcomputergrp|rmtusrgrp|security="(任意文字列)"」が含まれている場合
				foreach $param (qw(rmtcomputergrp rmtusrgrp security)) {
					if ((grep {m#^$param="[^"]+"$#} @record) >= 1) {
						push @record_reason, $param;
					}
				}
				# 「@record」に「rule_source="(任意文字列)"」が含まれている場合
				if ((grep {m#^rule_source="[^"]+"$#} @record) >= 1) {
					push @record_reason, "rule_source";
				}
				# 「@record」に「action="bypass"」が含まれている場合
				if ((grep {m#^action="bypass"$#} @record) >= 1) {
					push @record_reason, "action";
				}
				# 「@record_reason」の要素数が1以上である場合
				if (@record_reason >= 1) {
					print "#Disabled by the reason: ";
					print join ",", @record_reason;
					print "# ";
				}
				print "add rule ";
				print join " ", @record;
				print "\n";
			} elsif ($INPUT_MODE eq "profile") {
				# 何もしない
			}
		}
	} else {
		next RECORD_NAME_LINE;
	}
}
close(INPUT_FILE);
#####################
# メインループ 終了 #
#####################

