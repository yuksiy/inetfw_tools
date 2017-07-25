# inetfw_tools

## 概要

Windows Firewall の補足ツール

このパッケージは、Windows Firewall の標準コマンドラインツールである
「netsh advfirewall」で不足している機能を補足するツールを提供します。

## 使用方法

### inetfw.pl

Windows Firewall の設定を行います。(現状ではルールの追加のみ可能。)

手順例:

mDNSのUDP受信ルールを追加する場合:

    「Cygwin」を「管理者として実行」します。

    このツールで使用可能なスクリプトファイルを作成します。
    # echo 'add rule name="mDNS (UDP 受信)" enable="yes" dir="in" profile="private" group="mDNS" localip="any" remoteip="any" protocol="udp" localport="5353" remoteport="any" edge="no" program=%SystemRoot%"\\system32\\svchost.exe" service="dnscache" interfacetype="any" action="allow"' > add.in.private.mDNS.txt

    上記で作成したスクリプトファイルを実行します。
    # inetfw.pl -f add.in.private.mDNS.txt

* 「inetfw.pl」と「netsh advfirewall firewall add rule」コマンドとでは、
  Windows Firewall のルールの追加に関して、以下のような違いがあります。
  * 前者では以下の指定が可能。(後者では不可)  
    group, type_code
  * 前者では以下の指定が現状では不可。(後者では可能(?))  
    localport=IPHTTPS, remoteport=RPC|RPC-EPMap|IPHTTPS, rmtcomputergrp, rmtusrgrp, security, action=bypass

* 前者の詳細については「inetfw.pl --help」を、
  後者の詳細については「netsh advfirewall firewall add rule ?」を参照してください。

### inetfw_netsh.pl

netsh advfirewall の出力結果ファイルをフォーマット変換します。

手順例:

ルール一覧の出力結果ファイルをTSV形式にフォーマット変換する場合:  
(TSV形式とは[CSV形式](https://ja.wikipedia.org/wiki/Comma-Separated_Values)
の類似フォーマットであり、一般のテキストエディタで開くことができます。)

    「Cygwin」を「管理者として実行」します。

    このツールで使用可能な入力ファイルを作成します。
    # netsh advfirewall firewall show rule name=all verbose 2>&1 | iconv -f CP932 -t UTF-8 2>&1 | dos2unix > netsh-advfirewall-firewall-show-rule.ja.txt

    上記で作成した入力ファイルをフォーマット変換します。
    # inetfw_netsh.pl -t rule -f tsv netsh-advfirewall-firewall-show-rule.ja.txt > netsh-advfirewall-firewall-show-rule.ja.tsv

* ツールの詳細については「inetfw_netsh.pl --help」を参照してください。

### inetfw_netsh_main.bat

netsh advfirewall の各種出力結果ファイルを一括生成します。

手順例:

netsh advfirewall の各種出力結果ファイルを出力先ディレクトリ(DEST_DIR)配下に一括生成する場合:  
(出力先ディレクトリを省略すると、カレントディレクトリに出力されます。)

    「コマンド プロンプト」を「管理者として実行」します。

    mkdir DEST_DIR
    inetfw_netsh_main.bat DEST_DIR

* 出力先ディレクトリに一括生成されるファイルの実例等に関しては、
  [examples ディレクトリ](https://github.com/yuksiy/inetfw_tools/tree/master/examples)
  を参照してください。

## 動作環境

OS:

* Cygwin

依存パッケージ または 依存コマンド:

* make (インストール目的のみ)
* perl
* [Config-IniFiles](http://search.cpan.org/dist/Config-IniFiles/)
* [NetAddr-IP](http://search.cpan.org/dist/NetAddr-IP/)
* [Win32-API](http://search.cpan.org/dist/Win32-API/) (0.69 以降)
* [Win32-Console](http://search.cpan.org/dist/Win32-Console/)
* [Win32-OLE](http://search.cpan.org/dist/Win32-OLE/)
* [common_pl](https://github.com/yuksiy/common_pl)
* dos2unix (inetfw_netsh_main.batを使用する場合のみ)

## インストール

ソースからインストールする場合:

    (Cygwin の場合)
    # make install

fil_pkg.plを使用してインストールする場合:

[fil_pkg.pl](https://github.com/yuksiy/fil_tools_pl/blob/master/README.md#fil_pkgpl) を参照してください。

## インストール後の設定

環境変数「PATH」にインストール先ディレクトリを追加してください。

## 最新版の入手先

<https://github.com/yuksiy/inetfw_tools>

## License

MIT License. See [LICENSE](https://github.com/yuksiy/inetfw_tools/blob/master/LICENSE) file.

## Copyright

Copyright (c) 2010-2017 Yukio Shiiya
