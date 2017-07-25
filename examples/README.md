# examples

## 「default.win10home」ディレクトリ

Windows 10 Home が稼働中のPCにて「netsh advfirewall reset」を行った状態で、
[inetfw_netsh_main.bat](https://github.com/yuksiy/inetfw_tools/blob/master/README.md#inetfw_netsh_mainbat)
を実行することにより一括生成されたファイル、およびその派生ファイルを格納しています。

## 「default.win10home/output」ディレクトリ

* netsh-advfirewall-firewall-show-rule.ja.txt  
  ファイアウォールのルール一覧。

* netsh-advfirewall-firewall-show-rule.ja.tsv,  
  netsh-advfirewall-firewall-show-rule.ja.tsv.err  
  ファイアウォールのルール一覧を設定書向けのTSV形式に変換した出力結果ファイル、
  およびその変換過程で出力されたエラーメッセージファイル。  
  上記のTSVファイルを一般のテキストエディタで開き、
  表計算ソフトにコピー・アンド・ペーストし、書式を整えることによって、
  ファイアウォールの設定書として使用することができます。  
  また、変換過程でエラーが発生していなければ、エラーメッセージファイルのサイズは「0」になります。

* netsh-advfirewall-firewall-show-rule.cmd.ja.tsv,  
  netsh-advfirewall-firewall-show-rule.cmd.ja.tsv.err  
  ファイアウォールのルール一覧をコマンドライン検討向けのTSV形式に変換した出力結果ファイル、
  およびその変換過程で出力されたエラーメッセージファイル。  
  上記のTSVファイルを一般のテキストエディタで開き、
  表計算ソフトにコピー・アンド・ペーストし、書式を整えることによって、
  netshや[inetfw.pl](https://github.com/yuksiy/inetfw_tools/blob/master/README.md#inetfwpl)
  のコマンドラインの検討資料として使用することができます。  
  また、変換過程でエラーが発生していなければ、エラーメッセージファイルのサイズは「0」になります。

* netsh-advfirewall-firewall-show-rule.cmd.ja.txt,  
  netsh-advfirewall-firewall-show-rule.cmd.ja.txt.err  
  ファイアウォールのルール一覧を
  [inetfw.pl](https://github.com/yuksiy/inetfw_tools/blob/master/README.md#inetfwpl)
  で使用可能なスクリプトファイルに変換した出力結果ファイル、
  およびその変換過程で出力されたエラーメッセージファイル。  
  上記のスクリプトファイルを一般のテキストエディタで開き、
  必要に応じて内容を編集することによって、
  [inetfw.pl](https://github.com/yuksiy/inetfw_tools/blob/master/README.md#inetfwpl)
  のスクリプトファイルとして使用することができます。  
  また、変換過程でエラーが発生していなければ、エラーメッセージファイルのサイズは「0」になります。

* netsh-advfirewall-show-allprofiles.ja.txt  
  ファイアウォールのプロファイル一覧。

* netsh-advfirewall-show-allprofiles.ja.tsv  
  ファイアウォールのプロファイル一覧を設定書向けのTSV形式に変換した出力結果ファイル。

* netsh-advfirewall-show-allprofiles.cmd.ja.tsv  
  ファイアウォールのプロファイル一覧をコマンドライン検討向けのTSV形式に変換した出力結果ファイル。

[inetfw_netsh_main.bat](https://github.com/yuksiy/inetfw_tools/blob/master/README.md#inetfw_netsh_mainbat)
の実行時には、上記のファイル以外に以下のファイルも出力されますが、
配布するメリットよりデメリットの方が多いと判断したため、本ディレクトリには格納していません。

* netsh-advfirewall-export.wfw  
  「netsh advfirewall export」コマンドの出力結果ファイル。

* reg-export-FirewallRules.reg  
  「reg export "HKLM\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"」コマンドの出力結果ファイル。

## 「default.win10home/spreadsheet」ディレクトリ

* firewall-rule.ods  
  上記で生成された「netsh-advfirewall-firewall-show-rule.ja.tsv」ファイルを
  表計算ソフトにコピー・アンド・ペーストし、簡単に書式を整えた
  「ファイアウォール ルール設定書」の一例です。

* firewall-profile.ods  
  上記で生成された「netsh-advfirewall-show-allprofiles.ja.tsv」ファイルを
  表計算ソフトにコピー・アンド・ペーストし、簡単に書式を整えた
  「ファイアウォール プロファイル設定書」の一例です。
