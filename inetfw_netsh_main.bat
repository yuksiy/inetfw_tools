@echo off

rem ==============================================================================
rem   機能
rem     netsh advfirewall の各種出力結果ファイルの一括生成
rem   構文
rem     inetfw_netsh_main.bat [dest_dir]
rem
rem   Copyright (c) 2010-2017 Yukio Shiiya
rem
rem   This software is released under the MIT License.
rem   https://opensource.org/licenses/MIT
rem ==============================================================================

rem **********************************************************************
rem * 基本設定
rem **********************************************************************
rem 環境変数のローカライズ開始
setlocal

rem 遅延環境変数展開の有効化
verify other 2>nul
setlocal enabledelayedexpansion
if errorlevel 1 (
	echo -E Unable to enable delayedexpansion 1>&2
	exit /b 1
)

rem ウィンドウタイトルの設定
title %~nx0 %*

for /f "tokens=1" %%i in ('echo %~f0') do set SCRIPT_FULL_NAME=%%i
for /f "tokens=1" %%i in ('echo %~dp0') do set SCRIPT_ROOT=%%i
for /f "tokens=1" %%i in ('echo %~nx0') do set SCRIPT_NAME=%%i
set RAND=%RANDOM%

rem **********************************************************************
rem * 変数定義
rem **********************************************************************
rem ユーザ変数
set POLICY=netsh-advfirewall-export.wfw
set RULE_REG=reg-export-FirewallRules.reg
set RULE_REG_TMP=reg-export-FirewallRules.reg.tmp

set PROFILE_EN=netsh-advfirewall-show-allprofiles.en.txt
set PROFILE_JA=netsh-advfirewall-show-allprofiles.ja.txt
set PROFILE_TSV_EN=netsh-advfirewall-show-allprofiles.en.tsv
set PROFILE_TSV_JA=netsh-advfirewall-show-allprofiles.ja.tsv
set PROFILE_TSV_CMD_EN=netsh-advfirewall-show-allprofiles.cmd.en.tsv
set PROFILE_TSV_CMD_JA=netsh-advfirewall-show-allprofiles.cmd.ja.tsv

set RULE_EN=netsh-advfirewall-firewall-show-rule.en.txt
set RULE_JA=netsh-advfirewall-firewall-show-rule.ja.txt
set RULE_TSV_EN=netsh-advfirewall-firewall-show-rule.en.tsv
set RULE_TSV_EN_ERR=netsh-advfirewall-firewall-show-rule.en.tsv.err
set RULE_TSV_JA=netsh-advfirewall-firewall-show-rule.ja.tsv
set RULE_TSV_JA_ERR=netsh-advfirewall-firewall-show-rule.ja.tsv.err
set RULE_TSV_CMD_EN=netsh-advfirewall-firewall-show-rule.cmd.en.tsv
set RULE_TSV_CMD_EN_ERR=netsh-advfirewall-firewall-show-rule.cmd.en.tsv.err
set RULE_TSV_CMD_JA=netsh-advfirewall-firewall-show-rule.cmd.ja.tsv
set RULE_TSV_CMD_JA_ERR=netsh-advfirewall-firewall-show-rule.cmd.ja.tsv.err
set RULE_CMD_EN=netsh-advfirewall-firewall-show-rule.cmd.en.txt
set RULE_CMD_EN_ERR=netsh-advfirewall-firewall-show-rule.cmd.en.txt.err
set RULE_CMD_JA=netsh-advfirewall-firewall-show-rule.cmd.ja.txt
set RULE_CMD_JA_ERR=netsh-advfirewall-firewall-show-rule.cmd.ja.txt.err
set RULE_TMP_1=netsh-advfirewall-firewall-show-rule.tmp.1
set RULE_TMP_2=netsh-advfirewall-firewall-show-rule.tmp.2
set RULE_TMP_3=netsh-advfirewall-firewall-show-rule.tmp.3

rem システム環境 依存変数
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
	set CYGWINROOT=%SystemDrive%\cygwin64
) else (
	set CYGWINROOT=%SystemDrive%\cygwin
)
set PATH=%PATH%;%CYGWINROOT%\bin
set CYGWIN=nodosfilewarning
set LANG=ja_JP.UTF-8

set CAT=%CYGWINROOT%\bin\cat.exe
set ICONV=%CYGWINROOT%\bin\iconv.exe
set SED=%CYGWINROOT%\bin\sed.exe
set SORT=%CYGWINROOT%\bin\sort.exe
set PERL=%CYGWINROOT%\bin\perl.exe
set PERL5LIB=/usr/local/lib/site_perl

set REG2INT=%ICONV% -f UTF-16LE -t UTF-8

set EN2INT=%ICONV% -f UTF-8 -t UTF-8
set JA2INT=%ICONV% -f CP932 -t UTF-8

set INT2TSV_EN=%ICONV% -f UTF-8 -t UTF-8
set INT2TSV_JA=%ICONV% -f UTF-8 -t UTF-8

set INT2CMD_EN=%ICONV% -f UTF-8 -t UTF-8
set INT2CMD_JA=%ICONV% -f UTF-8 -t UTF-8

set INETFW_NETSH=%SCRIPT_ROOT%\inetfw_netsh.pl

set REGKEY_FirewallRules=HKLM\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\FirewallRules

rem プログラム内部変数
rem set DEBUG=TRUE

set RULE_TSV_HEADER=%SED% -n "1,1p"
set RULE_TSV_CONTENT=%SED% -n "2,$p"

set RULE_TSV_NAME=1
set RULE_TSV_DESCRIPTION=2
set RULE_TSV_ENABLE=3
set RULE_TSV_DIR=4
set RULE_TSV_PROFILE=5
set RULE_TSV_GROUP=6
set RULE_TSV_LOCALIP=7n
set RULE_TSV_REMOTEIP=8n
set RULE_TSV_PROTOCOL=9n
set RULE_TSV_TYPE_CODE=10n
set RULE_TSV_LOCALPORT=11n
set RULE_TSV_REMOTEPORT=12n
set RULE_TSV_EDGE=13
set RULE_TSV_PROGRAM=14
set RULE_TSV_SERVICE=15
set RULE_TSV_INTERFACETYPE=16
set RULE_TSV_RMTCOMPUTERGRP=17n
set RULE_TSV_RMTUSRGRP=18n
set RULE_TSV_SECURITY=19
set RULE_TSV_RULE_SOURCE=20
set RULE_TSV_ACTION=21

set RULE_CMD_HEADER=%SED% -n "1,/^# header_end$/p"
set RULE_CMD_CONTENT=%SED% -n "/^# header_end$/,$p" ^| %SED% "1d"

set RULE_CMD_NAME=2
rem set RULE_CMD_DESCRIPTION=
set RULE_CMD_ENABLE=3
set RULE_CMD_DIR=4
set RULE_CMD_PROFILE=5
rem set RULE_CMD_GROUP=
set RULE_CMD_LOCALIP=6n
set RULE_CMD_REMOTEIP=7n
set RULE_CMD_PROTOCOL=8n
set RULE_CMD_TYPE_CODE=9n
rem set RULE_CMD_LOCALPORT=n
rem set RULE_CMD_REMOTEPORT=n
set RULE_CMD_EDGE=10
rem set RULE_CMD_PROGRAM=
rem set RULE_CMD_SERVICE=
set RULE_CMD_INTERFACETYPE=11
rem set RULE_CMD_RMTCOMPUTERGRP=n
rem set RULE_CMD_RMTUSRGRP=n
set RULE_CMD_SECURITY=12
rem set RULE_CMD_RULE_SOURCE=
set RULE_CMD_ACTION=13

set SORT_RULE_TSV_BEFORE=%CAT%
set SORT_RULE_TSV_AFTER=%CAT%
set SORT_RULE_TSV=%SORT% -t"	" -k%RULE_TSV_NAME%,%RULE_TSV_NAME% -k%RULE_TSV_DIR%,%RULE_TSV_DIR% -k%RULE_TSV_PROFILE%,%RULE_TSV_PROFILE% -k%RULE_TSV_PROTOCOL%,%RULE_TSV_PROTOCOL%

set SORT_RULE_CMD_BEFORE=%SED% -e "s/ \(name\|enable\|dir\|profile\|localip\|remoteip\|protocol\|edge\|interfacetype\|security\|action\)=\"/\t\1=\"/g"
set SORT_RULE_CMD_AFTER=%SED%  -e "s/\t\(name\|enable\|dir\|profile\|localip\|remoteip\|protocol\|edge\|interfacetype\|security\|action\)=\"/ \1=\"/g"
set SORT_RULE_CMD=%SORT% -t"	" -k%RULE_CMD_NAME%,%RULE_CMD_NAME% -k%RULE_CMD_DIR%,%RULE_CMD_DIR% -k%RULE_CMD_PROFILE%,%RULE_CMD_PROFILE% -k%RULE_CMD_PROTOCOL%,%RULE_CMD_PROTOCOL%

rem **********************************************************************
rem * メインルーチン
rem **********************************************************************

rem 第1引数のチェック
if not "%~1"=="" (
	set dest_dir=%~1
	set POLICY=!dest_dir!\%POLICY%
	set RULE_REG=!dest_dir!\%RULE_REG%
	set RULE_REG_TMP=!dest_dir!\%RULE_REG_TMP%

	set PROFILE_EN=!dest_dir!\%PROFILE_EN%
	set PROFILE_JA=!dest_dir!\%PROFILE_JA%
	set PROFILE_TSV_EN=!dest_dir!\%PROFILE_TSV_EN%
	set PROFILE_TSV_JA=!dest_dir!\%PROFILE_TSV_JA%
	set PROFILE_TSV_CMD_EN=!dest_dir!\%PROFILE_TSV_CMD_EN%
	set PROFILE_TSV_CMD_JA=!dest_dir!\%PROFILE_TSV_CMD_JA%

	set RULE_EN=!dest_dir!\%RULE_EN%
	set RULE_JA=!dest_dir!\%RULE_JA%
	set RULE_TSV_EN=!dest_dir!\%RULE_TSV_EN%
	set RULE_TSV_EN_ERR=!dest_dir!\%RULE_TSV_EN_ERR%
	set RULE_TSV_JA=!dest_dir!\%RULE_TSV_JA%
	set RULE_TSV_JA_ERR=!dest_dir!\%RULE_TSV_JA_ERR%
	set RULE_TSV_CMD_EN=!dest_dir!\%RULE_TSV_CMD_EN%
	set RULE_TSV_CMD_EN_ERR=!dest_dir!\%RULE_TSV_CMD_EN_ERR%
	set RULE_TSV_CMD_JA=!dest_dir!\%RULE_TSV_CMD_JA%
	set RULE_TSV_CMD_JA_ERR=!dest_dir!\%RULE_TSV_CMD_JA_ERR%
	set RULE_CMD_EN=!dest_dir!\%RULE_CMD_EN%
	set RULE_CMD_EN_ERR=!dest_dir!\%RULE_CMD_EN_ERR%
	set RULE_CMD_JA=!dest_dir!\%RULE_CMD_JA%
	set RULE_CMD_JA_ERR=!dest_dir!\%RULE_CMD_JA_ERR%
	set RULE_TMP_1=!dest_dir!\%RULE_TMP_1%
	set RULE_TMP_2=!dest_dir!\%RULE_TMP_2%
	set RULE_TMP_3=!dest_dir!\%RULE_TMP_3%
)

if exist "%POLICY%" del /f "%POLICY%"
netsh advfirewall export "%POLICY%" > nul
if "%DEBUG%"=="TRUE" (sleep 2 & pause)

if exist "%RULE_REG%" del /f "%RULE_REG%"
if exist "%RULE_REG_TMP%" del /f "%RULE_REG_TMP%"
reg export "%REGKEY_FirewallRules%" "%RULE_REG_TMP%" > nul
%CAT% "%RULE_REG_TMP%" | %REG2INT% 2>&1 | dos2unix | %SED% "1s/^/#/" > "%RULE_REG%"
del /f "%RULE_REG_TMP%"
if "%DEBUG%"=="TRUE" (sleep 2 & pause)

if "%DEBUG%"=="TRUE" (
	chcp 65001 > nul
	netsh advfirewall show allprofiles                    2>&1 | %EN2INT% 2>&1 | dos2unix > "%PROFILE_EN%"
	if "%DEBUG%"=="TRUE" (sleep 2 & pause)
	netsh advfirewall firewall show rule name=all verbose 2>&1 | %EN2INT% 2>&1 | dos2unix > "%RULE_EN%"
	if "%DEBUG%"=="TRUE" (sleep 2 & pause)
)
chcp 932 > nul
netsh advfirewall show allprofiles                    2>&1 | %JA2INT% 2>&1 | dos2unix > "%PROFILE_JA%"
if "%DEBUG%"=="TRUE" (sleep 2 & pause)
netsh advfirewall firewall show rule name=all verbose 2>&1 | %JA2INT% 2>&1 | dos2unix > "%RULE_JA%"
if "%DEBUG%"=="TRUE" (sleep 2 & pause)

if "%DEBUG%"=="TRUE" (
	%PERL% "%INETFW_NETSH%" -t profile -f tsv    "%PROFILE_EN%" 2>&1 | %INT2TSV_EN% > "%PROFILE_TSV_EN%"     2>&1
	if "%DEBUG%"=="TRUE" (sleep 2)
	%PERL% "%INETFW_NETSH%" -t profile -f tsvcmd "%PROFILE_EN%" 2>&1 | %INT2TSV_EN% > "%PROFILE_TSV_CMD_EN%" 2>&1
	if "%DEBUG%"=="TRUE" (sleep 2)
)
%PERL% "%INETFW_NETSH%" -t profile -f tsv    "%PROFILE_JA%" 2>&1 | %INT2TSV_JA% > "%PROFILE_TSV_JA%"     2>&1
if "%DEBUG%"=="TRUE" (sleep 2)
%PERL% "%INETFW_NETSH%" -t profile -f tsvcmd "%PROFILE_JA%" 2>&1 | %INT2TSV_JA% > "%PROFILE_TSV_CMD_JA%" 2>&1
if "%DEBUG%"=="TRUE" (sleep 2)

if "%DEBUG%"=="TRUE" (
	%PERL% "%INETFW_NETSH%" -t rule -f tsv    -r "%RULE_REG%" "%RULE_EN%" 2> "%RULE_TSV_EN_ERR%"                 > "%RULE_TMP_1%"
	%CAT% "%RULE_TMP_1%" | %RULE_TSV_HEADER%                                                                     > "%RULE_TMP_2%"
	%CAT% "%RULE_TMP_1%" | %RULE_TSV_CONTENT% | %SORT_RULE_TSV_BEFORE% | %SORT_RULE_TSV% | %SORT_RULE_TSV_AFTER% > "%RULE_TMP_3%"
	%CAT% "%RULE_TMP_2%" "%RULE_TMP_3%" | %INT2TSV_EN% > "%RULE_TSV_EN%"     2>&1
	if "%DEBUG%"=="TRUE" (sleep 2)
	%PERL% "%INETFW_NETSH%" -t rule -f tsvcmd -r "%RULE_REG%" "%RULE_EN%" 2> "%RULE_TSV_CMD_EN_ERR%"             > "%RULE_TMP_1%"
	%CAT% "%RULE_TMP_1%" | %RULE_TSV_HEADER%                                                                     > "%RULE_TMP_2%"
	%CAT% "%RULE_TMP_1%" | %RULE_TSV_CONTENT% | %SORT_RULE_TSV_BEFORE% | %SORT_RULE_TSV% | %SORT_RULE_TSV_AFTER% > "%RULE_TMP_3%"
	%CAT% "%RULE_TMP_2%" "%RULE_TMP_3%" | %INT2TSV_EN% > "%RULE_TSV_CMD_EN%" 2>&1
	if "%DEBUG%"=="TRUE" (sleep 2)
	%PERL% "%INETFW_NETSH%" -t rule -f cmd    -r "%RULE_REG%" "%RULE_EN%" 2> "%RULE_CMD_EN_ERR%"                 > "%RULE_TMP_1%"
	%CAT% "%RULE_TMP_1%" | %RULE_CMD_HEADER%                                                                     > "%RULE_TMP_2%"
	%CAT% "%RULE_TMP_1%" | %RULE_CMD_CONTENT% | %SORT_RULE_CMD_BEFORE% | %SORT_RULE_CMD% | %SORT_RULE_CMD_AFTER% > "%RULE_TMP_3%"
	%CAT% "%RULE_TMP_2%" "%RULE_TMP_3%" | %INT2CMD_EN% > "%RULE_CMD_EN%"     2>&1
	if "%DEBUG%"=="TRUE" (sleep 2)
)
%PERL% "%INETFW_NETSH%" -t rule -f tsv    -r "%RULE_REG%" "%RULE_JA%" 2> "%RULE_TSV_JA_ERR%"                 > "%RULE_TMP_1%"
%CAT% "%RULE_TMP_1%" | %RULE_TSV_HEADER%                                                                     > "%RULE_TMP_2%"
%CAT% "%RULE_TMP_1%" | %RULE_TSV_CONTENT% | %SORT_RULE_TSV_BEFORE% | %SORT_RULE_TSV% | %SORT_RULE_TSV_AFTER% > "%RULE_TMP_3%"
%CAT% "%RULE_TMP_2%" "%RULE_TMP_3%" | %INT2TSV_JA% > "%RULE_TSV_JA%"     2>&1
if "%DEBUG%"=="TRUE" (sleep 2)
%PERL% "%INETFW_NETSH%" -t rule -f tsvcmd -r "%RULE_REG%" "%RULE_JA%" 2> "%RULE_TSV_CMD_JA_ERR%"             > "%RULE_TMP_1%"
%CAT% "%RULE_TMP_1%" | %RULE_TSV_HEADER%                                                                     > "%RULE_TMP_2%"
%CAT% "%RULE_TMP_1%" | %RULE_TSV_CONTENT% | %SORT_RULE_TSV_BEFORE% | %SORT_RULE_TSV% | %SORT_RULE_TSV_AFTER% > "%RULE_TMP_3%"
%CAT% "%RULE_TMP_2%" "%RULE_TMP_3%" | %INT2TSV_JA% > "%RULE_TSV_CMD_JA%" 2>&1
if "%DEBUG%"=="TRUE" (sleep 2)
%PERL% "%INETFW_NETSH%" -t rule -f cmd    -r "%RULE_REG%" "%RULE_JA%" 2> "%RULE_CMD_JA_ERR%"                 > "%RULE_TMP_1%"
%CAT% "%RULE_TMP_1%" | %RULE_CMD_HEADER%                                                                     > "%RULE_TMP_2%"
%CAT% "%RULE_TMP_1%" | %RULE_CMD_CONTENT% | %SORT_RULE_CMD_BEFORE% | %SORT_RULE_CMD% | %SORT_RULE_CMD_AFTER% > "%RULE_TMP_3%"
%CAT% "%RULE_TMP_2%" "%RULE_TMP_3%" | %INT2CMD_JA% > "%RULE_CMD_JA%"     2>&1
if "%DEBUG%"=="TRUE" (sleep 2)

if not "%DEBUG%"=="TRUE" (
	del /f "%RULE_TMP_1%"
	del /f "%RULE_TMP_2%"
	del /f "%RULE_TMP_3%"
)

goto :EOF

