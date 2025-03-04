rule PWS_Win32_QQpass_CZ_2147593121_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.CZ"
        threat_id = "2147593121"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {66 bf 01 00 0f b7 c7 8b 55 fc 0f b6 44 02 ff 66 89 45 fa 8d 45 f4 66 8b 55 fa 66 83 f2 ?? e8 ?? ?? ff ff 8b 55 f4 8b c6 e8 ?? ?? ff ff 47 66 ff cb 75 d1}  //weight: 3, accuracy: Low
        $x_1_2 = "JmpHookOff" ascii //weight: 1
        $x_1_3 = "JmpHookOn" ascii //weight: 1
        $x_1_4 = "hook.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_DA_2147593122_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.DA"
        threat_id = "2147593122"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 00 c3 00 00 75 73 65 72 33 32 2e 64 6c 6c 00 00 53 65 74 54 68 72 65 61 64 44 65 73 6b 74 6f 70 00 00 00 00 54 61 73 6b 4d 67 72 2e 65 78 45 00 55 8b ec 33 c0 55}  //weight: 1, accuracy: High
        $x_1_2 = "Hook.dll" ascii //weight: 1
        $x_1_3 = "MsgHookOff" ascii //weight: 1
        $x_1_4 = "MsgHookOn" ascii //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_DF_2147596543_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.DF"
        threat_id = "2147596543"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://jobylive2.w22.haohaohost.cn/c/abbx/qqpost.asp" ascii //weight: 1
        $x_1_2 = {5c 59 6c 64 71 71 2e 64 6c 6c 00 5c 51 51 2e 65 78 65 00 26 71 71 70 61 73 73 77 6f 72 64 3d 00 3f 71 71 6e 75 6d 62 65 72 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_DG_2147596544_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.DG"
        threat_id = "2147596544"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wgameclient.exe" ascii //weight: 1
        $x_1_2 = "cabalmain.exe" ascii //weight: 1
        $x_1_3 = "qqgame.exe" ascii //weight: 1
        $x_1_4 = "WOW.EXE" ascii //weight: 1
        $x_1_5 = {00 71 71 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_6 = "WOW.PS" ascii //weight: 1
        $x_1_7 = "ReadProcessMemory" ascii //weight: 1
        $x_1_8 = "WriteProcessMemory" ascii //weight: 1
        $x_1_9 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_10 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_11 = "CallNextHookEx" ascii //weight: 1
        $x_1_12 = "InternetReadFile" ascii //weight: 1
        $x_1_13 = "InternetCloseHandle" ascii //weight: 1
        $x_1_14 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_15 = "InternetOpenA" ascii //weight: 1
        $x_1_16 = "strrchr" ascii //weight: 1
        $x_1_17 = ".\\WTF\\config.wtf" ascii //weight: 1
        $x_1_18 = "LaTaleClient.EXE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (17 of ($x*))
}

rule PWS_Win32_QQpass_DH_2147596547_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.DH"
        threat_id = "2147596547"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 44 6f 77 6e 2e 64 6c 6c}  //weight: 10, accuracy: High
        $x_10_2 = {00 48 6f 6f 6b 43 6c}  //weight: 10, accuracy: High
        $x_10_3 = {00 48 6f 6f 6b 4f 6e}  //weight: 10, accuracy: High
        $x_2_4 = "http://www.126.com/" ascii //weight: 2
        $x_2_5 = "Name=" ascii //weight: 2
        $x_2_6 = "&Pass=" ascii //weight: 2
        $x_2_7 = "&Mac=" ascii //weight: 2
        $x_1_8 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_9 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_10 = "InternetReadFile" ascii //weight: 1
        $x_1_11 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_12 = "InternetOpenA" ascii //weight: 1
        $x_1_13 = "InternetConnectA" ascii //weight: 1
        $x_1_14 = "InternetCloseHandle" ascii //weight: 1
        $x_1_15 = "HttpSendRequestA" ascii //weight: 1
        $x_1_16 = "HttpQueryInfoA" ascii //weight: 1
        $x_1_17 = "HttpOpenRequestA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_10_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_DI_2147596568_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.DI"
        threat_id = "2147596568"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%SystemRoot%\\WinRaR.exe" ascii //weight: 1
        $x_1_2 = "%SystemRoot%\\winlogor.exe" ascii //weight: 1
        $x_1_3 = "%SystemRoot%\\intent.exe" ascii //weight: 1
        $x_1_4 = "%SystemRoot%\\sourro.exe" ascii //weight: 1
        $x_1_5 = "%SystemRoot%\\winadr.exe" ascii //weight: 1
        $x_1_6 = "%SystemRoot%\\winnt.exe" ascii //weight: 1
        $x_1_7 = "%SystemRoot%\\SVchont.exe" ascii //weight: 1
        $x_1_8 = "HookOn" ascii //weight: 1
        $x_1_9 = "HookOff" ascii //weight: 1
        $x_1_10 = "StartHook" ascii //weight: 1
        $x_1_11 = "WinExec" ascii //weight: 1
        $x_1_12 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (11 of ($x*))
}

rule PWS_Win32_QQpass_CX_2147596928_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.CX"
        threat_id = "2147596928"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "youmeiyougaocuo" ascii //weight: 1
        $x_1_2 = "____AVP.Root" ascii //weight: 1
        $x_1_3 = "SysWFGwd.dll" ascii //weight: 1
        $x_1_4 = "DownStart.txt" ascii //weight: 1
        $x_1_5 = "DLLFILE" ascii //weight: 1
        $x_1_6 = "JmpHookOff" ascii //weight: 1
        $x_1_7 = "JmpHookOn" ascii //weight: 1
        $x_1_8 = "ZXY_wfgWD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_A_2147597070_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.gen!A"
        threat_id = "2147597070"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "150"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "unhookwindowshookex" ascii //weight: 5
        $x_5_2 = "SetWindowsHookExA" ascii //weight: 5
        $x_5_3 = "callnexthookex" ascii //weight: 5
        $x_5_4 = "InternetReadFile" ascii //weight: 5
        $x_5_5 = "InternetOpenUrlA" ascii //weight: 5
        $x_5_6 = "InternetOpenA" ascii //weight: 5
        $x_5_7 = "InternetCloseHandle" ascii //weight: 5
        $x_10_8 = "hook.dll" ascii //weight: 10
        $x_10_9 = "MsgHookOff" ascii //weight: 10
        $x_10_10 = "MsgHookOn" ascii //weight: 10
        $x_5_11 = "THookAPI" ascii //weight: 5
        $x_3_12 = "Explorer.Exe" ascii //weight: 3
        $x_6_13 = "C:\\Windows\\iexplore.$" ascii //weight: 6
        $x_2_14 = "VerCLSID.exe" ascii //weight: 2
        $x_1_15 = "Accept: */*" ascii //weight: 1
        $x_1_16 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 1
        $x_1_17 = "#32770" ascii //weight: 1
        $x_1_18 = "HTTP/1.0" ascii //weight: 1
        $x_5_19 = "npkcrypt.sys" ascii //weight: 5
        $x_10_20 = "http://jump.qq.com/clienturl_15" ascii //weight: 10
        $x_15_21 = "http://jump.qq.com/clienturl_100?clientuin=" ascii //weight: 15
        $x_10_22 = "LoginCtrl.dll" ascii //weight: 10
        $x_5_23 = "Qq.Exe" ascii //weight: 5
        $x_5_24 = "QqList" ascii //weight: 5
        $x_5_25 = "QqGame.Exe" ascii //weight: 5
        $x_5_26 = "Tencent_QQToolBar" ascii //weight: 5
        $x_5_27 = "Tencent_QQBar" ascii //weight: 5
        $x_5_28 = "qqjddExe" ascii //weight: 5
        $x_5_29 = "qqjddDll" ascii //weight: 5
        $x_10_30 = "waiozongshichanggehongwonahsougehaoxiangzheyangchangdewodeguxiangzaiyuanfang" ascii //weight: 10
        $x_10_31 = "tianheiheitiootiantiandouyaoniaiwodexinsiyounicaibuyaowenwocongnalilai" ascii //weight: 10
        $x_10_32 = "ingdeshihou" ascii //weight: 10
        $x_3_33 = "&clientkey=" ascii //weight: 3
        $x_2_34 = "WebMail" ascii //weight: 2
        $x_3_35 = "name=\"uin\"" ascii //weight: 3
        $x_2_36 = "value=\"" ascii //weight: 2
        $x_3_37 = "name=\"k\"" ascii //weight: 3
        $x_3_38 = "&Uin=" ascii //weight: 3
        $x_2_39 = "mail.qq.com/cgi-bin/login" ascii //weight: 2
        $x_2_40 = "http://flash.chinaren.com/ip/ip.php" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 4 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((5 of ($x_10_*) and 15 of ($x_5_*) and 4 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_10_*) and 15 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_10_*) and 15 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*) and 15 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((5 of ($x_10_*) and 16 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_10_*) and 16 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_10_*) and 16 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_10_*) and 16 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_10_*) and 16 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*) and 16 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((5 of ($x_10_*) and 16 of ($x_5_*) and 5 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_10_*) and 16 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_10_*) and 16 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 4 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 5 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((5 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 5 of ($x_3_*))) or
            ((6 of ($x_10_*) and 13 of ($x_5_*) and 4 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((6 of ($x_10_*) and 13 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((6 of ($x_10_*) and 13 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_10_*) and 13 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((6 of ($x_10_*) and 14 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((6 of ($x_10_*) and 14 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((6 of ($x_10_*) and 14 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_10_*) and 14 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((6 of ($x_10_*) and 14 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_10_*) and 14 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((6 of ($x_10_*) and 14 of ($x_5_*) and 5 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((6 of ($x_10_*) and 14 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_10_*) and 14 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*))) or
            ((6 of ($x_10_*) and 15 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((6 of ($x_10_*) and 15 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_10_*) and 15 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((6 of ($x_10_*) and 15 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_10_*) and 15 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((6 of ($x_10_*) and 15 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((6 of ($x_10_*) and 15 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_10_*) and 15 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((6 of ($x_10_*) and 15 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_1_*))) or
            ((6 of ($x_10_*) and 15 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_10_*) and 15 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((6 of ($x_10_*) and 15 of ($x_5_*) and 5 of ($x_3_*))) or
            ((6 of ($x_10_*) and 16 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((6 of ($x_10_*) and 16 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_10_*) and 16 of ($x_5_*) and 5 of ($x_2_*))) or
            ((6 of ($x_10_*) and 16 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((6 of ($x_10_*) and 16 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_10_*) and 16 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((6 of ($x_10_*) and 16 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((6 of ($x_10_*) and 16 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_10_*) and 16 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((6 of ($x_10_*) and 16 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((6 of ($x_10_*) and 16 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((6 of ($x_10_*) and 16 of ($x_5_*) and 4 of ($x_3_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 4 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 5 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 5 of ($x_3_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 5 of ($x_2_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 3 of ($x_3_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 4 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 2 of ($x_2_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((6 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 2 of ($x_3_*))) or
            ((7 of ($x_10_*) and 11 of ($x_5_*) and 4 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((7 of ($x_10_*) and 11 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((7 of ($x_10_*) and 11 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((7 of ($x_10_*) and 11 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((7 of ($x_10_*) and 12 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((7 of ($x_10_*) and 12 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((7 of ($x_10_*) and 12 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((7 of ($x_10_*) and 12 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((7 of ($x_10_*) and 12 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((7 of ($x_10_*) and 12 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((7 of ($x_10_*) and 12 of ($x_5_*) and 5 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((7 of ($x_10_*) and 12 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((7 of ($x_10_*) and 12 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*))) or
            ((7 of ($x_10_*) and 13 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((7 of ($x_10_*) and 13 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((7 of ($x_10_*) and 13 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((7 of ($x_10_*) and 13 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((7 of ($x_10_*) and 13 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((7 of ($x_10_*) and 13 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((7 of ($x_10_*) and 13 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((7 of ($x_10_*) and 13 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((7 of ($x_10_*) and 13 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_1_*))) or
            ((7 of ($x_10_*) and 13 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((7 of ($x_10_*) and 13 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((7 of ($x_10_*) and 13 of ($x_5_*) and 5 of ($x_3_*))) or
            ((7 of ($x_10_*) and 14 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((7 of ($x_10_*) and 14 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((7 of ($x_10_*) and 14 of ($x_5_*) and 5 of ($x_2_*))) or
            ((7 of ($x_10_*) and 14 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((7 of ($x_10_*) and 14 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((7 of ($x_10_*) and 14 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((7 of ($x_10_*) and 14 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((7 of ($x_10_*) and 14 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((7 of ($x_10_*) and 14 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((7 of ($x_10_*) and 14 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((7 of ($x_10_*) and 14 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((7 of ($x_10_*) and 14 of ($x_5_*) and 4 of ($x_3_*))) or
            ((7 of ($x_10_*) and 15 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((7 of ($x_10_*) and 15 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((7 of ($x_10_*) and 15 of ($x_5_*) and 3 of ($x_2_*))) or
            ((7 of ($x_10_*) and 15 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((7 of ($x_10_*) and 15 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((7 of ($x_10_*) and 15 of ($x_5_*) and 2 of ($x_3_*))) or
            ((7 of ($x_10_*) and 16 of ($x_5_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 4 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 5 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 5 of ($x_3_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 5 of ($x_2_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 3 of ($x_3_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 4 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 2 of ($x_2_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 2 of ($x_3_*))) or
            ((7 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*))) or
            ((8 of ($x_10_*) and 9 of ($x_5_*) and 4 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((8 of ($x_10_*) and 9 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((8 of ($x_10_*) and 9 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((8 of ($x_10_*) and 9 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((8 of ($x_10_*) and 10 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((8 of ($x_10_*) and 10 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((8 of ($x_10_*) and 10 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((8 of ($x_10_*) and 10 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((8 of ($x_10_*) and 10 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((8 of ($x_10_*) and 10 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((8 of ($x_10_*) and 10 of ($x_5_*) and 5 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((8 of ($x_10_*) and 10 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((8 of ($x_10_*) and 10 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*))) or
            ((8 of ($x_10_*) and 11 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((8 of ($x_10_*) and 11 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((8 of ($x_10_*) and 11 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((8 of ($x_10_*) and 11 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((8 of ($x_10_*) and 11 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((8 of ($x_10_*) and 11 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((8 of ($x_10_*) and 11 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((8 of ($x_10_*) and 11 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((8 of ($x_10_*) and 11 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_1_*))) or
            ((8 of ($x_10_*) and 11 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((8 of ($x_10_*) and 11 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((8 of ($x_10_*) and 11 of ($x_5_*) and 5 of ($x_3_*))) or
            ((8 of ($x_10_*) and 12 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((8 of ($x_10_*) and 12 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((8 of ($x_10_*) and 12 of ($x_5_*) and 5 of ($x_2_*))) or
            ((8 of ($x_10_*) and 12 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((8 of ($x_10_*) and 12 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((8 of ($x_10_*) and 12 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((8 of ($x_10_*) and 12 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((8 of ($x_10_*) and 12 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((8 of ($x_10_*) and 12 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((8 of ($x_10_*) and 12 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((8 of ($x_10_*) and 12 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((8 of ($x_10_*) and 12 of ($x_5_*) and 4 of ($x_3_*))) or
            ((8 of ($x_10_*) and 13 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((8 of ($x_10_*) and 13 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((8 of ($x_10_*) and 13 of ($x_5_*) and 3 of ($x_2_*))) or
            ((8 of ($x_10_*) and 13 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((8 of ($x_10_*) and 13 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((8 of ($x_10_*) and 13 of ($x_5_*) and 2 of ($x_3_*))) or
            ((8 of ($x_10_*) and 14 of ($x_5_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 7 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 4 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 5 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 5 of ($x_3_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 5 of ($x_2_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 3 of ($x_3_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 4 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 2 of ($x_2_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 2 of ($x_3_*))) or
            ((8 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*))) or
            ((1 of ($x_15_*) and 2 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 16 of ($x_5_*) and 4 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 16 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 16 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 16 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 4 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 5 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 3 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 14 of ($x_5_*) and 4 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 14 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 14 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 14 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 15 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 15 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 15 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 15 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 15 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 15 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 15 of ($x_5_*) and 5 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 15 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 15 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 16 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 16 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 16 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 16 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 16 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 16 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 16 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 16 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 16 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 16 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 16 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 16 of ($x_5_*) and 5 of ($x_3_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 4 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 5 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 5 of ($x_3_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 4 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 12 of ($x_5_*) and 4 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 12 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 12 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 12 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 13 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 13 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 13 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 13 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 13 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 13 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 13 of ($x_5_*) and 5 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 13 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 13 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 14 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 14 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 14 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 14 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 14 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 14 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 14 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 14 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 14 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 14 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 14 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 14 of ($x_5_*) and 5 of ($x_3_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 15 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 15 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 15 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 15 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 15 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 15 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 15 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 15 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 15 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 15 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 15 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 15 of ($x_5_*) and 4 of ($x_3_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 16 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 16 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 16 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 16 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 16 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 16 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 4 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 5 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 5 of ($x_3_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 15 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_15_*) and 5 of ($x_10_*) and 1 of ($x_6_*) and 16 of ($x_5_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 10 of ($x_5_*) and 4 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 10 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 10 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 10 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 11 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 11 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 11 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 11 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 11 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 11 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 11 of ($x_5_*) and 5 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 11 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 11 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 12 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 12 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 12 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 12 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 12 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 12 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 12 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 12 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 12 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 12 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 12 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 12 of ($x_5_*) and 5 of ($x_3_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 13 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 13 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 13 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 13 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 13 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 13 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 13 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 13 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 13 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 13 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 13 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 13 of ($x_5_*) and 4 of ($x_3_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 14 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 14 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 14 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 14 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 14 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 14 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 15 of ($x_5_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 4 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 5 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 5 of ($x_3_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 13 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_15_*) and 6 of ($x_10_*) and 1 of ($x_6_*) and 14 of ($x_5_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 8 of ($x_5_*) and 4 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 8 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 8 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 8 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 9 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 9 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 9 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 9 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 9 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 9 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 9 of ($x_5_*) and 5 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 9 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 9 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 10 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 10 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 10 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 10 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 10 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 10 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 10 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 10 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 10 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 10 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 10 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 10 of ($x_5_*) and 5 of ($x_3_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 11 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 11 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 11 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 11 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 11 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 11 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 11 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 11 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 11 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 11 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 11 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 11 of ($x_5_*) and 4 of ($x_3_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 12 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 12 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 12 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 12 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 12 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 12 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 13 of ($x_5_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 6 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 7 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 7 of ($x_5_*) and 4 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 7 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 7 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 7 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 5 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 5 of ($x_3_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 11 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_15_*) and 7 of ($x_10_*) and 1 of ($x_6_*) and 12 of ($x_5_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 6 of ($x_5_*) and 4 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 6 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 6 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 6 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 7 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 7 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 7 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 7 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 7 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 7 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 7 of ($x_5_*) and 5 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 7 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 7 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 8 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 8 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 8 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 8 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 8 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 8 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 8 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 8 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 8 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 8 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 8 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 8 of ($x_5_*) and 5 of ($x_3_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 9 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 9 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 9 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 9 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 9 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 9 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 9 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 9 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 9 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 9 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 9 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 9 of ($x_5_*) and 4 of ($x_3_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 10 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 10 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 10 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 10 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 10 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 10 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 11 of ($x_5_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 4 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 5 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 5 of ($x_5_*) and 4 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 5 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 5 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 5 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 6 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 6 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 6 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 6 of ($x_5_*) and 3 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 6 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 6 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 6 of ($x_5_*) and 4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 6 of ($x_5_*) and 5 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 6 of ($x_5_*) and 5 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 6 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 7 of ($x_5_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 7 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 7 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 7 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 7 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 7 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 7 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 7 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 7 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 7 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 7 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 7 of ($x_5_*) and 5 of ($x_3_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 8 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 4 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 9 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_15_*) and 8 of ($x_10_*) and 1 of ($x_6_*) and 10 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_B_2147597646_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.gen!B"
        threat_id = "2147597646"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "delself.bat" ascii //weight: 1
        $x_1_2 = "25E1EECB-E580-4032-97A2-A456D33820D1" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_10_5 = {66 bf 01 00 0f b7 c7 8b 55 fc 0f b6 44 02 ff 66 89 45 fa 8d 45 f4 66 8b 55 fa 66 83 f2 0c e8 aa ee ff ff 8b 55 f4 8b c6 e8 00 ef ff ff 47 66 ff cb 75 d1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_CJM_2147597844_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.CJM"
        threat_id = "2147597844"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "MsgHookOp" ascii //weight: 10
        $x_10_2 = "5BD41097-3693-4133-820E-FDAC57AF00E2" ascii //weight: 10
        $x_1_3 = {4e 76 57 69 6e (30|2d|39) (30|2d|39) 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {4e 76 53 79 73 (30|2d|39) (30|2d|39) 2e}  //weight: 1, accuracy: Low
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_1_6 = "wininit.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_CJL_2147598497_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.CJL"
        threat_id = "2147598497"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {85 c0 7e 1a 8a 93 b8 60 40 00 30 16 46 43 81 e3 07 00 00 80 79 05 4b 83 cb f8 43 48 75 e6 5f 5e 5b c3}  //weight: 20, accuracy: High
        $x_10_2 = {8b d8 eb 01 4b 85 db 7e 15 80 7c 1e ff 5c 74 0e 80 7c 1e ff 3a 74 07 80 7c 1e ff 2f 75 e6 57 8b c6}  //weight: 10, accuracy: High
        $x_10_3 = {6a 00 6a 06 6a 02 6a 00 6a 00 68 00 00 00 c0 8b 45 fc 50 e8 22 f8 ff ff 8b d8 83 fb ff 74 58 57 a1 50 76 40 00 50 e8 c7 f8 ff ff}  //weight: 10, accuracy: High
        $x_1_4 = {00 4d 73 67 48 6f 6f 6b}  //weight: 1, accuracy: High
        $x_1_5 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_KA_2147599409_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.KA"
        threat_id = "2147599409"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "PLAT7MICROSOFTRU.EXE" ascii //weight: 1
        $x_1_3 = "TaskKiller.exe" ascii //weight: 1
        $x_1_4 = "shovth.exe" ascii //weight: 1
        $x_1_5 = "winsn.exe" ascii //weight: 1
        $x_1_6 = "winsos.exe" ascii //weight: 1
        $x_1_7 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_8 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_9 = "FindNextFileA" ascii //weight: 1
        $x_1_10 = "GetWindowsDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_DJ_2147600255_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.DJ"
        threat_id = "2147600255"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 6e 73 74 61 6c 6c 00 53 4f 46 54 57 41 52 45 5c 54 65 6e 63 65 6e 74 5c 51 51}  //weight: 1, accuracy: High
        $x_1_2 = {20 2f 53 54 41 54 3a 00 20 50 57 44 48 41 53 48 3a 00 00 00 20 2f 53 54 41 52 54 20 51 51 55 49 4e 3a}  //weight: 1, accuracy: High
        $x_1_3 = "\\systheoldmsg.txt" ascii //weight: 1
        $x_1_4 = "\\sysgui.gif" ascii //weight: 1
        $x_1_5 = "explorer.exe https://account.qq.com/cgi-bin/auth_forget" ascii //weight: 1
        $x_10_6 = "SetWindowsHookExA" ascii //weight: 10
        $x_10_7 = "GetSystemDirectoryA" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_EA_2147601177_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.EA"
        threat_id = "2147601177"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "353"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "\\QQHook.dll" ascii //weight: 100
        $x_100_2 = "HookStruct" ascii //weight: 100
        $x_100_3 = "installhook" ascii //weight: 100
        $x_10_4 = "\\winso32.sys" ascii //weight: 10
        $x_10_5 = "\\msxl32.dll" ascii //weight: 10
        $x_10_6 = "\\dele.ini" ascii //weight: 10
        $x_10_7 = "InternetOpenA" ascii //weight: 10
        $x_10_8 = "InternetReadFile" ascii //weight: 10
        $x_1_9 = "{523C33CB-510E-4857-9801-78F1D892879C}" ascii //weight: 1
        $x_1_10 = "{3CEFF6CD-6F08-4e4d-BCCD-FF7415288C3B}" ascii //weight: 1
        $x_1_11 = "\\gopen.exe" ascii //weight: 1
        $x_1_12 = "ccSvcHst.exe" ascii //weight: 1
        $x_1_13 = "RavMonD.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 5 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_CJO_2147604748_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.CJO"
        threat_id = "2147604748"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 00 74 6f 70 36 34 35 40 31 36 33 2e 63 6f 6d 00 00 43 6f 6d 62 6f 42 6f 78 00 00 00 00 ff ff ff ff 04 00 00 00 6e 75 6d 3d 00 00 00 00 ff ff ff ff 06 00 00 00 26 70 61 73 73 3d 00 00 ff ff ff ff 08 00 00 00 53 65 6e 64 20 4f 4b 21 00}  //weight: 2, accuracy: High
        $x_1_2 = "jump.qq.com/clienturl" ascii //weight: 1
        $x_1_3 = "smtp.sina.com.cn" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_5 = "MAIL FROM:<" ascii //weight: 1
        $x_1_6 = "InternetConnectA" ascii //weight: 1
        $x_1_7 = "QQHelperDll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_DL_2147606460_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.DL"
        threat_id = "2147606460"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 6e 73 74 61 6c 6c 00 53 4f 46 54 57 41 52 45 5c 54 65 6e 63 65 6e 74 5c 51 51}  //weight: 1, accuracy: High
        $x_1_2 = {20 2f 53 54 41 54 3a 00 20 50 57 44 48 41 53 48 3a 00 00 00 20 2f 53 54 41 52 54 20 51 51 55 49 4e 3a}  //weight: 1, accuracy: High
        $x_1_3 = "explorer.exe https://account.qq.com/cgi-bin/auth_forget" ascii //weight: 1
        $x_1_4 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_5 = "GetSystemDirectoryA" ascii //weight: 1
        $x_1_6 = {52 43 50 54 20 54 4f 3a 20 00 00 00 4d 41 49 4c 20 46 52 4f 4d 3a 20}  //weight: 1, accuracy: High
        $x_1_7 = {00 5c 6b 65 79 2e 64 61 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_C_2147606506_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.gen!C"
        threat_id = "2147606506"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 74 61 72 74 20 50 61 67 65 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e}  //weight: 10, accuracy: High
        $x_10_2 = "0:\\Program Files\\Internet Explorer\\IEXPLORE.EXE\"" ascii //weight: 10
        $x_5_3 = {00 00 53 6f 66 74 77 61 72 65 5c 4d 7a 5c 4f 70 65 6e 49 65}  //weight: 5, accuracy: High
        $x_5_4 = {00 00 53 6f 66 74 77 61 72 65 5c 58 50 5c 50 61 73 73 69 63 65}  //weight: 5, accuracy: High
        $x_3_5 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 3
        $x_3_6 = "InternetOpenUrlA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_D_2147610453_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.gen!D"
        threat_id = "2147610453"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "xingdeshihou" ascii //weight: 10
        $x_10_2 = "tianheiheitiootiantiandouyaoniaiwod" ascii //weight: 10
        $x_2_3 = "hongwonahsougehaoxiangzheyang" ascii //weight: 2
        $x_1_4 = {46 53 44 46 53 44 00 00 45 78 70 6c 6f 72 65 72 2e 45 78 65 00 00 00 00 56 65 72 43 4c 53 49 44 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_5 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_6 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_AA_2147616903_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.AA"
        threat_id = "2147616903"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "F:\\mck\\Kol.pas" ascii //weight: 10
        $x_2_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\run" ascii //weight: 2
        $x_2_3 = "QQ:-(" ascii //weight: 2
        $x_2_4 = "SOFTWARE\\Tencent\\QQ" ascii //weight: 2
        $x_2_5 = "c:\\tmpqq10000.tmp" ascii //weight: 2
        $x_1_6 = "KRegEx.exe" ascii //weight: 1
        $x_1_7 = "KVXP.kxp" ascii //weight: 1
        $x_1_8 = "360tray.exe" ascii //weight: 1
        $x_1_9 = "RSTray.exe" ascii //weight: 1
        $x_1_10 = "QQDoctor.exe" ascii //weight: 1
        $x_1_11 = "DrRtp.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_AU_2147617131_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.AU"
        threat_id = "2147617131"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff ff ff ff 06 00 00 00 71 71 2e 45 58 45 00 00 51 51 d3 c3 bb a7 b5 c7 c2 bc 00}  //weight: 5, accuracy: High
        $x_10_2 = "F:\\mck\\Kol.pas" ascii //weight: 10
        $x_1_3 = "QQ:-(" ascii //weight: 1
        $x_1_4 = {8b d8 83 7d ec 00 74 40 6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 c0 8b 45 f4 e8 ?? ?? ff ff 50 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_BC_2147617586_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.BC"
        threat_id = "2147617586"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a c2 8b fe 2c ?? 83 c9 ff d0 e0 00 04 32 33 c0 42 f2 ae f7 d1 49 3b d1 72 e6}  //weight: 10, accuracy: Low
        $x_10_2 = {00 51 51 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_3 = "\\Documents and Settings\\Administrator\\Application Data\\QQ" ascii //weight: 10
        $x_10_4 = "SafeBase\\" ascii //weight: 10
        $x_1_5 = "EnumProcessModules" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_BE_2147619830_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.BE"
        threat_id = "2147619830"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QQ.exe*TMShell.exe*TIMPlatform.exe*Rtxc.exe*Xdict.exe*clearhistory.exe*GameGuard.des" ascii //weight: 1
        $x_1_2 = "%x_{605272C9-BAE4-4826-9181-8C90A89FF03A}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_DP_2147621060_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.DP"
        threat_id = "2147621060"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Microsoft\\windows\\currentversion\\run" ascii //weight: 10
        $x_10_2 = "\\winstarter.exe" ascii //weight: 10
        $x_10_3 = {68 74 74 70 3a 2f 2f [0-32] 2e 61 73 70}  //weight: 10, accuracy: Low
        $x_10_4 = "&Password=" ascii //weight: 10
        $x_10_5 = "Tencent_QQBar" ascii //weight: 10
        $x_1_6 = "\\newumsg.exe" ascii //weight: 1
        $x_1_7 = "\\autorun.inf" ascii //weight: 1
        $x_1_8 = "\\sysautorun.inf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_BF_2147621479_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.BF"
        threat_id = "2147621479"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Documents and Settings\\Administrator\\Application Data\\QQ" ascii //weight: 1
        $x_1_2 = {6b 6a 6b 68 6a 68 67 00 25 64 00 00 5c 70 73 61 70 69 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 74 61 74 69 63 00 00 66 73 66 00 31 32 34 34 00 00 00 00 51 51}  //weight: 1, accuracy: High
        $x_1_4 = {6a 64 ff d7 68 ?? ?? ?? ?? 6a 00 ff d6 85 c0 a3 ?? ?? ?? ?? 74 ea e8 ?? ?? ff ff 6a 00 6a 00 6a 00 68 ?? ?? 00 10 6a 00 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_BI_2147622763_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.BI"
        threat_id = "2147622763"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dll_qqck" ascii //weight: 1
        $x_1_2 = "GetKeyboardState" ascii //weight: 1
        $x_1_3 = {74 a6 68 58 02 00 00 e8 ?? ?? ff ff 8b c6 e8 ?? ?? ff ff 8b 15 ?? ?? 40 00 89 02 6a 00 68 60 f0 00 00 68 12 01 00 00 56 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {68 a8 3e 00 00 8b 07 50 e8 ?? ?? ff ff 8b 15 ?? ?? 40 00 89 02 68 8a 00 00 00 8b 07 50 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_BJ_2147622971_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.BJ"
        threat_id = "2147622971"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\run" ascii //weight: 1
        $x_1_2 = {31 32 37 2e 30 2e 30 2e 31 [0-16] 6c 6f 63 61 6c 68 6f 73 74}  //weight: 1, accuracy: Low
        $x_1_3 = "attrib -s -h \"" ascii //weight: 1
        $x_1_4 = "sound\\system.wav" ascii //weight: 1
        $x_2_5 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1}  //weight: 2, accuracy: High
        $x_2_6 = {68 04 13 00 00 57 e8 ?? ?? ff ff 48 85 c0 0f 8c e4 00 00 00 40 89 45 ?? 33 f6 c7 45 ?? 01 00 00 00 33 c0 89 45 ?? 33 c0 89 45 ?? c7 45 ?? 00 08 00 00 8b 45 ?? 83 c0 70}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_CJ_2147623982_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.CJ"
        threat_id = "2147623982"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QQ.exe" ascii //weight: 1
        $x_1_2 = "login.dll" ascii //weight: 1
        $x_1_3 = "del /A:H \"%s\"" ascii //weight: 1
        $x_1_4 = "if exist \"%s\" goto Repeat" ascii //weight: 1
        $x_1_5 = {8d 51 01 8b 4c 24 04 56 0f b6 31 6b c0 21 03 c6 41 4a 75 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_BY_2147624671_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.BY"
        threat_id = "2147624671"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "62"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "http://www.xinhai168.c" wide //weight: 10
        $x_10_2 = "Software\\Microsoft\\Internet Explorer\\Main" wide //weight: 10
        $x_10_3 = "Start Page" wide //weight: 10
        $x_10_4 = "Software\\tencent\\qq" wide //weight: 10
        $x_10_5 = "qqlogin.exe" wide //weight: 10
        $x_10_6 = "qq.exe" wide //weight: 10
        $x_1_7 = "[autorun]" wide //weight: 1
        $x_1_8 = "autorun.inf" wide //weight: 1
        $x_1_9 = "shell\\open\\Default=1" wide //weight: 1
        $x_1_10 = {6f 00 70 00 65 00 6e 00 3d 00 [0-21] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_BM_2147625106_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.BM"
        threat_id = "2147625106"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 00 65 00 6e 00 63 00 65 00 6e 00 74 00 20 00 51 00 51 00 00 00 00 00 10 00 00 00 37 00 37 00 30 00 34 00 35 00 37 00 35 00 30 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {52 00 55 00 4e 00 44 00 31 00 31 00 33 00 32 00 00 00 00 00 0c 00 00 00 4b 00 49 00 4c 00 4c 00 51 00 51 00 00 00 00 00 1a 00 00 00 72 00 75 00 6e 00 64 00 31 00 31 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_BQ_2147626344_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.BQ"
        threat_id = "2147626344"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 01 59 2b ca 8a d1 02 d0 30 10 40 8d 14 01 3b d6 72}  //weight: 1, accuracy: High
        $x_1_2 = {c6 07 e9 8b 47 01 89 45 fc 8d 0c 18 8b 45 08 8d 4c 01 05 89 4d f8}  //weight: 1, accuracy: High
        $x_1_3 = {c6 06 e8 2b c6 83 e8 05 89 46 01 8b 45 0c 83 f8 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_QQpass_KB_2147627888_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.KB"
        threat_id = "2147627888"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 32 37 2e 30 2e 30 2e 31 20 77 77 77 2e 33 36 30 73 61 66 65 2e 63 6f 6d [0-5] 31 32 37 2e 30 2e 30 2e 31 20 77 77 77 2e 63 68 69 6e 61 6b 76 2e 63 6f 6d [0-5] 31 32 37 2e 30 2e 30 2e 31 20 77 77 77 2e 72 69 73 69 6e 67 2e 63 6f 6d 2e 63 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d [0-5] 5b 61 75 74 6f 72 75 6e 5d [0-5] 6f 70 65 6e 3d [0-5] 61 75 74 6f 72 75 6e 2e 69 6e 66 [0-10] 41 53 54 2e 65 78 65 2c 33 36 30 74 72 61 79 2e 65 78 65 2c 74 61 73 6b 6d 67 72 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {51 51 2e 65 78 65 [0-5] 5c 73 79 73 74 65 6d 33 32 5c [0-5] 64 64 69 6e 67 20 [0-5] 54 54 50 6c 61 74 66 6f 72 6d 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Disableregistrytools" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_CA_2147630678_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.CA"
        threat_id = "2147630678"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 3d 25 73 26 68 3d 25 64 26 76 3d 25 73 26 65 70 3d 25 73 26 64 62 3d 25 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 44 65 76 69 63 65 5c 4e 50 46 5f 00}  //weight: 1, accuracy: High
        $x_1_3 = {72 02 5d c3 5d c3 55 8b ec 83 05 ?? ?? ?? 00 01 72 02 5d c3 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_CB_2147630708_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.CB"
        threat_id = "2147630708"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 04 11 32 45 d0 88 04 31 8b 4d cc 83 c1 01}  //weight: 2, accuracy: High
        $x_1_2 = {26 00 4b 00 69 00 6c 00 6c 00 53 00 6f 00 66 00 74 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {26 00 77 00 65 00 72 00 74 00 79 00 75 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {44 00 69 00 73 00 6b 00 4e 00 75 00 6d 00 62 00 65 00 72 00 3d 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_CD_2147631248_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.CD"
        threat_id = "2147631248"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "TenQQAccount.dll" ascii //weight: 1
        $x_1_2 = "settellover|mradmin|" ascii //weight: 1
        $x_1_3 = "huai_huai" ascii //weight: 1
        $x_1_4 = "mrstr=" ascii //weight: 1
        $x_1_5 = "ADD_SEND|" ascii //weight: 1
        $x_10_6 = {8b 03 05 00 00 2f 00 50 6a 00 68 79 01 00 00 68 ?? ?? ?? ?? 6a 00 8b 0b 81 c1 00 00 21 00 ba ?? ?? ?? ?? a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 06 83 3e 00 74 ?? 33 c0 a3 ?? ?? ?? ?? 8b 06 83 c0 05 a3 ?? ?? ?? ?? 68 00 00 4f 00 6a 07 6a 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_DR_2147631278_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.DR"
        threat_id = "2147631278"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Program Files\\Tencent\\Q Q\\QQ.exe" ascii //weight: 1
        $x_1_2 = "http://www.ip138.com/ips.asp" ascii //weight: 1
        $x_1_3 = "\\QQVSET.INI" ascii //weight: 1
        $x_1_4 = "https://account.qq.com" ascii //weight: 1
        $x_1_5 = "\\KMe.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_CI_2147631742_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.CI"
        threat_id = "2147631742"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "taskkill /im qq.exe" ascii //weight: 2
        $x_2_2 = "PWDHASH:" ascii //weight: 2
        $x_1_3 = "autorun.inf" ascii //weight: 1
        $x_1_4 = "\\QQ\\registry.db" ascii //weight: 1
        $x_1_5 = "account.qq.com/cgi-bin/auth_forget?" ascii //weight: 1
        $x_1_6 = "ion\\Winlogon\\Userinit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_CV_2147631878_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.CV"
        threat_id = "2147631878"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 71 71 39 39 34 34 35 35 2e 63 6f 6d 2f [0-32] 2f 71 71 70 6f 73 74 2e 61 73 70 00 26 71 71 70 61 73 73 77 6f 72 64 3d 00 3f 71 71 6e 75 6d 62 65 72 3d 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 0b 00 01 16 68 01 00 01 52 e8 ?? ?? ?? ?? 83 c4 10 89 45 f8 8d 45 f8 50 8d 45 fc 50 b8 ?? ?? ?? ?? 89 45 f4 8d 45 f4 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_EE_2147635915_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.EE"
        threat_id = "2147635915"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 f5 8b 44 24 20 8a 1c 31 8a 04 02 8a 54 24 13 02 c1 32 c3 32 c2 02 d3 88 04 31}  //weight: 2, accuracy: High
        $x_1_2 = {85 c0 74 12 8d 54 24 10 52 e8}  //weight: 1, accuracy: High
        $x_2_3 = "ID=%d&Action=GetMyIP" ascii //weight: 2
        $x_2_4 = "Number=%s&PassWord=%s" ascii //weight: 2
        $x_1_5 = "QQHelperDll" ascii //weight: 1
        $x_1_6 = {00 71 71 63 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_2_7 = "168wd.com:81/" ascii //weight: 2
        $x_2_8 = "admin.com:81/" ascii //weight: 2
        $x_2_9 = {8b 48 7c 83 c0 14 85 c9 0f 84 ?? ?? 00 00 8b 70 6c 85 f6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_EC_2147635929_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.EC"
        threat_id = "2147635929"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "id.qq.com" ascii //weight: 1
        $x_1_2 = "aq.qq.com/cn/findpsw/findpsw_index" ascii //weight: 1
        $x_1_3 = ".woodc.com/qq/qq.asp" ascii //weight: 1
        $x_1_4 = "&qqpassword=" ascii //weight: 1
        $x_1_5 = "?qqnumber=" ascii //weight: 1
        $x_1_6 = "\\Bin\\QQ.exe" ascii //weight: 1
        $x_1_7 = {d7 a3 c4 fa d2 bb b7 ab b7 e7 cb b3 a3 ac d0 c4 cf eb ca c2 b3 c9 a3 a1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule PWS_Win32_QQpass_EG_2147636344_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.EG"
        threat_id = "2147636344"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&qqpassword=" ascii //weight: 1
        $x_1_2 = "?qqnumber=" ascii //weight: 1
        $x_1_3 = "\\Bin\\qqdat.exe" ascii //weight: 1
        $x_1_4 = "&PcacheTime=1216297713" ascii //weight: 1
        $x_1_5 = "yiyuyan" ascii //weight: 1
        $x_1_6 = {51 ce d2 b0 c9 cd bc b1 ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win32_QQpass_DS_2147636698_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.DS"
        threat_id = "2147636698"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 5c 2e 5c 73 6c 45 6e 75 6d 48 6f 6f 6b 32 00}  //weight: 1, accuracy: High
        $x_1_2 = {64 72 69 76 65 72 73 5c 64 48 6f 6f 6b 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_3 = "DD5FFEDC-8DC7-420F-B99C-770DBDEE5749" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_EF_2147636733_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.EF"
        threat_id = "2147636733"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 53 68 61 72 65 64 73 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_2 = "\\Common\\iexplore.ex" ascii //weight: 1
        $x_1_3 = "/Go.ashx?Mac=" ascii //weight: 1
        $x_1_4 = {83 1b 40 84 0f}  //weight: 1, accuracy: High
        $x_1_5 = "&UserId=14&Bate=" ascii //weight: 1
        $x_1_6 = "Q-$-DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_QQpass_EH_2147636983_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.EH"
        threat_id = "2147636983"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\TENCENT\\" ascii //weight: 10
        $x_4_2 = "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\" /v AppInit_DLLs /t reg_sz /d \"%s\" /f  " ascii //weight: 4
        $x_4_3 = "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\" /v LoadAppInit_DLLs /t reg_dword /d 1 /f " ascii //weight: 4
        $x_4_4 = "taskkill /f /im %s /t" ascii //weight: 4
        $x_4_5 = "del %0" ascii //weight: 4
        $x_1_6 = "hpig_WS2.dat" ascii //weight: 1
        $x_1_7 = "rxing.bat" ascii //weight: 1
        $x_1_8 = "hellboy7." ascii //weight: 1
        $x_1_9 = "hexil.dll" ascii //weight: 1
        $x_1_10 = "shengod.dat" ascii //weight: 1
        $x_1_11 = "ESETNOD.bat" ascii //weight: 1
        $x_1_12 = "fakews2help.dll" ascii //weight: 1
        $x_1_13 = "kxescore.exe" ascii //weight: 1
        $x_1_14 = "mssoft.bat" ascii //weight: 1
        $x_1_15 = "\\dllcache\\" ascii //weight: 1
        $x_1_16 = "JoachimPeiper.dat" ascii //weight: 1
        $x_1_17 = "c:\\dd.bat" ascii //weight: 1
        $x_1_18 = "hellp.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_4_*) and 12 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_4_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_4_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_EI_2147637648_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.EI"
        threat_id = "2147637648"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\system32\\rundll32.exe %s\\system32\\V3lght.dll,MXHDPUC%c%cdel" ascii //weight: 1
        $x_1_2 = "QuFu:%s  Name:%s  Pass:%s  JiaoSe_Pass:%s  ChuangKu_Pass:%s" ascii //weight: 1
        $x_1_3 = "login_mode=login&" ascii //weight: 1
        $x_1_4 = "MXD_JiaoSe" ascii //weight: 1
        $x_1_5 = "MXD_CangKu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_QQpass_DU_2147637800_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.DU"
        threat_id = "2147637800"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FakeWs2helpDLL" ascii //weight: 1
        $x_1_2 = "GET /postdata.asp HTTP/1.1" ascii //weight: 1
        $x_1_3 = "&QQNumber=%s&QQPassWord=%s" ascii //weight: 1
        $x_1_4 = "AutoLogin.db" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_DU_2147637800_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.DU"
        threat_id = "2147637800"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 81 3e 4d 5a 0f 85 16 01 00 00 8b 56 3c 03 d6 89 54 24 10 81 3a 50 45 00 00 0f 85 01 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "taskkill /f /im QQ.exe /t" ascii //weight: 1
        $x_1_3 = "ESET NOD32 Antivirus" ascii //weight: 1
        $x_1_4 = "SizeofResource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_EJ_2147638312_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.EJ"
        threat_id = "2147638312"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3b 5c 24 20 7c 06 33 db 33 c0 eb 03 8b c3 43 8a 14 37 8a 04 28 32 c2 74 04 88 06 eb 02 88 16 46 49 75 dd}  //weight: 1, accuracy: High
        $x_1_2 = "DebugInfoOut.txt" ascii //weight: 1
        $x_1_3 = "JoachimPeiper.dat" ascii //weight: 1
        $x_1_4 = "&QQNumber=%s&QQPassWord=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_EJ_2147638312_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.EJ"
        threat_id = "2147638312"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 04 0e fe 8b c6 41 8d 78 01 8a 10 40}  //weight: 2, accuracy: High
        $x_1_2 = {83 c0 fb 50 c6 45 ?? e9 c6 45 ?? eb}  //weight: 1, accuracy: Low
        $x_1_3 = "system32\\Drivers\\Beep.sys" wide //weight: 1
        $x_1_4 = "TsSafeEdit.dat" wide //weight: 1
        $x_1_5 = "QQUIN:%s PWDHASH:%S /STAT:40" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_EK_2147638313_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.EK"
        threat_id = "2147638313"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 0b 7c 16 83 f8 14 7f 11 83 c0 2f 0f 80 ?? 00 00 00 83 e8 0a e9 ?? 00 00 00 83 f8 15}  //weight: 1, accuracy: Low
        $x_1_2 = "/START QQUIN:" wide //weight: 1
        $x_1_3 = "cmd.exe /c start C:\\Windows\\" wide //weight: 1
        $x_1_4 = "TXGuiFoundation" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_EK_2147638313_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.EK"
        threat_id = "2147638313"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xiaofeng_aiQ2010_" ascii //weight: 1
        $x_1_2 = {58 33 36 32 37 34 20 ce aa b2 bb c4 dc b6 c1 a3 a1 00}  //weight: 1, accuracy: High
        $x_1_3 = "nloott?qdphbydoxhAwuxh?qdphbydoxhA?0b0Ailuvwnloowlph?qdphbydoxhA99?qdphbydoxhA?0b0AdvsXuo?qdphbydoxhA?" ascii //weight: 1
        $x_1_4 = {00 61 73 70 55 72 6c 00 26 50 61 73 73 57 6f 72 64 3d 00 3f 4e 75 6d 62 65 72 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_EL_2147638314_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.EL"
        threat_id = "2147638314"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 67 66 66 66 f7 e9 c1 fa 02 8b ?? c1 ?? 1f 03}  //weight: 1, accuracy: Low
        $x_1_2 = "taskkill /f /im %s /t" ascii //weight: 1
        $x_1_3 = {57 69 6e 64 6f 77 73 20 ce c4 bc fe b1 a3 bb a4}  //weight: 1, accuracy: High
        $x_1_4 = {6d 6f 76 65 20 25 73 20 25 73 0d 0a 64 65 6c 20 25 73 0d 0a 6d 6f 76 65}  //weight: 1, accuracy: High
        $x_1_5 = "hpig_WS2.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_QQpass_EM_2147638315_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.EM"
        threat_id = "2147638315"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 53 45 54 0d 0a 00 00 4d 41 49 4c 20 46 52 4f 4d 3a 3c 25 73 3e 0d 0a}  //weight: 1, accuracy: High
        $x_1_2 = {0d 0a 20 51 51 c3 dc c2 eb a3 ba 00 20 51 51 ba c5 c2 eb a3 ba 00 68 61 63 6b 64 6f 6e 67 40 31 36 33 2e 63 6f 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_ED_2147638749_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.ED"
        threat_id = "2147638749"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "set oexec=Wshell.Exec(program)" ascii //weight: 1
        $x_1_2 = {2f 53 54 41 52 54 20 51 51 55 49 4e 3a 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 71 71 2e 73 63 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 26 71 71 70 61 73 73 77 6f 72 64 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_EI_2147640534_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.EI"
        threat_id = "2147640534"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\2.jpg" ascii //weight: 1
        $x_1_2 = "jzyqfhdslinbc" ascii //weight: 1
        $x_1_3 = {26 51 51 50 61 73 73 57 6f 72 64 3d 00 3f 51 51 4e 75 6d 62 65 72 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = "1110/2hghf/mail.asp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_EN_2147640819_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.EN"
        threat_id = "2147640819"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "web0622155.w201.dns558.com/05/12w/qq21.asp" ascii //weight: 2
        $x_1_2 = "&QQPassWord=" ascii //weight: 1
        $x_1_3 = "TXGuiFoundation" ascii //weight: 1
        $x_1_4 = ":\\Program Files\\Foxit Reader\\svchosl.exe" ascii //weight: 1
        $x_1_5 = "CurrentVersion\\Explorer\\User Shell Folders\\Personal" ascii //weight: 1
        $x_1_6 = "TENCENT\\PLATFORM_TYPE_LIST\\" ascii //weight: 1
        $x_1_7 = "\\Tencent Files\\All Users \\Users" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_DW_2147641437_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.DW"
        threat_id = "2147641437"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {51 52 89 75 ?? c7 45 ?? 03 00 00 00 c7 45 ?? 08 40 00 00 ff 15}  //weight: 3, accuracy: Low
        $x_1_2 = "#QQUser#" wide //weight: 1
        $x_1_3 = "\\QQPop.vbp" wide //weight: 1
        $x_1_4 = "QQPop.cSysTray" ascii //weight: 1
        $x_1_5 = {75 00 73 00 65 00 72 00 3d 00 ?? ?? ?? ?? ?? ?? 26 00 6d 00 3d 00 ?? ?? ?? ?? ?? ?? 26 00 66 00 3d 00 ?? ?? ?? ?? ?? ?? 26 00 70 00 63 00 3d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_EX_2147641876_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.EX"
        threat_id = "2147641876"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=?gb2312?B?" ascii //weight: 1
        $x_1_2 = "#BOUNDARY#" ascii //weight: 1
        $x_1_3 = "%+.2d%.2d" ascii //weight: 1
        $x_1_4 = "yiyuyan" ascii //weight: 1
        $x_1_5 = "un\\360saft" ascii //weight: 1
        $x_1_6 = "QQ9093996" ascii //weight: 1
        $x_1_7 = "rer\\ie.exe" ascii //weight: 1
        $x_1_8 = "nxwazz1314" ascii //weight: 1
        $x_1_9 = "158416620" ascii //weight: 1
        $x_1_10 = "://ten-cent." ascii //weight: 1
        $x_1_11 = "taskmgr.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule PWS_Win32_QQpass_CIA_2147642532_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.CIA"
        threat_id = "2147642532"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d:\\sys.txt" ascii //weight: 1
        $x_1_2 = "d:\\Txs.dll" ascii //weight: 1
        $x_1_3 = "mm2020.usa20.ceshi6.com/SPOP/DXBPVQ/user.asp?username=" ascii //weight: 1
        $x_1_4 = {26 6f 70 5f 74 79 70 65 3d 61 64 64 26 73 75 62 6d 69 74 3d 6f 6b 00 26 61 32 3d 00 26 61 31 3d 00 26 70 61 73 73 77 6f 72 64 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_CJQ_2147643239_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.CJQ"
        threat_id = "2147643239"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0b 83 c3 04 8b 32 83 c2 04 f3 a4 48 75 f1}  //weight: 1, accuracy: High
        $x_1_2 = "http://2011qw.qqby.org/" ascii //weight: 1
        $x_1_3 = "taskkill /f /im QQ.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_CIK_2147644239_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.CIK"
        threat_id = "2147644239"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bb b6 d3 ad ca b9 d3 c3 33 51 b4 f3 b5 c1 a3 a1 0d 0a d7 f7 d5 df d0 a1 c8 fd 20 51 51 a3 ba 35 33 39 39 39 34 38 0d 0a}  //weight: 1, accuracy: High
        $x_1_2 = {ce a8 d2 bb b9 d9 b7 bd b2 a9 bf cd a3 ba 68 74 74 70 3a 2f 2f 68 69 2e 62 61 69 64 75 2e 63 6f 6d 2f 71 71 35 33 39 39 39 34 38 0d 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_CIM_2147644494_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.CIM"
        threat_id = "2147644494"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d:\\fdsf.bmp" ascii //weight: 1
        $x_1_2 = "JoachimPeiper.dat" ascii //weight: 1
        $x_1_3 = {49 57 49 4c 4c 4b 49 4c 4c 59 4f 55 00 00 00 00 45 58 50 4c 4f 50 45 52 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = {72 77 79 65 72 77 65 69 75 72 65 72 00 00 00 00 68 68 68 68 68 68 68 68 68 68 68 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_ET_2147648009_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.ET"
        threat_id = "2147648009"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 30 80 f3 69 88 1c 30 40 3d ?? ?? ?? ?? 72 ef}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 80 23 00 00 81 c6 00 04 00 00 8b fb 83 c4 04 f3 a5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_EY_2147649399_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.EY"
        threat_id = "2147649399"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /f /im QQ.exe" ascii //weight: 1
        $x_1_2 = "Software\\Classes\\Tencent\\URL Protocol" ascii //weight: 1
        $x_1_3 = {26 71 71 70 61 73 73 77 6f 72 64 3d 00 3f 71 71 6e 75 6d 62 65 72 3d}  //weight: 1, accuracy: High
        $x_1_4 = "qq/k102tr/mail.asp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_CJR_2147649465_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.CJR"
        threat_id = "2147649465"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 45 64 69 74 00 00 00 00 54 58 45 64 69 74 00}  //weight: 2, accuracy: High
        $x_1_2 = {51 51 32 30 31 30 00 00 54 58 47 75 69 46 6f 75 6e 64 61 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {09 00 00 00 57 69 6e 67 64 69 6e 67 73 00 00 00 7b 42 41 43 4b 53 50 41 43 45 7d 00 51 51 32 30 31 30 00}  //weight: 1, accuracy: High
        $x_2_4 = {0d 00 00 00 2f 63 6f 6e 6e 2e 61 73 70 3f 61 61 3d 00 00 00 ff ff ff ff 04 00 00 00 26 62 62 3d 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_EZ_2147650175_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.EZ"
        threat_id = "2147650175"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/mail.asp" ascii //weight: 1
        $x_1_2 = "&qqpassword=" ascii //weight: 1
        $x_1_3 = "?qqnumber=" ascii //weight: 1
        $x_1_4 = "Bin\\QQ.exe" ascii //weight: 1
        $x_1_5 = "\\All Users\\QQ\\Registry.db" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_F_2147651773_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.gen!F"
        threat_id = "2147651773"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "lyjzyq1@126.com" ascii //weight: 3
        $x_2_2 = "SOFTWARE\\TENCENT\\PLATFORM_TYPE_LIST\\1\\TypePath" ascii //weight: 2
        $x_2_3 = "/START QQUIN:" ascii //weight: 2
        $x_2_4 = "?qqinf=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_FD_2147652190_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.FD"
        threat_id = "2147652190"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://ten-cent.ys168.com" ascii //weight: 3
        $x_3_2 = "exefiles\\shell\\open\\command\\" ascii //weight: 3
        $x_1_3 = "[SYSRQ]" ascii //weight: 1
        $x_2_4 = "http://www.soqo.tk" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_FE_2147652709_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.FE"
        threat_id = "2147652709"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ddraw_.RegisterSpecialCase" ascii //weight: 2
        $x_2_2 = "\\dllcache\\ddraw.dll" ascii //weight: 2
        $x_2_3 = "%s?d80=2&d10=%s" ascii //weight: 2
        $x_2_4 = "QQYX_DLL.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_CJS_2147652886_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.CJS"
        threat_id = "2147652886"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0b 83 c3 04 8b 32 83 c2 04 f3 a4 48 75 f1}  //weight: 1, accuracy: High
        $x_1_2 = {2e 41 70 70 41 63 74 69 76 61 74 65 20 22 51 51 b5 c7 c2 bc 22}  //weight: 1, accuracy: High
        $x_1_3 = "?QQNumber=" ascii //weight: 1
        $x_1_4 = "&QQPassWord=" ascii //weight: 1
        $x_1_5 = "TXGuiFoundation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_CJZ_2147653778_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.CJZ"
        threat_id = "2147653778"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 6d 2e 65 78 65 00 00 71 71 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "\\QQ\\Registry.db" ascii //weight: 1
        $x_1_3 = "GetUpdateCommonDataFolder" ascii //weight: 1
        $x_1_4 = {8b f4 6a 00 6a 02 8b fc 6a 00 6a 08 ff 15 ?? ?? ?? ?? 3b fc e8 ?? ?? ?? ?? 50 6a 08 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_FG_2147654389_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.FG"
        threat_id = "2147654389"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "File buffer length error, sure repair." ascii //weight: 5
        $x_1_2 = "Windows mistakes" ascii //weight: 1
        $x_1_3 = "&qqpassword=" ascii //weight: 1
        $x_1_4 = "?qqnumber=" ascii //weight: 1
        $x_1_5 = {54 45 4e 43 45 4e 54 5c 51 51 32 30 30 39 5c 49 6e 73 74 61 6c 6c 00 5c 55 73 65 72 73 5c 41 6c 6c 20 55 73 65 72 73}  //weight: 1, accuracy: High
        $x_1_6 = "taskkill /f /im QQ.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_FK_2147654842_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.FK"
        threat_id = "2147654842"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 6d 2e 65 78 65 00 00 71 71 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "\\QQ\\Registry.db" ascii //weight: 1
        $x_1_3 = "&qqpassword=" ascii //weight: 1
        $x_1_4 = {8a 00 8b d5 88 01 41 5f 5d 84 c0 74 ?? 8a 02 88 01 41 42 84 c0 75 ?? b1 6d b0 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_FM_2147654863_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.FM"
        threat_id = "2147654863"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c6 44 24 18 45 c6 44 24 19 64 c6 44 24 1a 69 c6 44 24 1b 74}  //weight: 10, accuracy: High
        $x_1_2 = {6a 64 68 c8 00 00 00 6a 32 aa 6a 64 8d 54 ?? ?? 68 00 00 01 00}  //weight: 1, accuracy: Low
        $x_1_3 = "\\TM\\Registry.db" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_FP_2147655461_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.FP"
        threat_id = "2147655461"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 a4 26 c6 45 a5 71 c6 45 a6 71 c6 45 a7 70 c6 45 a8 61 c6 45 a9 73 c6 45 aa 73 c6 45 ab 77 c6 45 ac 6f c6 45 ad 72 c6 45 ae 64 c6 45 af 3d 88 5d b0 ff d7}  //weight: 1, accuracy: High
        $x_1_2 = {80 ea 03 88 94 05 98 fb ff ff 40 3b c7 7e eb 06 00 8a 90}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_FP_2147655461_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.FP"
        threat_id = "2147655461"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kwws=224:6158514<715732zhe" ascii //weight: 1
        $x_1_2 = {c6 85 04 e4 fd ff 71 c6 85 05 e4 fd ff 71 c6 85 06 e4 fd ff 2e c6 85 07 e4 fd ff 65 c6 85 08 e4 fd ff 78 c6 85 09 e4 fd ff 65}  //weight: 1, accuracy: High
        $x_1_3 = {c6 85 fc dc fd ff 5c c6 85 fd dc fd ff 51 c6 85 fe dc fd ff 51 c6 85 ff dc fd ff 5c c6 85 00 dd fd ff 52 c6 85 01 dd fd ff 65 c6 85 02 dd fd ff 67 c6 85 03 dd fd ff 69 c6 85 04 dd fd ff 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_FR_2147656788_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.FR"
        threat_id = "2147656788"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d 2e 2d 63 2d 6f 2d 6d 2d 2f 71 2d 71 00}  //weight: 1, accuracy: High
        $x_1_2 = ".asp?Login_Mark=" ascii //weight: 1
        $x_1_3 = "(\"qlogin_loading\").value=pt.list[" ascii //weight: 1
        $x_1_4 = "].key+\"-\"+pt.list[" ascii //weight: 1
        $x_1_5 = "HHExecScript" ascii //weight: 1
        $x_1_6 = {25 54 57 65 62 42 72 6f 77 73 65 72 50 72 69 6e 74 54 65 6d 70 6c 61 74 65 49 6e 73 74 61 6e 74 69 61 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_7 = {54 57 65 62 42 72 6f 77 73 65 72 4f 6e 46 75 6c 6c 53 63 72 65 65 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_FU_2147657228_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.FU"
        threat_id = "2147657228"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Global\\#MHT_%s#" ascii //weight: 1
        $x_1_2 = "Global\\#PER_%s#" ascii //weight: 1
        $x_1_3 = "Global\\PxTypeLibMH" ascii //weight: 1
        $x_1_4 = "BINRES" wide //weight: 1
        $x_1_5 = "Main_LoginAccountList" wide //weight: 1
        $x_1_6 = "\\All Users\\QQ\\Registry.db" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win32_QQpass_FX_2147657765_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.FX"
        threat_id = "2147657765"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Internal.exe" ascii //weight: 1
        $x_1_2 = "\\VodCatch" ascii //weight: 1
        $x_1_3 = {da d1 b6 51 51 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = "uQQ2012Version" ascii //weight: 1
        $x_1_5 = {4e 6f 44 72 69 76 65 73 00 00 00 00 52 65 73 74 72 69 63 74 52 75 6e 00 00 00 00 00 4e 6f 4e 65 74 43 6f 6e 6e 65 63 74 44 69 73 63 6f 6e 6e 65 63 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_GD_2147678364_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.GD"
        threat_id = "2147678364"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 6f 6d 65 2e 76 62 73 00 22 29 0d 0a 64 6f 20 75 6e 74 69 6c 20 69 65 2e 72 65 61 64 79 73 74 61 74 65 3d 34 0d 0a 6c 6f 6f 70 0d 0a 73 65 74 20 69 65 3d 6e 6f 74 68 69 6e 67 00 26 51 51 50 61 73 73 57 6f 72 64 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 66 69 6e 64 2e 61 73 70 3f 51 51 4e 75 6d 62 65 72 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 65 74 20 69 65 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 69 6e 74 65 72 6e 65 74 65 78 70 6c 6f 72 65 72 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 0d 0a 69 65 2e 76 69 73 69 62 6c 65 3d 46 41 4c 53 45 0d 0a}  //weight: 1, accuracy: High
        $x_1_4 = {40 55 73 65 72 00 43 3a 5c 55 73 65 72 57 6f 72 64 2e 69 6e 69 00 5c 48 6f 74 4b 65 79 54 61 79 2e 69 6e 69 00 49 20 27 6d 20 73 6f 72 72 79 00}  //weight: 1, accuracy: High
        $x_1_5 = {71 70 6c 75 73 72 70 00 71 70 72 65 67 69 73 74 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_QQpass_GF_2147682565_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.GF"
        threat_id = "2147682565"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0b 83 c3 04 8b 32 83 c2 04 f3 a4 48 75 f1}  //weight: 1, accuracy: High
        $x_1_2 = "aq.qq.com/cn2/findpsw" ascii //weight: 1
        $x_1_3 = "QQ.exe" ascii //weight: 1
        $x_1_4 = "QQ1546605717" ascii //weight: 1
        $x_1_5 = "zjtd000" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_QQpass_GR_2147697606_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.GR"
        threat_id = "2147697606"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 51 2e 65 78 65 00 54 58 47 75 69 46 6f 75 6e 64 61 74 69 6f 6e}  //weight: 1, accuracy: High
        $x_1_2 = "@CTXOPConntion_Class" ascii //weight: 1
        $x_1_3 = {42 44 45 2e 65 78 65 00 44 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 42 61 63 5c 42 44 45 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = "tool.chacuo.net/mailanonymous" ascii //weight: 1
        $x_1_5 = {26 62 65 66 6f 72 65 53 65 6e 64 3d 75 6e 64 65 66 69 6e 65 64 00 5f 73 25 33 44 00 5f 74 25 33 44}  //weight: 1, accuracy: High
        $x_1_6 = {26 74 79 70 65 3d 61 6e 6f 6e 79 6d 6f 75 73 26 61 72 67 3d 66 25 33 44 00 64 61 74 61 3d 00 50 4f 53 54}  //weight: 1, accuracy: High
        $x_1_7 = {4d 69 73 73 57 68 6f 5f 4f 4b 00 68 74 74 70 3d 00 4d 6f 7a 69 6c 6c 61 2f 34 2e 30}  //weight: 1, accuracy: High
        $x_1_8 = "ip.tool.la/" ascii //weight: 1
        $x_1_9 = {49 50 b5 d8 d6 b7 a3 ba 00 20 20 20 20 20 20 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_GT_2147705697_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.GT"
        threat_id = "2147705697"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "javascript:for(var C=0;C<q_aUinList.length;C++){var D=q_aUinList[C];document.write(D.uin+\",\"+D.key+\"[" ascii //weight: 2
        $x_2_2 = "xui.ptlogin2.qq.com/cgi-bin/qlogin?domain=qq.com&lang=2052&qtarget=0&jumpname=&ptcss=&param=u1" ascii //weight: 2
        $x_2_3 = "xnote.cn/api/note/save/" ascii //weight: 2
        $x_1_4 = "&clientkey=" ascii //weight: 1
        $x_1_5 = "50905069" ascii //weight: 1
        $x_1_6 = "mailto:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_GW_2147708700_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.GW"
        threat_id = "2147708700"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stepnum=%d&uid=%s&cmd=OPEN_URL" ascii //weight: 1
        $x_1_2 = "stepnum=%d&uid=%s&cmd=LoginQQ" ascii //weight: 1
        $x_1_3 = "POST /api.php?mod=yzm&act=state HTTP/1.1" ascii //weight: 1
        $x_1_4 = "form-data; name=\"user_pw\"" ascii //weight: 1
        $x_1_5 = "form-data; name=\"user_name\"" ascii //weight: 1
        $x_1_6 = "/update1.php?qqtype=%d&status=1&uid=%s" ascii //weight: 1
        $x_1_7 = "C:\\92B9EN1S.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_CKH_2147708746_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.CKH!bit"
        threat_id = "2147708746"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "qq.exe786464602A3F3F" ascii //weight: 2
        $x_1_2 = "SendSMSActive" ascii //weight: 1
        $x_1_3 = {41 63 74 69 6f 6e 3d 41 64 64 55 73 65 72 26 53 65 72 76 65 72 3d [0-8] 26 55 73 65 72 3d [0-16] 26 50 61 73 73 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQpass_CKL_2147733062_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.CKL!bit"
        threat_id = "2147733062"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "360tray" ascii //weight: 1
        $x_1_2 = "taskkill /im QQ.EXE" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "&password=1&op_type=add" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_A_2147742124_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.A!MTB"
        threat_id = "2147742124"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CometHitMove" ascii //weight: 1
        $x_1_2 = {69 32 2e 74 69 65 74 75 6b 75 2e 63 6f 6d 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 70 6e 67}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 65 61 67 75 65 20 6f 66 20 4c 65 67 65 6e 64 73 2e 65 78 65 00 6c 6f 6c 2e 6c 61 75 6e 63 68 65 72 5f 74 65 6e 63 65 6e 74 2e 65 78 65 00 4c 6f 6c 43 6c 69 65 6e 74 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = "CrackMe" ascii //weight: 1
        $x_1_5 = "&callback=141779064152214697&_=" ascii //weight: 1
        $x_1_6 = "path.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQpass_B_2147742233_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQpass.B!MTB"
        threat_id = "2147742233"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CometHitMove" ascii //weight: 1
        $x_1_2 = "CrackMe" ascii //weight: 1
        $x_1_3 = {2e 74 69 65 74 75 6b 75 2e 63 6f 6d 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 70 6e 67}  //weight: 1, accuracy: Low
        $x_1_4 = "path.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

