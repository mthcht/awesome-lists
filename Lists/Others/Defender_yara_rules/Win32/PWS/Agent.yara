rule PWS_Win32_Agent_AC_2147595516_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Agent.AC"
        threat_id = "2147595516"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SysWin64.Jmp" ascii //weight: 1
        $x_1_2 = "SysWin64.Lst" ascii //weight: 1
        $x_1_3 = "CLSID\\{40117B96-998D-4D80-8F89-5E9DBD9F3460}" ascii //weight: 1
        $x_1_4 = "(&O)\\command=AutoRun.exe" ascii //weight: 1
        $x_1_5 = "shellexecute=AutoRun.exe" ascii //weight: 1
        $x_1_6 = "E:\\AutoRun.exe" ascii //weight: 1
        $x_1_7 = "E:\\AutoRun.Inf" ascii //weight: 1
        $x_1_8 = "WinSys64.Tao" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule PWS_Win32_Agent_AD_2147595517_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Agent.AD"
        threat_id = "2147595517"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Tencent\\Gm" ascii //weight: 1
        $x_1_2 = "http://www.126.cn/" ascii //weight: 1
        $x_1_3 = "Tencent_QQToolBar" ascii //weight: 1
        $x_1_4 = "ExplOrer.exe" ascii //weight: 1
        $x_1_5 = "SysWin64.Jmp" ascii //weight: 1
        $x_1_6 = "SysWin64.Lst" ascii //weight: 1
        $x_1_7 = "&PassWord=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Agent_IK_2147598556_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Agent.IK!dll"
        threat_id = "2147598556"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2533"
        strings_accuracy = "High"
    strings:
        $x_1000_1 = "203.121.69.232" ascii //weight: 1000
        $x_1000_2 = "Mozilla/5.0 Gecko/20050212 Firefox/1.5.0.2" ascii //weight: 1000
        $x_100_3 = "aol92.exe" ascii //weight: 100
        $x_100_4 = "KB0626395.log" ascii //weight: 100
        $x_100_5 = "passwd123" ascii //weight: 100
        $x_100_6 = "cookies.zip" ascii //weight: 100
        $x_100_7 = "flash.zip" ascii //weight: 100
        $x_10_8 = "webcashmgmt.com" ascii //weight: 10
        $x_10_9 = "nationalcity.com/corporate" ascii //weight: 10
        $x_10_10 = "www.enternetbank.com/ewb/" ascii //weight: 10
        $x_10_11 = "treasury.pncbank" ascii //weight: 10
        $x_10_12 = "business.ml.com" ascii //weight: 10
        $x_1_13 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_14 = "InternetReadFile" ascii //weight: 1
        $x_1_15 = "InternetWriteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1000_*) and 5 of ($x_100_*) and 3 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_1000_*) and 5 of ($x_100_*) and 4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Agent_DP_2147603114_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Agent.DP"
        threat_id = "2147603114"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SYSTEM\\CurrentControlSet\\Services\\srservice" ascii //weight: 1
        $x_1_2 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
        $x_1_3 = "PK11_GetInternalKeySlot" ascii //weight: 1
        $x_1_4 = "Software\\Adobe\\STR" ascii //weight: 1
        $x_1_5 = "WM_HTML_GETOBJECT" ascii //weight: 1
        $x_1_6 = "YAHOO MESSENGER" ascii //weight: 1
        $x_1_7 = "MSN MESSENGER" ascii //weight: 1
        $x_1_8 = "IM sessions" ascii //weight: 1
        $x_1_9 = "RCPT TO:<" ascii //weight: 1
        $x_1_10 = "PASSWORDS" ascii //weight: 1
        $x_1_11 = "TFTPSend" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Agent_J_2147651207_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Agent.J"
        threat_id = "2147651207"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 72 76 65 72 2e 64 6c 6c 00 52 75 6b 6f 75}  //weight: 1, accuracy: High
        $x_1_2 = {77 69 6e 73 74 61 30 00 73 68 69 74}  //weight: 1, accuracy: High
        $x_1_3 = "\\Xlog.dat" ascii //weight: 1
        $x_1_4 = "DNAMMOC\\NEPO\\LLEHS\\EXE.EROLPXEI\\SNOITACILPPa" ascii //weight: 1
        $x_1_5 = {2d 2f 2d 20 2d 2f 2d 00 00 61 76 61 73 74 00 00 00 61 76 69 72 61}  //weight: 1, accuracy: High
        $x_1_6 = {5c 53 69 6e 63 65 00 08 00 53 4f 46 54 57 41 52 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

