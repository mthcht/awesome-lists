rule Trojan_Win32_Kolweb_L_2147599929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kolweb.L"
        threat_id = "2147599929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kolweb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "87"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\explorer\\Browser Helper Objects\\" ascii //weight: 20
        $x_20_2 = "Software\\NVIDIA Corporation\\Cpanel\\Desktops" ascii //weight: 20
        $x_20_3 = "TIEBrowserHelperFactory" ascii //weight: 20
        $x_20_4 = "http://www.forgotabouttroubles.com/yep/" ascii //weight: 20
        $x_20_5 = "http://www.followwhiterabbit.com/yep/" ascii //weight: 20
        $x_1_6 = "lastdesktop" ascii //weight: 1
        $x_1_7 = "desktoplist" ascii //weight: 1
        $x_1_8 = "useddesktop" ascii //weight: 1
        $x_1_9 = "Last User ID" ascii //weight: 1
        $x_1_10 = "Default User ID" ascii //weight: 1
        $x_1_11 = "LastConnected" ascii //weight: 1
        $x_1_12 = "FirstConnected" ascii //weight: 1
        $x_1_13 = "desctop_" ascii //weight: 1
        $x_1_14 = "settings.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_20_*) and 7 of ($x_1_*))) or
            ((5 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Kolweb_M_2147602549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kolweb.M"
        threat_id = "2147602549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kolweb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YahooStock\\xcurrent\\_IEBrowserHelper" ascii //weight: 1
        $x_1_2 = "CurrentVersion\\explorer\\Browser Helper Objects" ascii //weight: 1
        $x_1_3 = {67 65 74 68 6f 73 74 62 79 61 64 64 72 00 00 00 73 6f 63 6b 65 74}  //weight: 1, accuracy: High
        $x_1_4 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_5 = {33 c0 89 45 fc 8b 45 0c 3d fd 00 00 00 7f 25 0f 84 76 01 00 00 83 e8 66 74 3a 83 e8 0b 74 57 2d 89 00 00 00 74 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kolweb_P_2147603115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kolweb.P"
        threat_id = "2147603115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kolweb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Set FileSystemObject = CreateObject(\"scripting.filesystemobject\")" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Internet Explorer\\Toolbar" ascii //weight: 1
        $x_1_5 = "Set Shell = CreateObject(\"Wscript.Shell\")" ascii //weight: 1
        $x_1_6 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_7 = "exefile\\shell\\Open\\Command" ascii //weight: 1
        $x_1_8 = "piffile\\shell\\Open\\Command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kolweb_Q_2147623107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kolweb.Q"
        threat_id = "2147623107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kolweb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 72 69 76 65 72 61 2e 64 6c 6c 20 64 72 69 76 65 72 61 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {83 e8 10 74 ?? 83 e8 10 74 ?? e9 ?? ?? 00 00 33 c0 89 44 24 08 8d 44 24 08 50 68 7f 66 04 40 8b 46 28 50 e8 ?? ?? ff ff 8b d0 8b c6 e8 ?? ?? ff ff 66 c7 04 24 03 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

