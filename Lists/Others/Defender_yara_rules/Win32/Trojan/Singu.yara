rule Trojan_Win32_Singu_A_2147603493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Singu.A"
        threat_id = "2147603493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Singu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 4f 00 00 00 8d 7c 24 ?? 50 68 90 02 00 00 f3 ab 53 ff d5 53 68 3c 01 00 00 8d 54 24 ?? 6a 01 52 ff 15 ?? ?? 40 00 b9 4f 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 bc 03 00 00 f3 a4 b9 4f 00 00 00 8d 7c 24 ?? f3 ab 53 ff d5 53 6a 10 8d 44 24 ?? 6a 01 50 ff 15 ?? ?? 40 00 8d 4c 24 ?? 68 3c 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 b4 03 00 00 ff 75 ?? ff d7 ff 75 ?? 6a 02 6a 01 68 ?? ?? 00 10 ff d3 83 c4 28 83 3d f4 ?? ?? 10 00 0f ?? ?? 00 00 00 6a 00 68 b6 03 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Singu_B_2147603512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Singu.B"
        threat_id = "2147603512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Singu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "155"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "%sWin32en.bat" ascii //weight: 100
        $x_10_2 = "RCPT TO:%s" ascii //weight: 10
        $x_10_3 = "MAIL FROM:%s" ascii //weight: 10
        $x_10_4 = "\\WINDOWS\\SYSTEM32\\Kernel*.DLL" ascii //weight: 10
        $x_10_5 = "CLSID\\{EC83B900-B33A-D316-EF7D-0006CA350705}" ascii //weight: 10
        $x_10_6 = "InternetReadFile" ascii //weight: 10
        $x_1_7 = "%s\\stat.ini" ascii //weight: 1
        $x_1_8 = "sendpass" ascii //weight: 1
        $x_1_9 = "system.dll" ascii //weight: 1
        $x_1_10 = "backinfo.ini" ascii //weight: 1
        $x_1_11 = "../update.exe" ascii //weight: 1
        $x_1_12 = "Get Mail For Us!" ascii //weight: 1
        $x_1_13 = "We Will Get Mail!" ascii //weight: 1
        $x_1_14 = "%s?action=getcmd&hostid=%s&hostname=%s" ascii //weight: 1
        $x_1_15 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\IEXPLORE.EXE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 5 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

