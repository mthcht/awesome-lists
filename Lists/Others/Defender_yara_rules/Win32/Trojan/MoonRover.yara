rule Trojan_Win32_MoonRover_DA_2147819993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MoonRover.DA!MTB"
        threat_id = "2147819993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MoonRover"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\System Volume Information\\*.*" wide //weight: 1
        $x_1_2 = "C:\\aaa_TouchMeNot_\\*.*" wide //weight: 1
        $x_1_3 = "WinSock 2.0" ascii //weight: 1
        $x_1_4 = "MPGoodStatus" ascii //weight: 1
        $x_1_5 = "GetLogicalDrives" ascii //weight: 1
        $x_1_6 = "GetDiskFreeSpaceW" ascii //weight: 1
        $x_1_7 = "O Mamma Mia..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

