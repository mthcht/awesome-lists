rule Trojan_Win32_SusMountlocker_A_2147955538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusMountlocker.A"
        threat_id = "2147955538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusMountlocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c echo" ascii //weight: 1
        $x_1_2 = " > " wide //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_4 = "readme.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

