rule Trojan_Win32_SusColdFire_A_2147955555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusColdFire.A"
        threat_id = "2147955555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusColdFire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_2 = "coldfire.exe " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

