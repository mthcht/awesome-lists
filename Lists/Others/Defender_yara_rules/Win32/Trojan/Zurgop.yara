rule Trojan_Win32_Zurgop_SK_2147764345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zurgop.SK!MSR"
        threat_id = "2147764345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zurgop"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 84 24 9c 02 00 00 8a 94 06 3b 2d 0b 00 88 14 01 5e 81 c4 94 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

