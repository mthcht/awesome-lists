rule Trojan_Win32_Brresmon_RR_2147962513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Brresmon.RR!MTB"
        threat_id = "2147962513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Brresmon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 45 fe 8b ca c1 f9 06 83 e2 3f 6b d2 38 8b 0c 8d 48 9f 41 00 88 44 11 29 8b 0b 8b c1 c1 f8 06 83 e1 3f 6b d1 38 8b 0c 85 48 9f 41 00 8b 45 14 c1 e8 10 32 44 11 2d 24 01 30 44 11 2d f6 45 ff 48 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

