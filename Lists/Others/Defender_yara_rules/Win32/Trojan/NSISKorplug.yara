rule Trojan_Win32_NSISKorplug_OR_2147796150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISKorplug.OR!MTB"
        threat_id = "2147796150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISKorplug"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 20 56 c6 44 24 21 69 c6 44 24 24 75 c6 44 24 25 61 c6 44 24 26 6c c6 44 24 27 50 c6 44 24 29 6f 88 54 24 2b c6 44 24 2c 63 c6 44 24 2e 00}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e8 08 c1 e9 10 88 46 07 88 4e 08 c1 ea 18 88 56 09 c6 46 0a c3 8b 4c 24 08 8d 44 24 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

