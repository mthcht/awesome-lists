rule Trojan_Win32_BruteRatel_DC_2147832590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BruteRatel.DC!MTB"
        threat_id = "2147832590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BruteRatel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 7a ff cc 74 4b 85 c0 75 03 83 ea 20 8a 1a 80 fb e9 74 06 80 7a 03 e9 75 05 41 31 c0 eb e1}  //weight: 1, accuracy: High
        $x_1_2 = {31 c0 80 fb b8 75 2d 80 7a 05 e8 75 27 80 7a 06 03 75 21 80 7a 0d 8b 75 1b 80 7a 0e d4 75 15 0f b6 42 02 c1 e0 08 89 c3 0f b6 42 01 09 d8 01 c8 eb 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

