rule Backdoor_Win64_BruteRatel_ZZ_2147832497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/BruteRatel.ZZ"
        threat_id = "2147832497"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "BruteRatel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 79 ff cc 74 58 45 85 c0 75 04 48 83 e9 20 44 8a 09 41 80 f9 e9 74 0a 44 8a 41 03 41 80 f8 e9 75 07 ff c2 45 31 c0 eb d7}  //weight: 1, accuracy: High
        $x_1_2 = {31 c0 41 80 f9 4c 75 2f 80 79 01 8b 75 29 80 79 02 d1 75 21 41 80 f8 b8 75 1b 80 79 06 00 75 17 0f b6 41 05 c1 e0 08 41 89 c0 0f b6 41 04 44 09 c0 01 d0 eb 02 31 c0 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_BruteRatel_AA_2147839775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/BruteRatel.AA!MTB"
        threat_id = "2147839775"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "BruteRatel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 e4 f0 68 ?? ?? ?? ?? 5a e8 00 00 00 00 59 48 01 d1 48 83 c1 ?? ff d1}  //weight: 1, accuracy: Low
        $x_1_2 = {41 59 e8 00 00 00 00 41 58 4d 01 c8 49 83 c0 ?? 41 ff d0 20 00 59 68 ?? ?? ?? ?? 41 59}  //weight: 1, accuracy: Low
        $x_1_3 = {0f be 11 45 31 c0 84 d2 74 ?? 66 0f 1f 44 00 00 44 89 c0 48 83 c1 01 c1 e0 ?? 44 01 c0 0d 00 00 80 02 44 8d 04 02 0f be 11 84 d2 75 ?? 44 89 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_BruteRatel_MB_2147895634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/BruteRatel.MB!MTB"
        threat_id = "2147895634"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "BruteRatel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 27 00 00 00 f7 f9 8b c2 48 98 48 8d 0d ?? ?? ?? ?? 0f be 04 01 8b 8c 24 80 00 00 00 33 c8 8b c1 48 63 4c 24 30 48 8b 54 24 70 88 04 0a e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

