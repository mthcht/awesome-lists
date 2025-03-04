rule Trojan_Win64_WinGo_GA_2147896253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WinGo.GA!MTB"
        threat_id = "2147896253"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WinGo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {4c 89 5c 24 28 44 89 4c 24 18 41 89 d5 c1 ea 18 0f b6 d2 4c 8d 3d 2d 39 0e 00 41 8b 14 97 42 33 14 a0 41 c1 e9 10 45 0f b6 c9 48 8d 3d 16 3d 0e 00 42 33 14 8f 45 89 d1 41 c1 ea 08 45 0f b6 d2 48 8d 35 00 41 0e 00 42 33 14 96 45 0f b6 d0 49 8d 5c 24 01 4c 8d 1d ec 44 0e 00 43 33 14 93 0f 1f 84 00 00 00 00 00 48 39 d9}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_WinGo_CCJR_2147923576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WinGo.CCJR!MTB"
        threat_id = "2147923576"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WinGo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 0f b6 14 11 44 31 d7 41 88 3c 30 48 ff c6 4c 89 c0 4c 89 ca 48 39 f3 7e ?? 0f b6 3c 30 48 85 c9 74 ?? 49 89 c0 48 89 f0 49 89 d1 48 99 48 f7 f9 48 39 d1 77}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

