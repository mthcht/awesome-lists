rule Trojan_Win64_Spynoon_MFP_2147781045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Spynoon.MFP!MTB"
        threat_id = "2147781045"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 0b 28 14 00 00 0a 11 0b 6f ?? ?? ?? 0a 13 ?? 06 11 ?? 11 ?? 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 ?? 28 ?? ?? ?? 0a 11 ?? 6f ?? ?? ?? 0a 13 ?? 28 ?? ?? ?? 0a 13 ?? 1a 8d 01 ?? ?? 01 13 ?? 11 ?? 16 11 ?? a2 11 ?? 17 7e ?? ?? ?? 0a a2 11 ?? 18 06 11 ?? 6f ?? ?? ?? 0a a2 11 ?? 19 17 8c ?? ?? ?? 01 a2 11 ?? 13 ?? 11 ?? 11 ?? 6f ?? ?? ?? 0a 11 ?? 20 ?? ?? ?? 00 14 14 11 ?? 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 26 de}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Spynoon_AP_2147982132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Spynoon.AP!MTB"
        threat_id = "2147982132"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {99 41 f7 f8 48 63 d2 8a 04 17 30 04 0b 48 ff c1}  //weight: 15, accuracy: High
        $x_5_2 = {48 89 f8 48 8d 57 1e 80 30 ?? 48 ff c0 48 39 d0 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

