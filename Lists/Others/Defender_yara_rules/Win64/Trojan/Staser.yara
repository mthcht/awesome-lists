rule Trojan_Win64_Staser_NS_2147909033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Staser.NS!MTB"
        threat_id = "2147909033"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {31 c0 4c 8d 44 24 ?? 4c 89 c7 f3 48 ab 48 8b 3d a8 9f 85 01 44 8b 0f 45 85 c9 0f 85 ?? ?? ?? ?? 65 48 8b 04 25 30 00 00 00 48 8b 1d ?? ?? ?? ?? 48 8b 70 08 31 ed 4c 8b 25 ?? ?? ?? ?? eb 16 0f 1f}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Staser_LMA_2147962515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Staser.LMA!MTB"
        threat_id = "2147962515"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {80 f2 41 41 88 10 4d 8d 40 01 41 0f b6 10 84 d2}  //weight: 20, accuracy: High
        $x_10_2 = {80 f1 41 88 0a 48 8d 52 01 0f b6 0a 84 c9}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

