rule Trojan_Win64_Bazar_EA_2147853200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bazar.EA!MTB"
        threat_id = "2147853200"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 89 84 24 f8 00 00 00 b8 0a 00 00 00 48 01 f8 48 89 44 24 78 bd 03 00 00 00 48 89 c8 48 09 e8 48 89 84 24 f0 00 00 00 48 09 cb 48 89 c8 48 09 e8 48 89 84 24 e8 00 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bazar_GA_2147928156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bazar.GA!MTB"
        threat_id = "2147928156"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 31 d2 49 f7 f0 45 8a 14 11}  //weight: 1, accuracy: High
        $x_1_2 = {44 30 14 0f 48 ff c1 48 89 c8 48 81 f9 [0-4] 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Bazar_AI_2147928719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bazar.AI!MTB"
        threat_id = "2147928719"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 31 d2 49 f7 f1 45 8a 14 ?? 44 30 14 0f 48 ff c1 48 89 c8 48 81 f9 ?? ?? ?? ?? 76 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

