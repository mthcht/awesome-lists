rule Trojan_Win64_Cerbu_AMS_2147851297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cerbu.AMS!MTB"
        threat_id = "2147851297"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 1f 80 00 00 00 00 0f b6 14 0b 48 8d 49 01 80 f2 71 41 ff c0 88 51 ff 48 8b 54 24 70 49 63 c0 48 3b c2}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 44 24 28 33 d2 88 44 24 40 89 44 24 20 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cerbu_GTT_2147926640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cerbu.GTT!MTB"
        threat_id = "2147926640"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 f0 13 20 b3 ?? ff 00 18 a5 ?? ?? ?? ?? 48 08 ed 89 ba ?? ?? ?? ?? f7 e3 01 00 00 00 51 32 d6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Cerbu_AB_2147951435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Cerbu.AB!MTB"
        threat_id = "2147951435"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 0f b7 47 06 ff c6 48 83 c3 28 3b f0 0f 85 51 ff ff ff 0f b7 c8 41 0f b7 5f 14 45 33 f6 48 83 c3 18 49 03 df 66 85 c9 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

