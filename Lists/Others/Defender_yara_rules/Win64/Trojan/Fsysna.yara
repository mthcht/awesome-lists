rule Trojan_Win64_Fsysna_NFC_2147899903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fsysna.NFC!MTB"
        threat_id = "2147899903"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {75 e2 48 8b 84 24 ?? ?? ?? ?? 89 44 24 28 48 8d 84 24 ?? ?? ?? ?? 48 89 44 24 20 41 b9 ?? ?? ?? ?? 45 33 c0 48 8d 15 a9 d0 02 00}  //weight: 5, accuracy: Low
        $x_1_2 = "CmNtZC5leGUgL2Mg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fsysna_KK_2147978900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fsysna.KK!MTB"
        threat_id = "2147978900"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fsysna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {0f b6 44 24 07 48 8b 4c 24 10 8b 54 24 08 44 0f b6 04 11 41 31 c0 44 88 04 11 8b 44 24 08 83 c0 01 89 44 24 08}  //weight: 20, accuracy: High
        $x_10_2 = {0f b6 94 14 80 00 00 00 30 54 0e ff 48 8d 14 0f 48 ff c2 48 ff c1 48 83 fa 01}  //weight: 10, accuracy: High
        $x_10_3 = {46 0f b6 8c 0c 80 00 00 00 45 30 08 49 ff c0 fe c2 49 39 c0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

