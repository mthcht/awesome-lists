rule Trojan_Win64_Havokiz_DX_2147890339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Havokiz.DX!MTB"
        threat_id = "2147890339"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Havokiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 94 03 f0 00 00 00 80 fa ff 75 10 c6 84 03 f0 00 00 00 00 48 83 e8 01 73 e6 eb 0b 48 98 ff c2 88 94 03 f0 00 00 00 31 c0 48 63 d0 ff c0 8a 54 14 30 30 16 48 ff c6 e9}  //weight: 1, accuracy: High
        $x_1_2 = {45 31 d1 44 32 52 ff 41 31 c1 89 c8 01 c9 c0 e8 07 45 31 c8 0f af c7 44 88 42 fe 45 89 d0 44 31 c0 31 c1 88 4a ff 49 39 d3 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Havokiz_SA_2147892307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Havokiz.SA!MTB"
        threat_id = "2147892307"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Havokiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 0f b6 c0 0f af d0 48 ?? ?? ?? ?? ?? ?? 88 14 01 ff 43 ?? 48 ?? ?? ?? ?? ?? ?? 8b 4b ?? 2b 48 ?? 8b 83 ?? ?? ?? ?? 83 c1 ?? 01 8b ?? ?? ?? ?? 09 05 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 8b 48 ?? 33 8b ?? ?? ?? ?? 83 e9 ?? 09 4b ?? 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Havokiz_PADG_2147901854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Havokiz.PADG!MTB"
        threat_id = "2147901854"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Havokiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 83 fb 0f 48 0f 47 cf 33 d2 48 f7 f6 44 32 04 0a 45 88 01 41 ff c2 4d 8d 49 01 49 63 c2 48 3b ?? ?? ?? ?? ?? 72 d0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Havokiz_TI_2147907118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Havokiz.TI!MTB"
        threat_id = "2147907118"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Havokiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c0 89 44 24 ?? b8 ?? ?? ?? ?? 48 6b c0 ?? b9 ?? ?? ?? ?? 48 6b c9 ?? 48 8b 54 24 ?? 4c 8b ?? 24 ?? 41 8b 4c 08 ?? 8b 44 02 ?? 0b c1 35 ?? ?? ?? ?? 39 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

