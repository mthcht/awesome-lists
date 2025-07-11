rule Trojan_MSIL_Pretoria_SK_2147917681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Pretoria.SK!MTB"
        threat_id = "2147917681"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pretoria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 7e 02 00 00 04 8e 69 5d 0b 02 06 02 06 91 7e 02 00 00 04 07 91 61 d2 9c 06 17 58 0a 06 02 8e 69 32 dd}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Pretoria_ZLR_2147946101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Pretoria.ZLR!MTB"
        threat_id = "2147946101"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pretoria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {1f 09 0b 04 03 07 5d 9a 28 ?? 00 00 0a 02 28 ?? 00 00 06 28 ?? 01 00 0a 0a 2b 00 06 2a}  //weight: 6, accuracy: Low
        $x_5_2 = {02 07 02 07 91 07 03 28 ?? 01 00 06 9c 07 17 d6 0b 07 06 31 eb 2a}  //weight: 5, accuracy: Low
        $x_4_3 = {02 03 04 28 ?? 01 00 06 00 02 0a 2b 00 06 2a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

