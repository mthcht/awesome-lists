rule Trojan_MSIL_StealerMulti_RDA_2147835627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerMulti.RDA!MTB"
        threat_id = "2147835627"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerMulti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 22 00 00 0a 0b 72 ?? ?? ?? ?? 28 11 00 00 0a 11 04 8d 05 00 00 01 13 05 07 11 05 16 11 04 6f 20 00 00 0a 26 72 ?? ?? ?? ?? 28 11 00 00 0a 11 05 13 07 de ?? 07 14 fe 01}  //weight: 2, accuracy: Low
        $x_2_2 = {6f 16 00 00 0a 0d 02 28 ?? ?? ?? ?? 09 16 28 17 00 00 0a 13 06 02 28 ?? ?? ?? ?? 26 09 72 ?? ?? ?? ?? 20 14 01 00 00 14 11 06 14 6f 13 00 00 0a 13 07 11 07 74 26 00 00 01 28 11 00 00 0a 2b ?? 72 ?? ?? ?? ?? 28 11 00 00 0a 73 18 00 00 0a 7a 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerMulti_RDB_2147844560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerMulti.RDB!MTB"
        threat_id = "2147844560"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerMulti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8e 69 5d 91 03 11 04 91 61 d2 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

