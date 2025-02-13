rule Trojan_MSIL_PureLogs_SK_2147903203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.SK!MTB"
        threat_id = "2147903203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 8d 17 00 00 01 13 05 11 04 11 05 16 09 6f 13 00 00 0a 26 11 05 28 01 00 00 2b 28 02 00 00 2b 0a de 16}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_SL_2147914284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.SL!MTB"
        threat_id = "2147914284"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 7b 57 00 00 04 06 07 03 6f 2a 00 00 0a 0c 08 2c 0f 07 08 58 0b 03 08 59 fe 0b 01 00 03 16 30 df}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_KAF_2147917510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.KAF!MTB"
        threat_id = "2147917510"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {95 58 20 ff 00 00 00 5f 95 61 28 ?? 00 00 0a 9c fe 0c 06 00 20 ?? 00 00 00 6a 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogs_SN_2147917691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogs.SN!MTB"
        threat_id = "2147917691"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 72 01 00 00 70 20 00 01 00 00 14 14 14 6f 18 00 00 0a 26 de 03}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

