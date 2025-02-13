rule TrojanDropper_MSIL_Marsilia_NIT_2147921879_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Marsilia.NIT!MTB"
        threat_id = "2147921879"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 6f 1c 00 00 0a 73 19 00 00 0a 13 06 1a 8d 1a 00 00 01 13 07 11 06 11 07 16 1a 6f ?? 00 00 0a 26 11 07 16 28 ?? 00 00 0a 13 08 11 06 16 73 1f 00 00 0a 13 09 11 09 11 05 6f ?? 00 00 0a 73 20 00 00 0a 13 0a 11 0a 11 05 6f ?? 00 00 0a 6f ?? 00 00 0a 11 0a 13 0a dd 63 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_Marsilia_NIT_2147921879_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Marsilia.NIT!MTB"
        threat_id = "2147921879"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marsilia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "embeddedBatchScript" ascii //weight: 1
        $x_1_2 = "TEMP\\b2a.c" ascii //weight: 1
        $x_2_3 = {28 05 00 00 0a 1b 8d 0a 00 00 01 13 04 11 04 16 72 27 00 00 70 a2 11 04 17 7e 01 00 00 04 a2 11 04 18 72 31 00 00 70 a2 11 04 19 7e 02 00 00 04 a2 11 04 1a 72 35 00 00 70 a2 11 04 28 06 00 00 0a 28 07 00 00 0a 0a 06 28 08 00 00 0a 2c 11 06 20 80 00 00 00 28 09 00 00 0a 06 28 0a 00 00 0a 06 72 3f 00 00 70 28 04 00 00 06 28 05 00 00 06 28 0b 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

