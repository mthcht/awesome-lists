rule TrojanDropper_MSIL_Seraph_ARAU_2147839815_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Seraph.ARAU!MTB"
        threat_id = "2147839815"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 13 0b 11 0b 17 58 0d 09 20 00 01 00 00 5d 0d 11 05 11 09 09 94 58 13 05 11 05 20 00 01 00 00 5d 13 05 11 09 09 94 13 07 11 09 09 11 09 11 05 94 9e 11 09 11 05 11 07 9e 11 09 11 09 09 94 11 09 11 05 94 58 20 00 01 00 00 5d 94 13 06 11 0a 11 04 07 11 04 91 11 06 61 d2 9c 11 04 13 0b 11 0b 17 58 13 04 11 04 07 8e 69 32 94}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_Seraph_PAAX_2147853147_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Seraph.PAAX!MTB"
        threat_id = "2147853147"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rrwpacxtsgivduqrccoqwt" ascii //weight: 1
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_Seraph_AKS_2147913913_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Seraph.AKS!MTB"
        threat_id = "2147913913"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seraph"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 02 28 23 00 00 0a 7e ?? ?? ?? 04 15 16 28 ?? ?? ?? 0a 16 9a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a de 40}  //weight: 5, accuracy: Low
        $x_1_2 = "$d755c575-03a8-4e4a-88dc-3768dc14b2a7" ascii //weight: 1
        $x_1_3 = "yutrnno.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

