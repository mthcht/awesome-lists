rule Ransom_MSIL_Paradise_PA_2147788115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Paradise.PA!MTB"
        threat_id = "2147788115"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Paradise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files have been encrypted," ascii //weight: 1
        $x_1_2 = "#DECRYPT MY FILES#" wide //weight: 1
        $x_1_3 = "\\DecryptionInfo" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Paradise_APA_2147946837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Paradise.APA!MTB"
        threat_id = "2147946837"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Paradise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 05 16 13 06 2b 37 1f 75 8d ?? ?? ?? 01 13 07 16 13 08 2b 15 11 07 11 08 08 11 05 91 9c 11 05 17 58 13 05 11 08 17 58 13 08 11 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

