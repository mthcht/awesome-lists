rule Ransom_MSIL_Makop_MAK_2147794936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Makop.MAK!MTB"
        threat_id = "2147794936"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Makop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "makop" ascii //weight: 1
        $x_1_2 = "Encrypted:" ascii //weight: 1
        $x_1_3 = "Failed to encrypt:" ascii //weight: 1
        $x_1_4 = "your files have been encrypted" ascii //weight: 1
        $x_1_5 = "\\README-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Makop_XY_2147901546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Makop.XY!MTB"
        threat_id = "2147901546"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Makop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {58 4a 03 8e 69 5d 03 06 1a 58 4a 03 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 2f 00 00 0a 03 06 1a 58 4a 1d 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Makop_BK_2147931600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Makop.BK!MTB"
        threat_id = "2147931600"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Makop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {59 03 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 03 8e 69 17 59 6a 06 17 58 6e 5a 31}  //weight: 4, accuracy: High
        $x_1_2 = {03 08 03 8e 69 5d 91 07 08 07 8e 69 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

