rule Backdoor_MSIL_Mokes_MBP_2147838042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Mokes.MBP!MTB"
        threat_id = "2147838042"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fsfhrgdddffdffffkhsjd" ascii //weight: 1
        $x_1_2 = "nhffskdsfkdfddafrffddhfscffdf" ascii //weight: 1
        $x_1_3 = "sdfffdsshfffdhf" ascii //weight: 1
        $x_1_4 = "fffffff" wide //weight: 1
        $x_1_5 = "GetMethod" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Mokes_AAZU_2147899113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Mokes.AAZU!MTB"
        threat_id = "2147899113"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 08 03 8e 69 5d 18 58 1d 58 1f 09 59 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 18 58 1d 58 1f 09 59 91 61 28 ?? 00 00 0a 03 08 20 87 10 00 00 58 20 86 10 00 00 59 03 8e 69 5d 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Mokes_AHNA_2147935314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Mokes.AHNA!MTB"
        threat_id = "2147935314"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 04 07 8e 69 5d 91 13 05 06 11 04 8f ?? 00 00 01 25 47 11 05 1e 5a 20 00 01 00 00 5d d2 61 d2 52 08 11 04 06 11 04 91 11 04 1f 0e 5a 20 00 01 00 00 5d 59 11 05 61 d2 9c 11 04 17 58 13 04 11 04 06 8e 69 32 b9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Mokes_ASNA_2147935721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Mokes.ASNA!MTB"
        threat_id = "2147935721"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {16 13 04 2b 22 06 09 8f 21 00 00 01 25 47 07 11 04 91 09 1f 1e 5d 58 d2 61 d2 52 09 17 58 0d 11 04 17 58 08 5d 13 04 09 06 8e 69 32 d8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

