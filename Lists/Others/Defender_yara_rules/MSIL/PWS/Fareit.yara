rule PWS_MSIL_Fareit_VJ_2147746273_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Fareit.VJ!MTB"
        threat_id = "2147746273"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a2 25 17 28 ?? ?? ?? 06 a2 25 18 28 ?? ?? ?? 06 a2 25 19 28 ?? ?? ?? 06 a2 25 1a 28 ?? ?? ?? 06 a2 25 1b 28 ?? ?? ?? 06 a2 25 1c 28 ?? ?? ?? 06 a2 20 ?? ?? ?? 00 20 ?? ?? ?? 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 2a 07 00 25 16 28 ?? ?? ?? 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Fareit_ABY_2147829923_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Fareit.ABY!MTB"
        threat_id = "2147829923"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {57 d5 02 e8 09 03 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 26 00 00 00 12 00 00 00 39 00 00 00 66 02 00 00 17 00 00 00}  //weight: 4, accuracy: High
        $x_1_2 = "TransformFinalBlock" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "Confuser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

