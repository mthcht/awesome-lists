rule TrojanDropper_MSIL_Azorult_E_2147759783_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Azorult.E!MTB"
        threat_id = "2147759783"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 03 6f 1f 00 00 0a 7e 07 00 00 04 03 7e 07 00 00 04 6f 1d 00 00 0a 5d 6f 1f 00 00 0a 61 [0-48] 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_Azorult_F_2147759861_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Azorult.F!MTB"
        threat_id = "2147759861"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 01 25 d0 01 00 00 04 28 21 00 00 0a 73 22 00 00 0a 0a 73 23 00 00 0a [0-32] 73 24 00 00 0a [0-48] 6f 25 00 00 0a 1e 5b 6f 26 00 00 0a 6f 27 00 00 0a [0-48] 6f 28 00 00 0a 1e 5b 6f 26 00 00 0a 6f 29 00 00 0a [0-48] 6f 2a 00 00 0a 17 73 2b 00 00 0a [0-48] 8e 69 6f 2c 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

