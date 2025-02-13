rule TrojanDropper_MSIL_Ader_ARA_2147838111_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Ader.ARA!MTB"
        threat_id = "2147838111"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 09 11 05 09 8e 69 5d 91 08 11 05 91 61 d2 6f ?? ?? ?? 0a 11 05 17 58 13 05 11 05 08 8e 69 32 de}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

