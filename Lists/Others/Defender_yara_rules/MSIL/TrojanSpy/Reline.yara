rule TrojanSpy_MSIL_Reline_SK_2147946127_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Reline.SK!MTB"
        threat_id = "2147946127"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 3a 06 00 00 00 28 13 00 00 06 0a 06 39 0a 00 00 00 06 16 06 8e 69 28 04 00 00 0a dd 13 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

