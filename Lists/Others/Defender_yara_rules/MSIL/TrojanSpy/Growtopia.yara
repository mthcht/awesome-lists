rule TrojanSpy_MSIL_Growtopia_AGR_2147946484_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Growtopia.AGR!MTB"
        threat_id = "2147946484"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Growtopia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 16 1f 30 11 14 16 91 59 d2 13 17 00 11 14 13 20 16 13 21 2b 1b 11 20 11 21 91 13 22 11 15 11 17 11 22 58 d2 6f ?? 00 00 0a 00 11 21 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

