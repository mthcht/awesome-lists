rule Ransom_MSIL_Wessy_MA_2147901279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Wessy.MA!MTB"
        threat_id = "2147901279"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wessy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 1f 10 8d ?? ?? ?? 01 25 d0 74 00 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 07 6f ?? ?? ?? 0a 17 73 21 00 00 0a 25 02 16 02 8e 69 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

