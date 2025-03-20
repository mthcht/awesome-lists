rule Trojan_MSIL_Purelogstealer_SRT_2147936584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Purelogstealer.SRT!MTB"
        threat_id = "2147936584"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Purelogstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 10 00 00 0a 07 6f 11 00 00 0a 6f 12 00 00 0a 06 fe 06 ?? ?? ?? 06 73 13 00 00 0a 28 01 00 00 2b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

