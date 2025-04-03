rule Backdoor_MSIL_VenomRat_AXPA_2147937744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/VenomRat.AXPA!MTB"
        threat_id = "2147937744"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VenomRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 1b 2b 1c 2b 21 73 ?? ?? 00 0a 25 72 ?? ?? 00 70 2b 17 2b 1c 2b 1d 2b 22 2b 27 de 2d 02 2b e2 28 ?? ?? 00 06 2b dd 0a 2b dc 28 ?? ?? 00 0a 2b e2 06 2b e1 28 ?? ?? 00 06 2b dc 6f ?? ?? 00 0a 2b d7 0b 2b d6}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

