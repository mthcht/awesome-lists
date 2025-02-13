rule Trojan_MSIL_FrauDropper_ARA_2147837755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FrauDropper.ARA!MTB"
        threat_id = "2147837755"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FrauDropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 17 58 20 00 01 00 00 5d 13 04 11 05 07 11 04 91 58 20 00 01 00 00 5d 13 05 07 11 04 91 0d 07 11 04 07 11 05 91 9c 07 11 05 09 9c 07 11 04 91 07 11 05 91 58 20 00 01 00 00 5d 13 07 02 11 06 8f 16 00 00 01 25 71 16 00 00 01 07 11 07 91 61 d2 81 16 00 00 01 11 06 17 58 13 06 11 06 02 16 6f ?? ?? ?? 0a 32 98}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

