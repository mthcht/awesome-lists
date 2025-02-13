rule Trojan_MSIL_Lethic_GN_2147760544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lethic.GN!MTB"
        threat_id = "2147760544"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lethic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 07 08 9e 11 04 11 07 d4 7e ?? ?? ?? 04 11 07 d4 91 09 09 06 95 09 07 95 58 20 ?? ?? ?? 00 5f 95 61 28 ?? ?? ?? 0a 9c 00 11 07 17 6a 58 13 07 11 07 11 04 8e 69 17 59 6a fe 02 16 fe 01 13 08 11 08 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

