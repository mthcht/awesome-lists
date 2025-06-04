rule Trojan_MSIL_Dcrat_ZAT_2147942841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dcrat.ZAT!MTB"
        threat_id = "2147942841"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dcrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {01 00 04 02 7b ?? 01 00 04 02 7b ?? 01 00 04 91 02 7b ?? 01 00 04 02 7b ?? 01 00 04 91 58 20 00 01 00 00 5d 91 0c 06 07 03 07 91 08 61 d2 9c 07 17 58 0b 07 03 8e 69}  //weight: 6, accuracy: Low
        $x_5_2 = {23 07 02 7b ?? 01 00 04 09 91 58 03 09 06 5d 91 58 20 00 01 00 00 5d 0b 02 09 07 28 ?? 00 00 06 09 17 58 0d 09 20 00 01 00 00 32 d5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

