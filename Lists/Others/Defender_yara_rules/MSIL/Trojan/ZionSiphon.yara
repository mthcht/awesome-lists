rule Trojan_MSIL_ZionSiphon_AZS_2147970363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZionSiphon.AZS!MTB"
        threat_id = "2147970363"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZionSiphon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 16 07 a2 14 14 28 ?? 00 00 0a 00 11 08 14 72 ?? 09 00 70 17 8d ?? 00 00 01 25 16 72 ?? 09 00 70 a2 14 14 28 ?? 00 00 0a 00 11 08 14 72 ?? 09 00 70 16 8d ?? 00 00 01 14 14 14 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

