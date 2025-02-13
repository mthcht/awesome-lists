rule Trojan_MSIL_Strela_DV_2147852521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Strela.DV!MTB"
        threat_id = "2147852521"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Strela"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 17 58 08 5d 0b 02 7b 0a 00 00 04 06 ?? ?? ?? ?? ?? 0d 02 7b 0a 00 00 04 07 ?? ?? ?? ?? ?? 13 04 11 05 09 7b 08 00 00 04 11 04 7b 09 00 00 04 5a 11 04 7b 08 00 00 04 09 7b 09 00 00 04 5a 59 58 13 05 06 17 58 0a 06 08 32 b5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

