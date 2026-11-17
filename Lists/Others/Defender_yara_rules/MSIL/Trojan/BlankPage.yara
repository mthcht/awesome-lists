rule Trojan_MSIL_BlankPage_AB_2147982211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BlankPage.AB!MTB"
        threat_id = "2147982211"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlankPage"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {05 06 06 06 28 ?? 00 00 0a 6f ?? 00 00 0a 0c 0e 04 06 06 06 28 ?? 00 00 0a 6f ?? 00 00 0a 0d 1f 0b 8d ?? 00 00 01 13 07 11 07 16 72 ?? 00 00 70 a2 11 07 17 06 a2 11 07 18 72 ?? 00 00 70 28 ?? 00 00 06 a2 11 07 19 06 a2 11 07 1a 72 ?? 00 00 70 a2 11 07 1b 06 a2}  //weight: 2, accuracy: Low
        $x_1_2 = {0c 08 16 6f ?? ?? ?? 0a 00 08 17 6f ?? ?? ?? 0a 00 08 0a 06 28 ?? ?? ?? 0a 0b 07 2d 03 16 2b 06 07 6f ?? ?? ?? 0a 00 0d de 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

