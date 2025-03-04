rule Trojan_MSIL_AvemariaRat_KDFA_2147825478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AvemariaRat.KDFA!MTB"
        threat_id = "2147825478"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AvemariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 16 e0 00 00 0c 2b 16 20 30 1e 63 9b 28 ?? ?? ?? 06 07 08 28 ?? ?? ?? 06 0b 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d df}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

