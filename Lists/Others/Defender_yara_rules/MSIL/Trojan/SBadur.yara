rule Trojan_MSIL_SBadur_SX_2147965729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SBadur.SX!MTB"
        threat_id = "2147965729"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SBadur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {70 11 06 8c 2d 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 00 20 e8 03 00 00 28 ?? 00 00 0a 00 00 11 06 17 59 13 06}  //weight: 20, accuracy: Low
        $x_10_2 = {2c 02 2b 6c 72 ?? ?? 00 70 08 28 ?? 00 00 06 13 05 11 05 2c 02 2b 59 1f 0c 28 ?? 00 00 0a 00 72 ?? ?? 00 70 28 ?? 00 00 0a 00 1b 13 06 2b 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

