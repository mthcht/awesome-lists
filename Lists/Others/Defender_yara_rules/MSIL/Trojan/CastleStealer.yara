rule Trojan_MSIL_CastleStealer_CZ_2147972207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CastleStealer.CZ!MTB"
        threat_id = "2147972207"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CastleStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 17 62 6f ?? ?? ?? ?? 94 7e ?? ?? ?? ?? 02 03 17 62 17 58 6f ?? ?? ?? ?? 94 1a 62 60 2a}  //weight: 5, accuracy: Low
        $x_5_2 = {61 13 0b 11 0b 1f 0f 5f 17}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

