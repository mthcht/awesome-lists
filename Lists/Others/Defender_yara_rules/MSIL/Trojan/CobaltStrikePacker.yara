rule Trojan_MSIL_CobaltStrikePacker_AL_2147845275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrikePacker.AL!MTB"
        threat_id = "2147845275"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrikePacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 0a 16 9a 72 ?? ?? ?? 70 18 17 8d ?? ?? 00 01 25 16 72 ?? ?? ?? 70 a2 28 ?? ?? 00 0a 28 ?? ?? 00 ?? 28 ?? ?? 00 0a 72 ?? ?? ?? 70 18 18 8d ?? ?? 00 01 25 16 16 8c ?? ?? 00 01 a2 25 17 19 8d ?? ?? 00 01 25 16 28 ?? ?? 00 06 16 9a a2 25 17 28 ?? ?? 00 06 17 9a a2 25 18 72 ?? ?? ?? 70 a2 a2 28 ?? ?? 00 ?? 26 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

