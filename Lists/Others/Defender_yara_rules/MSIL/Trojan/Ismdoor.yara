rule Trojan_MSIL_Ismdoor_AL_2147789165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ismdoor.AL!MTB"
        threat_id = "2147789165"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ismdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 17 da 17 d6 8d ?? 00 00 01 0b 02 07 16 03 28 ?? 00 00 0a 00 07 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_10_2 = {02 02 02 1f 3c 6a d6 28 ?? 00 00 0a 28 ?? 00 00 0a 6a d6 20 88 00 00 00 6a d6 28 ?? 00 00 0a 28 ?? 00 00 0a 6a d6 1f 18 6a d6 28 ?? 00 00 0a 1f 10 28 ?? 00 00 06 0b}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

