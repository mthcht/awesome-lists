rule Trojan_MSIL_Kryptic_QB_2147781705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kryptic.QB!MTB"
        threat_id = "2147781705"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kryptic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 11 00 16 17 73 ?? ?? ?? 0a 13 07 38 ?? ?? ?? 00 11 06 1f 10 3f ?? ?? ?? ff 38 ?? ?? ?? 00 02 28 ?? ?? ?? 06 73 ?? ?? ?? 0a 13 00 38 ?? ?? ?? ff 00 11 00 6f ?? ?? ?? 0a d4 8d ?? ?? ?? 01 13 08 38 ?? ?? ?? 00 11 01 11 08 16 11 09 28 ?? ?? ?? 06 38 ?? ?? ?? 00 11 07 11 08 16 11 08 8e 69 6f ?? ?? ?? 0a 13 09 38 ?? ?? ?? 00 11 09 39 ?? ?? ?? 00 38 ?? ?? ?? ff 11 09 11 08 8e 69}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "GetMethod" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

