rule Trojan_MSIL_ShellCodeLoader_LVK_2147969750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellCodeLoader.LVK!MTB"
        threat_id = "2147969750"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellCodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 08 2b 1f 09 07 1f 40 5a 11 08 58 04 07 1f 40 5a 11 08 58 91 11 09 11 08 91 61 d2 9c 11 08 17 58 13 08 11 08 1f 40 fe 04 13 0b 11 0b 2d d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ShellCodeLoader_AX_2147982528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellCodeLoader.AX!MTB"
        threat_id = "2147982528"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellCodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 06 72 f8 00 00 70 6f ?? 00 00 0a 0b 7e ?? 00 00 0a 07 8e 69 20 00 30 00 00 1f 40 28 ?? 00 00 06 0c 07 16 08 07 8e 69 28 ?? 00 00 0a 00 7e ?? 00 00 0a 16 08 7e ?? 00 00 0a 16 7e ?? 00 00 0a 28 ?? 00 00 06 0d 09 15 28 ?? 00 00 06 26 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

