rule Trojan_MSIL_Shellcode_SK_2147909721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shellcode.SK!MTB"
        threat_id = "2147909721"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shellcode"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 06 07 06 07 91 20 a0 06 00 00 59 d2 9c 00 07 17 58 0b 07 06 8e 69 fe 04 13 0a 11 0a 2d e1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Shellcode_BAA_2147957859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shellcode.BAA!MTB"
        threat_id = "2147957859"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shellcode"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 17 00 00 0a 13 04 00 09 11 04 ?? ?? ?? ?? ?? 00 11 04 ?? ?? ?? ?? ?? 13 05 de 5c 11 04 14 fe 01 13 06 11 06 2d 08 11 04 ?? ?? ?? ?? ?? 00 dc 09 14 fe 01 13 06 11 06 2d 07 09 ?? ?? ?? ?? ?? 00 dc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

