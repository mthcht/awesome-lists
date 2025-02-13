rule Trojan_MSIL_Badur_GNF_2147900128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Badur.GNF!MTB"
        threat_id = "2147900128"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Badur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "discord.gg/FhAXUKwNnx" wide //weight: 1
        $x_1_2 = "iniciador no pudo leer la versi" ascii //weight: 1
        $x_1_3 = "s4.sondevs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Badur_PTFI_2147900532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Badur.PTFI!MTB"
        threat_id = "2147900532"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Badur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 a3 00 00 70 73 11 00 00 0a 28 ?? 00 00 0a 72 f7 00 00 70 28 ?? 00 00 0a 6f 14 00 00 0a 00 2b 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

