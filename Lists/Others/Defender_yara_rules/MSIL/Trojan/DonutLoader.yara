rule Trojan_MSIL_DonutLoader_EAEP_2147935748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DonutLoader.EAEP!MTB"
        threat_id = "2147935748"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 12 02 7b 0f 00 00 04 28 07 00 00 0a 2c 0a 12 02 7b 08 00 00 04 0a 2b 0a 07 12 02 28 ?? ?? ?? 06 2d dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DonutLoader_ZGL_2147955953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DonutLoader.ZGL!MTB"
        threat_id = "2147955953"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DonutLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {91 58 20 00 01 00 00 5d 91 0c 06 07 03 07 91 08 61 d2 9c 00 07 17 58 0b 07 03 8e 69 fe 04 0d 09 3a 74 ff ff ff 06 13 04 2b 00 11 04 2a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

