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

