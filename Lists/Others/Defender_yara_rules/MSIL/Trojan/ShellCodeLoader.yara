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

