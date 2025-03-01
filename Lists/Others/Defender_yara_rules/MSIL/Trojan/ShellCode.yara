rule Trojan_MSIL_ShellCode_AF_2147896077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellCode.AF!MTB"
        threat_id = "2147896077"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellCode"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 06 91 03 06 91 fe 01 0c 08 2d 05 00 16 0b 2b 13 00 06 17 58 0a 06 02 8e 69 fe 04 0c 08 2d df}  //weight: 10, accuracy: High
        $x_10_2 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d e1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

