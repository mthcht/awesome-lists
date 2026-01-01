rule Trojan_MSIL_ShellcodeLoader_PGSL_2147959923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellcodeLoader.PGSL!MTB"
        threat_id = "2147959923"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellcodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 09 00 00 70 0a 06 17 8d ?? 00 00 01 0c 08 16 1f 2c 9d 08 6f ?? 00 00 0a 7e ?? 00 00 04 2d 11 14 fe 06 17 00 00 06}  //weight: 5, accuracy: Low
        $x_5_2 = {47 20 00 72 00 65 00 73 00 65 00 74 00 3d 00 20 00 33 00 36 00 30 00 30 00 20 00 61 00 63 00 74 00 69 00 6f 00 6e 00 73 00 3d 00 20 00 72 00 65 00 73 00 74 00 61 00 72 00 74 00 2f 00 31 00 30 00 30 00 30 00 30 00 00 0d 73 00 74 00 61 00 72 00 74 00 20 00 00 0d 73 00 63 00 2e 00 65 00 78 00 65}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

