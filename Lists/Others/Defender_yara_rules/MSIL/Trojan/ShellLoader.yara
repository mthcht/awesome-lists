rule Trojan_MSIL_ShellLoader_SX_2147976798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellLoader.SX!MTB"
        threat_id = "2147976798"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {0d 08 28 0c 00 00 0a 09 1a 6f 0d 00 00 0a 7e 08 00 00 0a 09 8e 69 28 0e 00 00 0a 20 00 30 00 00 1f 40 28 03 00 00 06}  //weight: 6, accuracy: High
        $x_4_2 = {13 1e 12 12 28 23 00 00 0a 28 24 00 00 0a 13 22 11 22 19 28 19 00 00 0a 13 23 7e 08 00 00 0a 13 14 08}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

