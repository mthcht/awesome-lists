rule Trojan_Linux_StealthLoader_2147808231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/StealthLoader"
        threat_id = "2147808231"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "StealthLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_16_1 = "+2rpBJ0TYb5p2yDEO793gUUL4qCRUvgk9g2pegGah7I=" wide //weight: 16
        $x_16_2 = "OgYeMQQiZiIaOWkT/FnPxg==" wide //weight: 16
        $x_8_3 = "temp0" wide //weight: 8
        $x_8_4 = "CreateDecryptor" ascii //weight: 8
        $x_4_5 = "Windows Update Runner" ascii //weight: 4
        $x_2_6 = "VirtualProtectEx" ascii //weight: 2
        $x_1_7 = "GetProcAddress" ascii //weight: 1
        $x_1_8 = "LoadLibrary" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_16_*) and 2 of ($x_8_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_16_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_16_*) and 1 of ($x_8_*))) or
            (all of ($x*))
        )
}

