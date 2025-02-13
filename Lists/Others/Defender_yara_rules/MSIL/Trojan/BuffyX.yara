rule Trojan_MSIL_BuffyX_2147720052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BuffyX"
        threat_id = "2147720052"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BuffyX"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 09 2d 02 16 0a 03 28 ?? ?? ?? ?? 13 04 03 28 ?? ?? ?? ?? 13 05 11 04 72 ?? ?? ?? ?? 11 05 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 06 11 06 28 ?? ?? ?? ?? 13 07 11 07 09 16 09 8e 69 6f ?? ?? ?? ?? de 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {02 8e 69 0a 02 06 1b 59 91 0b 16 0c 1a 8d 67 00 00 01 0d 16 13 04 14 13 05 14 13 06 14 13 07 03 2c 36 28 ?? ?? ?? ?? 03 6f ?? ?? ?? ?? 13 08 11 08 13 0e 16 13 0f 2b 16 11 0e 11 0f 91 13 09 08 07 11 09 61 d2 61 d2 0c 11 0f 17 58 13 0f 11 0f 11 0e 8e 69 32 e2 2b 02 07 0c 16 13 0a 2b 12 09 11 0a 02 06 1a 59 11 0a 58 91 9c 11 0a 17 58 13 0a 11 0a 1a 32 e9 09 28 ?? ?? ?? ?? 13 04 02 06 11 04 59 06 28 ?? ?? ?? ?? 13 05 16 13 0b 11 05 8e 69 8d 67 00 00 01 13 07 11 05 13 10 16 13 11 2b 1c 11 10 11 11 91 13 0c 11 07 11 0b 25 17 58 13 0b 11 0c 08 61 d2 9c 11 11 17 58 13 11 11 11 11 10 8e 69 32 dc 11 07 28 ?? ?? ?? ?? 13 06 11 06 13 0d de 09 26 14 13 06 de 00 11 06 2a 11 0d 2a}  //weight: 1, accuracy: Low
        $x_1_3 = "CloudClimb" ascii //weight: 1
        $x_1_4 = "iamgeBuffer" ascii //weight: 1
        $x_1_5 = "ImageInfoHiden" ascii //weight: 1
        $x_1_6 = "LoadImage" ascii //weight: 1
        $x_1_7 = "ProcessThread" ascii //weight: 1
        $x_1_8 = "RunByML" ascii //weight: 1
        $x_1_9 = "UnAppendDllBytes" ascii //weight: 1
        $x_1_10 = "UnPack" ascii //weight: 1
        $x_1_11 = "VULibMe" ascii //weight: 1
        $x_1_12 = "http://images.timekard.com/default.png" wide //weight: 1
        $x_1_13 = "abcdefg" wide //weight: 1
        $x_1_14 = "_hiden.bmp" wide //weight: 1
        $x_1_15 = "_out.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

