rule PWS_MSIL_Parple_A_2147639068_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Parple.A"
        threat_id = "2147639068"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Parple"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 13 09 11 09 16 1f 12 9c 11 09 17 1f 34 9c 11 09 18 1f 56 9c 11 09 19 1f 78}  //weight: 1, accuracy: High
        $x_1_2 = {20 33 d4 00 00 0a}  //weight: 1, accuracy: High
        $x_1_3 = {20 f2 03 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_MSIL_Parple_B_2147639073_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Parple.B"
        threat_id = "2147639073"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Parple"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 0b 07 16 1f 64 9c 07 17 1f 55 9c 07 18 1f 40 9c 07 19 1f 37}  //weight: 1, accuracy: High
        $x_1_2 = {01 13 08 11 08 16 1f 12 9c 11 08 17 1f 34 9c 11 08 18 1f 56 9c 11 08 19 1f 78}  //weight: 1, accuracy: High
        $x_1_3 = {06 1f 10 1f 3d 9c 06 1f 11 1f 40 9c 06 1f 12 1f 4b 9c 06 1f 13 1f 51 9c 06 1f 14 1f 63 9c 06 1f 15 1f 6a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

