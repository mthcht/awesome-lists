rule TrojanDropper_Win32_Umrena_B_2147609485_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Umrena.B"
        threat_id = "2147609485"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Umrena"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 90 00 83 c1 01 3d 55 40 56 7c f2 31 c0 8d 85 00 ac 1e 50 68 04 01 00 00 e8 53 40 55 83 cf 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Umrena_F_2147649605_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Umrena.F"
        threat_id = "2147649605"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Umrena"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 2f 63 6c 69 63 6b 73 63 72 69 70 74 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 48 45 78 65 63 00}  //weight: 1, accuracy: High
        $x_1_3 = {01 f1 77 69 6e 74 68 75 6d 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

