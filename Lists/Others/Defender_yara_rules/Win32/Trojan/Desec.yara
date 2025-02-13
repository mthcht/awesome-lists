rule Trojan_Win32_Desec_123956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Desec"
        threat_id = "123956"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Desec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {53 74 61 72 74 53 65 72 76 69 63 65 20 66 61 69 6c 65 64 2c 20 65 72 72 6f 72 20 63 6f 64 65 20 3d 20 25 64 00 00 00 00 4f 70 65 6e 53 65 72 76 69 63 65 20 66 61 69 6c 65 64 2c 20 65 72 72 6f 72 20 63 6f 64 65 20 3d 20 25 64 00 4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 20 66 61 69 6c 65 64 2c 20 65 72 72 6f 72 20 63 6f 64 65 20 3d 20 25 64 00 00 00 64 65 6c 20 25 30 00 00 69 66 20 65 78 69 73 74 20 22 25 73 22 20 20 67 6f 74 6f 20 74 72 79 0d 0a 00 00 00 64 65 6c 20 22 25 73 22 0d 0a 00 00 3a 74 72 79 0d 0a 00 00 5c 00 00 00 5c 64 73 65 74 75 70 2e 62 61 74 00}  //weight: 3, accuracy: High
        $x_3_2 = {47 6c 6f 62 61 6c 5c 00 45 72 72 6f 72 00 00 00 [0-32] 2e 64 6c 6c [0-10] 42 49 4e 46 49 4c 45 00 5c 73 79 73 74 65 6d 33 32 5c}  //weight: 3, accuracy: Low
        $x_3_3 = "Security Service" ascii //weight: 3
        $x_1_4 = "madDisAsm" ascii //weight: 1
        $x_1_5 = "madCodeHook" ascii //weight: 1
        $x_1_6 = "Unknown exception. If you want to know more, you have to add SysUtils to your project." ascii //weight: 1
        $x_2_7 = "_fucking_" ascii //weight: 2
        $x_2_8 = "_smoking_" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

