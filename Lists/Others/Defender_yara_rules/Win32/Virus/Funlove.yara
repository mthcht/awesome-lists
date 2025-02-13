rule Virus_Win32_Funlove_4070_2147601061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Funlove.4070"
        threat_id = "2147601061"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Funlove"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c6 2c ac 0a c0 75 fb 8b 46 fc 0d 20 20 20 20 3d 6f 63 78 20 74 0e 3d 73 63 72 20 74 07 3d 65 78 65 20 75 37 8b 47 20 3d 00 20 00 00 72 2d 3c 03}  //weight: 1, accuracy: High
        $x_1_2 = {66 81 3f 4d 5a 0f 85 ?? ?? ?? ?? 66 83 7f 18 40 0f 85 ?? ?? ?? ?? 81 7f 3c 00 1c 00 00 0f 87 ?? ?? ?? ?? 03 7f 3c 8b 07 3d 50 45 00 00 0f 85 ?? ?? ?? ?? 66 83 7f 5c 02 0f 85 ?? ?? ?? ?? 8b f7 83 c6 18 66 03 77 14 56 8b 47 28 8b 4e 0c 03 4e 08 3b c1 72 05 83 c6 28 eb f1}  //weight: 1, accuracy: Low
        $x_1_3 = {8d b3 00 10 00 00 c7 06 40 3a 5c 20 c6 46 03 00 56 e8 ?? ?? 00 00 3c 03 74 04 3c 04 75 12 83 c6 03 56 e8 ?? ?? 00 00 56 e8 ?? ?? 00 00 83 ee 03 8a 83 00 10 00 00 fe c0 88 83 00 10 00 00 3c 5a 76 ca}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 00 2a 2e 2a 00 8d bb 00 12 00 00 8d b3 00 10 00 00 57 56 e8 ?? ?? 00 00 83 f8 ff 74 40 89 45 fc f6 07 10 74 3e 80 7f 2c 2e 74 17 8b f7 83 c6 2c 8b 7d 08 a4 80 3e 00 75 fa b0 5c aa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

