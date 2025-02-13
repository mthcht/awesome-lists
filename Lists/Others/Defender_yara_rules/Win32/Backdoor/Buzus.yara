rule Backdoor_Win32_Buzus_C_2147608023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Buzus.C"
        threat_id = "2147608023"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Buzus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 3d 6a 01 68 ?? ?? 00 30 68 ?? ?? 00 30 8d 85 7c ff ff ff 50 b9 02 00 00 00 ba ?? ?? 00 30 8b 45 fc e8 ?? ?? ff ff 8b 85 7c ff ff ff e8 ?? ?? ff ff 50 68 ?? ?? 00 30 6a 00 e8 ?? ?? ff ff 8b 45 f4 ba ?? ?? 00 30 e8 ?? ?? ff ff 75 21 6a 01 68 ?? ?? 00 30 68 ?? ?? 00 30 8b 45 fc e8 ?? ?? ff ff 50 68 ?? ?? 00 30 6a 00 e8 ?? ?? ff ff 8b 45 f4 ba ?? ?? 00 30 e8 ?? ?? ff ff 75 13}  //weight: 1, accuracy: Low
        $x_1_2 = {45 78 65 63 75 74 65 46 69 6c 65 [0-16] 53 68 75 74 64 6f 77 6e [0-16] 53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 [0-16] 4c 6f 67 6f 66 66 [0-16] 52 65 62 6f 6f 74 [0-16] 53 63 72 65 65 6e 73 68 6f 74 [0-16] 2e 70 6d 62 [0-16] 57 65 62 63 61 6d [0-16] 43 61 70 74 75 72 65 57 69 6e 64 6f 77}  //weight: 1, accuracy: Low
        $x_1_3 = {47 65 74 4f 6e 6c 69 6e 65 4c 6f 67 67 65 72 53 74 61 74 65 [0-5] 47 65 74 50 6c 75 67 69 6e 44 69 72 65 63 74 6f 72 79 [0-5] 53 65 74 4f 6e 6c 69 6e 65 4c 6f 67 67 65 72 53 74 61 74 65}  //weight: 1, accuracy: Low
        $x_1_4 = {54 49 45 66 6d 66 75 66 4c 66 7a 42 [0-16] 74 69 6d 78 62 71 6a 2f 65 6d 6d [0-16] 63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6f 6e 41 [0-16] 49 73 4e 54 41 64 6d 69 6e [0-16] 69 6f 63 74 6c 73 6f 63 6b 65 74 [0-16] 4d 61 6b 65 53 75 72 65 44 69 72 65 63 74 6f 72 79 50 61 74 68 45 78 69 73 74 73 [0-16] 2d 73 [0-32] 53 6c 68 53 6c 68 20 46 69 6e 61 6c [0-32] 53 65 72 76 65 72 53 74 61 72 74 75 70 [0-255] 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

