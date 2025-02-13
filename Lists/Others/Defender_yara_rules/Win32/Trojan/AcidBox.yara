rule Trojan_Win32_AcidBox_B_2147836218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AcidBox.B!dha"
        threat_id = "2147836218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AcidBox"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {78 70 70 77 ?? 70 08 08 00 00 08 00 08 00 07 08 00 00 00 25 73 5c 25 73 00 00 00 00 00 00 00 25 73 5c 25 ?? 7b 25 73 7d 00 00 00 00 00 00 00 25 73 5c 5b 5b 25 73 5d 5d 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 5c 2e 5c 50 43 49 58 41 ?? 43 46 47 44 45 56 00}  //weight: 1, accuracy: Low
        $x_1_3 = {57 48 83 ec 30 48 8b f9 48 85 c9 75 ?? bb 02 24 03 a0 8d 71 01}  //weight: 1, accuracy: Low
        $x_1_4 = {81 3f ba ad ca fe 74 ?? bb 02 24 03 a0 89 5c 24 20 e9 5b 01 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 5f 04 c7 47 04 11 22 33 44 8b d6 48 8b cf e8 ?? ?? 00 00 be 01 00 00 00 3b d8 74 ?? bb 07 24 03 a0}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 4f 08 b8 10 10 00 00 3b c8 7f 7f 74 6f 81 e9 01 10 00 00 74 ?? ff c9 74 3f ff c9 74 2e ff c9 74 15 ff c9 75 ?? 48 8b 57 18 8b 4f 0c}  //weight: 1, accuracy: Low
        $x_1_7 = {81 e9 11 10 00 00 74 ?? ff c9 74 40 ff c9 74 31 ff c9 74 1a ff c9 74 0b bb 02 24 03 a0}  //weight: 1, accuracy: Low
        $x_1_8 = {c7 44 24 3d 68 69 6e 65 66 c7 44 24 ?? 61 63 66 c7 44 24 ?? 5c 52 c7 44 24 ?? 67 69 73 74 66 c7 44 24 ?? 79 5c 66 c7 44 24 ?? 5c 00 c6 44 24 ?? 72 c6 44 24 ?? 4d c6 44 24 ?? 65 c7 85 ?? ?? 00 00 6e 75 6d 00 c6 85 a0 02 00 00 45}  //weight: 1, accuracy: Low
        $x_1_9 = {49 89 73 c8 45 33 f6 4d 89 73 d0 41 21 73 18 33 c0 41 89 43 1c 41 21 43 08 48 85 c9 75 ?? bb 02 05 01 80}  //weight: 1, accuracy: Low
        $x_1_10 = {66 c7 44 24 ?? 45 76 66 c7 44 24 ?? 6f 74 66 c7 44 24 ?? 66 79 c7 44 24 ?? 42 46 45 5f 66 c7 44 24 ?? 65 6e 66 c7 44 24 ?? 5f 00 c6 44 24 ?? 74 c6 44 24 ?? 5f c6 44 24 ?? 4e c6 44 24 ?? 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_AcidBox_C_2147836219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AcidBox.C!dha"
        threat_id = "2147836219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AcidBox"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 00 43 00 49 00 ?? 00 41 00 5f 00 43 00 66 00 67 00 2e 00 73 00 79 00 73 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {50 00 43 00 49 00 ?? 00 41 00 20 00 43 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 ?? 00 6f 00 6e 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 00 44 00 65 00 76 00 ?? 00 63 00 65 00 5c 00 50 00 43 00 49 00 58 00 41 00 5f ?? 43 00 46 00 47 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 00 44 00 6f 00 73 00 ?? 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 50 00 43 00 49 00 ?? 00 41 00 5f 00 43 00 46 00 47 00 44 00 45 00 56 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {48 85 d2 0f 84 ?? ?? 00 00 b9 55 aa 55 aa 39 4a 18 0f 85 ?? ?? 00 00 39 0d 06 6e 00 00 0f 85 ?? ?? 00 00 81 3d fa 6d 00 00 99 99 99 99}  //weight: 1, accuracy: Low
        $x_1_6 = {41 c7 04 24 10 14 06 a0 89 ?? 64 07 00 00 48 89 be 68 07 00 00 48 89 be 70 07 00 00 48 89 be 78 07 00 00 c7 06 99 f1 55 a1 44 89 7e ?? c6 86 a4 01 00 00 05 c7 86 a8 01 00 00 fc ff ff ff 48 89 9e 00 02 00 00 44 89 ae 08 02 00 00}  //weight: 1, accuracy: Low
        $x_1_7 = {41 b8 03 05 06 a0 44 89 44 24 20 eb ?? 41 b8 02 05 06 a0 41 8b c0 48 8b 5c 24 40}  //weight: 1, accuracy: Low
        $x_1_8 = {48 8b 41 10 3b 90 f4 00 00 00 1b ?? 25 09 03 06 a0 89 04 24 eb 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

