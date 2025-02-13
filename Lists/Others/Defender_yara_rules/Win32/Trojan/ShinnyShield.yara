rule Trojan_Win32_ShinnyShield_A_2147851678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShinnyShield.A"
        threat_id = "2147851678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShinnyShield"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 61 69 6c 65 64 20 74 6f 20 64 6f 77 6e 6c 6f 61 64 20 66 69 6c 65 2e 20 52 65 61 70 70 ?? 79 69 6e 67 20 6f 6c 64 20 70 61 74 63 68 2e 20 45 72 72 6f 72 20 63 6f 64 65 3a}  //weight: 1, accuracy: Low
        $x_1_2 = {57 6f 72 6d 20 64 65 61 63 74 69 76 61 74 65 64 20 62 79 20 63 ?? 6e 74 72 6f 6c 20 73 65 72 76 65 72 2e}  //weight: 1, accuracy: Low
        $x_1_3 = {57 6f 72 6d 20 6b 69 6c 6c 65 64 20 62 79 20 63 6f 6e ?? 72 6f 6c 20 73 65 72 76 65 72 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {55 6e 6b 6e 6f 77 6e 20 6f 72 20 6d 69 73 73 69 ?? 67 20 77 6f 72 6d 20 69 6e 73 74 72 75 63 74 69 6f 6e 2e}  //weight: 1, accuracy: Low
        $x_1_5 = {57 6f 72 6d 20 66 61 69 6c 65 64 20 74 6f 20 72 65 74 72 69 ?? 76 65 20 64 61 74 61 20 66 72 6f 6d 20 74 68 65 20 63 6f 6e 74 72 6f 6c 20 73 65 72 76 65 72 2e}  //weight: 1, accuracy: Low
        $x_1_6 = {55 73 65 72 20 77 61 73 20 72 61 6e 64 6f 6d 6c 79 20 73 65 6c 65 63 ?? 65 64 20 74 6f 20 62 65 20 61 20 73 70 72 65 61 64 65 72 20 69 6e 20 6d 6f 64 64 65 64 20 6c 6f 62 62 69 65 73 2e}  //weight: 1, accuracy: Low
        $x_1_7 = {55 73 65 72 20 77 61 73 20 73 65 6c 65 63 74 65 64 20 74 6f 20 62 65 20 61 20 68 6f 73 74 2f 69 67 6e 6f 72 65 20 6d ?? 64 64 65 64 20 6c 6f 62 62 69 65 73 2f 6a 6f 69 6e 20 75 6e 6d 6f 64 64 65 64 20 6c 6f 62 62 69 65 73 20 6f 6e 6c 79}  //weight: 1, accuracy: Low
        $x_1_8 = {75 73 65 72 6e 61 6d 65 3d 25 73 26 73 74 65 61 6d 49 44 3d 25 6c 6c 64 26 ?? 70 75 3d 25 73 26 67 70 75 3d 25 73 26 77 69 6e 76 65 72 3d 25 73}  //weight: 1, accuracy: Low
        $x_1_9 = {6b 77 77 73 3d 32 32 7a 7a 7a 31 76 6b 6c 71 7c 7a 64 75 68 31 ?? 7c 76 77 68 70 76 32 77 68 6f 68 70 68 77 75 7c}  //weight: 1, accuracy: Low
        $x_1_10 = {52 65 66 75 73 69 6e 67 20 74 6f 20 6a 6f 69 6e 20 62 6c 61 63 ?? 6c 69 73 74 65 64 20 6c 6f 62 62 79 2e}  //weight: 1, accuracy: Low
        $x_1_11 = {55 6e 61 75 74 68 6f 72 69 7a 65 64 20 52 43 45 20 61 74 74 ?? 6d 70 74 20 64 65 74 65 63 74 65 64 2e}  //weight: 1, accuracy: Low
        $x_1_12 = {67 65 74 20 63 75 63 6b 65 64 20 ?? 79 20 73 68 69 6e 79}  //weight: 1, accuracy: Low
        $x_1_13 = {77 6f 72 6d 53 74 61 74 75 73 20 69 6e ?? 65 63 74 65 64 20 25 73}  //weight: 1, accuracy: Low
        $x_1_14 = {34 68 25 75 74 7c 6a 77 78 6d 6a 71 71 25 32 48 74 72 72 66 73 69 25 ?? 2d 53 6a 7c 32 54 67 6f 6a 68 79 25 58 7e 78 79 6a 72 33 53 6a 79 33 5c 6a 67 48 71 6e 6a 73 79 2e 33 49 74 7c 73 71 74 66 69 4b 6e 71 6a}  //weight: 1, accuracy: Low
        $x_1_15 = {6d 79 79 75 3f 34 34 7c 7c 7c 33 78 6d 6e 73 7e 7c 66 77 6a 33 78 7e 78 79 6a 72 78 34 69 ?? 74 7a 73 69 33 69 71 71 2c 31 25 2c 69 78 74 7a 73 69 33 69 71 71 2c 2e 40}  //weight: 1, accuracy: Low
        $x_1_16 = {31 6a 6f 69 6e 50 61 72 74 79 20 31 34 39 20 31 20 31 20 30 20 30 20 30 20 31 34 35 20 30 20 30 20 31 20 32 20 ?? 20 34 20 35 20 36 20 37 20 38 20 39 20 31 30 20 31 31 20 31 32 20 31 33 20 31 34 20 31 35 20 31 36 20 31 37 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

