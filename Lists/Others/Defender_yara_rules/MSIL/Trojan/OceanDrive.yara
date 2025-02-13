rule Trojan_MSIL_OceanDrive_A_2147767195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/OceanDrive.A!dha"
        threat_id = "2147767195"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "OceanDrive"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 6d 00 6f 00 76 00 65 00 20 00 67 00 64 00 72 ?? 69 00 76 00 65 00 2e 00 65 00 78 00 65 00 20 00 22 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 00 80 95 5c 00 41 00 70 00 70}  //weight: 1, accuracy: Low
        $x_1_2 = {65 78 65 63 75 74 65 00 67 64 72 69 76 65 00 52 65 6d 6f 76 65 ?? 67 64 72 69 76 65 2e 65 78 65 00 49 6e 64 65 78 4f 66 00}  //weight: 1, accuracy: Low
        $x_1_3 = {61 00 70 00 71 00 75 00 39 00 70 00 35 00 33 00 66 00 38 00 66 00 6b ?? 6a 00 35 00 6b 00 37 00 37 00 67 00 70 00 6d 00 38 00 68 00 69 00 75 00 35 00 6f 00 67 00 75 00 36 00 39 00 30 00 69}  //weight: 1, accuracy: Low
        $x_1_4 = {38 00 37 00 4c 00 77 00 77 00 69 00 54 00 47 00 68 00 62 00 68 ?? 47 00 4a 00 68 00 67 00 37 00 35 00 4d 00 56 00 6b 00 61 00 59 00 4e 00 76}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 00 20 00 55 00 54 00 46 00 2d 00 38 00 0a 00 0a 00 7b 00 0a ?? 20 00 20 00 22 00 6e 00 61 00 6d 00 65 00 22 00 3a 00 20 00 22 00 01 5d 22 00 0a 00 7d 00 0a 00 0a 00 2d 00 2d 00 62 00 6f 00 75 00 6e 00 64 00 61 00 72 00 79 00 5f 00 74 00 61 00 67}  //weight: 1, accuracy: Low
        $x_1_6 = {64 00 72 00 69 00 76 00 65 00 2f 00 76 00 33 00 2f 00 66 00 69 ?? 6c 00 65 00 73 00 00 03 7d 00 00 01 00 0d 69 00 64 00 22 00 3a 00 20 00 22 00 00}  //weight: 1, accuracy: Low
        $x_1_7 = {64 00 72 00 69 00 76 00 65 00 2f 00 76 00 33 00 2f 00 66 00 69 00 6c ?? 65 00 73 00 2f 00 00 15 3f 00 61 00 6c 00 74 00 3d 00 6d 00 65 00 64 00 69 00 61 00 00 03 0a 00 00}  //weight: 1, accuracy: Low
        $x_1_8 = {3f 00 61 00 6c 00 74 00 3d 00 6d 00 65 00 64 00 69 00 61 00 00 03 0a 00 ?? 0f 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 0f 20 00 20 00 45 00 72 00 72 00 6f 00 72 00 00}  //weight: 1, accuracy: Low
        $x_1_9 = {5f 00 72 00 65 00 70 00 6f 00 72 00 74 00 5f 00 00 07 64 00 69 ?? 72 00 00 09 63 00 6d 00 64 00 5f 00 00}  //weight: 1, accuracy: Low
        $x_1_10 = {31 00 2f 00 2f 00 30 00 39 00 57 00 67 00 5f 00 6f 00 75 00 48 00 78 ?? 58 00 34 00 30 00 4e 00 43 00 67 00 59 00 49 00 41 00 52 00 41 00 41 00 47 00 41 00 6b 00 53 00 4e 00 77 00 46 00 2d 00 4c 00 39 00}  //weight: 1, accuracy: Low
        $x_1_11 = {49 00 72 00 74 00 52 00 66 00 76 00 59 00 71 00 33 00 43 00 4f 00 51 00 50 ?? 46 00 74 00 2d 00 51 00 4a 00 63 00 65 00 71 00 63 00 76 00 47 00 4a 00 78 00 31 00 36 00 47 00 54 00 6a 00 39 00}  //weight: 1, accuracy: Low
        $x_1_12 = {17 43 00 61 00 6e 00 27 00 74 00 20 00 66 00 69 00 6e 00 64 00 20 ?? 01 05 6f 00 72 00 00 47 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 6f 00 61 00 75 00 74 00 68 00 32 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 61 00 70 00 69 00 73}  //weight: 1, accuracy: Low
        $x_1_13 = {55 70 6c 6f 61 64 00 63 6f 6d 70 5f 69 64 00 63 6d 64 00 72 65 ?? 64 46 69 6c 65 00 63 72 65 61 74 65 46 69 6c 65 00 64 65 6c 65 74 65 00 65 78 65 63 75 74 65}  //weight: 1, accuracy: Low
        $x_1_14 = {50 72 6f 67 72 61 6d 00 [0-17] 72 65 66 72 65 73 68 5f 74 6f 6b 65 ?? 00 61 63 63 65 73 73 5f 74 6f 6b 65 6e 00 4d 61 69 6e}  //weight: 1, accuracy: Low
        $x_1_15 = {63 63 74 6f 72 00 67 65 74 00 6c 69 73 74 00 70 6f ?? 74 00 45 78 65 46 72 6f 6d 54 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MSIL_OceanDrive_B_2147767196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/OceanDrive.B!dha"
        threat_id = "2147767196"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "OceanDrive"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 d4 01 00 70 0a 1b 8d 11 00 00 01 25 16 72 61 02 00 70 a2 25 17 02 ?? 25 18 72 fe 02 00 70 a2 25 19 03 a2 25 1a 72 5c 03 00 70 a2 28 14 00 00 0a 0b 06 07 28 07 00 00 06 26 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {72 81 05 00 70 0a 02 0b 16 0c 2b 1a 07 08 9a 0d 06 09 28 0a 00 00 ?? 72 ?? ?? ?? 70 28 13 00 00 0a 0a 08 17 58 0c 08 07 8e 69 32 e0 28 37 00 00 0a 13 04 12 04 28 38 00 00 0a 72 ?? ?? ?? 70 7e 03 00 00 04 28 13 00 00 0a 06 28 03 00 00 06 2a}  //weight: 1, accuracy: Low
        $x_1_3 = {72 91 05 00 70 06 72 e7 ?? 00 70 28 13 00 00 0a 28 04 00 00 06 72 91 05 00 70 06 28 18 00 00 0a 28 05 00 00 06 [0-16] 6f 28 00 00 0a 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

