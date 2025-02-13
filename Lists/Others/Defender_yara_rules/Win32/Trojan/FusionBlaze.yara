rule Trojan_Win32_FusionBlaze_A_2147725399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FusionBlaze.A!dha"
        threat_id = "2147725399"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FusionBlaze"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 1c 56 6a 06 6a 01 6a 02 ff 15 ?? ?? ?? ?? 6a 00 6a 00 8b f0 8d 45 fc 50 6a}  //weight: 1, accuracy: Low
        $x_1_2 = {0c 8d 4d e4 51 6a 0c 8d 55 f0 52 68 04 00 00 98 56 c7 45 f0 01 00 00 00 c7 45 f4 00 f4 01 00 c7}  //weight: 1, accuracy: High
        $x_1_3 = {45 f8 e8 03 00 00 c7 45 fc 00 00 00 00 ff 15 ?? ?? ?? ?? 40 f7 d8 1b c0 23 c6 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_FusionBlaze_B_2147725421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FusionBlaze.B!dha"
        threat_id = "2147725421"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FusionBlaze"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 25 00 73 00 5c 00 25 00 73 00 2e 00 6d 00 75 00 69 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 25 00 73 00 5c 00 65 00 6e 00 2d 00 55 00 53 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 2e 00 6d 00 75 00 69 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 0d 0a 0d 0a 61 50 4c 69 62 20 76 31 2e 30 31 20 20 2d 20 20 74 68 65 20 73 6d 61 6c 6c 65 72 20 74 68 65 20 62 65 74 74 65 72 20 3a 29 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 00 72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 20 00 25 00 73 00 20 00 25 00 73 00 20 00 25 00 73 00 20 00 67 00 6f 00 20 00 22 00 25 00 73 00 22 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 25 30 32 64 2f 25 30 32 64 2f 25 64 20 20 25 30 32 64 3a 25 30 32 64 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 6e 65 77 20 62 61 73 65 3a 25 70 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 68 6b 20 70 6f 72 74 20 6d 75 74 65 78 00}  //weight: 1, accuracy: High
        $x_2_8 = {25 00 64 00 20 00 43 00 6f 00 72 00 65 00 20 00 25 00 2e 00 32 00 66 00 20 00 47 00 48 00 7a 00 00 00}  //weight: 2, accuracy: High
        $x_2_9 = {00 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 50 00 61 00 74 00 68 00 3d 00 25 00 5b 00 5e 00 7c 00 5d 00 00 00}  //weight: 2, accuracy: High
        $x_2_10 = {00 00 77 00 69 00 6e 00 4d 00 61 00 69 00 6e 00 20 00 73 00 74 00 61 00 74 00 69 00 63 00 20 00 67 00 72 00 65 00 65 00 6e 00 00 00}  //weight: 2, accuracy: High
        $x_2_11 = {00 00 64 00 6c 00 6c 00 6d 00 61 00 69 00 6e 00 20 00 73 00 74 00 61 00 74 00 69 00 63 00 20 00 67 00 72 00 65 00 65 00 6e 00 00 00}  //weight: 2, accuracy: High
        $x_2_12 = {00 31 7c 25 5b 5e 7c 5d 7c 25 5b 5e 7c 5d 7c 25 5b 5e 7c 5d 7c 00}  //weight: 2, accuracy: High
        $x_2_13 = {00 50 4b 54 5f 46 49 4c 45 5f 44 52 49 56 45 5f 52 45 51 00}  //weight: 2, accuracy: High
        $x_2_14 = {00 72 65 63 76 20 46 49 4c 45 5f 4d 47 52 5f 44 49 52 00}  //weight: 2, accuracy: High
        $x_2_15 = {00 72 65 63 76 20 46 49 4c 45 5f 4d 47 52 5f 52 45 4e 41 4d 45 00}  //weight: 2, accuracy: High
        $x_2_16 = {00 72 65 63 76 20 46 49 4c 45 5f 4d 47 52 5f 4e 45 57 44 49 52 00}  //weight: 2, accuracy: High
        $x_2_17 = {00 72 65 63 76 20 46 49 4c 45 5f 4d 47 52 5f 44 45 4c 45 54 45 00}  //weight: 2, accuracy: High
        $x_2_18 = {00 50 4b 54 5f 46 49 4c 45 5f 44 4f 57 4e 4c 4f 41 44 5f 52 45 51 00}  //weight: 2, accuracy: High
        $x_2_19 = {00 50 4b 54 5f 46 49 4c 45 5f 55 50 4c 4f 41 44 5f 52 45 51 00}  //weight: 2, accuracy: High
        $x_3_20 = {00 00 5b 00 47 00 72 00 65 00 65 00 6e 00 5d 00 20 00 70 00 69 00 64 00 3d 00 25 00 64 00 20 00 74 00 69 00 64 00 3d 00 25 00 64 00 20 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 50 00 61 00 74 00 68 00 3d 00 25 00 73 00 7c 00 00 00}  //weight: 3, accuracy: High
        $x_3_21 = {00 00 5b 00 47 00 72 00 65 00 65 00 6e 00 20 00 72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 5d 00 20 00 70 00 69 00 64 00 3d 00 25 00 64 00 20 00 74 00 69 00 64 00 3d 00 25 00 64 00 20 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 4d 00 6f 00 64 00 75 00 6c 00 65 00 3d 00 25 00 73 00 20 00 72 00 65 00 61 00 6c 00 4d 00 6f 00 64 00 75 00 6c 00 65 00 3d 00 25 00 73 00 00 00}  //weight: 3, accuracy: High
        $x_3_22 = {00 00 25 00 73 00 20 00 5b 00 50 00 45 00 4c 00 6f 00 61 00 64 00 65 00 72 00 5d 00 20 00 70 00 69 00 64 00 3d 00 25 00 64 00 20 00 74 00 69 00 64 00 3d 00 25 00 64 00 20 00 68 00 4d 00 6f 00 64 00 75 00 6c 00 65 00 3d 00 30 00 78 00 25 00 70 00 20 00 65 00 6e 00 74 00 72 00 79 00 3d 00 30 00 78 00 25 00 70 00 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FusionBlaze_C_2147725422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FusionBlaze.C!dha"
        threat_id = "2147725422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FusionBlaze"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[injectPE] svcName=%s modulePath=%s| pid=%d tid=%d hModule=0x%p entry=0x%p" ascii //weight: 1
        $x_1_2 = "%s:%d:%s:%d:%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FusionBlaze_C_2147725422_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FusionBlaze.C!dha"
        threat_id = "2147725422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FusionBlaze"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {45 3a 5c 66 61 73 74 65 72 2d 73 70 65 65 64 2d 73 72 63 5c 7a 5f 67 72 65 65 6e 5f 76 65 72 5c 52 65 6c 65 61 73 65 5c [0-16] 2e 70 64 62}  //weight: 20, accuracy: Low
        $x_1_2 = {00 2a 2a 2e 73 68 74 6d 6c 24 7c 2a 2a 2e 73 68 74 6d 24 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 2a 2a 2e 63 67 69 24 7c 2a 2a 2e 70 6c 24 7c 2a 2a 2e 70 68 70 24 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 35 00 2e 00 30 00 20 00 28 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 36 00 2e 00 31 00 3b 00 20 00 57 00 4f 00 57 00 36 00 34 00 3b 00 20 00 54 00 72 00 69 00 64 00 65 00 6e 00 74 00 2f 00 37 00 2e 00 30 00 3b 00 20 00 72 00 76 00 3a 00 31 00 31 00 2e 00 30 00 29 00 20 00 6c 00 69 00 6b 00 65 00 20 00 47 00 65 00 63 00 6b 00 6f 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 61 73 6b 2f 6d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 54 65 72 6d 69 6e 61 6c 20 53 65 72 76 65 72 5c 57 64 73 5c 72 64 70 77 64 5c 54 64 73 5c 74 63 70 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 5f 67 72 65 65 6e 5f 76 65 72 5f 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 67 72 6f 75 70 5f 74 65 73 74 5f 69 64 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 5f 5f 74 65 73 74 5f 65 76 65 6e 74 5f 5f 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 65 78 61 6d 70 6c 65 3a 09 52 61 6c 5f 73 2e 65 78 65 20 2d 68 0a 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 41 72 67 73 20 65 72 72 6f 72 21 21 0a 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 65 78 61 6d 70 6c 65 3a 09 52 61 6c 5f 73 2e 65 78 65 20 2d 73 20 64 6f 6d 61 69 6e 2f 69 70 20 70 6f 72 74}  //weight: 1, accuracy: High
        $x_1_13 = {00 73 6f 63 6b 73 20 69 6e 69 74 20 65 72 72 6f 72 21 0a 00}  //weight: 1, accuracy: High
        $x_1_14 = {00 70 72 6f 78 79 49 70 20 6f 72 20 70 6f 72 74 20 65 72 72 6f 72 21 0a 00}  //weight: 1, accuracy: High
        $x_1_15 = {00 73 74 61 72 74 20 77 6f 72 6b 2e 2e 2e 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_20_*))) or
            (all of ($x*))
        )
}

