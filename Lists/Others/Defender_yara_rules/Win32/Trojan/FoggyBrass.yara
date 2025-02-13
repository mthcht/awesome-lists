rule Trojan_Win32_FoggyBrass_A_2147724719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FoggyBrass.A!dha"
        threat_id = "2147724719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FoggyBrass"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 33 33 70 3a 6f 6f 00}  //weight: 1, accuracy: High
        $x_2_2 = {56 78 7a 72 75 75 61 2f 35 2e 30 20 28 4e 72 77 64 78 6e 6a 20 57 4b 20 36 2e 31 3b 20 4e 58 4e 36 34 29 20 43 68 69 78 76 65 2f 32 38 2e 30 2e 31 35 30 30 2e 39 35 20 4a 61 66 61 69 72 2f 35 33 37 2e 33 36 00}  //weight: 2, accuracy: High
        $x_2_3 = "----FormBoundary" ascii //weight: 2
        $x_2_4 = "----FxivBxlwdaip" ascii //weight: 2
        $x_1_5 = "Acceyk:" ascii //weight: 1
        $x_2_6 = {43 78 77 6b 65 77 6b 2d 44 72 6a 79 78 6a 72 6b 72 78 77 3a 20 66 78 69 76 2d 64 61 6b 61 3b 00}  //weight: 2, accuracy: High
        $x_2_7 = {2a 64 4a 55 21 2a 4a 45 26 21 4d 40 55 4e 51 40 00}  //weight: 2, accuracy: High
        $x_2_8 = {74 33 34 6b 6a 66 64 6c 61 34 35 6c 00}  //weight: 2, accuracy: High
        $x_2_9 = {34 73 33 43 35 4b 44 4d 6c 78 69 61 4a 31 74 4f 62 58 63 51 72 2d 65 6f 32 47 20 7a 59 41 38 39 56 66 4c 2f 71 5a 57 49 30 6b 4e 54 55 5c 67 79 46 53 64 6e 68 37 42 36 5f 6d 6a 48 77 75 50 76 00}  //weight: 2, accuracy: High
        $x_2_10 = {48 61 4f 50 77 77 76 6f 5f 2e 59 74 28 44 61 70 76 33 50 35 77 69 3b 74 48 5a 7a 45 74 73 59 2e 59 3b 74 20 50 49 57 61 46 37 74 38 39 74 54 2e 73 3b 74 20 43 20 54 68 3b 74 39 6c 50 57 69 49 33 00}  //weight: 2, accuracy: High
        $x_2_11 = {36 61 49 33 69 49 33 78 39 2f 70 69 3a 74 76 70 70 77 50 44 76 33 50 61 49 6f 75 78 46 46 46 78 2d 61 6c 5c 78 53 6c 77 69 49 44 61 57 69 57 00}  //weight: 2, accuracy: High
        $x_2_12 = {30 33 33 70 3a 6f 6f 46 46 46 2e 70 53 49 76 2e 41 6c 6f 5c 76 50 49 6f 5c 76 50 49 2e 76 37 70 00}  //weight: 2, accuracy: High
        $x_2_13 = {30 33 33 70 3a 6f 6f 57 61 49 4c 37 76 49 2e 76 49 57 61 49 4c 2e 49 69 33 6f 46 69 35 4c 69 76 6c 6f 70 61 70 53 70 6f 77 50 37 33 2e 76 37 00}  //weight: 2, accuracy: High
        $x_2_14 = {30 33 33 70 3a 6f 6f 46 46 46 2e 30 46 76 49 41 2f 53 2e 44 61 5c 6f 37 53 35 6f 70 6c 61 57 53 44 33 6f 70 6c 61 57 53 44 69 2e 76 37 70 00}  //weight: 2, accuracy: High
        $x_2_15 = {30 33 33 70 3a 6f 6f 50 77 61 6e 69 37 6e 44 2e 44 61 5c 6f 79 61 5c 69 64 76 4c 69 73 6f 4e 4e 5a 6f 64 6a 5a 6f 77 50 37 33 2e 76 37 70 00}  //weight: 2, accuracy: High
        $x_2_16 = {5a 43 71 39 20 58 52 45 66 48 50 44 6c 61 37 61 2d 33 66 20 50 49 57 61 46 37 74 38 39 66 36 53 6c 6c 69 49 33 72 69 6c 37 50 61 49 00}  //weight: 2, accuracy: High
        $x_2_17 = {6a 42 63 71 78 4a 73 4a 58 78 45 4d 7a 6a 78 4a 42 68 5a 78 5a 6a 34 45 73 4a 6a 43 00}  //weight: 2, accuracy: High
        $x_1_18 = {be 06 00 00 c7 ?? ?? ?? ?? ?? d9 95 06 00 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FoggyBrass_B_2147724720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FoggyBrass.B!dha"
        threat_id = "2147724720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FoggyBrass"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0e 33 c0 8a 0c 0a 0f 1f 40 00 3a 88 ?? ?? ?? 00 74 ?? 40 83 f8 ?? 72 ?? eb ?? 8b 4e ?? 83 c0 ?? 83 e0 ?? 8a}  //weight: 1, accuracy: Low
        $x_1_2 = "4s3C5KDMlxiaJ1tObXcQr-eo2G zYA89VfL/qZWI0kNTU\\gyFSdnh7B6_mjHwuPv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

