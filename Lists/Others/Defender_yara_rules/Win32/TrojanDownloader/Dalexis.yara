rule TrojanDownloader_Win32_Dalexis_A_2147688296_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dalexis.A"
        threat_id = "2147688296"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dalexis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 47 00 45 00 54 00 00 00 25 00 73 00 75 00 70 00 64 00 61 00 74 00 65 00 5f 00 25 00 64 00 2e 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 00 73 00 74 00 65 00 6d 00 70 00 5f 00 63 00 61 00 62 00 5f 00 25 00 64 00 2e 00 63 00 61 00 62 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {83 c4 14 57 68 80 00 00 00 6a 02 57 6a 01 68 00 00 00 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dalexis_A_2147688296_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dalexis.A"
        threat_id = "2147688296"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dalexis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {47 00 45 00 54 00 00 00 25 00 73 00 75 00 70 00 64 00 61 00 74 00 65 00 5f 00 25 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: High
        $x_2_2 = "%stemp_cab_%d.cab" wide //weight: 2
        $x_1_3 = {6a 01 68 00 00 00 40 8d 85 ?? ?? ?? ?? 50 89 ?? ?? ff 15 ?? ?? ?? ?? 8b ?? 83 ?? ff 75 0a 68 ea 03 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 01 68 00 00 00 40 8d 85 ?? ?? ?? ?? 50 89 5d ?? ff 15 ?? ?? ?? ?? 89 45 ?? 83 f8 ff 75 0a 68 ea 03 00 00 e9 ?? ?? ?? ?? 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Dalexis_C_2147690633_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dalexis.C"
        threat_id = "2147690633"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dalexis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 8d 34 03 8a 0e 8d 54 3d f0 8a 02 32 c8 32 c1 47 88 0e 88 02 83 ff 10 75 02 33 ff}  //weight: 1, accuracy: High
        $x_1_2 = {47 00 45 00 54 00 00 00 25 00 73 00 25 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "%stemp_cab_%d.cab" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dalexis_A_2147691481_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dalexis.A!!Dalexis"
        threat_id = "2147691481"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dalexis"
        severity = "Critical"
        info = "Dalexis: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {47 00 45 00 54 00 00 00 25 00 73 00 75 00 70 00 64 00 61 00 74 00 65 00 5f 00 25 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: High
        $x_2_2 = "%stemp_cab_%d.cab" wide //weight: 2
        $x_1_3 = {6a 01 68 00 00 00 40 8d 85 ?? ?? ?? ?? 50 89 ?? ?? ff 15 ?? ?? ?? ?? 8b ?? 83 ?? ff 75 0a 68 ea 03 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 01 68 00 00 00 40 8d 85 ?? ?? ?? ?? 50 89 5d ?? ff 15 ?? ?? ?? ?? 89 45 ?? 83 f8 ff 75 0a 68 ea 03 00 00 e9 ?? ?? ?? ?? 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Dalexis_C_2147691482_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dalexis.C!!Dalexis"
        threat_id = "2147691482"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dalexis"
        severity = "Critical"
        info = "Dalexis: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 8d 34 03 8a 0e 8d 54 3d f0 8a 02 32 c8 32 c1 47 88 0e 88 02 83 ff 10 75 02 33 ff}  //weight: 1, accuracy: High
        $x_1_2 = {47 00 45 00 54 00 00 00 25 00 73 00 25 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "%stemp_cab_%d.cab" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dalexis_D_2147691540_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dalexis.D"
        threat_id = "2147691540"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dalexis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 08 8d 34 03 8a 0e 8d 54 3d f0 8a 02 32 c8 32 c1 47 88 0e 88 02 83 ff 10 75 02 33 ff}  //weight: 5, accuracy: High
        $x_5_2 = {68 60 ea 00 00 b8 c0 d4 01 00 e8 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 59 50 ff d6 3b df 5b 74 27 6a 0a}  //weight: 5, accuracy: Low
        $x_1_3 = ".tar.gz" wide //weight: 1
        $x_1_4 = "hello.jpg" wide //weight: 1
        $x_1_5 = "mp3avimpgmdvflv" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Dalexis_D_2147692132_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dalexis.D!!Dalexis"
        threat_id = "2147692132"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dalexis"
        severity = "Critical"
        info = "Dalexis: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 08 8d 34 03 8a 0e 8d 54 3d f0 8a 02 32 c8 32 c1 47 88 0e 88 02 83 ff 10 75 02 33 ff}  //weight: 5, accuracy: High
        $x_5_2 = {68 60 ea 00 00 b8 c0 d4 01 00 e8 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 59 50 ff d6 3b df 5b 74 27 6a 0a}  //weight: 5, accuracy: Low
        $x_1_3 = ".tar.gz" wide //weight: 1
        $x_1_4 = "hello.jpg" wide //weight: 1
        $x_1_5 = "mp3avimpgmdvflv" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Dalexis_F_2147694111_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dalexis.F"
        threat_id = "2147694111"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dalexis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 7c 24 10 00 88 0a 74 05 30 0c 3e eb 03 30 04 3e 47 83 ff 10 75 02 33 ff}  //weight: 2, accuracy: High
        $x_5_2 = {68 60 ea 00 00 b8 c0 d4 01 00 e8 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 59 50 ff d6 3b df 5b 74 27 6a 0a}  //weight: 5, accuracy: Low
        $x_1_3 = "%08x.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dalexis_F_2147694111_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dalexis.F"
        threat_id = "2147694111"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dalexis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "klipopga.pdb" ascii //weight: 1
        $x_1_2 = "BhXYJmlenxHfx" ascii //weight: 1
        $x_1_3 = {b9 c6 78 3e 17 81 e9 f6 71 3e 17 51 b8 c6 78 3e 17 2d f6 71 3e 17 50 be f6 71 42 17 81 ee f6 71 3e 17}  //weight: 1, accuracy: High
        $x_1_4 = {f8 83 d0 04 83 c3 f7 f7 d3 29 fb 43 29 ff 4f 21 df c1 c7 03 c1 c7 05 89 1e f8 83 d6 04 8d 52 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

