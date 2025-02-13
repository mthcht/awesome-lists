rule TrojanDropper_Win32_Slingshot_A_2147726431_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Slingshot.A.dll!dha"
        threat_id = "2147726431"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Slingshot"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 20 8b 54 24 0c 8b 87 ?? ?? ?? ?? 8d 8b ?? ?? ?? ?? 51 52 ff d0 8b 5c 24 18 8b 74 24 10 85 c0 75 12 5e 5d b8 39 01 00 c0}  //weight: 1, accuracy: Low
        $x_2_2 = {b9 32 00 00 00 b8 6e 00 00 00 66 89 44 24 06 66 89 4c 24 0e ba 2e 00 00 00 b9 6c 00 00 00 66 89 54 24 10 b8 33 00 00 00}  //weight: 2, accuracy: High
        $x_2_3 = {8d 34 02 8b 41 1c 2b c2 8d 44 30 fc 3b f0 73 0e 90 81 3e c0 e8 05 24 74 0a 46 3b f0 72 f3}  //weight: 2, accuracy: High
        $x_1_4 = {8a 10 8b 4c 24 14 53 55 56 57 33 ff 88 11}  //weight: 1, accuracy: High
        $x_2_5 = {80 3b 50 75 24 80 7b 01 45 75 1e 80 7b 02 4d 75 18 80 7b 03 43 75 12 80 7b 04 52 75 0c 80 7b 05 54 75 06 8b 54 24 ?? 89 32 85 f6 75 13 85 c9 75 0f}  //weight: 2, accuracy: Low
        $x_2_6 = {66 83 f8 09 72 ?? 75 0a 66 83 be ?? ?? 00 00 04 72 ?? c6 45 f8 5a c6 45 f9 2a c6 45 fa d7 c6 45 fb 39 c6 45 fc 25 c6 45 fd ae c6 45 fe 18}  //weight: 2, accuracy: Low
        $x_1_7 = {00 4c 6f 61 64 50 61 79 6c 6f 61 64 00}  //weight: 1, accuracy: High
        $x_1_8 = "%hs -p 0x%p -s %d" ascii //weight: 1
        $x_1_9 = "a:s:o:l:r:z:" ascii //weight: 1
        $x_1_10 = ".binlines" ascii //weight: 1
        $x_1_11 = "-500\\INFO5" ascii //weight: 1
        $x_1_12 = {00 5c 73 79 6d 73 00}  //weight: 1, accuracy: High
        $x_2_13 = {53 00 73 00 20 00 2d 00 61 00 20 00 [0-16] 20 00 2d 00 73 00 20 00 [0-16] 20 00 2d 00 6f 00}  //weight: 2, accuracy: Low
        $x_2_14 = {53 73 20 2d 61 20 [0-16] 20 2d 73 20 [0-16] 20 2d 6f}  //weight: 2, accuracy: Low
        $x_2_15 = {6d 65 70 67 04 00 c7 44 24}  //weight: 2, accuracy: Low
        $x_2_16 = {0d d0 ad 2b 03 00 c7 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

