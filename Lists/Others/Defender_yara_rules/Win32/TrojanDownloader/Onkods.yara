rule TrojanDownloader_Win32_Onkods_C_2147804151_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Onkods.C"
        threat_id = "2147804151"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Onkods"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {0f b6 d2 03 c2 99 f7 fb 0f b6 44 14 14 30 41 ff 80 39 00 75}  //weight: 100, accuracy: High
        $x_100_2 = {0f b6 01 0f b6 ca 03 c1 8b 4c 24 18 99 f7 f9 0f b6 54 14 1c 30 55 ff 80 7d 00 00 75}  //weight: 100, accuracy: High
        $x_100_3 = {0f b6 44 3c ?? 0f b6 d2 03 c2 99 f7 fd 0f b6 44 14 ?? 30 41 ff 80 39 00 75}  //weight: 100, accuracy: Low
        $x_100_4 = {0f b6 54 3c ?? 0f b6 44 34 ?? 03 c2 99 f7 fb 0f b6 44 14 ?? 30 41 ff 80 39 00 75}  //weight: 100, accuracy: Low
        $x_100_5 = {30 02 8a 02 30 44 2c ?? 0f b6 12 0f b6 44 2c ?? 03 c2 99 f7 f9 0f b6 44 14 ?? 30 43 ff}  //weight: 100, accuracy: Low
        $x_100_6 = {0f b6 44 2c ?? 30 44 1c 00 8a 44 1c 00 30 44 2c 00 8a 44 2c 00 30 44 1c 00 0f b6 54 2c 00 0f b6 44 1c 00 03 c2 99 f7 f9 0f b6 44 14 00 30 47 ff}  //weight: 100, accuracy: Low
        $x_100_7 = {30 02 8a 02 30 44 0c ?? 0f b6 44 0c ?? 0f b6 0a 03 c1 99 f7 7c 24 ?? 8a 54 14 ?? 30 55 ff}  //weight: 100, accuracy: Low
        $x_100_8 = {99 f7 fd 0f b7 c2 0f b7 d8 0f b6 44 1c ?? 30 44 3c ?? 8a 44 3c ?? 30 44 1c ?? 8a 44 1c ?? 30 44 3c ?? 0f b6 44 3c ?? 0f b6 4c 1c ?? 03 c1 99 f7 fd 8a 54 14 ?? 30 16 46}  //weight: 100, accuracy: Low
        $x_100_9 = {99 f7 f9 0f b7 c2 0f b7 d8 0f b6 44 1c ?? 30 44 2c ?? 8a 44 2c ?? 30 44 1c ?? 8a 44 1c ?? 30 44 2c ?? 0f b6 54 1c ?? 0f b6 44 2c ?? 03 c2 99 f7 f9 0f b6 44 14 ?? 30 07 47}  //weight: 100, accuracy: Low
        $x_100_10 = {0f b6 54 04 ?? 30 54 0c ?? 8a 54 0c ?? 30 54 04 ?? 8a 54 04 ?? 30 54 0c ?? 8a 4c 0c ?? 89 44 24 ?? 8d 44 04 ?? 0f b6 00 0f b6 c9 03 c1 99 f7 7c 24 ?? 8b 44 24 ?? 40 89 44 24 ?? 0f b6 54 14 ?? 30 50 ff}  //weight: 100, accuracy: Low
        $x_100_11 = {0f b6 44 1c ?? 30 44 3c ?? 8a 44 3c ?? 30 44 1c ?? 8a 44 1c ?? 30 44 3c ?? 0f b6 4c 1c ?? 0f b6 44 3c ?? 03 c1 99 f7 fd 8a 54 14 ?? 30 56 ff}  //weight: 100, accuracy: Low
        $x_100_12 = {0f b6 44 14 ?? 0f b6 4c 24 ?? 03 c1 99 f7 7c 24 ?? 68 ?? ?? ?? ?? 0f b6 54 14 ?? 30 55 00 ff d6 68 ?? ?? ?? ?? ff d7 68 ?? ?? ?? ?? 45 ff d6 68 ?? ?? ?? ?? ff d7 80 7d 00 00 0f 85}  //weight: 100, accuracy: Low
        $x_100_13 = {30 1a 8a 1a 30 5c 04 ?? 8a 5c 04 ?? 0f b6 02 0f b6 d3 8b 5c 24 ?? 03 c2 99 f7 fb 8a 44 14 ?? 30 41 ff 80 39 00 75}  //weight: 100, accuracy: Low
        $x_100_14 = {0f b6 54 04 ?? 30 54 2c ?? 8a 54 2c ?? 30 54 04 ?? 8a 54 04 ?? 30 54 2c ?? 8a 54 2c ?? 89 44 24 ?? 8d 44 04 ?? 0f b6 00 0f b6 d2 03 c2 99 f7 fb 8a 44 14 ?? 30 41 ff 80 39 00 75}  //weight: 100, accuracy: Low
        $x_100_15 = {0f b6 44 1c ?? 03 c5 99 f7 f9 0f b7 c2 0f b7 e8 8a 54 2c ?? 30 54 1c ?? 8a 44 1c ?? 30 44 2c ?? 8a 44 2c ?? 30 44 1c ?? 0f b6 54 2c ?? 0f b6 44 1c ?? 03 c2 99 f7 f9 8d 4c 24}  //weight: 100, accuracy: Low
        $x_100_16 = {0f b6 54 04 ?? 30 54 2c ?? 8a 54 2c ?? 30 54 04 ?? 8a 54 04 ?? 30 54 2c ?? 8a 54 2c ?? 89 44 24 ?? 8d 44 04 ?? 0f b6 00 0f b6 d2 03 c2 99 f7 f9 8a 44 14 ?? 30 43 ff}  //weight: 100, accuracy: Low
        $x_100_17 = {0f b6 44 3c ?? 03 c3 99 f7 fd 0f b7 c2 0f b7 d8 0f b6 44 1c ?? 30 44 3c ?? 8a 44 3c ?? 30 44 1c ?? 8a 44 1c ?? 30 44 3c ?? 8a 4c 3c ?? 0f b6 44 1c ?? 0f b6 c9 03 c1 99 f7 fd}  //weight: 100, accuracy: Low
        $x_100_18 = {0f b6 44 14 ?? 0f b6 4c 24 ?? 03 c1 99 f7 7c 24 ?? 8b 44 24 ?? 8b 4c 24 ?? 53 0f b6 54 14 ?? 30 10 8b 44 24}  //weight: 100, accuracy: Low
        $x_100_19 = {0f b6 44 04 ?? 0f b6 4c 24 ?? 03 c1 99 f7 7c 24 ?? 8b 44 24 ?? 56 57 55 0f b6 54 14 ?? 30 10 ff d3 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 44 24 ?? 40 80 38 00 89 44 24 ?? 0f 85}  //weight: 100, accuracy: Low
        $x_100_20 = {0f b6 44 14 ?? 0f b6 4c 24 ?? 03 c1 99 f7 7c 24 ?? 68 ?? ?? ?? ?? 0f b6 54 14 ?? 30 55 00 ff d6 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff d7 45 80 7d 00 00 0f 85}  //weight: 100, accuracy: Low
        $x_100_21 = {0f b6 44 04 ?? 0f b6 4c 24 ?? 03 c1 99 f7 7c 24 ?? 8b 44 24 ?? 68 ?? ?? ?? ?? 0f b6 54 14 ?? 30 10 04 00 8b 44 24}  //weight: 100, accuracy: Low
        $x_100_22 = {ff d7 8b 4c 24 ?? 0f b6 54 0c ?? 0f b6 44 24 ?? 03 c2 99 f7 7c 24 ?? 8b 44 24 ?? 55 53 0f b6 4c 14 ?? 30 08 ff 15 ?? ?? ?? ?? ff 44 24 04}  //weight: 100, accuracy: Low
        $x_100_23 = {ff d3 8b 44 24 14 0f b6 44 04 ?? 0f b6 4c 24 ?? 03 c1 99 f7 7c 24 ?? 8b 44 24 ?? 56 57 55 0f b6 54 14 ?? 30 10 ff d3 ff 44 24 03}  //weight: 100, accuracy: Low
        $x_100_24 = {0f b6 54 0c ?? 0f b6 44 24 ?? 03 c2 99 f7 7c 24 ?? 8b 44 24 ?? 57 55 53 0f b6 4c 14 ?? 30 08 ff 15 ?? ?? ?? ?? ff 44 24 03}  //weight: 100, accuracy: Low
        $x_100_25 = {0f b6 44 04 ?? 0f b6 4c 24 ?? 03 c1 99 f7 7c 24 ?? 8b 44 24 ?? 8b 4c 24 01 0f b6 54 14 00 30 10 8b 44 24 01 8b 54 24 01 50 51 52 ff 15 ?? ?? ?? ?? ff 44 24 03}  //weight: 100, accuracy: Low
        $x_100_26 = {0f b6 44 0c ?? 0f b6 54 24 ?? 03 c2 99 f7 7c 24 ?? 8b 44 24 ?? 0f b6 4c 14 00 8b 54 24 01 30 08 52 ff 15 ?? ?? ?? ?? ff 44 24 03}  //weight: 100, accuracy: Low
        $x_100_27 = {0f b6 44 14 ?? 0f b6 4c 24 ?? 03 c1 99 f7 7c 24 ?? 0f b6 54 14 00 8b 44 24 ?? 30 10 8b 44 24 01 8b 4c 24 01 8b 54 24 01 50 8b 44 24 ?? 51 8b 4c 24 ?? 52 50 51 ff 15 ?? ?? ?? ?? ff 44 24 04}  //weight: 100, accuracy: Low
        $x_100_28 = {0f b6 54 0c ?? 0f b6 44 24 ?? 03 c2 99 f7 7c 24 ?? 8b 44 24 ?? 0f b6 4c 14 00 8b 54 24 01 30 08 52 ff 15 ?? ?? ?? ?? ff 44 24 03}  //weight: 100, accuracy: Low
        $x_100_29 = {8a 4c 24 60 8b 44 24 ?? 30 4c 04 ?? 8a 44 04 01 88 44 24 60 ff 74 24 60 ff 15 ?? ?? ?? ?? 8b ?? 24 ?? 0f b6 ?? ?? 01 0f b6 ?? 24 60 03 c1 99 f7 7c 24 ?? 8b 44 24 ?? ff 74 24 60 8a 4c 14 ?? 30 08 ff 15 ?? ?? ?? ?? ff 44 24 0a}  //weight: 100, accuracy: Low
        $x_100_30 = {8a 4c 24 60 8b 44 24 ?? 30 4c 04 ?? 8a 44 04 01 88 44 24 60 ff 74 24 60 ff 74 24 ?? [0-8] ff 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 c1 99 f7 7c 24 ?? ff 74 24 60 8b 44 24 60 ff 74 24 03 04 8a 4c 14 ?? 30 08 ff 15 ?? ?? ?? ?? ff 44 24}  //weight: 100, accuracy: Low
        $x_100_31 = {8a 4c 24 60 8b 44 24 ?? 30 4c 04 ?? 8a 44 04 01 88 44 24 60 ff 74 24 60 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 0f b6 44 04 01 0f b6 4c 24 60 03 c1 99 f7 7c 24 ?? 8a 4c 14 01 8b 44 24 ?? ff 74 24 60 30 08 ff 15 ?? ?? ?? ?? ff 44 24 08}  //weight: 100, accuracy: Low
        $x_100_32 = {8a 4c 24 60 8b 44 24 ?? 30 4c 04 ?? 8a 44 04 ?? 88 44 24 60 ff 74 24 60 ff 74 24 ?? ff 74 24 ?? ff ?? 8b 44 24 ?? 0f b6 44 04 ?? 0f b6 4c 24 60 03 c1 99 f7 7c 24 ?? ff 74 24 60 8b 44 24 60 ff 74 24 ?? ff 74 24 ?? 8a 4c 14 ?? 30 08 ff ?? ff 44 24}  //weight: 100, accuracy: Low
        $x_100_33 = {30 08 8a 00 57 53 88 45 13 ff d6 8b 45 f8 0f b6 44 05 b8 0f b6 4d 13 03 c1 99 f7 7d f0 8b 45 0c 57 53 8a 4c 15 b8 30 08 ff d6 ff 45 0c}  //weight: 100, accuracy: High
        $x_100_34 = {8a 4c 24 60 8b 44 24 ?? 30 4c 04 ?? 8a 44 04 01 57 55 53 88 44 24 ?? ff d6 8b 44 24 ?? 0f b6 44 04 01 0f b6 4c 24 60 03 c1 99 f7 7c 24 ?? 8b 44 24 ?? 57 55 53 8a 4c 14 ?? 30 08 ff d6 ff 44 24 07}  //weight: 100, accuracy: Low
        $x_100_35 = {ff d3 8b 44 24 ?? 0f b6 44 04 ?? 0f b6 4c 24 ?? 03 c1 99 f7 7c 24 ?? 8b 44 24 ?? 6a 00 56 56 8a 4c 14 ?? 30 08 ff d7 6a 00 56 ff d5 68 ?? ?? ?? ?? ff d3 ff 44 24 04}  //weight: 100, accuracy: Low
        $x_100_36 = {8b 44 24 14 0f b6 44 04 20 0f b6 4c 24 60 03 c1 99 f7 7c 24 1c 8b 44 24 5c [0-16] (8a 4c 14 ??|0f b6 54 14 ??) [0-48] ff 44 24 5c}  //weight: 100, accuracy: Low
        $x_100_37 = {8b 44 24 14 0f b6 44 04 20 0f b6 cb 03 c1 99 f7 7c 24 18 8b 5c 24 5c [0-2] 56 8a 44 14 ?? 30 03 [0-16] 43 [0-1] 89 5c 24 ?? [0-32] 80 3b 00 0f 85}  //weight: 100, accuracy: Low
        $x_100_38 = {8b 44 24 14 0f b6 44 04 (24|20) 0f b6 4c 24 (64|60) 03 c1 99 f7 7c 24 18 [0-16] 56 0f b6 54 14 ?? 30 13 [0-48] 80 3b 00 0f 85}  //weight: 100, accuracy: Low
        $x_100_39 = {8b 44 24 10 0f b6 44 04 20 0f b6 4c 24 60 03 c1 99 f7 7c 24 18 0f b6 54 14 20 30 13 [0-64] 80 3b 00 0f 85}  //weight: 100, accuracy: Low
        $x_100_40 = {0f b6 4c 24 60 03 c1 99 f7 7c 24 ?? 8b 44 24 5c 09 00 8b ?? 24 ?? 0f b6 44 ?? 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-32] 0f b6 54 14 ?? 30 10}  //weight: 100, accuracy: Low
        $x_100_41 = {0f b6 44 24 60 03 c2 99 f7 7c 24 1c 8b 44 24 5c 09 00 8b ?? 24 14 0f b6 54 ?? 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-32] (8a|0f b6) 4c 14 ?? 30 08}  //weight: 100, accuracy: Low
        $x_100_42 = {0f b6 4c 24 64 03 c1 99 f7 7c 24 18 09 00 8b ?? 24 14 0f b6 44 ?? 24 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-32] 0f b6 54 14 ?? 30 (13|10)}  //weight: 100, accuracy: Low
        $x_100_43 = {8d 47 01 99 f7 7d ?? 0f b7 c2 0f b7 f8 8d 4c 3d c4 0f b6 01 03 c3 99 f7 7d 00 0f b7 c2 0f b7 d8 8d 44 1d c4 03 00 89 45 00}  //weight: 100, accuracy: Low
        $x_100_44 = {8a 09 0f b6 c9 03 c1 99 f7 7d ?? 8a 44 15 ?? 30 ?? ?? 80 ?? 00 8b 45 ?? 40 99 f7 7d ?? 0f b7 c2 8d 4c 05 ?? 89 45 ?? 0f b6 01 03 c3 99 f7 7d}  //weight: 100, accuracy: Low
        $x_100_45 = {8a 09 0f b6 c9 03 c1 99 f7 7c 24 ?? 8a 44 14 ?? 30 ?? ?? 80 ?? 00 8d 45 01 99 f7 7c 24 ?? 0f b7 c2 0f b7 e8 8d 4c 2c ?? 0f b6 01 03 c3 99 f7 7c 24}  //weight: 100, accuracy: Low
        $x_100_46 = {8b 45 fc 0f b6 7d 14 8d 4c 05 c0 99 f7 ff 8b 45 08 0f b7 7d 10 0f be 14 02 0f b6 01 03 d3 03 c2 99 f7 ff 0f b7 c2 0f b7 d8 8d 7c 1d c0 8a 07 32 01 88 01 30 07 8a 07 30 01 ff 45 fc ff 4d f8 75 bf}  //weight: 100, accuracy: High
        $x_100_47 = {0f b6 7c 24 5c 8b c3 99 f7 ff 8b 44 24 50 8d 4c 1c 18 0f be 14 02 0f b6 01 03 d5 03 c2 99 f7 7c 24 10 0f b7 c2 0f b7 e8 8d 7c 2c 18 8a 07 32 01 88 01 30 07 8a 07 30 01 43 ff 4c 24 14 75 c1}  //weight: 100, accuracy: High
        $x_100_48 = {99 f7 f9 8b 44 24 ?? 8d 74 3c ?? 8a 1e ff 74 24 ?? 0f be 0c 02 0f b6 c3 03 cd 03 c1 99 f7 7c 24 ?? 0f b7 ea ff 15 ?? ?? ?? ?? 0f b7 ed 8d 44 2c ?? 8a 08 32 cb 88 0e 30 08 8a 18}  //weight: 100, accuracy: Low
        $x_100_49 = {99 f7 f9 8b 44 24 ?? ff 74 24 ?? 0f be 0c 02 0f b6 06 03 cb 03 c1 0f b7 4c 24 ?? 99 f7 f9 0f b7 da ff 15 ?? ?? ?? ?? 0f b7 db 8d 44 1c ?? 8a 08 32 0e 6a 00 88 0e 30 08 8a 00}  //weight: 100, accuracy: Low
        $x_100_50 = {99 f7 f9 8b 44 24 ?? ff 74 24 ?? 0f be 0c 02 0f b6 07 03 cd 03 c1 0f b7 4c 24 ?? 99 f7 f9 0f b7 ea ff 15 ?? ?? ?? ?? 0f b7 ed 8d 44 2c ?? 8a 08 32 0f 6a 00 88 0f 30 08 8a 00}  //weight: 100, accuracy: Low
        $x_100_51 = {99 f7 ff 8a 0e 8b 44 24 54 0f be 14 02 03 d5 0f b6 c1 03 c2 99 f7 fb 0f b7 c2 0f b7 e8 33 c0 50 50 ff 74 24 64 8d 7c 2c 28 8a 1f 32 d9 50 88 1e}  //weight: 100, accuracy: High
        $x_100_52 = {99 f7 fd 8b 44 24 58 8a 0f 0f b7 6c 24 60 0f be 14 02 03 54 24 14 0f b6 c1 03 c2 99 f7 fd 0f b7 c2 8d 6c 04 20 89 44 24 14 8a 45 00 32 c1 88 44 24 13 88 07}  //weight: 100, accuracy: High
        $x_100_53 = {99 f7 ff 8a 0e 8b 44 24 5c 0f be 14 02 03 d5 0f b6 c1 03 c2 99 f7 7c 24 18 0f b7 c2 0f b7 e8 8d 7c 2c 24 8a 07 32 c1 88 44 24 13 88 06}  //weight: 100, accuracy: High
        $x_100_54 = {0f b6 74 24 ?? 8b c3 99 f7 fe 8b 44 24 ?? 0f b7 74 24 ?? 8d 4c 1c ?? 0f be 14 02 0f b6 01 03 d7 03 c2 99 f7 fe 0f b7 c2 0f b7 f8 8d 74 3c ?? 8a 06 32 01 88 01 30 06 8a 06 30 01 43 ff 4c 24 ?? 75 be}  //weight: 100, accuracy: Low
        $x_100_55 = {8a 07 30 06 8a 06 [0-16] ff 74 24 ?? 88 44 24 [0-7] 0f b6 4c 24 ?? 0f b6 07 03 c1 99 f7 7c 24 [0-6] 8a 44 14 ?? 30 03 43 [0-32] 80 3b 00 0f 85}  //weight: 100, accuracy: Low
        $x_100_56 = {0f b6 5c 24 ?? 8b ?? 99 f7 fb 8a 5c ?? ?? 8b 44 24 ?? ?? 0f be 14 02 03 d1 0f b7 4c 24 ?? 0f b6 c3 03 c2 99 f7 f9 0f b7 c2 0f b7 c8 8a 44 0c ?? 32 c3 88 44 ?? ?? 30 44 0c ?? 8a 44 0c ?? 30 44 ?? ?? 83 6c 24 ?? 01 75 b7}  //weight: 100, accuracy: Low
        $x_100_57 = {33 c9 89 44 24 ?? 8b ?? 99 f7 fd 8a 5c ?? ?? 8b 44 24 ?? ?? 0f be 14 02 03 d1 0f b7 4c 24 ?? 0f b6 c3 03 c2 99 f7 f9 0f b7 c2 0f b7 c8 8a 44 0c ?? 32 c3 88 44 ?? ?? 30 44 0c ?? 8a 44 0c ?? 30 44 ?? ?? 83 6c 24 ?? 01 75 bc}  //weight: 100, accuracy: Low
        $x_1_58 = {6a 04 6a 32 8d 54 24 ?? 56 52 e8 ?? ?? ?? ?? 83 c4 10 83 c6 64 83 ef 01 75 e6 0c 00 [0-7] bf 0b 00 00 00}  //weight: 1, accuracy: Low
        $x_1_59 = {6a 04 6a 32 8d 54 24 ?? 57 52 e8 ?? ?? ?? ?? 83 c4 10 83 c7 64 83 eb 01 75 e6 0c 00 [0-7] bb 0b 00 00 00}  //weight: 1, accuracy: Low
        $x_1_60 = {6a 04 6a 32 8d ?? 24 ?? 56 ?? e8 ?? ?? ?? ?? 83 c4 10 83 c6 64 83 ef 01 75 e6 0c 00 [0-7] bf 0b 00 00 00}  //weight: 1, accuracy: Low
        $x_1_61 = {6a 04 6a 32 8d 54 24 ?? 53 52 e8 ?? ?? ?? ?? 83 c4 10 83 c3 64 83 ed 01 75 e6 0c 00 [0-7] bd 0b 00 00 00}  //weight: 1, accuracy: Low
        $x_1_62 = {6a 04 6a 32 8d 54 24 ?? ?? 52 e8 ?? ?? ?? ?? 83 c4 10 83 ?? 64 83 6c 24 ?? 01 75 e4 0f 00 [0-7] c7 44 24 ?? 0b 00 00 00}  //weight: 1, accuracy: Low
        $x_1_63 = {6a 04 6a 32 52 8d 44 24 ?? 50 e8 ?? ?? ?? ?? 83 44 24 ?? 64 83 c4 10 83 6c 24 ?? 01 75}  //weight: 1, accuracy: Low
        $x_1_64 = {5f 6a 04 6a 32 8d 44 24 ?? 56 50 e8 ?? ?? ?? ?? 83 c4 10 83 c6 64 4f 75 e8 09 00 [0-7] 6a 0b}  //weight: 1, accuracy: Low
        $x_1_65 = {6a 04 6a 32 ff 74 24 ?? 8d 44 24 ?? 50 e8 ?? ?? ?? ?? 83 44 24 ?? 64 83 c4 10 ff 4c 24 ?? 75 e0 0f 00 [0-7] c7 44 24 ?? 0b 00 00 00}  //weight: 1, accuracy: Low
        $x_1_66 = {5b 6a 04 6a 32 8d 44 24 ?? 57 50 e8 ?? ?? ?? ?? 83 c4 10 83 c7 64 4b 75 e8 09 00 [0-7] 6a 0b}  //weight: 1, accuracy: Low
        $x_1_67 = {6a 04 6a 32 8d 45 ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 10 83 ?? 64 ?? 75 e9 0a 00 [0-7] 6a 0b}  //weight: 1, accuracy: Low
        $x_1_68 = {6a 04 6a 32 ff 74 24 ?? 8d 44 24 ?? 50 e8 ?? ?? ?? ?? 83 44 24 ?? 64 83 c4 10 ff 4c 24 ?? 75 e0 0f 00 [0-7] c7 44 24 ?? 0f 00 00 00}  //weight: 1, accuracy: Low
        $x_1_69 = {6a 04 6a 32 8d 44 24 ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 10 83 ?? 64 ff 4c 24 ?? 75 e5 0f 00 [0-7] c7 44 24 ?? 0f 00 00 00}  //weight: 1, accuracy: Low
        $x_1_70 = {6a 04 6a 32 8d 44 24 ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 10 83 ?? 64 (4b|4f) 75 e8 09 00 [0-7] 6a 0f}  //weight: 1, accuracy: Low
        $x_1_71 = {6a 04 6a 32 51 8d 54 24 ?? 52 e8 ?? ?? ?? ?? 83 44 24 ?? 64 83 c4 10 83 6c 24 ?? 01 75 0f 00 [0-7] c7 44 24 ?? 0b 00 00 00}  //weight: 1, accuracy: Low
        $x_1_72 = {6a 04 6a 32 8d 4c 24 ?? ?? 51 e8 ?? ?? ?? ?? 83 c4 10 83 ?? 64 83 6c 24 ?? 01 75 e4 18 00 [0-16] c7 44 24 ?? 0b 00 00 00}  //weight: 1, accuracy: Low
        $x_1_73 = {6a 04 6a 32 ?? 8d 4c 24 ?? 51 e8 ?? ?? ?? ?? 83 44 24 ?? 64 83 c4 10 83 6c 24 ?? 01 75 ?? 0f 00 [0-7] c7 44 24 ?? 0b 00 00 00}  //weight: 1, accuracy: Low
        $x_1_74 = {64 ff 4c 24 ?? 75 ?? 6a 04 6a 32 8d 44 24 ?? 50 8d 44 24 ?? 50 e8 ?? ?? ?? ?? 83 c4 10 bf 04 00 83 44 24}  //weight: 1, accuracy: Low
        $x_1_75 = {6a 04 6a 32 8d 54 24 ?? ?? 52 e8 ?? ?? ?? ?? 83 c4 10 [0-64] 83 ?? 64 83 [0-3] 01 [0-64] 6a 04 6a 32 8d 44 24 ?? 50 8d 4c 24 ?? 51 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Onkods_A_2147804180_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Onkods.A"
        threat_id = "2147804180"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Onkods"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 63 3a 5c 55 73 65 72 73 5c 73 5c 44 65 73 6b 74 6f 70 5c}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 6a 00 6a 02 6a 00 6a 00 68 00 00 00 40 8d ?? ?? ?? ff ff 06 01 01 01 01 01 01 50 51 52 53 56 57 ff (95 ?? ??|55 ??) 89 85 ?? ?? ff ff 00 10 8d ?? ?? ?? ff ff 06 01 01 01 01 01 01 50 51 52 53 56 57 68 ff 03 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 00 6a 20 6a 00 6a 00 6a 00 8d ?? ?? ?? ff ff 06 01 01 01 01 01 01 50 51 52 53 56 57 6a 00 ff (95 ?? ??|55 ??) 00 20 b8 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {0f b7 45 fc 83 c0 01 0f b7 4d 10 99 f7 f9 66 89 55 fc 0f b7 45 ?? 0f b7 55 fc 0f b6 4c 15 ?? 03 c1 0f b7 4d 10 99 f7 f9 66 89 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Onkods_A_2147804180_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Onkods.A"
        threat_id = "2147804180"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Onkods"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 02 6a 00 6a 00 [0-6] 68 00 00 00 40 8d ?? 24 ?? ?? 00 00 [0-16] 06 01 01 01 01 01 01 50 51 52 53 56 57 [0-16] ff 54 24 ?? 00 10 8d ?? 24 ?? 06 01 01 01 01 01 01 50 51 52 53 56 57 68 ff 03 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {56 56 6a 02 56 56 [0-6] 68 00 00 00 40 8d ?? 24 ?? ?? 00 00 [0-16] 06 01 01 01 01 01 01 50 51 52 53 56 57 [0-16] ff 54 24 ?? 00 10 8d ?? 24 ?? 06 01 01 01 01 01 01 50 51 52 53 56 57 68 ff 03 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 00 00 40 8d 84 24 ?? 00 00 00 50 [0-1] ff 54 24 ?? 8b ?? 24 ?? 8d 4c 24 ?? 51 68 ff 03 00 00 8d 94 24 ?? ?? 00 00 52 ?? 8b ?? ff}  //weight: 1, accuracy: Low
        $x_10_4 = {8b c6 99 f7 fd 8a 5c 34 ?? 8b 44 24 ?? 46 0f be 14 02}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

