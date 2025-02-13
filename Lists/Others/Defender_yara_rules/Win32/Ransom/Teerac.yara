rule Ransom_Win32_Teerac_A_2147686764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teerac.A"
        threat_id = "2147686764"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teerac"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 1a 8d 53 fc 33 c9 8b c6 85 d2 74 0f 90 90 81 38 ef be ad de 74 29 41 40 3b ca 72 f2}  //weight: 1, accuracy: High
        $x_1_2 = {8b 8b 28 02 00 00 8a 14 08 8b 4d fc 80 f2 ?? 88 14 01 40 3b 86 ?? ?? ?? ?? 72 e5}  //weight: 1, accuracy: Low
        $x_1_3 = {81 fb 41 50 33 32 75 0b 8b 5e 04 83 fb 18}  //weight: 1, accuracy: High
        $x_1_4 = {ff d3 83 f8 ff 75 0a 6a 64 ff d7 46 83 fe 64 7c ef}  //weight: 1, accuracy: High
        $x_1_5 = "S:(ML;;NRNWNX;;;LW)" wide //weight: 1
        $x_1_6 = "racketeer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Teerac_A_2147686764_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teerac.A"
        threat_id = "2147686764"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teerac"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c5 89 45 fc 53 68 ?? ?? ?? ?? b8 20 00 00 00 8d 5d ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c5 89 45 fc 53 56 57 68 ?? ?? ?? ?? b8 19 00 00 00 8d 5d ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {75 38 53 68 ?? ?? ?? ?? b8 11 00 00 00 8d 5d ?? e8}  //weight: 1, accuracy: Low
        $x_1_4 = {eb 0a 8d a4 24 00 00 00 00 8d 49 00 68 ?? ?? ?? ?? b8 18 00 00 00 8d 5d ?? e8}  //weight: 1, accuracy: Low
        $x_1_5 = {74 07 68 98 3a 00 00 ff d7 68 ?? ?? ?? ?? b8 18 00 00 00 8d 5d ?? e8}  //weight: 1, accuracy: Low
        $x_1_6 = {be 06 00 00 00 f7 f6 66 0f be 92 ?? ?? ?? ?? 66 89 14 4b eb 13 be 14 00 00 00 f7 f6 66 0f be 82 ?? ?? ?? ?? 66 89 04 4b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_Teerac_A_2147686764_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teerac.A"
        threat_id = "2147686764"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teerac"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {61 00 76 00 69 00 00 00 77 00 61 00 76 00 00 00 6d 00 70 00 33 00 00 00 67 00 69 00 66 00 00 00 69 00 63 00 6f 00 00 00 70 00 6e 00 67 00 00 00 62 00 6d 00 70 00 00 00 69 00 6e 00 66 00 00 00 6d 00 61 00 6e 00 69 00 66 00 65 00 73 00 74 00 00 00 00 00 63 00 68 00 6d 00 00 00}  //weight: 5, accuracy: High
        $x_5_2 = {41 00 6c 00 6c 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 77 00 61 00 73 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 77 00 69 00 74 00 68 00 20 00 43 00 72 00 79 00 70 00 74 00 6f 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 21 00 0d 00}  //weight: 5, accuracy: High
        $x_5_3 = {42 00 69 00 74 00 20 00 54 00 6f 00 72 00 72 00 65 00 6e 00 74 00 20 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 5c 00 43 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 00 00}  //weight: 5, accuracy: High
        $x_1_4 = {65 00 78 00 65 00 00 00 2e 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "!!! YOUR SYSTEM IS HACKED !!!" ascii //weight: 1
        $x_1_6 = "!!! SISTEMINIZ HACKLENDI !!!" ascii //weight: 1
        $x_1_7 = "X:\\racketeer\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Teerac_A_2147689327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teerac.A!!Teerac.gen!A"
        threat_id = "2147689327"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teerac"
        severity = "Critical"
        info = "Teerac: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 1a 8d 53 fc 33 c9 8b c6 85 d2 74 0f 90 90 81 38 ef be ad de 74 29 41 40 3b ca 72 f2}  //weight: 1, accuracy: High
        $x_1_2 = {8b 8b 28 02 00 00 8a 14 08 8b 4d fc 80 f2 ?? 88 14 01 40 3b 86 ?? ?? ?? ?? 72 e5}  //weight: 1, accuracy: Low
        $x_1_3 = {81 fb 41 50 33 32 75 0b 8b 5e 04 83 fb 18}  //weight: 1, accuracy: High
        $x_1_4 = {ff d3 83 f8 ff 75 0a 6a 64 ff d7 46 83 fe 64 7c ef}  //weight: 1, accuracy: High
        $x_1_5 = "S:(ML;;NRNWNX;;;LW)" wide //weight: 1
        $x_1_6 = "racketeer" ascii //weight: 1
        $n_100_7 = {04 1b b9 45 d9 bf 4e fb 0c a0 fd 63 37 51 db 8a}  //weight: -100, accuracy: High
        $n_100_8 = {1b 1e 84 b0 21 b5 8a 47 29 d1 06 9b a2 84 80 bb}  //weight: -100, accuracy: High
        $n_100_9 = {0f 66 8f b0 f0 f0 02 b7 74 c7 dd bd 76 9e e5 b1}  //weight: -100, accuracy: High
        $n_100_10 = {09 16 82 54 62 be a1 55 94 45 0e 89 7e 8d 3a e6}  //weight: -100, accuracy: High
        $n_100_11 = {02 26 e6 bd a7 6d ae 71 1e 3d b2 32 1e 3b 53 08}  //weight: -100, accuracy: High
        $n_100_12 = {01 7c a1 9b 58 59 e8 3f 44 d8 74 c1 ce 50 6e 6d}  //weight: -100, accuracy: High
        $n_100_13 = {33 00 00 00 4e a1 d8 07 70 a9 bb e9 44 00 00 00 00 00 4e}  //weight: -100, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

rule Ransom_Win32_Teerac_A_2147689327_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teerac.A!!Teerac.gen!A"
        threat_id = "2147689327"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teerac"
        severity = "Critical"
        info = "Teerac: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c5 89 45 fc 53 68 ?? ?? ?? ?? b8 20 00 00 00 8d 5d ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c5 89 45 fc 53 56 57 68 ?? ?? ?? ?? b8 19 00 00 00 8d 5d ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {75 38 53 68 ?? ?? ?? ?? b8 11 00 00 00 8d 5d ?? e8}  //weight: 1, accuracy: Low
        $x_1_4 = {eb 0a 8d a4 24 00 00 00 00 8d 49 00 68 ?? ?? ?? ?? b8 18 00 00 00 8d 5d ?? e8}  //weight: 1, accuracy: Low
        $x_1_5 = {74 07 68 98 3a 00 00 ff d7 68 ?? ?? ?? ?? b8 18 00 00 00 8d 5d ?? e8}  //weight: 1, accuracy: Low
        $x_1_6 = {be 06 00 00 00 f7 f6 66 0f be 92 ?? ?? ?? ?? 66 89 14 4b eb 13 be 14 00 00 00 f7 f6 66 0f be 82 ?? ?? ?? ?? 66 89 04 4b}  //weight: 1, accuracy: Low
        $n_100_7 = {04 1b b9 45 d9 bf 4e fb 0c a0 fd 63 37 51 db 8a}  //weight: -100, accuracy: High
        $n_100_8 = {1b 1e 84 b0 21 b5 8a 47 29 d1 06 9b a2 84 80 bb}  //weight: -100, accuracy: High
        $n_100_9 = {0f 66 8f b0 f0 f0 02 b7 74 c7 dd bd 76 9e e5 b1}  //weight: -100, accuracy: High
        $n_100_10 = {09 16 82 54 62 be a1 55 94 45 0e 89 7e 8d 3a e6}  //weight: -100, accuracy: High
        $n_100_11 = {02 26 e6 bd a7 6d ae 71 1e 3d b2 32 1e 3b 53 08}  //weight: -100, accuracy: High
        $n_100_12 = {01 7c a1 9b 58 59 e8 3f 44 d8 74 c1 ce 50 6e 6d}  //weight: -100, accuracy: High
        $n_100_13 = {33 00 00 00 4e a1 d8 07 70 a9 bb e9 44 00 00 00 00 00 4e}  //weight: -100, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (4 of ($x*))
}

rule Ransom_Win32_Teerac_A_2147689327_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teerac.A!!Teerac.gen!A"
        threat_id = "2147689327"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teerac"
        severity = "Critical"
        info = "Teerac: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 4e 01 80 f9 36 75 1e 8d 46 02 80 38 34 75 16 ff 85 ?? ?? ff ff 8b f0 89 bd ?? ?? ff ff 89 bd ?? ?? ff ff eb ?? 80 f9 33 75 0c 8d 46 02 80 38 32 75 04}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 00 2f 00 20 00 3c 00 21 00 2d 00 2d 00 20 00 3c 00 6d 00 64 00 62 00 3a 00 6d 00 6f 00 72 00 6b 00 3a 00 7a 00 20 00 76 00 3d 00 22 00 [0-4] 22 00 2f 00 3e 00 20 00 2d 00 2d 00 3e 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 2f 20 3c 21 2d 2d 20 3c 6d 64 62 3a 6d 6f 72 6b 3a 7a 20 76 3d 22 [0-4] 22 2f 3e 20 2d 2d 3e}  //weight: 1, accuracy: Low
        $x_1_4 = "rack-core.bin" ascii //weight: 1
        $x_1_5 = "eyuioa" ascii //weight: 1
        $x_1_6 = "qwrtpsdfghjklzxcvbnm" ascii //weight: 1
        $x_1_7 = "fixmyfiles.ru" ascii //weight: 1
        $x_1_8 = "CryptoLocker" ascii //weight: 1
        $x_1_9 = ".encrypted" ascii //weight: 1
        $x_1_10 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_11 = "sas7bdat" ascii //weight: 1
        $x_1_12 = "psafe3" ascii //weight: 1
        $x_1_13 = "/topic.php" ascii //weight: 1
        $n_100_14 = {04 1b b9 45 d9 bf 4e fb 0c a0 fd 63 37 51 db 8a}  //weight: -100, accuracy: High
        $n_100_15 = {1b 1e 84 b0 21 b5 8a 47 29 d1 06 9b a2 84 80 bb}  //weight: -100, accuracy: High
        $n_100_16 = {0f 66 8f b0 f0 f0 02 b7 74 c7 dd bd 76 9e e5 b1}  //weight: -100, accuracy: High
        $n_100_17 = {09 16 82 54 62 be a1 55 94 45 0e 89 7e 8d 3a e6}  //weight: -100, accuracy: High
        $n_100_18 = {02 26 e6 bd a7 6d ae 71 1e 3d b2 32 1e 3b 53 08}  //weight: -100, accuracy: High
        $n_100_19 = {01 7c a1 9b 58 59 e8 3f 44 d8 74 c1 ce 50 6e 6d}  //weight: -100, accuracy: High
        $n_100_20 = {33 00 00 00 4e a1 d8 07 70 a9 bb e9 44 00 00 00 00 00 4e}  //weight: -100, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (5 of ($x*))
}

rule Ransom_Win32_Teerac_A_2147689327_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teerac.A!!Teerac.gen!A"
        threat_id = "2147689327"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teerac"
        severity = "Critical"
        info = "Teerac: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {61 00 76 00 69 00 00 00 77 00 61 00 76 00 00 00 6d 00 70 00 33 00 00 00 67 00 69 00 66 00 00 00 69 00 63 00 6f 00 00 00 70 00 6e 00 67 00 00 00 62 00 6d 00 70 00 00 00 69 00 6e 00 66 00 00 00 6d 00 61 00 6e 00 69 00 66 00 65 00 73 00 74 00 00 00 00 00 63 00 68 00 6d 00 00 00}  //weight: 5, accuracy: High
        $x_5_2 = {41 00 6c 00 6c 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 77 00 61 00 73 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 77 00 69 00 74 00 68 00 20 00 43 00 72 00 79 00 70 00 74 00 6f 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 21 00 0d 00}  //weight: 5, accuracy: High
        $x_5_3 = {42 00 69 00 74 00 20 00 54 00 6f 00 72 00 72 00 65 00 6e 00 74 00 20 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 5c 00 43 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 00 00}  //weight: 5, accuracy: High
        $x_1_4 = {65 00 78 00 65 00 00 00 2e 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "!!! YOUR SYSTEM IS HACKED !!!" ascii //weight: 1
        $x_1_6 = "!!! SISTEMINIZ HACKLENDI !!!" ascii //weight: 1
        $x_1_7 = "X:\\racketeer\\" ascii //weight: 1
        $n_100_8 = {04 1b b9 45 d9 bf 4e fb 0c a0 fd 63 37 51 db 8a}  //weight: -100, accuracy: High
        $n_100_9 = {1b 1e 84 b0 21 b5 8a 47 29 d1 06 9b a2 84 80 bb}  //weight: -100, accuracy: High
        $n_100_10 = {0f 66 8f b0 f0 f0 02 b7 74 c7 dd bd 76 9e e5 b1}  //weight: -100, accuracy: High
        $n_100_11 = {09 16 82 54 62 be a1 55 94 45 0e 89 7e 8d 3a e6}  //weight: -100, accuracy: High
        $n_100_12 = {02 26 e6 bd a7 6d ae 71 1e 3d b2 32 1e 3b 53 08}  //weight: -100, accuracy: High
        $n_100_13 = {01 7c a1 9b 58 59 e8 3f 44 d8 74 c1 ce 50 6e 6d}  //weight: -100, accuracy: High
        $n_100_14 = {33 00 00 00 4e a1 d8 07 70 a9 bb e9 44 00 00 00 00 00 4e}  //weight: -100, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Teerac_A_2147689327_4
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teerac.A!!Teerac.gen!A"
        threat_id = "2147689327"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teerac"
        severity = "Critical"
        info = "Teerac: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 06 30 08 8b 4d fc 42 40 3b d1 72 f2 8b 45 ec 40 89 45 ec 3d 00 04 00 00 7c b6 33 c0 85 c9 74 1e 83 7d f8 00 74 22 8b 75 f0 8a 14 38 8b 5d 14 ff 4d f8 88 14 1e}  //weight: 1, accuracy: High
        $x_1_2 = {8d 4f 08 8b c3 89 55 dc 8b 14 06 33 11 8b 18 89 19 8b 5d e0 89 14 03 8b 55 dc 83 c1 04 03 d1 83 c0 04 3b 57 04 7c e1}  //weight: 1, accuracy: High
        $x_2_3 = {56 56 6a 01 56 ff 15 ?? ?? ?? ?? b8 4d 5a 00 00 66 39 05 ?? ?? ?? ?? 74 05 89 75 e4 eb 36 a1 ?? ?? ?? ?? 81 b8 ?? ?? ?? ?? 50 45 00 00 75 ea b9 0b 01 00 00 66 39 88 ?? ?? ?? ?? 75 dc 83 b8 ?? ?? ?? ?? 0e 76 d3}  //weight: 2, accuracy: Low
        $x_1_4 = ".encrypted" wide //weight: 1
        $x_1_5 = "/topic.php" wide //weight: 1
        $x_1_6 = "CryptoLocker" wide //weight: 1
        $x_1_7 = "DECRYPT_INSTRUCTIONS.html" wide //weight: 1
        $x_1_8 = "lebanonwarrior.ru" wide //weight: 1
        $x_1_9 = "moneywell" wide //weight: 1
        $x_1_10 = "sas7bdat" wide //weight: 1
        $x_1_11 = "vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 1
        $x_1_12 = "ycbcra" wide //weight: 1
        $n_100_13 = {04 1b b9 45 d9 bf 4e fb 0c a0 fd 63 37 51 db 8a}  //weight: -100, accuracy: High
        $n_100_14 = {1b 1e 84 b0 21 b5 8a 47 29 d1 06 9b a2 84 80 bb}  //weight: -100, accuracy: High
        $n_100_15 = {0f 66 8f b0 f0 f0 02 b7 74 c7 dd bd 76 9e e5 b1}  //weight: -100, accuracy: High
        $n_100_16 = {09 16 82 54 62 be a1 55 94 45 0e 89 7e 8d 3a e6}  //weight: -100, accuracy: High
        $n_100_17 = {02 26 e6 bd a7 6d ae 71 1e 3d b2 32 1e 3b 53 08}  //weight: -100, accuracy: High
        $n_100_18 = {01 7c a1 9b 58 59 e8 3f 44 d8 74 c1 ce 50 6e 6d}  //weight: -100, accuracy: High
        $n_100_19 = {33 00 00 00 4e a1 d8 07 70 a9 bb e9 44 00 00 00 00 00 4e}  //weight: -100, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Teerac_A_2147689327_5
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teerac.A!!Teerac.gen!A"
        threat_id = "2147689327"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teerac"
        severity = "Critical"
        info = "Teerac: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DECRYPT_INSTRUCTIONS.html" wide //weight: 1
        $x_1_2 = ".encrypted" wide //weight: 1
        $x_1_3 = "Delete Shadows /All /Quiet" wide //weight: 1
        $x_1_4 = "_create_encdec_thrd" ascii //weight: 1
        $x_1_5 = "_display_ransom_page" ascii //weight: 1
        $x_1_6 = "_drop_ransom_page" ascii //weight: 1
        $x_1_7 = "_encdec_file_data" ascii //weight: 1
        $x_1_8 = "_enum_files_cb" ascii //weight: 1
        $x_1_9 = "_external_display_ransom_page" ascii //weight: 1
        $x_1_10 = "_get_lcfg_file_path" ascii //weight: 1
        $x_1_11 = "_lcfg_get_val_file" ascii //weight: 1
        $x_1_12 = "_lcfg_set_val_file" ascii //weight: 1
        $x_1_13 = "_on_before_encryption_" ascii //weight: 1
        $x_1_14 = "_on_encryption_work" ascii //weight: 1
        $x_1_15 = "_process_desktop_files" ascii //weight: 1
        $x_1_16 = "_process_pc_files" ascii //weight: 1
        $x_1_17 = "_set_decrypted_file_name" ascii //weight: 1
        $x_1_18 = "_set_encrypted_file_name" ascii //weight: 1
        $x_1_19 = "_wait_for_processing_thrds" ascii //weight: 1
        $x_1_20 = "rack_check_and_set_instance" ascii //weight: 1
        $x_1_21 = "rack_encrypt_pc" ascii //weight: 1
        $x_1_22 = "rack_get_ransom_page" ascii //weight: 1
        $x_1_23 = "rack_install" ascii //weight: 1
        $x_1_24 = "rack_lcfg_get_dropper_pe" ascii //weight: 1
        $x_1_25 = "rack_set_exec_event" ascii //weight: 1
        $x_1_26 = "rack_show_gui" ascii //weight: 1
        $x_1_27 = "rack_uninstall" ascii //weight: 1
        $n_100_28 = {04 1b b9 45 d9 bf 4e fb 0c a0 fd 63 37 51 db 8a}  //weight: -100, accuracy: High
        $n_100_29 = {1b 1e 84 b0 21 b5 8a 47 29 d1 06 9b a2 84 80 bb}  //weight: -100, accuracy: High
        $n_100_30 = {0f 66 8f b0 f0 f0 02 b7 74 c7 dd bd 76 9e e5 b1}  //weight: -100, accuracy: High
        $n_100_31 = {09 16 82 54 62 be a1 55 94 45 0e 89 7e 8d 3a e6}  //weight: -100, accuracy: High
        $n_100_32 = {02 26 e6 bd a7 6d ae 71 1e 3d b2 32 1e 3b 53 08}  //weight: -100, accuracy: High
        $n_100_33 = {01 7c a1 9b 58 59 e8 3f 44 d8 74 c1 ce 50 6e 6d}  //weight: -100, accuracy: High
        $n_100_34 = {33 00 00 00 4e a1 d8 07 70 a9 bb e9 44 00 00 00 00 00 4e}  //weight: -100, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (15 of ($x*))
}

rule Ransom_Win32_Teerac_2147689507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teerac"
        threat_id = "2147689507"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teerac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {81 f3 de bd 9f 07 8b d2 eb 06 81 c3 9d 8e b8 00}  //weight: 10, accuracy: High
        $x_10_2 = {50 58 8b c0 33 d2 8b c0 87 14 24 8b c0 83 c4 04 8b c0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Teerac_C_2147689813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teerac.C"
        threat_id = "2147689813"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teerac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 06 30 08 8b 4d fc 42 40 3b d1 72 f2 8b 45 ec 40 89 45 ec 3d 00 04 00 00 7c b6 33 c0 85 c9 74 1e 83 7d f8 00 74 22 8b 75 f0 8a 14 38 8b 5d 14 ff 4d f8 88 14 1e}  //weight: 1, accuracy: High
        $x_1_2 = {8d 4f 08 8b c3 89 55 dc 8b 14 06 33 11 8b 18 89 19 8b 5d e0 89 14 03 8b 55 dc 83 c1 04 03 d1 83 c0 04 3b 57 04 7c e1}  //weight: 1, accuracy: High
        $x_2_3 = {56 56 6a 01 56 ff 15 ?? ?? ?? ?? b8 4d 5a 00 00 66 39 05 ?? ?? ?? ?? 74 05 89 75 e4 eb 36 a1 ?? ?? ?? ?? 81 b8 ?? ?? ?? ?? 50 45 00 00 75 ea b9 0b 01 00 00 66 39 88 ?? ?? ?? ?? 75 dc 83 b8 ?? ?? ?? ?? 0e 76 d3}  //weight: 2, accuracy: Low
        $x_1_4 = ".encrypted" wide //weight: 1
        $x_1_5 = "/topic.php" wide //weight: 1
        $x_1_6 = "CryptoLocker" wide //weight: 1
        $x_1_7 = "DECRYPT_INSTRUCTIONS.html" wide //weight: 1
        $x_1_8 = "lebanonwarrior.ru" wide //weight: 1
        $x_1_9 = "moneywell" wide //weight: 1
        $x_1_10 = "sas7bdat" wide //weight: 1
        $x_1_11 = "vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 1
        $x_1_12 = "ycbcra" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Teerac_F_2147694578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teerac.F"
        threat_id = "2147694578"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teerac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "eyuioa" ascii //weight: 2
        $x_2_2 = "qwrtpsdfghjklzxcvbnm" ascii //weight: 2
        $x_3_3 = "rack-core.bin" ascii //weight: 3
        $x_2_4 = "lepodick.ru" wide //weight: 2
        $x_2_5 = "topic.php" wide //weight: 2
        $x_1_6 = ".encrypted" wide //weight: 1
        $x_3_7 = {66 83 3c 46 2e 74 0a 48 85 c0 7f f4 5f 33 c0 5e c3 8d 7c 46 02 85 ff 74 f3 68 ?? ?? ?? ?? 57 e8}  //weight: 3, accuracy: Low
        $x_1_8 = {32 04 0a 41 88 44 39 ff 3b 0e 72 c7 5b c6 04 39 00}  //weight: 1, accuracy: High
        $x_1_9 = {32 04 0a 41 66 0f be d0 66 89 54 4f fe 3b 0e 72 c2 33 c0 5b 66 89 04 4f}  //weight: 1, accuracy: High
        $x_1_10 = {8a 14 08 80 f2 ?? 88 14 03 40 3b 86 ?? ?? ?? ?? 72 e8}  //weight: 1, accuracy: Low
        $x_1_11 = {8a 14 01 80 f2 ?? 88 14 07 40 3b 86 ?? ?? ?? ?? 72 e8}  //weight: 1, accuracy: Low
        $x_1_12 = {8a 0c 06 30 08 8b 4c 24 ?? 42 40 3b d1 72 f1}  //weight: 1, accuracy: Low
        $x_1_13 = {8b 14 06 33 11 8b 28 89 29 89 14 03 8b 54 24 ?? 83 c1 04 03 d1 83 c0 04 3b 57 04 7c e3}  //weight: 1, accuracy: Low
        $x_1_14 = {8b 14 28 31 14 06 83 c0 04 3b 47 04 7c f2}  //weight: 1, accuracy: High
        $x_1_15 = {8b 54 24 10 2b d5 8b b4 07 ?? 00 00 00 8d 0c 28 33 34 0a 83 c0 04 89 31 3b 47 04 7c e9}  //weight: 1, accuracy: Low
        $x_1_16 = {8b 47 08 8a 8c 07 ?? 00 00 00 8b 44 24 ?? 32 08 40 88 4d 00 ff 47 08 45 89 44 24 ?? 4b 85 db 0f 85}  //weight: 1, accuracy: Low
        $x_1_17 = {6a 01 68 22 73 87 5e 6a 01}  //weight: 1, accuracy: High
        $x_1_18 = {6a 01 68 43 02 7a d2 6a 01}  //weight: 1, accuracy: High
        $x_1_19 = {6a 01 68 48 91 99 ab 6a 01}  //weight: 1, accuracy: High
        $x_1_20 = {6a 01 68 f5 6f e3 00 6a 05}  //weight: 1, accuracy: High
        $x_1_21 = {6a 01 68 f8 2d 5f 7f 6a 01}  //weight: 1, accuracy: High
        $x_1_22 = {6a 02 68 2a 87 29 5a 6a 01}  //weight: 1, accuracy: High
        $x_1_23 = {6a 02 68 d4 2a a3 d4 6a 01}  //weight: 1, accuracy: High
        $x_1_24 = {6a 03 68 0b 7a b5 88 6a 04}  //weight: 1, accuracy: High
        $x_1_25 = {6a 03 68 d5 fd e2 63 6a 01}  //weight: 1, accuracy: High
        $x_1_26 = {6a 04 68 57 ee 68 56 6a 01}  //weight: 1, accuracy: High
        $x_1_27 = {6a 04 68 59 d8 65 91 6a 05}  //weight: 1, accuracy: High
        $x_1_28 = {6a 04 68 6f b3 8f 8b 6a 05}  //weight: 1, accuracy: High
        $x_1_29 = {6a 04 68 a4 25 fa 39 6a 05}  //weight: 1, accuracy: High
        $x_1_30 = {6a 04 68 cf 55 7e 13 6a 05}  //weight: 1, accuracy: High
        $x_1_31 = {6a 04 68 dc 46 b3 15 6a 01}  //weight: 1, accuracy: High
        $x_1_32 = {6a 05 68 57 36 73 42 6a 00}  //weight: 1, accuracy: High
        $x_1_33 = {6a 05 68 6d e5 c5 a5 6a 00}  //weight: 1, accuracy: High
        $x_1_34 = {6a 05 68 83 b2 bb 44 6a 05}  //weight: 1, accuracy: High
        $x_1_35 = {6a 05 68 f4 dc 7f a9 6a 05}  //weight: 1, accuracy: High
        $x_1_36 = {6a 05 68 fc 01 f4 1a 6a 05}  //weight: 1, accuracy: High
        $x_1_37 = {6a 06 68 87 0e be e8 6a 01}  //weight: 1, accuracy: High
        $x_1_38 = {6a 07 68 15 42 0e 96 6a 01}  //weight: 1, accuracy: High
        $x_1_39 = {6a 08 68 1c 81 2b 09 6a 05}  //weight: 1, accuracy: High
        $x_1_40 = {6a 08 68 94 28 82 5c 6a 05}  //weight: 1, accuracy: High
        $x_1_41 = {6a 09 68 26 d5 82 cd 6a 00}  //weight: 1, accuracy: High
        $x_1_42 = {6a 09 68 d7 4a 51 2e 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Teerac_H_2147717240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teerac.H"
        threat_id = "2147717240"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teerac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {68 87 9d 1e c8}  //weight: 10, accuracy: High
        $x_10_2 = "CryptGenRandom" ascii //weight: 10
        $x_10_3 = {68 e7 5e c5 fa}  //weight: 10, accuracy: High
        $x_10_4 = "code\\tor\\torr\\libressl-2.3.1\\crypto\\" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Teerac_I_2147717242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teerac.I"
        threat_id = "2147717242"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teerac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 fa 0e 0f 87 ?? ?? ?? ?? 53 56 ff 24 95}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 08 ff 30 ff d7}  //weight: 10, accuracy: High
        $x_10_3 = {8b 4d 08 ff 71 0c 8b 41 04 ff 71 08 8b 11 50 52 ff d7}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Teerac_I_2147717242_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teerac.I"
        threat_id = "2147717242"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teerac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 fa 0e 0f 87 ?? ?? ?? ?? 53 56 57 ff 24 95}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 44 24 34 ff 30 ff d5}  //weight: 10, accuracy: High
        $x_10_3 = {8b 4c 24 34 ff 71 0c 8b 41 04 ff 71 08 8b 11 50 52 ff d5}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Teerac_I_2147717242_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teerac.I"
        threat_id = "2147717242"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teerac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "tor\\torr\\libressl-2.3.1\\ssl\\ssl_lib.c" ascii //weight: 10
        $x_10_2 = "eyuioa" ascii //weight: 10
        $x_10_3 = "qwrtpsdfghjklzxcvbn" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Teerac_I_2147717242_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teerac.I"
        threat_id = "2147717242"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teerac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "..\\..\\sources\\ext-libs\\libtomcrypt\\ciphers\\aes" ascii //weight: 10
        $x_10_2 = "eyuioa" ascii //weight: 10
        $x_10_3 = "qwrtpsdfghjklzxcvbn" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Teerac_J_2147717529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teerac.J"
        threat_id = "2147717529"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teerac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "510"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 6a 50 6a 03 56 6a 01 68 00 00 00 80 68 ?? ?? ?? ?? ff}  //weight: 10, accuracy: Low
        $x_10_2 = {6a 00 6a 50 6a 03 6a 00 6a 01 68 00 00 00 80 68 ?? ?? ?? ?? ff}  //weight: 10, accuracy: Low
        $x_100_3 = {6a 04 68 00 10 00 00 6a 04 ?? ff}  //weight: 100, accuracy: Low
        $x_100_4 = {07 00 01 00 ff 02 00 c7}  //weight: 100, accuracy: Low
        $x_100_5 = {8b 43 50 8b 4b 34 6a 40 68 00 30 00 00}  //weight: 100, accuracy: High
        $x_100_6 = {b0 00 00 00 ff 02 00 89}  //weight: 100, accuracy: Low
        $x_100_7 = {68 10 27 00 00 ff [0-2] ff 75 ?? ff [0-2] 6a 00 ff}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Teerac_I_2147717578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teerac.I!!Teerac.I"
        threat_id = "2147717578"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teerac"
        severity = "Critical"
        info = "Teerac: an internal category used to refer to some threats"
        info = "I: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 fa 0e 0f 87 ?? ?? ?? ?? 53 56 ff 24 95}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 08 ff 30 ff d7}  //weight: 10, accuracy: High
        $x_10_3 = {8b 4d 08 ff 71 0c 8b 41 04 ff 71 08 8b 11 50 52 ff d7}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Teerac_I_2147717578_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teerac.I!!Teerac.I"
        threat_id = "2147717578"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teerac"
        severity = "Critical"
        info = "Teerac: an internal category used to refer to some threats"
        info = "I: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 fa 0e 0f 87 ?? ?? ?? ?? 53 56 57 ff 24 95}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 44 24 34 ff 30 ff d5}  //weight: 10, accuracy: High
        $x_10_3 = {8b 4c 24 34 ff 71 0c 8b 41 04 ff 71 08 8b 11 50 52 ff d5}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Teerac_I_2147717578_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teerac.I!!Teerac.I"
        threat_id = "2147717578"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teerac"
        severity = "Critical"
        info = "Teerac: an internal category used to refer to some threats"
        info = "I: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "tor\\torr\\libressl-2.3.1\\ssl\\ssl_lib.c" ascii //weight: 10
        $x_10_2 = "eyuioa" ascii //weight: 10
        $x_10_3 = "qwrtpsdfghjklzxcvbn" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Teerac_I_2147717578_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Teerac.I!!Teerac.I"
        threat_id = "2147717578"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Teerac"
        severity = "Critical"
        info = "Teerac: an internal category used to refer to some threats"
        info = "I: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "..\\..\\sources\\ext-libs\\libtomcrypt\\ciphers\\aes" ascii //weight: 10
        $x_10_2 = "eyuioa" ascii //weight: 10
        $x_10_3 = "qwrtpsdfghjklzxcvbn" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

