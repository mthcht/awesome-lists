rule Ransom_Win32_Reveton_A_2147651658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Reveton.A"
        threat_id = "2147651658"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Reveton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {64 ff 30 64 89 20 83 eb 01 72 07 74 0e 4b 74 22 eb 43 55 e8}  //weight: 5, accuracy: High
        $x_5_2 = {74 44 c7 04 24 28 01 00 00 8b d4 8b c3 e8}  //weight: 5, accuracy: High
        $x_1_3 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 00}  //weight: 1, accuracy: High
        $x_1_4 = {4e 4f 54 45 56 45 52 00}  //weight: 1, accuracy: High
        $x_1_5 = {48 4e 61 76 69 67 61 74 65 32 00}  //weight: 1, accuracy: High
        $x_1_6 = {49 45 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {2c 58 31 31 00}  //weight: 1, accuracy: High
        $x_1_8 = {2c 53 75 70 70 53 00}  //weight: 1, accuracy: High
        $x_2_9 = {c7 45 a0 44 00 00 00 89 5d dc c7 45 cc 01 01 00 00 66 c7 45 d0 00 00 8d 45 90 50 8d 45 a0}  //weight: 2, accuracy: High
        $x_2_10 = {31 32 33 32 31 33 31 32 30 32 30 2e 74 6d 70 00}  //weight: 2, accuracy: High
        $x_1_11 = {2c 53 74 61 72 74 41 73 00}  //weight: 1, accuracy: High
        $x_1_12 = {4e 6f 50 72 6f 74 65 63 74 65 64 4d 6f 64 65 42 61 6e 6e 65 72 2a 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e}  //weight: 1, accuracy: Low
        $x_1_13 = {58 32 31 33 31 39 32 33 00}  //weight: 1, accuracy: High
        $x_1_14 = {43 48 52 4f 4d 45 2e 45 58 45 [0-16] 49 45 58 50 4c 4f 52 45 2e 45 58 45 [0-16] 4f 50 45 52 41 2e 45 58 45 [0-16] 46 49 52 45 46 4f 58 2e 45 58 45 [0-16] 53 41 46 41 52 49 2e 45 58 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 9 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Reveton_B_2147653665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Reveton.B"
        threat_id = "2147653665"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Reveton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 45 f8 50 6a 00 6a 00 68 94 80 40 00 6a 00 6a 00 e8 ed ba ff ff eb 3c 8b 43 0c}  //weight: 2, accuracy: High
        $x_2_2 = {83 f8 28 0f 87 44 03 00 00 ff 24 85 f1 67 40 00}  //weight: 2, accuracy: High
        $x_1_3 = {2e 74 6d 70 2c 58 35 30 00}  //weight: 1, accuracy: High
        $x_1_4 = {63 74 66 6d 6f 6e 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = {25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 63 74 66 6d 6f 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 52 75 6e 5c 63 74 66 6d 6f 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {5c 53 45 4e 53 5c 50 61 72 61 6d 65 74 65 72 73 5c 53 65 72 76 69 63 65 44 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_8 = {53 4f 46 54 57 41 52 45 5c 4c 49 44 00}  //weight: 1, accuracy: High
        $x_1_9 = {53 75 6e 63 68 20 49 4f 4b 00}  //weight: 1, accuracy: High
        $x_1_10 = {53 65 6e 64 20 52 65 63 76 20 43 6f 6d 70 6c 69 74 65 00}  //weight: 1, accuracy: High
        $x_1_11 = {46 30 30 30 38 38 38 0d 47 65 74 20 53 4d 20 4b 65 79 20 2d 20}  //weight: 1, accuracy: High
        $x_1_12 = "SBrowser - " ascii //weight: 1
        $x_1_13 = "Starter OK Name: " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_1_*))) or
            ((1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_2_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Reveton_D_2147654461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Reveton.D"
        threat_id = "2147654461"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Reveton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 68 38 01 00 00 8d 85 ac fe ff ff 50 53 e8 ?? ?? ?? ?? 40 0f 84 ?? ?? ?? ?? 6a 00 68 00 01 00 00 8d 85 ac fd ff ff 50 53 e8 ?? ?? ?? ?? 3d 00 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "CurrentControlSet\\Services\\SENS\\Parameters\\ServiceDll" ascii //weight: 1
        $x_1_3 = "CurrentVersion\\Explorer\\Shell Folders\\Startup" ascii //weight: 1
        $x_1_4 = "CurrentVersion\\Explorer\\Shell Folders\\Common AppData" ascii //weight: 1
        $x_1_5 = "Windows\\CurrentVersion\\Run\\ctfmon.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Reveton_F_2147658474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Reveton.F"
        threat_id = "2147658474"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Reveton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = "NoProtectedModeBanner" ascii //weight: 1
        $x_3_3 = {46 69 6c 65 4d 65 6d 2e 64 6c 6c 00 [0-3] 64 65 66 61 75 6c 74}  //weight: 3, accuracy: Low
        $x_2_4 = {00 4c 6f 63 6b 2e 64 6c 6c}  //weight: 2, accuracy: High
        $x_3_5 = {8b ce ba 01 00 00 00 d3 e2 4a 23 54 24 28 0f b7 4c 24 42 03 d1 8b 4c 24 34 8b 14 91 89 54 24 40 e9 ?? ?? ff ff 8b 04 24 c7 40 18 ?? ?? ?? ?? 8b 44 24 04 c7 00 12 00 00 00 eb ?? f7 c6 40 00 00 00 75 ?? 8b ce ba 01 00 00 00 d3 e2 4a 23 54 24 28 0f b7 44 24 42 03 d0 8b 4c 24 30 8b 14 91 89 54 24 40}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Reveton_A_2147661406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Reveton.gen!A"
        threat_id = "2147661406"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Reveton"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = "NoProtectedModeBanner" ascii //weight: 1
        $x_3_3 = {46 69 6c 65 4d 65 6d 2e 64 6c 6c 00 [0-3] 64 65 66 61 75 6c 74}  //weight: 3, accuracy: Low
        $x_2_4 = {00 4c 6f 63 6b 2e 64 6c 6c}  //weight: 2, accuracy: High
        $x_5_5 = {8b ce ba 01 00 00 00 d3 e2 4a 23 54 24 28 0f b7 4c 24 42 03 d1 8b 4c 24 34 8b 14 91 89 54 24 40 e9 ?? ?? ff ff 8b 04 24 c7 40 18 ?? ?? ?? ?? 8b 44 24 04 c7 00 12 00 00 00 eb ?? f7 c6 40 00 00 00 75 ?? 8b ce ba 01 00 00 00 d3 e2 4a 23 54 24 28 0f b7 44 24 42 03 d0 8b 4c 24 30 8b 14 91 89 54 24 40}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Reveton_N_2147670681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Reveton.N"
        threat_id = "2147670681"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Reveton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {64 8b 05 30 00 00 00 8b 40 0c 8b 40 0c 8b 00 3b 70 18 75 f9 8b 30 8b 58 04 89 33 8b 70 04 8b 18 89 73 04 8d 40 08 8b 30 8b 58 04 89 33 8b 70 04 8b 18 89 73 04}  //weight: 10, accuracy: High
        $x_1_2 = "JimmMonsterNew\\ServerWinlock" ascii //weight: 1
        $x_1_3 = {72 75 6e 63 74 66 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 4c 6f 63 6b 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_5 = {43 6f 75 6e 74 72 79 3a ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 43 69 74 79 3a ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 49 50 3a}  //weight: 1, accuracy: Low
        $x_1_6 = "CurrentVersion\\Winlogon\\Shell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Reveton_O_2147670728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Reveton.O"
        threat_id = "2147670728"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Reveton"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 00 61 00 63 00 72 00 6f 00 6d 00 65 00 64 00 69 00 61 00 5c 00 46 00 6c 00 61 00 73 00 68 00 20 00 50 00 6c 00 61 00 79 00 65 00 72 00 5c 00 6d 00 61 00 63 00 72 00 6f 00 6d 00 65 00 64 00 69 00 61 00 2e 00 63 00 6f 00 6d 00 5c 00 73 00 75 00 70 00 70 00 6f 00 72 00 74 00 5c 00 66 00 6c 00 61 00 73 00 68 00 70 00 6c 00 61 00 79 00 65 00 72 00 5c 00 73 00 79 00 73 00 5c 00 00 00 73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 2e 00 73 00 6f 00 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = "http://%s/usa/index.php" wide //weight: 1
        $x_1_3 = "DisableTaskMgr" wide //weight: 1
        $x_1_4 = "DisableRegistryTools" wide //weight: 1
        $x_1_5 = {75 75 69 64 3d 90 1e 09 00 26 6f 73 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = {8b 4e 2c 8b 51 04 33 c0 89 44 32 28 8b 4e 2c 8b 51 08 89 44 32 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_Reveton_Q_2147678731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Reveton.Q"
        threat_id = "2147678731"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Reveton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 93 00 05 00 00 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8a 93 00 06 00 00 88 10 a1 ?? ?? ?? ?? 8a 93 01 06 00 00 88 10 a1 ?? ?? ?? ?? 8b 93 02 06 00 00 89 10}  //weight: 2, accuracy: Low
        $x_1_2 = "FBI - Computer locked." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Reveton_R_2147680129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Reveton.R"
        threat_id = "2147680129"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Reveton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {64 8b 05 30 00 00 00 8b 40 0c 8b 40 0c 8b 00 3b 70 18 75 f9 8b 30 8b 58 04 89 33 8b 70 04 8b 18 89 73 04 8d 40 08 8b 30 8b 58 04 89 33 8b 70 04 8b 18 89 73 04}  //weight: 10, accuracy: High
        $x_1_2 = {52 55 4e 44 4c 4c 33 32 2e 45 58 45 00 00 00 00 ff ff ff ff 0c 00 00 00 6d 73 63 6f 6e 66 69 67 2e 6c 6e 6b}  //weight: 1, accuracy: High
        $x_1_3 = {9a 02 00 00 6a 00 6a 04 8d 45 ?? 50 53 e8 ?? ?? ?? ?? 40 0f 84 03 00 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Reveton_T_2147681923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Reveton.T"
        threat_id = "2147681923"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Reveton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {64 8b 05 30 00 00 00 8b 40 0c 8b 40 0c 8b 00 3b 70 18 75 f9 8b 30 8b 58 04 89 33 8b 70 04 8b 18 89 73 04 8d 40 08 8b 30 8b 58 04 89 33 8b 70 04 8b 18 89 73 04}  //weight: 10, accuracy: High
        $x_1_2 = {52 55 4e 44 4c 4c 33 32 2e 45 58 45 00 00 00 00 ff ff ff ff 0d 00 00 00 72 65 67 6d 6f 6e 73 74 64 2e 6c 6e 6b}  //weight: 1, accuracy: High
        $x_1_3 = {9a 02 00 00 6a 00 6a 04 8d 45 ?? 50 53 e8 ?? ?? ?? ?? 40 0f 84 03 00 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Reveton_U_2147682478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Reveton.U"
        threat_id = "2147682478"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Reveton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 b8 7e 2a 00 00 00 0f 85 ?? ?? 00 00 8d 95 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 80 e4 2a 00 00 e8 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 66 ba 50 00}  //weight: 1, accuracy: Low
        $x_1_2 = {9a 02 00 00 6a 00 6a 04 8d 45 ?? 50 53 e8 ?? ?? ?? ?? 40 0f 84 03 00 c7}  //weight: 1, accuracy: Low
        $x_1_3 = "impmtcngt,amo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Reveton_V_2147682535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Reveton.V"
        threat_id = "2147682535"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Reveton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "106"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {8b 55 fc 0f b6 54 1a ff 66 81 f2 9a 02 88 54 18 ff 43 4e 75 e3}  //weight: 50, accuracy: High
        $x_50_2 = "My Own Capture Window" ascii //weight: 50
        $x_1_3 = {8d 93 00 01 00 00 e8 ?? ?? ?? ?? 8b 45 f0 8d 55 f4 e8 ?? ?? ?? ?? 8b 55 f4 8d 83 00 01 00 00 b9 ff 00 00 00 e8 ?? ?? ?? ?? 8d 45 e8 8d 93 00 11 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 83 00 01 00 00 b9 ff 00 00 00 e8 ?? ?? ?? ?? 8d 45 ?? 8d 93 00 02 00 00 e8 ?? ?? ?? ?? 8b 45 ?? 8d 55 ?? e8 ?? ?? ?? ?? 8b 55 ?? 8d 83 00 02 00 00}  //weight: 1, accuracy: Low
        $x_5_5 = {b9 38 2d 00 00 8b 45 f4 e8 ?? ?? ?? ?? 8b c3 e8 ?? ?? ?? ?? c6 45 ?? 01}  //weight: 5, accuracy: Low
        $x_5_6 = {b9 78 0e 00 00 8b 45 f4 e8 ?? ?? ?? ?? 8b c3 e8 ?? ?? ?? ?? c6 45 ?? 01 eb}  //weight: 5, accuracy: Low
        $x_5_7 = {b9 38 31 00 00 8b 45 f4 e8 ?? ?? ?? ?? 8b c3 e8 ?? ?? ?? ?? c6 45 ?? 01}  //weight: 5, accuracy: Low
        $x_5_8 = {b9 38 36 00 00 8b 45 f4 e8 ?? ?? ?? ?? 8b c3 e8 ?? ?? ?? ?? c6 45 ?? 01}  //weight: 5, accuracy: Low
        $x_5_9 = {b9 38 36 00 00 8b 45 f4 e8 ?? ?? ?? ?? 33 c9 33 d2 8b 45 f4 8b 18 ff 53 10}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_50_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Reveton_W_2147682811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Reveton.W"
        threat_id = "2147682811"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Reveton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {64 8b 05 30 00 00 00 8b 40 0c 8b 40 0c 8b 00 3b 70 18 75 f9 8b 30 8b 58 04 89 33 8b 70 04 8b 18 89 73 04 8d 40 08 8b 30 8b 58 04 89 33 8b 70 04 8b 18 89 73 04}  //weight: 10, accuracy: High
        $x_1_2 = {4c 4e 4b 20 53 74 61 72 74 00 00 00 ff ff ff ff 05 00 00 00 4f 4b 4c 30 31}  //weight: 1, accuracy: High
        $x_1_3 = {9a 02 00 00 6a 00 6a 04 8d 45 ?? 50 53 e8 ?? ?? ?? ?? 40 0f 84 03 00 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Reveton_X_2147683053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Reveton.X"
        threat_id = "2147683053"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Reveton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 fc 0f b6 54 1a ff 66 81 f2 9a 02 88 54 18 ff 43 4e 75 e3}  //weight: 10, accuracy: High
        $x_1_2 = "GL300 Function Start Complite" ascii //weight: 1
        $x_1_3 = {47 4c 33 30 30 00 00 00 ff ff ff ff 16 00 00 00 5c 73 79 73 74 65 6d 33 32 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65}  //weight: 1, accuracy: High
        $x_10_4 = {9a 02 00 00 6a 00 6a 04 8d 45 ?? 50 53 e8 ?? ?? ?? ?? 40 0f 84 03 00 c7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Reveton_Y_2147683615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Reveton.Y"
        threat_id = "2147683615"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Reveton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 fc 0f b6 54 1a ff 66 81 f2 9a 02 88 54 18 ff 43 4e 75 e3}  //weight: 10, accuracy: High
        $x_1_2 = "GL300 Function Start Complite" ascii //weight: 1
        $x_1_3 = {47 4c 33 30 30 00 00 00 ff ff ff ff 16 00 00 00 5c 73 79 73 74 65 6d 33 32 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = {58 4c 32 30 30 20 46 75 6e 63 74 69 6f 6e 20 53 74 61 72 74 20 43 6f 6d 70 6c 69 74 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {46 46 5a 31 20 46 75 6e 63 74 69 6f 6e 20 4c 6f 63 6b 20 53 74 61 72 74 20 43 6f 6d 70 6c 69 74 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {43 43 5a 31 20 46 75 6e 63 74 69 6f 6e 20 4c 6f 63 6b 20 53 74 61 72 74 20 43 6f 6d 70 6c 69 74 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {53 74 61 72 74 20 44 69 63 6f 6d 70 72 65 73 73 20 54 6f 20 4c 6f 61 64 6c 69 62 00}  //weight: 1, accuracy: High
        $x_1_8 = "Lock DLL Download" ascii //weight: 1
        $x_1_9 = "X:\\PGP\\Programming\\JimmMonsterNew\\ServerWinlock\\" ascii //weight: 1
        $x_10_10 = {2c 01 00 00 6a 00 6a 04 8d 45 ?? 50 53 e8 ?? ?? ?? ?? 40 0f 84 03 00 c7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Reveton_AA_2147686451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Reveton.AA"
        threat_id = "2147686451"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Reveton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 fc 0f b6 54 1a ff 66 81 f2 9a 02 88 54 18 ff 43 4e 75 e3}  //weight: 10, accuracy: High
        $x_1_2 = {64 65 66 61 75 6c 74 58 31 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 73 79 73 74 65 6d 33 32 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_10_3 = {a7 02 00 00 6a 00 6a 04 8d 45 ?? 50 53 e8 ?? ?? ?? ?? 40 0f 84 03 00 c7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Reveton_Z_2147687976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Reveton.Z"
        threat_id = "2147687976"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Reveton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 fc 0f b6 54 1a ff 66 81 f2 9a 02 88 54 18 ff 43 4e 75 e3}  //weight: 10, accuracy: High
        $x_1_2 = {57 41 4c 4c 45 54 2e 44 41 54 00 00 ff ff ff ff 09 00 00 00 42 4c 41 43 4b 43 4f 49 4e}  //weight: 1, accuracy: High
        $x_10_3 = {2c 01 00 00 6a 00 6a 04 8d 45 ?? 50 53 e8 ?? ?? ?? ?? 40 0f 84 03 00 c7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Reveton_AB_2147690279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Reveton.AB"
        threat_id = "2147690279"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Reveton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 fc 0f b6 54 1a ff 66 81 f2 9a 02 88 54 18 ff 43 4e 75 e3}  //weight: 10, accuracy: High
        $x_1_2 = {cc d3 c8 ce cf db d6 00 ff}  //weight: 1, accuracy: High
        $x_10_3 = {a7 02 00 00 6a 00 6a 04 8d 45 ?? 50 53 e8 ?? ?? ?? ?? 40 0f 84 03 00 c7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Reveton_EM_2147794959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Reveton.EM!MTB"
        threat_id = "2147794959"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Reveton"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2b 55 e0 8a 1e 8b 75 e8 8d 7e 01 89 7d e8 88 1e 8b 75 e4 01 ce 89 55 e0 89 75 e4 8b 55 e4 f7 5d c8}  //weight: 10, accuracy: High
        $x_10_2 = {2b 85 50 ff ff ff 8b 8d 58 ff ff ff 01 f1 20 9d 3b ff ff ff 89 8d 58 ff ff ff 31 c9 2b 8d 40 ff ff ff 89 85 50 ff ff ff 89 8d 40 ff ff ff 8b 85 58 ff ff ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

