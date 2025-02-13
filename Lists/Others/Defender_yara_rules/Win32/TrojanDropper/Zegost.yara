rule TrojanDropper_Win32_Zegost_B_2147635820_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zegost.B"
        threat_id = "2147635820"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "mIcRoSoFt\\wINDoWS nt\\currentVerSioN\\sVChoST" ascii //weight: 2
        $x_2_2 = "%sot%%\\System32\\svc%s %s%s%s" ascii //weight: 2
        $x_2_3 = "k- exe.tsoh" ascii //weight: 2
        $x_1_4 = "reMOTeReGIScrY" ascii //weight: 1
        $x_1_5 = "ik\\labolGs%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Zegost_B_2147635820_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zegost.B"
        threat_id = "2147635820"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {e8 00 00 00 00 5d 81 ed ?? ?? ?? ?? bb ?? ?? ?? ?? 03 dd b9 ?? ?? ?? ?? ?? 80 33 [0-1] 43 e2}  //weight: 2, accuracy: Low
        $x_2_2 = "jehmTimhystehGetS" ascii //weight: 2
        $x_2_3 = {83 c4 0c c6 45 ?? 47 c6 45 ?? 6f c6 45 ?? 62 c6 45 ?? 61 c6 45 ?? 5c c6 45 ?? 6b c6 45 ?? 69}  //weight: 2, accuracy: Low
        $x_1_4 = "k- exe.tsoh" ascii //weight: 1
        $x_1_5 = "ik\\labolGs%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Zegost_B_2147635820_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zegost.B"
        threat_id = "2147635820"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PROFILE%\\Application Data\\" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\mIcRoSoFt\\wINDoWS nt\\currentVerSioN\\sVChoST" ascii //weight: 1
        $x_3_3 = ".3322.org" ascii //weight: 3
        $x_2_4 = "k- exe.tsoh" ascii //weight: 2
        $x_3_5 = "%sot%%\\System32\\svc%s %s%s%s" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Zegost_B_2147635820_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zegost.B"
        threat_id = "2147635820"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 d2 8a 11 8b 45 fc 25 ff 00 00 00 33 d0 8b 4d ?? 88 11}  //weight: 5, accuracy: Low
        $x_5_2 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 7d 16 6a 7a 6a 62 e8 ?? ?? ?? ?? 83 c4 08 8b 55 08 03 55 fc 88 02 eb d9}  //weight: 5, accuracy: Low
        $x_1_3 = "PROFILE%\\Application Data\\" ascii //weight: 1
        $x_1_4 = ".3322.org" ascii //weight: 1
        $x_1_5 = "k- exe.tsoh" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\mIcRoSoFt\\wINDoWS nt\\currentVerSioN\\sVChoST" ascii //weight: 1
        $x_1_7 = "%sot%%\\System32\\svc%s %s%s%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Zegost_G_2147642343_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zegost.G"
        threat_id = "2147642343"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 75 63 6b 59 6f 75 [0-16] 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74 [0-16] 46 75 63 6b 59 6f 75}  //weight: 2, accuracy: Low
        $x_1_2 = "taskkill /f /t /im ZhuDongFangYu.exe" ascii //weight: 1
        $x_1_3 = {80 04 11 7a 03 ca 8b ?? ?? 80 34 11 19 03 ca 42 3b ?? 7c}  //weight: 1, accuracy: Low
        $x_1_4 = {25 73 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 4c 6f 63 61 6c 20 53 65 72 76 65 72 [0-16] 57 69 6e 64 73}  //weight: 1, accuracy: Low
        $x_1_5 = {8a 14 01 80 c2 7a 80 f2 19 88 14 01 41 3b ce}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Zegost_G_2147642343_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zegost.G"
        threat_id = "2147642343"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 3f 00 0f 00 8d 4d ?? 6a 00 ?? 68 02 00 00 80 c6 45 ?? 4f c6 45 ?? 46 c6 45 ?? 54 c6 45 ?? 57 c6 45 ?? 41 c6 45 ?? 52 c6 45 ?? 45 c6 45 ?? 33 c6 45 ?? 36}  //weight: 5, accuracy: Low
        $x_4_2 = {53 50 ff 75 ?? c6 45 ?? 6e c6 45 ?? 65 c6 45 ?? 74 c6 45 ?? 73 c6 45 ?? 76 c6 45 ?? 63 c6 45 ?? 73 88 5d ?? ff 15}  //weight: 4, accuracy: Low
        $x_1_3 = "%ProgramFiles%\\Google\\" ascii //weight: 1
        $x_1_4 = "%s\\%d_res.tmp" ascii //weight: 1
        $x_1_5 = "netsvcs_0x%d" ascii //weight: 1
        $x_1_6 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" ascii //weight: 1
        $x_2_7 = "C:\\svchest%i%i%i.Zip" ascii //weight: 2
        $x_1_8 = "%s%d_res.tmp" wide //weight: 1
        $x_2_9 = "%s\\%sex.dll" ascii //weight: 2
        $x_3_10 = {53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 25 00 73 00 00 00 00 00 25 00 73 00 5c 00 69 00 65 00 73 00 65 00 76 00 65 00 72 00 5f 00 78 00 78 00 00 00 25 00 73 00 5c 00 55 00 70 00 64 00 61 00 74 00 65 00}  //weight: 3, accuracy: High
        $x_1_11 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ascii //weight: 1
        $x_3_12 = {6a 02 6a 00 68 00 fc ff ff 56 ff 15 ?? ?? ?? ?? 68 00 04 00 00 e8}  //weight: 3, accuracy: Low
        $x_1_13 = "%s\\%s32.dll" ascii //weight: 1
        $x_3_14 = {68 02 00 00 80 c7 45 ?? 20 01 00 00 c6 45 ?? 54 c6 45 ?? 79 c6 45 ?? 70 c6 45 ?? 65 c6 45 ?? 00 e8}  //weight: 3, accuracy: Low
        $x_2_15 = {00 80 b8 7f 75 ?? 8b 44 24 ?? 85 c0 75}  //weight: 2, accuracy: Low
        $x_2_16 = {00 08 f5 7f 75 ?? 8b 44 24 ?? 85 c0 75}  //weight: 2, accuracy: Low
        $x_2_17 = {6a 00 50 c6 44 24 ?? 73 c6 44 24 ?? 74 c6 44 24 ?? 61 c6 44 24 ?? 6c c6 44 24 ?? 6c c6 44 24 ?? 4d c6 44 24 ?? 6f c6 44 24 ?? 64 c6 44 24 ?? 75 c6 44 24 ?? 6c 88 5c 24}  //weight: 2, accuracy: Low
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
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Zegost_E_2147647764_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zegost.E"
        threat_id = "2147647764"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {57 68 00 00 40 06 c7 44 24 14 00 00 00 00 c7 44 24 28 00 00 40 06 e8 ?? ?? ?? ?? 8b 4c 24 28 8b f0 8b d1 33 c0 8b fe 53 c1 e9 02 f3 ab 8b ca}  //weight: 4, accuracy: Low
        $x_4_2 = {8b c8 81 e1 01 00 00 80 79 ?? 49 83 c9 fe 41 8a 0c 30 74 ?? 80 c1 0d eb ?? 80 c1 fe 88 0c 30 8b 4c 24 20 40 3b c1}  //weight: 4, accuracy: Low
        $x_4_3 = {8d 7c 24 6c 83 c9 ff 33 c0 8d 94 24 ac 00 00 00 f2 ae f7 d1 2b f9 8b c1 8b f7 8b fa c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 ff d3}  //weight: 4, accuracy: High
        $x_1_4 = ".jpg" ascii //weight: 1
        $x_1_5 = "iamsleeping" ascii //weight: 1
        $x_1_6 = "lknxotd" ascii //weight: 1
        $x_1_7 = "Fdr138ip2" ascii //weight: 1
        $x_1_8 = "sgfdfds58r" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Zegost_F_2147648834_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zegost.F"
        threat_id = "2147648834"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {b9 41 00 00 00 33 c0 8d bd ?? ?? ff ff 88 45 ?? f3 ab 8d 8d ?? ?? ff ff 56 8d 55 ?? 51 8d 85 ?? ?? ff ff 52 50 c6 45 ?? 25 88 5d ?? c6 45 ?? 5c c6 45 ?? 25 88 5d ?? c6 45 ?? 65 c6 45 ?? 78 c6 45 ?? 2e c6 45 ?? 64 c6 45 ?? 6c c6 45 ?? 6c e8}  //weight: 5, accuracy: Low
        $x_2_2 = {00 80 b8 7f 75 ?? 8b 44 24 ?? 85 c0 75}  //weight: 2, accuracy: Low
        $x_2_3 = {00 08 f5 7f 75 ?? 8b 44 24 ?? 85 c0 75}  //weight: 2, accuracy: Low
        $x_2_4 = {68 02 00 00 80 c7 45 ?? 20 01 00 00 c6 45 ?? 54 c6 45 ?? 79 c6 45 ?? 70 c6 45 ?? 65 c6 45 ?? 00 e8}  //weight: 2, accuracy: Low
        $x_1_5 = "rtg43ws" ascii //weight: 1
        $x_1_6 = "Windows Event Engine" ascii //weight: 1
        $x_1_7 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 00 00 00 00 6e 65 74 73 76 63 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Zegost_H_2147648836_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zegost.H"
        threat_id = "2147648836"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6a 02 6a 00 68 00 fc ff ff 56 ff 15 ?? ?? ?? ?? 68 00 04 00 00 e8}  //weight: 3, accuracy: Low
        $x_2_2 = "netsvcs_0x%d" ascii //weight: 2
        $x_1_3 = "%s\\%d_ttt.tmp" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ascii //weight: 1
        $x_1_5 = "RsTray.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Zegost_L_2147651882_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zegost.L"
        threat_id = "2147651882"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c0 b1 11 8a 90 ?? ?? ?? ?? 32 d1 88 90 ?? ?? ?? ?? 40 3d 00 ?? 02 00 7c ea}  //weight: 5, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ascii //weight: 1
        $x_1_3 = "\\Parameters" ascii //weight: 1
        $x_1_4 = "cmd.exe /c rundll32.exe %s hi" ascii //weight: 1
        $x_1_5 = "InstallModule" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Zegost_M_2147652897_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zegost.M"
        threat_id = "2147652897"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {47 68 30 73 74 20 55 70 64 61 74 65 00}  //weight: 2, accuracy: High
        $x_1_2 = {6e 65 74 73 76 63 73 5f 30 78 25 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 50 41 44 [0-7] 44 4c 4c 00 42 49 4e 00 53 65 72 76 69 63 65}  //weight: 1, accuracy: Low
        $x_1_4 = {43 72 65 61 74 65 53 65 72 76 69 63 65 28 50 61 72 61 6d 65 74 65 72 73 29 [0-7] 25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73}  //weight: 1, accuracy: Low
        $x_2_5 = {68 ff 01 0f 00 ?? ?? 53 [0-3] ff 15 ?? ?? ?? ?? 8b d8 3b ?? 89 5d ?? 75 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Zegost_Q_2147655621_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zegost.Q"
        threat_id = "2147655621"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 00}  //weight: 1, accuracy: High
        $x_1_2 = {22 25 73 22 20 61 62 6f 75 74 3a 62 6c 61 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_3 = "Storm ddos Server" ascii //weight: 1
        $x_1_4 = {b9 00 08 00 00 33 c0 8d bc 24 ?? ?? 00 00 50 f3 ab 8b 83 ?? 00 00 00 8d 94 24 ?? ?? 00 00 68 00 20 00 00 52 50 ff d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Zegost_R_2147657540_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zegost.R"
        threat_id = "2147657540"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 65 72 76 65 72 2e 44 61 74 00 48 61 69 00}  //weight: 1, accuracy: High
        $x_1_2 = {32 d3 02 d3 88}  //weight: 1, accuracy: High
        $x_1_3 = {2b c8 8a 14 01 8a 18 32 da 88 18 40 4e 75 f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Zegost_T_2147661782_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zegost.T"
        threat_id = "2147661782"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 25 73 5c 42 61 69 44 75 25 63 25 63 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 5c 43 72 65 61 74 65 53 61 66 65 50 72 6f 63 65 73 73 2e 69 6e 66 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 25 73 25 64 2e 25 73 00 65 78 65 00 25 73 00 00 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 68 74 74 70 3a 2f 2f 71 77 73 74 31 74 2e 33 33 32 32 2e 6f 72 67 3a 38 30 38 37}  //weight: 1, accuracy: High
        $x_1_5 = {56 8b 74 24 10 85 f6 7e 19 8b 44 24 08 8b 4c 24 0c 53 2b c8 8a 14 01 8a 18 32 da 88 18 40 4e 75 f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Zegost_W_2147687866_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zegost.W"
        threat_id = "2147687866"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 ff d6 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 8b 75 fc 81 be ?? ?? 00 00 20 01 00 00 8d 46 10 50 74 0d 68 ?? ?? ?? ?? e8 ?? ?? ff ff 59 eb 05}  //weight: 2, accuracy: Low
        $x_1_2 = "[%02d/%02d/%d %02d:%02d:%02d] (%s)" ascii //weight: 1
        $x_1_3 = {47 6c 6f 62 61 6c 5c 47 68 30 73 74 20 25 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 5c 2e 5c 52 45 53 53 44 54 44 4f 53 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Zegost_X_2147688890_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zegost.X"
        threat_id = "2147688890"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 2c 56 c6 44 24 2d 69 c6 44 24 2e 72 c6 44 24 2f 74 c6 44 24 30 75 c6 44 24 31 61 c6 44 24 32 6c c6 44 24 33 50 c6 44 24 34 72 c6 44 24 35 6f c6 44 24 36 74 c6 44 24 37 65 c6 44 24 38 63 c6 44 24 39 74 c6 44 24 3a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4c 24 04 8a 14 08 80 c2 7a 88 14 08 8b 4c 24 04 8a 14 08 80 f2 59 88 14 08 40 3b c6 7c e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Zegost_Y_2147688942_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zegost.Y"
        threat_id = "2147688942"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "0\\rossecorPlartneC\\metsyS\\NOITPIRCSED\\ERAWDRAH" ascii //weight: 1
        $x_1_2 = "Http/1.1 403 Forbidden" ascii //weight: 1
        $x_1_3 = {8a 1c 11 80 c3 7a 88 1c 11 8b 55 fc 8a 1c 11 80 f3 19 88 1c 11}  //weight: 1, accuracy: High
        $x_1_4 = {c6 44 24 10 7e 89 44 24 04 89 44 24 08 8d 44 24 00 c6 44 24 11 4d 50 68 ?? ?? ?? ?? 68 02 00 00 80 c6 44 24 1e 48 c6 44 24 1f 7a c6 44 24 20 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

