rule Ransom_Win32_LockScreen_A_2147630457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.gen!A"
        threat_id = "2147630457"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 8b 40 08 81 38 54 44 53 de 0f 85 f0 02 00 00 8b 45 fc 80 b8 9e 00 00 00 00 0f 84 e0 02 00 00 8b 45 fc 83 b8 a0 00 00 00 00 75 7b ba 00 80 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d8 8b 45 fc 89 98 a0 00 00 00 85 db 74 42 8b 45 f8}  //weight: 1, accuracy: Low
        $x_1_2 = "49685761" ascii //weight: 1
        $x_1_3 = "06159230" ascii //weight: 1
        $x_1_4 = "plugin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockScreen_B_2147632476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.B"
        threat_id = "2147632476"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ": moduletehsupport@gmail.com" wide //weight: 1
        $x_1_2 = "DisableTaskMgr" wide //weight: 1
        $x_1_3 = "http://www.pornhub.com/" wide //weight: 1
        $x_1_4 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 57 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 00 00 55 00 73 00 65 00 72 00 69 00 6e 00 69 00 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockScreen_H_2147636198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.H"
        threat_id = "2147636198"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 ab ad 2d ?? ?? ?? ?? 03 c2 ab ad}  //weight: 1, accuracy: Low
        $x_1_2 = {74 13 34 0e 66 0f b6 c0 42 66 89 01 8a 02 83 c1 02 3c 0e 75 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockScreen_H_2147636198_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.H"
        threat_id = "2147636198"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 ab ad 2d ?? ?? ?? ?? 03 c2 ab ad}  //weight: 1, accuracy: Low
        $x_1_2 = {77 03 80 c1 ?? 0f be c9 69 c9 ?? 00 00 00 03 c8 c1 c1 ?? 8b c1 8a 0a 84 c9 75 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockScreen_H_2147636198_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.H"
        threat_id = "2147636198"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ab ad c1 c8 ?? ab ad c1 (c0|c8) ?? ab ad}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 1c 0a 3b 19 75 ?? 83 ee 04 83 c1 04 83 fe 04 73 ee}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 31 3b 30 75 ?? 83 ea 04 83 c0 04 83 c1 04 83 fa 04 73 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockScreen_O_2147637730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.O"
        threat_id = "2147637730"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 65 6c 6c 6f 70 00 00 ff ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {62 65 6c 6c 69 73 73 69 6d 6d 6f 00 ff ff ff ff}  //weight: 1, accuracy: High
        $x_1_3 = "DisableTaskMgr" ascii //weight: 1
        $x_1_4 = {6e 75 6d 00}  //weight: 1, accuracy: High
        $x_1_5 = {70 61 6c 6f 00}  //weight: 1, accuracy: High
        $x_2_6 = {4d 49 43 52 4f 53 4f 46 54 20 53 59 53 54 45 4d 20 53 45 43 55 52 49 54 59 00}  //weight: 2, accuracy: High
        $x_2_7 = {5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 75 74 6c 6f 6f 6b 20 45 78 70 72 65 73 73 5c 00}  //weight: 2, accuracy: High
        $x_2_8 = {55 ad 4c fc 48 2b 3f af 4d 52 50 9e 3a 8a 4b 89 3e d6 55 64 46 98 62 12 5c 1e 6b 73 68 4e 6c 0b 68 32 5f 07 6d af 55 c2 48 57 6e f6 6d 77 65 0f 68 72 68 06 64 77 19 e3 3e 60 71 a4 69 5c 6b d8 5e f1 6c 28 6c be 55 33 00 00 00 00 ff ff ff ff}  //weight: 2, accuracy: High
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

rule Ransom_Win32_LockScreen_X_2147640546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.X"
        threat_id = "2147640546"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "To unlock the need for 2 hours, follow these steps" ascii //weight: 1
        $x_1_2 = "In case of refusal to pay, will begin removing" ascii //weight: 1
        $x_1_3 = {b9 af 00 00 00 ba 97 00 00 00 e8 ?? ?? ?? ?? 33 c9 ba b3 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockScreen_AB_2147640848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.AB"
        threat_id = "2147640848"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "llA mE kcoL" ascii //weight: 1
        $x_1_2 = "exe.tiniresu\\" wide //weight: 1
        $x_1_3 = "exe.rerolpxe" ascii //weight: 1
        $x_1_4 = "edom SOD ni nur eb tonnac margorp sihT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_LockScreen_AN_2147641902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.AN"
        threat_id = "2147641902"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 51 13 14 71 33 81 ff da 00 0c 03 01 00 02 11 03 11 00 3f 00 f9 20 a7 ed 9c 01 d9 8f e4 6a 7d}  //weight: 1, accuracy: High
        $x_1_2 = {30 04 39 04 c7 85 ?? ?? ?? ?? 34 04 51 04 c7 85 ?? ?? ?? ?? 42 04 35 04 c7 85 ?? ?? ?? ?? 20 00 3a 04 c7 85 ?? ?? ?? ?? 3e 04 34 04}  //weight: 1, accuracy: Low
        $x_1_3 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 46 00 20 00 2f 00 49 00 4d 00 20 00 74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockScreen_AO_2147641906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.AO"
        threat_id = "2147641906"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 65 6c 65 74 65 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {0c 77 69 6e 6c 6f 63 6b 69 6d 61 67 65}  //weight: 1, accuracy: High
        $x_1_3 = {cd e5 e2 e5 f0 ed fb e9 20 ea ee e4 20 e4 ee f1}  //weight: 1, accuracy: High
        $x_1_4 = {d0 e5 e4 e0 ea f2 ee f0 20 f0 e5 e5 f1 f2 f0 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_LockScreen_AR_2147642422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.AR"
        threat_id = "2147642422"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "taskkill /F /IM taskmgr.exe" wide //weight: 3
        $x_4_2 = {20 00 79 00 63 00 3b 04 79 00 33 04 79 00 2c 00 20 00 42 00 61 00 3c 04 20 00 3d 04 65 00 6f 00}  //weight: 4, accuracy: High
        $x_3_3 = {42 00 48 00 18 04 4d 00 41 00 48 00 18 04 45 00 21 00 21 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockScreen_B_2147643778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.gen!B"
        threat_id = "2147643778"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b0 65 88 45 e0 8d 4d dc b0 6c 51 c7 45 dc 6b 65 72 6e}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 4c 02 02 83 c0 02 66 89 08 66 3b cb 75 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_LockScreen_BA_2147644815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.BA"
        threat_id = "2147644815"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 68 a6 00 00 00 68 c4 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {38 ff 75 1a 6a 00 6a 00 68 06 00 a1 ?? ?? ?? ?? 83}  //weight: 1, accuracy: Low
        $x_1_3 = {c2 e2 e5 e4 e8 f2 e5 20 f1 fe e4 e0 20 ea ee e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_LockScreen_BD_2147646068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.BD"
        threat_id = "2147646068"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 03 ba 01 00 00 80 8b 03 e8 ?? ?? ?? ?? b1 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c3 8b d4 b9 01 04 00 00 e8 ?? ?? ?? ?? 81 c4 04 04 00 00 5b c3}  //weight: 1, accuracy: Low
        $x_1_3 = {40 65 63 68 6f 20 6f 66 66 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 54 69 74 6c 65}  //weight: 1, accuracy: Low
        $x_1_4 = {c4 e8 f1 ef e5 f2 f7 e5 f0 20 e7 e0 e4 e0 f7 20 57 69 6e 64 6f 77 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {74 61 73 6b 6d 67 72 2e 65 78 65 00 6f 70 65 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockScreen_BN_2147651932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.BN"
        threat_id = "2147651932"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c4 e8 f1 ef e5 f2 f7 e5 f0 20 e7 e0 e4 e0 f7 20 57 69 6e 64 6f 77 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {d0 b8 d1 82 d0 b5 20 d0 b2 d0 ba d0 bb d0 b0 d0 b4 d0 ba d1 83 20 22 57 65 62 4d 6f 6e 65 79 22}  //weight: 1, accuracy: High
        $x_1_3 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 6f 70 65 6e 00 00 00 00 65 78 70 6c 6f 72 65 72 00 00 00 00 ff ff ff ff 0c 00 00 00 cd e5 e2 e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_LockScreen_BO_2147651992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.BO"
        threat_id = "2147651992"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gema" ascii //weight: 1
        $x_1_2 = "/gate.php?hwid=" ascii //weight: 1
        $x_1_3 = "&localip=" ascii //weight: 1
        $x_1_4 = "&winver=" ascii //weight: 1
        $x_1_5 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\ERAWTFOS" ascii //weight: 1
        $x_1_6 = "stnenopmoC dellatsnI\\puteS evitcA\\tfosorciM\\ERAWTFOS" ascii //weight: 1
        $x_1_7 = {2f 41 63 74 69 76 65 58 00 00 ff ff ff ff 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Ransom_Win32_LockScreen_BR_2147653150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.BR"
        threat_id = "2147653150"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b0 6f b1 57 83 c4 0c c6 45 a0 53 c6 45 a1 65 c6 45 a2 74 88 4d a3 c6 45 a4 69 c6 45 a5 6e}  //weight: 1, accuracy: High
        $x_1_2 = {ff d3 50 8b 5d 84 ff d3 89 85 68 ff ff ff 33 c9 89 4d 94 b8}  //weight: 1, accuracy: High
        $x_1_3 = {3b c8 72 0a 8b c1 59 94 8b 00 89 04 24 c3 2d 00 10 00 00 85 00 eb e9}  //weight: 1, accuracy: High
        $x_1_4 = {74 18 8d 9d 44 f9 ff ff 53 8b 9d 20 f9 ff ff ff d3 50 8b 9d 24 f9 ff ff ff d3 68 06 02 00 00}  //weight: 1, accuracy: High
        $x_10_5 = "taskkill /F /IM taskmgr.exe" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_LockScreen_BV_2147654587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.BV"
        threat_id = "2147654587"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Vinyl Cowboy Messy Deity Heckle Digs" wide //weight: 1
        $x_1_2 = "Poop Ankle Truly" wide //weight: 1
        $x_1_3 = "Ember Rambo Keys Seats" wide //weight: 1
        $x_1_4 = "Swing Cooper Epoch Pooh" wide //weight: 1
        $x_1_5 = "Chili Chew" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockScreen_BW_2147655591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.BW"
        threat_id = "2147655591"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {76 0c 6a 00 6a 01 6a 12 50 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 85 c0 76 0c 6a 00 6a 01 6a 12 50 e8}  //weight: 2, accuracy: Low
        $x_1_2 = {f6 45 08 02 74 0b 66 83 39 73 75 05 66 c7 01 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 53 61 66 65 42 6f 6f 74 5c 4d 00 ff ff ff ff 31 00}  //weight: 1, accuracy: High
        $x_1_4 = {c4 e8 f1 ef e5 f2 f7 e5 f0 20 e7 e0 e4 e0 f7 20 57 69 6e 64 6f 77 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {cc ee e9 20 ea ee ec ef fc fe f2 e5 f0 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e 00 ?? ?? ?? ?? ?? ?? ?? ?? 43 3a 5c}  //weight: 1, accuracy: Low
        $x_1_7 = {6a 13 8b 43 4c 50 8b 43 48 50 8b 43 44 50 8b 43 40 50 6a ff 8b c3 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b 07 8b 70 44 8b c6 8b 17 03 42 4c 83 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_LockScreen_BX_2147656170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.BX"
        threat_id = "2147656170"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 69 6c 65 6e 63 65 ?? 6c 6f 63 6b ?? 62 6f 74 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = {70 61 79 6d 65 6e 74 20 76 61 6c 69 64 61 74 69 6f 6e 20 77 69 6c 6c 20 74 61 6b 65 [0-32] 62 65 66 6f 72 65 20 79 6f 75 20 77 69 6c 6c 20 67 65 74 20 61 63 63 65 73 73 20 74 6f 20 79 6f 75 72 20 73 79 73 74 65 6d}  //weight: 1, accuracy: Low
        $x_1_3 = {80 fa 37 75 ?? 80 3d ?? ?? ?? ?? 36 75 ?? 80 3d ?? ?? ?? ?? 33 75 ?? 38 15 ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? 8b c6 8d 70 01 8a 08 40 3a cb 75 ?? 2b c6 83 f8 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockScreen_CG_2147658661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.CG"
        threat_id = "2147658661"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ">>unlock.Name" wide //weight: 1
        $x_1_2 = ">>code.Name" wide //weight: 1
        $x_2_3 = "winlock.Properties" ascii //weight: 2
        $x_1_4 = "masterwin" ascii //weight: 1
        $x_5_5 = {ca 16 bf 16 d2 16 d4 16 c6 16 d4 16 da 16 cd 16 d3 16}  //weight: 5, accuracy: High
        $x_4_6 = {0d 09 06 08 59 61 d2 13 04 09 1e 63 08 61 d2 13 05 07 08 11 05 1e 62 11 04 60 d1 9d 08 17 58 0c 08 07 8e 69}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_LockScreen_CL_2147660468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.CL"
        threat_id = "2147660468"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 5c 6e 75 52 5c 6e 6f 69 73 72 65 56 74 6e 65 72 72 75 43 5c 73 77 6f 64 6e 69 57 5c 74 66 6f 73 6f 72 63 69 4d 5c 45 52 41 57 54 46 4f 53 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 0c 8b 55 08 85 d2 75 23 3d 04 02 00 00 74 07 3d 05 02 00 00 75 15 3d 05 02 00 00 75 07 6a 01 e8 ?? ?? ?? ?? b8 02 00 00 00 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockScreen_CO_2147661226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.CO"
        threat_id = "2147661226"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 06 6a 01 6a 02 ff 15 ?? ?? ?? ?? 83 f8 ff 0f 84 ?? ?? 00 00 a3 ?? ?? ?? ?? ba ?? ?? ?? ?? 8b 4c 24 08 89 4a 04 c7 02 02 00 00 50 6a 10}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 02 ff 15 ?? ?? ?? ?? 33 f6 46 3b 35 ?? ?? ?? ?? (74 ??|0f 84 ?? ?? ?? ??) 3c b5 ?? ?? ?? ?? 81 3f 68 74 74 70 75 03 83 c7 07 6a 2f 57 ff 15 ?? ?? ?? ?? 0b c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockScreen_CZ_2147674489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.CZ"
        threat_id = "2147674489"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c4 e8 f1 ef e5 f2 f7 e5 f0 20 e7 e0 e4 e0 f7 20 57 69 6e 64 6f 77 73 00}  //weight: 5, accuracy: High
        $x_1_2 = {01 3d 57 69 6e 6c 6f 63 6b 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 6c 6f 63 6b 2e 6e 6f 6e 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 4c 6f 63 6b 41 70 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 70 6f 6c 69 63 69 65 73 65 78 70 6c 6f 72 65 72 00}  //weight: 1, accuracy: High
        $x_1_6 = {6e 6f 63 6c 6f 73 65 00 ?? ?? ?? ?? ?? ?? ?? ?? 6e 6f 6c 6f 67 6f 66 66 00}  //weight: 1, accuracy: Low
        $x_1_7 = {5c 43 6f 6e 74 72 6f 6c 5c 53 61 66 65 42 6f 6f 74 5c 4d 00 ?? ?? ?? ?? 31 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_LockScreen_DC_2147678611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.DC"
        threat_id = "2147678611"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FBI Online Agent v" ascii //weight: 1
        $x_1_2 = "unuathorized cyberactivity" ascii //weight: 1
        $x_1_3 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 66 6c 61 73 68 70 6c 61 79 65 72 5c 73 79 73 5c 23 6c 6f 63 61 6c 5c 00}  //weight: 1, accuracy: High
        $x_1_5 = "%s%d-%d-%d_%d" ascii //weight: 1
        $x_1_6 = {3a 2f 2f 6c 6f 63 61 6c 2f 31 32 33 2e 73 77 66 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockScreen_DD_2147678928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.DD"
        threat_id = "2147678928"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 40 9c 00 00 8d 85 70 c6 fe ff 50 e8 ?? ?? ?? ?? 85 c0 0f 84 d9 01 00 00 8b bd f0 fe ff ff c1 ef 02 0f 84 a8 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "FBI Online Agent v.2." ascii //weight: 1
        $x_1_3 = "Article 184 - Pornography" ascii //weight: 1
        $x_1_4 = "moneypack_card_number=" ascii //weight: 1
        $x_1_5 = "After paying the fine your computer will be unlocked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_LockScreen_DF_2147679330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.DF"
        threat_id = "2147679330"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6f 6c 69 63 65 [0-5] 52 65 70 6f 72 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = "<m>Press ESC and try to connect to the Internet." ascii //weight: 1
        $x_1_3 = "h.phphmain" ascii //weight: 1
        $x_1_4 = {6c 6f 63 6b 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockScreen_DF_2147679330_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.DF"
        threat_id = "2147679330"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 6c 6f 62 61 6c 5c 75 79 75 79 37 36 36 72 67 64 79 72 35 35 00}  //weight: 1, accuracy: High
        $x_1_2 = {47 6c 6f 62 61 6c 5c 6f 75 38 36 67 65 35 38 67 79 00}  //weight: 1, accuracy: High
        $x_1_3 = {47 6c 6f 62 61 6c 5c 69 69 6f 79 38 38 68 67 79 36 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 00 42 00 61 00 73 00 65 00 4e 00 61 00 6d 00 65 00 64 00 4f 00 62 00 6a 00 65 00 63 00 74 00 73 00 5c 00 74 00 74 00 79 00 74 00 36 00 37 00 67 00 79 00 73 00 69 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 00 42 00 61 00 73 00 65 00 4e 00 61 00 6d 00 65 00 64 00 4f 00 62 00 6a 00 65 00 63 00 74 00 73 00 5c 00 64 00 69 00 64 00 6f 00 6f 00 75 00 64 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 00 42 00 61 00 73 00 65 00 4e 00 61 00 6d 00 65 00 64 00 4f 00 62 00 6a 00 65 00 63 00 74 00 73 00 5c 00 36 00 36 00 64 00 6a 00 38 00 75 00 67 00 64 00 6a 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {5c 00 74 00 65 00 73 00 74 00 5c 00 76 00 69 00 73 00 74 00 61 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {5c 00 74 00 65 00 73 00 74 00 5c 00 37 00 2d 00 36 00 34 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_LockScreen_DM_2147696879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.DM"
        threat_id = "2147696879"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://premiumtabs.org/combat/index.php/api/gettextdata?data={%22id%22:%221%22}" ascii //weight: 10
        $x_1_2 = "C:\\Windows\\combat.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_LockScreen_DN_2147697333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.DN"
        threat_id = "2147697333"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 6e 6c 6f 63 6b 5f 73 79 73 74 65 6d 00}  //weight: 1, accuracy: High
        $x_1_2 = {4b 69 6c 6c 45 78 70 6c 6f 72 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 69 73 61 62 6c 65 52 65 67 65 64 69 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {4c 6f 63 6b 53 79 73 74 65 6d 00}  //weight: 1, accuracy: High
        $x_1_5 = "WINLOCK" ascii //weight: 1
        $x_1_6 = {77 00 69 00 6e 00 6c 00 6f 00 63 00 6b 00 66 00 69 00 6c 00 65 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_LockScreen_DO_2147705698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.DO"
        threat_id = "2147705698"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "192.168.0.101" wide //weight: 1
        $x_1_2 = "Welcome to your system!" wide //weight: 1
        $x_1_3 = {46 3a 5c d0 91 d0 bb d0 be d0 ba d0 b8 d1 80 d0 b0 d1 82 d0 be d1 80 5c d0 91 d0 bb d0 be d0 ba d0 b8 d1 80 d0 b0 d1 82 d0 be d1 80 5c 6f 62 6a 5c 78 38 36 5c 52 65 6c 65 61 73 65 5c d0 91 d0 bb d0 be d0 ba d0 b8 d1 80 d0 b0 d1 82 d0 be d1 80 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_4 = "WINLOCK555\\RUBIN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_LockScreen_SA_2147740837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.SA"
        threat_id = "2147740837"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CryptoLockerFileList.txt" wide //weight: 1
        $x_1_2 = "files on this computer or device have just been encrypted" wide //weight: 1
        $x_1_3 = "Send bitcoins to this bitcoin address" wide //weight: 1
        $x_1_4 = "Cryptographic Locker" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_LockScreen_LK_2147755307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockScreen.LK!MTB"
        threat_id = "2147755307"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockScreen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ollydbg.exe" ascii //weight: 1
        $x_1_2 = "ProcessHacker.exe" ascii //weight: 1
        $x_1_3 = "Computer Information" ascii //weight: 1
        $x_1_4 = "InfoSteal" ascii //weight: 1
        $x_1_5 = "isRansomePopup" ascii //weight: 1
        $x_1_6 = "ransomeEncPath" ascii //weight: 1
        $x_1_7 = ":8083/welcome.do" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

