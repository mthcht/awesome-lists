rule TrojanDropper_Win32_Rovnix_A_2147649546_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rovnix.A"
        threat_id = "2147649546"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4f 3c 48 8d 14 39 8b 4a 50 8b 5a 28 66 83 4a 16 01}  //weight: 1, accuracy: High
        $x_1_2 = {66 b8 00 10 40 00 0f 23 d0 0f 21 f8 66 0d 2a 00 33 00 0f 23 f8}  //weight: 1, accuracy: High
        $x_1_3 = {66 3d 46 4a 74 0d 83 c6 10 0f b7 06 66 85 c0 75 ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Rovnix_B_2147653874_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rovnix.B"
        threat_id = "2147653874"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attrib -r -s -h%%1" ascii //weight: 1
        $x_1_2 = {8b 47 3c 03 c7 0f b7 48 06 0f b7 50 14 6b c9 28 03 c8 8d 74 0a 40 eb 09 66 3d 46 4a 74 0d 83 c6 10 0f b7 06 66 85 c0 75 ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Rovnix_C_2147654392_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rovnix.C"
        threat_id = "2147654392"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 00 42 00 52 00 00 00 5c 00 3f 00 3f 00 5c 00 50 00 48 00 59 00 53 00 49 00 43 00 41 00 4c 00 44 00 52 00 49 00 56 00 45 00 30 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 88 fe 01 00 00 81 f9 55 aa 00 00 74 05 e9 ?? ?? ?? ?? 8b 55 ?? 81 c2 be 01 00 00 89 55 ?? c7 45 ?? 00 00 00 00 83 7d ?? 04 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Rovnix_D_2147657307_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rovnix.D"
        threat_id = "2147657307"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 3c 30 33 75 09 81 3c 30 33 33 33 33 74 09 83 c0 01 3b c7 72 ea}  //weight: 1, accuracy: High
        $x_1_2 = {eb 09 66 3d 46 4a 74 0d 83 c6 14 0f b7 06 66 85 c0 75 ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Rovnix_E_2147657830_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rovnix.E"
        threat_id = "2147657830"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 f9 33 75 ?? 8b 55 10 03 55 ?? 81 3a 33 33 33 33}  //weight: 4, accuracy: Low
        $x_1_2 = "BKInstall" ascii //weight: 1
        $x_1_3 = "BKSetup" wide //weight: 1
        $x_1_4 = "attrib -r -s -h%%1" ascii //weight: 1
        $x_1_5 = {3d 46 4a 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Rovnix_F_2147657831_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rovnix.F"
        threat_id = "2147657831"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BkInstall_" ascii //weight: 1
        $x_1_2 = "Start_Install_Bootkit" ascii //weight: 1
        $x_1_3 = {68 35 bf a0 be 6a 01 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_4 = {68 6f fe e2 62 6a 05 6a 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_Win32_Rovnix_G_2147659271_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rovnix.G"
        threat_id = "2147659271"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 00 77 d0 83 7d 14 00 75 06 81 f3 ?? ?? ?? ?? 89 5d fc 61}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 9c 83 c0 08 89 45 98 ff 75 80 ff 75 84 ff 75 88 ff 75 8c ff 35 e8 c0 42 00 ff 35 e4 c0 42 00 ff 75 98 ff 55 98}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Rovnix_H_2147680142_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rovnix.H"
        threat_id = "2147680142"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 3c 30 33 75 09 81 3c 30 33 33 33 33 74 09 83 c0 01 3b c7 72 ea}  //weight: 1, accuracy: High
        $x_1_2 = {8b 2c 86 03 ea 33 6b 0a 8a ca d3 c5 83 c0 01 83 ea 01 3b 44 24 48 89 6c 86 fc 72 e4}  //weight: 1, accuracy: High
        $x_1_3 = {81 3c 31 77 77 77 77 74 16 41 3b cf 72 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Rovnix_I_2147682280_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rovnix.I"
        threat_id = "2147682280"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 3c 30 33 75 09 81 3c 30 33 33 33 33 74 07 40 3b c7 72 ec}  //weight: 2, accuracy: High
        $x_2_2 = {8a 14 08 80 fa eb 75 0a 0f b6 4c 08 01 8d 44 08 02 c3 80 fa e9 75 0a 0f b7 54 08 01 8d 44 10 03}  //weight: 2, accuracy: High
        $x_2_3 = {b9 46 4a 00 00 66 3b c1 74 1a 0f b7 46 14 83 c6 14 66 85 c0 75 ea ba 46 4a 00 00}  //weight: 2, accuracy: High
        $x_1_4 = {ba 55 aa 00 00 66 39 93 fe 01 00 00 75 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Rovnix_J_2147683319_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rovnix.J"
        threat_id = "2147683319"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SETUP: Started as win32 process 0x%x" ascii //weight: 1
        $x_1_2 = "SETUP: No joined BK loader found" ascii //weight: 1
        $x_1_3 = "Setup: Installation failed WriteSectors" ascii //weight: 1
        $x_1_4 = "\\Device\\Harddisk0\\Partition%u" wide //weight: 1
        $x_1_5 = "Setup: Payload of %u bytes successfully written at sector %x" ascii //weight: 1
        $x_3_6 = {8d 49 08 8d 34 c8 b9 46 4a 00 00 0f b7 06}  //weight: 3, accuracy: High
        $x_3_7 = {8b 04 b3 03 c2 33 47 0a 0f b6 ca d3 c0 46 4a 89 44 b3 fc 3b 75 08 72 e8}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Rovnix_L_2147684898_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rovnix.L"
        threat_id = "2147684898"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 3a 33 33 33 33 75 02 eb 02}  //weight: 2, accuracy: High
        $x_1_2 = {81 f9 55 aa 00 00 74 09 c7 45 ?? cb 00 00 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 88 fe 01 00 00 81 f9 55 aa 00 00 74 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Rovnix_P_2147690645_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rovnix.P"
        threat_id = "2147690645"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rovnix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 19 0f be 55 10 8b 45 08 03 45 fc 0f be 08 33 ca 8b 55 08 03 55 fc 88 0a eb d6}  //weight: 1, accuracy: High
        $x_1_2 = {b8 68 58 4d 56}  //weight: 1, accuracy: High
        $x_1_3 = {42 6b 49 6e 73 74 61 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {6a 04 8d 4d d4 51 68 18 00 36 83 8b 55 dc 52 ff 15}  //weight: 1, accuracy: High
        $x_1_5 = "Global\\UAC%s%u" wide //weight: 1
        $x_1_6 = "Global\\BD%s%u" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

