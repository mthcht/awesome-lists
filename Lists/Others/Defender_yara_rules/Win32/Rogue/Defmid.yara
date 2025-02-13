rule Rogue_Win32_Defmid_159648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Defmid"
        threat_id = "159648"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Defmid"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/sw/l.php?" ascii //weight: 1
        $x_1_2 = "aff_id" ascii //weight: 1
        $x_1_3 = {4d 61 63 68 69 6e 65 47 75 69 64 00 42 42 30 32 42 37 45 45 2d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Defmid_159648_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Defmid"
        threat_id = "159648"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Defmid"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 c0 5e c2 04 00 8b 4e 0c 6a 00 6a 00 6a 00 6a 02 6a 00 51 ff 15 ?? ?? ?? ?? 85 c0 89 46 10 75 06 32 c0 5e c2 04 00 6a 00 6a 00 6a 00 6a 04 50 ff 15 ?? ?? ?? ?? 89 06 b0 01 5e c2 04 00}  //weight: 1, accuracy: Low
        $x_1_2 = "BB02B7EE-5FC2-407d-A6EC-5DB24C0FA7C3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Defmid_159648_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Defmid"
        threat_id = "159648"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Defmid"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System Defender Downloader" ascii //weight: 1
        $x_1_2 = "update.dat" ascii //weight: 1
        $x_1_3 = "&log_id=" ascii //weight: 1
        $x_1_4 = "msctls_progress32" ascii //weight: 1
        $x_1_5 = "Installing System Defender" ascii //weight: 1
        $x_1_6 = "wm_id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Defmid_159648_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Defmid"
        threat_id = "159648"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Defmid"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System Defender" ascii //weight: 1
        $x_1_2 = "timalwareDefender_dll.dll" ascii //weight: 1
        $x_1_3 = "nder_start_scan" wide //weight: 1
        $x_1_4 = {70 00 75 00 72 00 63 00 68 00 61 00 73 00 65 00 2f 00 67 00 65 00 74 00 2e 00 70 00 68 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {2f 00 73 00 63 00 61 00 6e 00 5f 00 6f 00 76 00 65 00 72 00 2e 00 67 00 69 00 66 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Rogue_Win32_Defmid_159648_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Defmid"
        threat_id = "159648"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Defmid"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "skin/progress.js" wide //weight: 1
        $x_1_2 = "Can not download the installation package." ascii //weight: 1
        $x_1_3 = {4d 61 63 68 69 6e 65 47 75 69 64 00 69 6e 73 74 61 6c 6c 00 7b 00 00 00 7d 00 00 00 7b 00 00 00 7d 00 00 00 53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 43 4c 53 49 44}  //weight: 1, accuracy: High
        $x_1_4 = {70 00 72 00 6f 00 67 00 72 00 65 00 73 00 73 00 2e 00 68 00 74 00 6d 00 6c 00 [0-5] 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 75 00 70 00 64 00 61 00 74 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Defmid_159648_5
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Defmid"
        threat_id = "159648"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Defmid"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 63 2f 00 00 ff 15 ?? ?? ?? ?? 66 89 45 ?? 56 6a 01 6a 02 ff 15 ?? ?? ?? ?? 8b f8 83 ce ff 3b fe 75}  //weight: 3, accuracy: Low
        $x_3_2 = {6a 03 8d 85 ?? ?? ff ff 50 6a 08 8d 4d ?? 51 e8 ?? ?? ?? ?? 8d 55 ?? 52 e8 ?? ?? ?? ?? 83 c4 14 48 83 f8 04 77}  //weight: 3, accuracy: Low
        $x_1_3 = "awd_start_scan" ascii //weight: 1
        $x_1_4 = "awd_show_security_center" ascii //weight: 1
        $x_1_5 = "awd_uninstall" ascii //weight: 1
        $x_1_6 = "http://alerts.local/alert1.html" wide //weight: 1
        $x_1_7 = ".local/scan_results.html" wide //weight: 1
        $x_1_8 = "threats_high_cnt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Defmid_159648_6
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Defmid"
        threat_id = "159648"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Defmid"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2e 63 65 2e 6d 73 00 49 6e 74 65 72 6e 65 74 20 44 65 66 65 6e 64 65 72 20 32 30 31 31 00}  //weight: 3, accuracy: High
        $x_1_2 = "InstallDefender Setup: Installing" ascii //weight: 1
        $x_1_3 = {26 43 6c 6f 73 65 00 49 6e 73 74 61 6c 6c 44 65 66 65 6e 64 65 72 [0-5] 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: Low
        $x_2_4 = {43 6f 6d 6d 6f 6e 46 69 6c 65 73 44 69 72 [0-7] 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 [0-7] 66 75 63 6b}  //weight: 2, accuracy: Low
        $x_3_5 = {49 6e 74 65 72 6e 65 74 20 44 65 66 65 6e 64 65 72 20 32 30 31 31 [0-5] 47 65 74 56 65 72 73 69 6f 6e 2e 64 6c 6c 00 67 65 74 56}  //weight: 3, accuracy: Low
        $x_3_6 = {49 6e 74 65 72 6e 65 74 20 53 65 63 75 72 69 74 79 20 32 30 31 31 [0-5] 47 65 74 56 65 72 73 69 6f 6e 2e 64 6c 6c 00 67 65 74 56}  //weight: 3, accuracy: Low
        $x_3_7 = {2e 63 65 2e 6d 73 00 53 6f 66 74 77 61 72 65 20 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 2e 2e 2e [0-5] 47 65 74 56 65 72 73 69 6f 6e 2e 64 6c 6c 00 67 65 74 56}  //weight: 3, accuracy: Low
        $x_3_8 = {2e 63 6f 2e 63 63 00 [0-9] 49 6e 73 74 61 6c 6c [0-16] 47 65 74 56 65 72 73 69 6f 6e 2e 64 6c 6c 00 67 65 74 56}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Defmid_159648_7
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Defmid"
        threat_id = "159648"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Defmid"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 79 73 74 65 6d 20 44 65 66 65 6e 64 65 72 20 44 6f 77 6e 6c 6f 61 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {49 6e 73 74 61 6c 6c 69 6e 67 20 53 79 73 74 65 6d 20 44 65 66 65 6e 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {49 6e 73 74 61 6c 6c 69 6e 67 20 53 65 63 75 72 69 74 79 20 44 65 66 65 6e 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 65 63 75 72 69 74 79 20 44 65 66 65 6e 64 65 72 20 44 6f 77 6e 6c 6f 61 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_5 = "/sw/l.php" ascii //weight: 1
        $x_1_6 = {75 70 64 61 74 65 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_7 = "aff_id" ascii //weight: 1
        $x_1_8 = "dropper_big" ascii //weight: 1
        $x_2_9 = "BB02B7EE-5FC2-407d-A6EC-5DB24C0FA7C" ascii //weight: 2
        $x_1_10 = {8b 45 fc 83 c0 01 89 ?? ?? 83 ?? ?? ?? 29 73 ?? 8b 4d 0c 51 8b 55 08 52 e8}  //weight: 1, accuracy: Low
        $x_1_11 = {88 01 0f b6 55 0c 81 f2 e9 00 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {88 4a 05 0f b6 45 0c 35 e4 00 00 00}  //weight: 1, accuracy: High
        $x_1_13 = {88 50 31 0f b6 4d 0c 83 f1 5a}  //weight: 1, accuracy: High
        $x_1_14 = {83 f2 09 8b 45 08 88 ?? ?? 00 00 00 0f b6 4d 0c eb}  //weight: 1, accuracy: Low
        $x_2_15 = {a3 a3 8b 4d 08 33 ?? ?? ?? ?? ?? 8b 55 08}  //weight: 2, accuracy: Low
        $x_1_16 = {41 6e 74 69 6d 61 6c 77 61 72 65 20 54 6f 6f 6c 20 44 6f 77 6e 6c 6f 61 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_17 = "Internet Protection" ascii //weight: 1
        $x_1_18 = {69 6e 73 74 61 6c 6c 20 77 6f 72 6b 65 72 00 73 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_2_19 = "Antivirus Center " ascii //weight: 2
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

rule Rogue_Win32_Defmid_159648_8
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Defmid"
        threat_id = "159648"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Defmid"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 4d f0 0f b6 55 0c 81 c2 0c 03 00 00 0f b6 c2 35 da 03 00 00 8b 4d 10}  //weight: 2, accuracy: High
        $x_2_2 = {35 a7 07 00 00 8b 4d 10 88 81 4a 07 00 00 0f b6 55 0c}  //weight: 2, accuracy: High
        $x_1_3 = {2f 00 69 00 65 00 2e 00 67 00 69 00 66 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "are.IEMo" wide //weight: 1
        $x_1_5 = {6e 00 6f 00 72 00 65 00 5f 00 69 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 00 3a 00 2f 00 2f 00 64 00 65 00 66 00 65 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {20 65 6e 74 65 72 20 79 6f 75 72 20 61 63 74 00}  //weight: 1, accuracy: High
        $x_1_8 = {61 00 6c 00 65 00 72 00 74 00 38 00 2e 00 68 00 74 00 6d 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_2_9 = "Vanish System Defender" ascii //weight: 2
        $x_2_10 = {0f b6 c8 81 f1 5c 04 00 00 8b 55 0c 88 8a}  //weight: 2, accuracy: High
        $x_1_11 = {61 00 6c 00 65 00 72 00 74 00 36 00 2e 00 68 00 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {74 00 6d 00 6c 00 00 00 53 79 73 74 65 6d 20 44}  //weight: 1, accuracy: High
        $x_1_13 = {41 00 6e 00 74 00 69 00 6d 00 61 00 6c 00 77 00 00 00}  //weight: 1, accuracy: High
        $x_1_14 = {00 69 6d 61 6c 77 61 72 65 20 54 6f 6f 6c}  //weight: 1, accuracy: High
        $x_1_15 = {00 00 74 00 68 00 72 00 65 00 61 00 74 00 5f 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_16 = {00 00 69 00 72 00 75 00 73 00 70 00 72 00 6f 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_17 = {00 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_2_18 = {0f b6 4d 08 81 c1 2f 07 00 00 0f b6 d1}  //weight: 2, accuracy: High
        $x_1_19 = "system scan w" ascii //weight: 1
        $x_1_20 = {00 00 2f 00 6d 00 61 00 69 00 6e 00 5f 00 73 00 63 00 00 00}  //weight: 1, accuracy: High
        $x_2_21 = {05 5e 0c 00 00 0f b6 c8 81 f1 11 0c 00 00 8b 55 0c}  //weight: 2, accuracy: High
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

