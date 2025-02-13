rule PWS_Win32_Fareit_2147806423_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit"
        threat_id = "2147806423"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "PWDFILE0YUIPKDFILE0YUICRYPTED" ascii //weight: 20
        $x_1_2 = "/gate.php" ascii //weight: 1
        $x_1_3 = {73 6f 66 74 77 61 72 65 5c 77 69 6e 72 61 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_2147806423_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit"
        threat_id = "2147806423"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/gate.php" ascii //weight: 1
        $x_2_2 = "PWDFILE0YUIPKDFILE0YUICRYPTED" ascii //weight: 2
        $x_1_3 = "Software\\WinRAR" ascii //weight: 1
        $x_1_4 = "Software\\Far2\\SavedDialogHistory\\FTPHost" ascii //weight: 1
        $x_1_5 = {48 57 49 44 [0-5] 7b 25 30 38 58 2d 25 30 34 58 2d 25 30 34 58 2d 25 30 32 58 25 30 32 58 2d 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Fareit_2147806423_2
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit"
        threat_id = "2147806423"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$GTNGHO = \"c16d8a2bd8009cbcb1720095fe0de8770b3ddacd09d53f48ff96c0a7f2a980b9cd2a6755580e73d94e8caeee5b4f60733" wide //weight: 1
        $x_1_2 = "$GUJZNO = \"544B434F7262636F5769776E6642796C6D4B7573566666434A6C795670526E7853555055615A436A76766" wide //weight: 1
        $x_1_3 = "$XZKEWT = \"e41bc114f88227caf6f4899e246a27b841ef24ec28e6512fffbf5e3052cf228a906d7529b15791479e947" wide //weight: 1
        $x_1_4 = "filewrite(FileOpen(@TempDir & \"\"\\lol.bin\"\",18), \"\"0x\"\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_AD_2147806424_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.AD!MTB"
        threat_id = "2147806424"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 ff 34 0e bb ?? ?? ?? ?? 5a 31 da 89 14 08 [0-144] 83 e9 04 7d ?? ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_AD_2147806424_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.AD!MTB"
        threat_id = "2147806424"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 68 ?? ?? ?? ?? 6a 00 ff d0 25 00 a1 ?? ?? ?? ?? 48 66 81 38 4d 5a 75 f8 05 ?? ?? ?? ?? 8b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_AD_2147806424_2
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.AD!MTB"
        threat_id = "2147806424"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 00 7f ff 00 49 [0-8] 49 [0-8] 49 [0-8] 49 [0-16] ff 34 0f [0-48] 31 34 24 [0-48] 8f 04 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_AD_2147806424_3
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.AD!MTB"
        threat_id = "2147806424"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 40 42 0f 00 [0-37] 81 c3 0d 18 81 00 [0-37] 39 18 75 [0-96] ff d3 [0-16] e8 ?? ?? 00 00 [0-16] b9 41 41 41 41 [0-16] 46 [0-10] ff 37 [0-10] 31 34 24 [0-21] bb 00 60 00 00 [0-21] 83 eb 04 [0-16] ff 34 1f [0-10] 31 f2 [0-10] 89 14 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_C_2147806607_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.gen!C"
        threat_id = "2147806607"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 d8 1b ff 68 ?? ?? ?? 00 81 e7 00 00 04 00 ff d6 f7 d8 1b f6 33 db 53 81 e6 ?? ?? ?? 00 56 57 ff 15 ?? ?? ?? 00 89 45 fc 8d 45 f4 50 89 5d f4 89 5d f8 ff 15 ?? ?? ?? 00 8b 7d f8 0b 7d f4 56 f7 df 1b ff 53 ff 75 fc 81 e7 [0-10] ff 15 ?? ?? ?? 00 8b f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_G_2147806618_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.gen!G"
        threat_id = "2147806618"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 00 6a 02 ff 75 f8 6a 00 ff 73 04 ff 15 ?? ?? ?? ?? 0b c0 74 ?? ff 75 f8 e8 ?? ?? ?? ?? eb ?? ff 75 f8 e8 ?? ?? ?? ?? bf ?? ?? ?? ?? c7 45 fc 00 00 00 00 8d 45 fc 50 6a 00 6a 02 57 6a 00 ff 73 04 ff 15 ?? ?? ?? ?? 0b c0 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = "PKDFILE0YUICRYPTED0YUI1.0" ascii //weight: 1
        $x_1_3 = "PWDFILE0YUI" ascii //weight: 1
        $x_1_4 = {00 43 6c 69 65 6e 74 20 48 61 73 68 00 53 54 41 54 55 53 2d 49 4d 50 4f 52 54 2d 4f 4b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_Fareit_L_2147806772_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.gen!L"
        threat_id = "2147806772"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 6f 66 74 77 61 72 65 5c 77 69 6e 72 61 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 65 73 74 73 6f 66 74 5c 61 6c 66 74 70 00 69 6e 74 65 72 6e 65 74 20 65 78 70 6c 6f 72 65 72 00 77 69 6e 69 6e 65 74 63 61 63 68 65 63 72 65 64 65 6e 74 69 61 6c 73 00 6d 73 20 69 65 20 66 74 70 20 70 61 73 73 77 6f 72 64 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {69 6e 65 74 63 6f 6d 6d 20 73 65 72 76 65 72 20 70 61 73 73 77 6f 72 64 73 00 6f 75 74 6c 6f 6f 6b 20 61 63 63 6f 75 6e 74 20 6d 61 6e 61 67 65 72 20 70 61 73 73 77 6f 72 64 73 00}  //weight: 1, accuracy: High
        $x_10_4 = {b9 94 11 00 00 b0 0d f2 ae b8 94 11 00 00 2b c1}  //weight: 10, accuracy: High
        $x_10_5 = {8b d0 d1 e2 b9 09 00 00 00 d1 ea 73 ?? 81 f2 31 92 a9 fc 81 f2 11 11 11 11}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Fareit_E_2147806788_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.gen!E"
        threat_id = "2147806788"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Far2\\SavedDialogHistory\\FTPHost" ascii //weight: 1
        $x_1_2 = "\\VanDyke\\Config\\Sessions" ascii //weight: 1
        $x_2_3 = {00 6f 69 64 2e 62 61 74 00}  //weight: 2, accuracy: High
        $x_2_4 = {00 61 62 63 64 2e 62 61 74 00}  //weight: 2, accuracy: High
        $x_10_5 = {80 3f 09 74 19 80 3f 0d 74 14 80 3f 0a 74 0f 80 3f 5b 74 0a 80 3f 5d 74 05 80 3f 60 75 03 c6 07 20 47 80 3f 00 75 d9}  //weight: 10, accuracy: High
        $x_10_6 = {eb 2d 8b 17 8b 45 08 25 ff 7f ff ff 39 42 04 75 1b 6a 00 8d 42 08 50 68 ?? ?? ?? ?? ff 32 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Fareit_SM_2147806801_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.SM!MTB"
        threat_id = "2147806801"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b d0 83 e2 01 85 d2 75 0e 8b d3 03 d0 73 05 e8 60 d1 f8 ff 80 32 9c 40 3d bc 18 01 00 75 e1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_SM_2147806801_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.SM!MTB"
        threat_id = "2147806801"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bb 01 00 00 00 90 90 90 90 8b c2 03 c3 90 90 90 c6 00 94 90 90 90 90 43 81 fb 7f 2f 4b 22 75 e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_SM_2147806801_2
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.SM!MTB"
        threat_id = "2147806801"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 f6 89 f6 89 f6 8b c1 be 03 00 00 00 33 d2 f7 f6 85 d2 75 1e 89 f6 89 f6 8b c3 03 c1 73 05 e8 4f af f9 ff 89 f6 89 f6 89 f6 89 f6 89 f6 80 30 27 89 f6 89 f6 41 81 f9 a1 f7 00 00 75 c2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_SM_2147806801_3
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.SM!MTB"
        threat_id = "2147806801"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 f6 89 f6 89 f6 89 f6 8b c1 bb 03 00 00 00 33 d2 f7 f3 85 d2 75 28 89 f6 89 f6 89 f6 8b d6 03 d1 89 f6 89 f6 89 f6 89 f6 b0 29 89 f6 89 f6 89 f6 89 f6 89 f6 30 02 89 f6 89 f6 89 f6 89 f6 89 f6 89 f6 89 f6 41 81 f9 16 1f 01 00 75 b2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_SM_2147806801_4
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.SM!MTB"
        threat_id = "2147806801"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 7d e8 00 76 30 8b 45 e8 83 e0 03 85 c0 75 15 8b 45 e8 8a 80 88 80 46 00 34 71 8b 55 fc 03 55 e8 88 02 eb 11 8b 45 e8 8a 80 88 80 46 00 8b 55 fc 03 55 e8 88 02 ff 45 e8 81 7d e8 22 83 00 00 75 be}  //weight: 2, accuracy: High
        $x_2_2 = {85 c0 76 20 8b c8 83 e1 03 85 c9 75 0e 8a 0a 80 f1 f5 8b 5d fc 03 d8 88 0b eb 09 8b 4d fc 03 c8 8a 1a 88 19 40 42 3d a1 7c 00 00 75 d3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Fareit_SM_2147806801_5
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.SM!MTB"
        threat_id = "2147806801"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 90 5c 8e 45 00 32 15 f8 2c 46 00 90 90 90 8b c7 03 c3 90 90 8b f0 90 8b c6 e8 8d fd ff ff 90 90 90 90 90 43 81 fb 12 5b 00 00 75}  //weight: 2, accuracy: High
        $x_1_2 = {89 f6 89 f6 89 f6 8b c1 be 03 00 00 00 33 d2 f7 f6 85 d2 75 1e 89 f6 89 f6 8b c3 03 c1 73 05 e8 4f af f9 ff 89 f6 89 f6 89 f6 89 f6 89 f6 80 30 [0-4] 89 f6 89 f6 41 81 f9 [0-4] 75 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Fareit_SM_2147806801_6
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.SM!MTB"
        threat_id = "2147806801"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 f9 00 74 11 83 7d fc 04 75 0b c7 45 fc 00 00 00 00 80 34 01 19 8b 7d fc 47 89 7d fc 41 89 d3 39 d9 75}  //weight: 2, accuracy: High
        $x_2_2 = {83 f9 00 74 11 83 7d fc 04 75 0b c7 45 fc 00 00 00 00 80 34 01 50 8b 7d fc 47 89 7d fc 41 89 d3 39 d9 75 dc}  //weight: 2, accuracy: High
        $x_2_3 = {83 f9 00 74 11 83 7d fc 04 75 0b c7 45 fc 00 00 00 00 80 34 01 3e 8b 7d fc 47 89 7d fc 41 89 d3 39 d9 75 dc}  //weight: 2, accuracy: High
        $x_1_4 = {83 f9 00 74 11 83 7d fc 04 75 0b c7 45 fc 00 00 00 00 80 34 01 [0-4] 8b 7d fc 47 89 7d fc 41 89 d3 39 d9 75 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Fareit_VE_2147806802_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.VE!MTB"
        threat_id = "2147806802"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4b 38 f4 8b 17 f7 c1 ?? ?? ?? ?? 31 da 66 85 d0 39 ca 75}  //weight: 2, accuracy: Low
        $x_2_2 = {2a 22 3b f0 13 36 87 0b 08 57 25 33 0a 84 14 aa 16 17 eb}  //weight: 2, accuracy: High
        $x_1_3 = {31 f1 16 17 eb}  //weight: 1, accuracy: High
        $x_1_4 = {8d 81 63 bc ae 1e 8a 03 50 b8 ?? ?? ?? ?? 3d ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? 58 68 ?? ?? ?? ?? 83 c4 ?? 89 0c 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Fareit_V_2147806803_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.V!MTB"
        threat_id = "2147806803"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 e8 ?? ?? ?? ?? 89 45 fc 8b 45 08 0f be 00 33 45 fc 8b 4d 08 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 85 50 f6 ff ff 40 89 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 3b 45 94 73 ?? 8b 45 ec 89 85 ?? ?? ?? ?? ff b5 ?? ?? ?? ?? ff b5 ?? ?? ?? ?? ff 75 e8 e8 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Fareit_V_2147806803_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.V!MTB"
        threat_id = "2147806803"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "DcduovS1BKPt234" wide //weight: 1
        $x_1_3 = "b9MZ13169" wide //weight: 1
        $x_1_4 = "mwH6cuzlep2zPZqcQtG81" wide //weight: 1
        $x_1_5 = "YEErVkgTXk7ZS8mD6e2XjplIeh2ZK2103" wide //weight: 1
        $x_1_6 = "XfbbbQQ3gPuzxIQE5U3UVQ7pBsuPVV0LYzZfm5GG182" wide //weight: 1
        $x_1_7 = "bWx7n0EZqcgQ207" wide //weight: 1
        $x_1_8 = "z2Q8SNJdCQ44LwSqFabWUfHrDKupSOc33" wide //weight: 1
        $x_1_9 = "jwyFcE5B2r2WD0tB4Ivf9JZnaFpEZyZse35KRRQ160" wide //weight: 1
        $x_1_10 = "TgMyKnOKCGoF0eKMmjlKwUytznzsMrvpUp29" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Fareit_VK_2147806804_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.VK!MTB"
        threat_id = "2147806804"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = {5f 8b 10 53}  //weight: 1, accuracy: High
        $x_1_3 = {5b 31 f2 57}  //weight: 1, accuracy: High
        $x_1_4 = {5f 89 10 57}  //weight: 1, accuracy: High
        $x_1_5 = {8b 9c 24 1c 01 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {8b 94 24 20 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_VK_2147806804_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.VK!MTB"
        threat_id = "2147806804"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = {58 52 81 ca ?? ?? ?? ?? 5a 51 81 f1 ?? ?? ?? ?? 59 8f 04 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_VK_2147806804_2
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.VK!MTB"
        threat_id = "2147806804"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = {8f 04 18 16 17 eb 03 00 83 c4}  //weight: 1, accuracy: Low
        $x_1_3 = {31 34 24 68 03 00 83 c4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_2147806805_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit!MTB"
        threat_id = "2147806805"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = {b8 00 10 b0 01}  //weight: 1, accuracy: High
        $x_1_3 = {b8 00 10 b0 02}  //weight: 1, accuracy: High
        $x_1_4 = {2d 00 00 70 01}  //weight: 1, accuracy: High
        $x_1_5 = {2d 00 00 70 02}  //weight: 1, accuracy: High
        $x_1_6 = {68 2f 37 02 00}  //weight: 1, accuracy: High
        $x_1_7 = {81 c2 1e 23 8e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win32_Fareit_2147806805_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit!MTB"
        threat_id = "2147806805"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c9 8b 1c 0a 81 f3 ?? ?? ?? ?? 89 1c 08 f8 83 c1 04 81 f9 ?? ?? ?? ?? 75 ?? ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_2147806805_2
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit!MTB"
        threat_id = "2147806805"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 d9 04 0f 8d ?? ?? ff ff 00 02 89 1c 08 00 02 81 f3 00 02 8b 1c 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_2147806805_3
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit!MTB"
        threat_id = "2147806805"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = {83 fb 00 7f c0 00 83 eb 04 [0-32] ff 34 1f [0-32] 8f 04 18 [0-32] 31 34 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_2147806805_4
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit!MTB"
        threat_id = "2147806805"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = {83 f9 00 7f 20 00 09 1c 08 50 00 31 f3 30 00 8b 1c 0f 10 00 49 10 00 49 10 00 49 10 00 49}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_2147806805_5
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit!MTB"
        threat_id = "2147806805"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "TpJmbeq2ZuU07if5RiHyg07UA9AZ6shj19" wide //weight: 1
        $x_1_3 = {83 fb 00 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_2147806805_6
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit!MTB"
        threat_id = "2147806805"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = {83 c7 04 85 ff 00 83 c2 04 ff 00 83 c4 04 ff 00 89 0c 18 ff 00 8b 0c 24 ff 00 31 34 24 ff 00 ff 37}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c7 04 66 ff 00 83 c2 04 ff 00 83 c4 04 ff 00 89 0c 18 ff 00 8b 0c 24 ff 00 31 34 24 ff 00 ff 37}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_Fareit_2147806805_7
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit!MTB"
        threat_id = "2147806805"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = {8f 04 18 66 ff 00 ff 31 [0-255] 31 34 24 [0-255] 8f 04 18 [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
        $x_1_3 = {8f 04 18 81 ff 00 ff 31 [0-255] 31 34 24 [0-255] 8f 04 18 [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
        $x_1_4 = {8f 04 18 85 ff 00 ff 31 [0-255] 31 34 24 [0-255] 8f 04 18 [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_Fareit_VD_2147806806_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.VD!MTB"
        threat_id = "2147806806"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 43 4e 75 0b 00 8b cf b2 [0-8] 8a 03 32 c2 88 01 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_F_2147806856_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.gen!F"
        threat_id = "2147806856"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 5c 1e 04 8b c3 33 d2 f7 f1 03 d7 8a 02 88 84 1d 00 ff ff ff 8b c3 40 88 44 1e 05 8d 43 01}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 12 c1 e2 02 03 c2 01 d8 8b 30 01 de eb ?? ff 45}  //weight: 1, accuracy: Low
        $x_1_3 = {bf cc cc cc 0c 8a 1e 46 80 fb 20 74 f8 b5 00 80 fb 2d 74 62 80 fb 2b 74 5f 80 fb 24 74 5f 80 fb 78 74 5a 80 fb 58 74 55 80 fb 30 75 13 8a 1e 46 80 fb 78 74 48 80 fb 58 74 43 84 db 74 20 eb 04}  //weight: 1, accuracy: High
        $x_1_4 = "Tibia" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_A_2147806870_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.gen!A"
        threat_id = "2147806870"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 d1 e2 b9 09 00 00 00 d1 ea 73 ?? 81 f2 31 92 a9 fc 81 f2 11 11 11 11}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 94 11 00 00 b0 0d f2 ae b8 94 11 00 00 2b c1}  //weight: 1, accuracy: High
        $x_1_3 = {4d 65 73 6f 61 6d 65 72 69 63 61 00 [0-3] 68 74 74 70}  //weight: 1, accuracy: Low
        $x_1_4 = "PKDFILE0CRYPTED" ascii //weight: 1
        $x_1_5 = "CRYPTED0DF" ascii //weight: 1
        $x_1_6 = {6a 6f 6c 70 ?? ?? ?? ?? ?? ?? 64 65 6c}  //weight: 1, accuracy: Low
        $x_1_7 = {7b 25 30 38 58 2d 25 30 34 58 2d 25 30 34 58 2d 25 30 32 58 25 30 32 58 2d 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 7d 00 (??|?? ??|?? ?? ??|?? ?? ?? ??|?? ?? ?? ?? ??|?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??) 48 57 49 44 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_Fareit_B_2147806871_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.gen!B"
        threat_id = "2147806871"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 3a 5c 68 56 6a 6a 6d 73 63 6b 5c 7a 75 6e 7a 4d 6f 5c 64 41 51 51 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = {30 00 78 00 37 00 38 00 33 00 37 00 38 00 34 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 00 3a 00 5c 00 44 00 4b 00 4a 00 4b 00 4a 00 5c 00 2e 00 5c 00 44 00 4b 00 4a 00 4b 00 4a 00 53 00 5c 00 2e 00 2e 00 5c 00 4b 00 44 00 4a 00 4b 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_D_2147806872_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.gen!D"
        threat_id = "2147806872"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PKDFILE0CRYPTED" ascii //weight: 1
        $x_1_2 = "Far\\Plugins\\FTP\\Hosts" ascii //weight: 1
        $x_2_3 = {00 43 6c 69 65 6e 74 20 48 61 73 68 00 53 54 41 54 55 53 2d 49 4d 50 4f 52 54 2d 4f 4b 00}  //weight: 2, accuracy: High
        $x_2_4 = {00 5c 45 73 74 73 6f 66 74 5c 41 4c 46 54 50 00 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 00 57 69 6e 69 6e 65 74 43 61 63 68 65 43 72 65 64 65 6e 74 69 61 6c 73 00 4d 53 20 49 45 20 46 54 50 20 50 61 73 73 77 6f 72 64 73 00}  //weight: 2, accuracy: High
        $x_2_5 = {00 5c 49 70 73 77 69 74 63 68 5c 57 53 5f 46 54 50 00 5c 77 69 6e 2e 69 6e 69 00 2e 69 6e 69 00 57 53 5f 46 54 50 00 44 49 52 00 78 44 45 46 44 49 52 00 43 55 54 45 46 54 50 00 51 43 48 69 73 74 6f 72 79 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_K_2147806873_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.gen!K"
        threat_id = "2147806873"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 d1 e2 b9 09 00 00 00 d1 ea 73 ?? 81 f2 31 92 a9 fc 81 f2 11 11 11 11}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 2d 8b 17 8b 45 08 25 ff 7f ff ff 39 42 04 75 1b 6a 00 8d 42 08 50 68 ?? ?? ?? ?? ff 32 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {50 6a 00 6a 02 ff 75 f8 6a 00 ff 73 04 ff 15 ?? ?? ?? ?? 0b c0 74 ?? ff 75 f8 e8 ?? ?? ?? ?? eb ?? ff 75 f8 e8 ?? ?? ?? ?? bf ?? ?? ?? ?? c7 45 fc 00 00 00 00 8d 45 fc 50 6a 00 6a 02 57 6a 00 ff 73 04 ff 15 ?? ?? ?? ?? 0b c0 0f 84}  //weight: 1, accuracy: Low
        $x_1_4 = {69 6e 65 74 63 6f 6d 6d 20 73 65 72 76 65 72 20 70 61 73 73 77 6f 72 64 73 00 6f 75 74 6c 6f 6f 6b 20 61 63 63 6f 75 6e 74 20 6d 61 6e 61 67 65 72 20 70 61 73 73 77 6f 72 64 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_AJ_2147806876_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.AJ!bit"
        threat_id = "2147806876"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {e3 40 fe 45 ?? 0f b6 45 ?? 0f b6 14 38 88 55 ?? 00 55 ?? 0f b6 45 ?? 8a 14 38 88 55 ?? 0f b6 45 ?? 88 14 38 0f b6 45 ?? 8a 55 ?? 88 14 38 8a 55 ?? 02 55 ?? 8a 14 3a 8b 45 ?? 30 14 30 ff 45 ?? e2 c0}  //weight: 3, accuracy: Low
        $x_3_2 = {8b d0 c1 ea 08 32 07 25 ff 00 00 00 8b 04 85 ?? ?? ?? ?? 33 c2 47 e2 e8}  //weight: 3, accuracy: Low
        $x_1_3 = "SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_5 = "SiteServer %d\\Remote Directory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Fareit_BB_2147806877_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.BB!bit"
        threat_id = "2147806877"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 0c 8b 00 8b 00 8b 40 18}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 ce 8a 04 01 32 04 fd ?? ?? ?? ?? 46 88 04 11 0f b7 04 fd ?? ?? ?? ?? 66 3b f0 72 db 07 00 8b 04 fd}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 04 07 33 c1 c1 e9 08 0f b6 c0 33 0c 85 ?? ?? ?? ?? 47 8b 45 ?? 3b fb 72 e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_BD_2147806878_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.BD!bit"
        threat_id = "2147806878"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FILEINSTALL ( \"encrypted.bin\" , @TEMPDIR & \"\\1.resource" wide //weight: 1
        $x_1_2 = {20 00 5f 00 52 00 55 00 4e 00 50 00 45 00 20 00 28 00 20 00 46 00 49 00 4c 00 45 00 52 00 45 00 41 00 44 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 31 00 2e 00 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 22 00 20 00 29 00 20 00 2c 00 20 00 40 00 53 00 59 00 53 00 54 00 45 00 4d 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_SU_2147806879_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.SU!MTB"
        threat_id = "2147806879"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 41 41 41 41 [0-16] 83 c6 01 [0-5] 8b 17 [0-16] 31 f2 [0-16] 39 ca 75}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 00 5f 00 00 [0-16] 49 [0-16] 8b 1c 0f [0-16] 53 [0-32] 31 34 24 [0-37] 8f 04 08 [0-21] 83 f9 00 7f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_SV_2147806880_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.SV!MTB"
        threat_id = "2147806880"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 41 41 41 41 [0-16] 46 [0-5] 8b 17 [0-16] 31 f2 [0-16] 39 ca 75}  //weight: 1, accuracy: Low
        $x_1_2 = {68 e0 5e 00 00 [0-16] 59 [0-16] 49 [0-16] 8b 1c 0f [0-16] 53 [0-32] 31 34 24 [0-37] 8f 04 08 [0-21] 83 f9 00 7f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_Delph_2147806881_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.Delph!MTB"
        threat_id = "2147806881"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 55 f7 88 10 [0-5] 8d 45 f8 e8 ?? ?? ff ff 30 00 8a 16 [0-5] 80 f2 ?? 88 55 f7 [0-5] 8a 55 f7 88 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_Delph_2147806882_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.Delph.AD!MTB"
        threat_id = "2147806882"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "AD: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1a 80 f3 ?? 88 5d f7 [0-5] 8b 5d f8 8b fb 8a 5d f7 88 1f [0-48] 03 4d fc ff d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_Delph_2147806883_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.Delph.AE!MTB"
        threat_id = "2147806883"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "AE: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 55 fb 88 10 [0-5] 8d 45 f4 e8 ?? ?? ff ff [0-8] 46 4f 75 30 00 8a 16 [0-5] 80 f2 ?? 88 55 fb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 fc 03 45 f8 [0-7] 8a 13 [0-4] 80 f2 ?? [0-4] 88 10 [0-7] 8d 45 ?? e8 ?? ?? ff ff [0-7] 43 4e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Fareit_G_2147806884_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.G!MTB"
        threat_id = "2147806884"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 00 c3 53 8b d8 6a 00 e8 ?? ?? ?? ?? 90 90 8b c3 34 ?? 90 90 5b c3 53 56 57 55 51 8b da 8b f0 54 6a 40 68 ?? ?? ?? ?? 56 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_G_2147806884_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.G!MTB"
        threat_id = "2147806884"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 34 0e 81 34 24 ?? ?? ?? ?? 8f 04 08 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {00 00 59 83 e9 04 e8 ?? ff ff ff 83 e9 03 e0 f6 e8 ?? ff ff ff ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_H_2147806885_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.H!MTB"
        threat_id = "2147806885"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5e 31 c9 b9 00 [0-79] ff 34 0e [0-255] 31 04 24 [0-255] 0f 8d ?? ?? ff ff [0-159] ff e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_H_2147806885_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.H!MTB"
        threat_id = "2147806885"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 75 07 b8 01 00 00 00 eb 02 33 c0 90 8b de 03 d9 73 05 e8 ?? ?? ?? ?? 89 5d f8 85 c0 75 1f 90 90 8a 1a 88 5d f7 90 90 8b 5d f8 8b fb 8a 5d f7 88 1f 83 c1 01 73 05 e8 ?? ?? ?? ?? 90 90 90 ff 45 fc 42 81 7d fc f1 e7 00 00 75 b3}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 89 06 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 ff 75 fc 90 58 90 f7 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_J_2147806886_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.J!MTB"
        threat_id = "2147806886"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5e 31 30 57 81 f7 [0-255] 5f 39 18 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {5f 01 c8 56 81 d6 ?? ?? ?? ?? 81 d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_J_2147806886_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.J!MTB"
        threat_id = "2147806886"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 75 07 b8 01 00 00 00 eb 02 33 c0 [0-4] 8b 5d ?? 03 de 89 5d ?? [0-4] 85 c0 75 ?? [0-4] 8a 1a 88 5d ?? [0-4] 8b 5d ?? 8b fb 8a 5d ?? 88 1f [0-4] 46 [0-4] 42 49 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 5a 59 59 64 89 10 68 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_DA_2147806887_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.DA!MTB"
        threat_id = "2147806887"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {68 41 41 41 41 [0-16] 46 [0-16] 8b 17 [0-16] 33 14 [0-16] 39 ca 75}  //weight: 20, accuracy: Low
        $x_5_2 = {b9 f0 5f 00 00 [0-16] 49 [0-16] ff 34 0f [0-16] 5b [0-16] 31 f3 [0-37] 09 1c 08 [0-16] 83 f9 00 7f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_SF_2147806888_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.SF!MTB"
        threat_id = "2147806888"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 e0 5e 00 00 [0-5] 59 [0-5] 83 e9 04 [0-5] 8b 1c 0f [0-32] 31 f3 [0-32] 09 1c 08 [0-32] 83 f9 00 7f}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 70 2b 41 41 [0-5] 81 c1 d1 15 00 00 [0-5] 46 [0-32] 8b 1f [0-5] 31 f3 [0-5] 39 cb 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_SF_2147806888_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.SF!MTB"
        threat_id = "2147806888"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {01 d3 81 fb 3f 4a a9 cc 66 85 db eb 05 00 00 00 00 00 89 0b 66 85 c0 85 d2 eb 05 00 00 00 00 00 83 c2 04 3d 6f f1 ec 9c 81 ff 96 3b 30 f5 83 c7 04 eb 09 00 00 00 00 00 00 00 00 00 66 85 db 66 85 db 81 fa c4 b7 00 00 eb 02 00 00 74 20}  //weight: 4, accuracy: High
        $x_1_2 = "pDOHV4MbCRbXwDBDUqASRPRN3AO112" wide //weight: 1
        $x_1_3 = "waEPBGXzAncb6b8DdBLf52w2KdJna3hPAyDp9cY242" wide //weight: 1
        $x_1_4 = "M6pz2k22SiRJz72sOnq0e7s183" wide //weight: 1
        $x_1_5 = "DiTMKY8ykQSpCykGjhWIO61" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Fareit_A_2147806889_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.A!MTB"
        threat_id = "2147806889"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 02 90 90 90 34 dd 88 45 fb 90 90 90 90 90 8b 4d fc 8a 45 fb 88 01 90 8b 45 f4 40 89 45 f4 90 90 90 ff 45 f0 42 81 7d}  //weight: 1, accuracy: High
        $x_1_2 = "Mqbi2WFeyf1" ascii //weight: 1
        $x_1_3 = "PonZPtAJ0jHE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_A_2147806889_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.A!MTB"
        threat_id = "2147806889"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff 34 0e 81 34 24 0f ba b9 7a 8f 04 08 c3}  //weight: 5, accuracy: High
        $x_10_2 = {6a 40 ff d0 e8 ?? ?? ?? ?? 5e 81 c6 ?? ?? ?? ?? 68 ?? ?? ?? ?? 59 83 e9 04 e8 ?? ?? ?? ?? 83 e9 03 e0 f6 e8 ?? ?? ?? ?? ff e0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_A_2147806889_2
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.A!MTB"
        threat_id = "2147806889"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = {31 34 24 81 ff 00 ff 37 [0-255] 31 34 24 [0-255] 8b 0c 24 [0-255] 89 0c 18}  //weight: 1, accuracy: Low
        $x_1_3 = {31 34 24 85 ff 00 ff 37 [0-255] 31 34 24 [0-255] 8b 0c 24 [0-255] 89 0c 18}  //weight: 1, accuracy: Low
        $x_1_4 = {31 34 24 66 ff 00 ff 37 [0-255] 31 34 24 [0-255] 8b 0c 24 [0-255] 89 0c 18}  //weight: 1, accuracy: Low
        $x_1_5 = {31 34 24 66 ff 00 ff 37 [0-255] 31 34 24 [0-255] 8f 04 18 [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
        $x_1_6 = {31 34 24 85 ff 00 ff 37 [0-255] 31 34 24 [0-255] 8f 04 18 [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
        $x_1_7 = {31 34 24 81 ff 00 ff 37 [0-255] 31 34 24 [0-255] 8f 04 18 [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
        $x_1_8 = {31 34 24 eb ff 00 ff 37 [0-255] 31 34 24 [0-255] 8f 04 18 [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
        $x_1_9 = {31 34 24 66 ff 00 ff 31 [0-255] 31 34 24 [0-255] 8f 04 10 [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
        $x_1_10 = {8f 04 10 66 ff 00 ff 31 [0-255] 31 34 24 [0-255] 8f 04 18 [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
        $x_1_11 = {8f 04 10 81 ff 00 ff 31 [0-255] 31 34 24 [0-255] 8f 04 10 [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
        $x_1_12 = {8f 04 18 81 ff 00 ff 37 [0-255] 31 34 24 [0-255] 8f 04 10 [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
        $x_1_13 = {8f 04 18 66 ff 00 ff 37 [0-255] 31 34 24 [0-255] 8f 04 18 [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_Fareit_B_2147806890_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.B!MTB"
        threat_id = "2147806890"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fa 41 41 41 41 0f 85 ff 00 46 [0-32] 8b 17 [0-32] 56 [0-32] 33 14 24 [0-32] 5e [0-32] 81 fa 41 41 41 41 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {81 fa 41 41 41 41 75 ff 00 46 [0-32] ff 37 [0-32] 31 34 24 [0-32] 5a [0-32] 81 fa 41 41 41 41 75}  //weight: 1, accuracy: Low
        $x_1_3 = {bb 00 00 40 00 [0-48] 81 c3 00 10 00 00 [0-48] 8b 03 [0-48] bb [0-64] 81 c3 [0-64] 39 18 75}  //weight: 1, accuracy: Low
        $x_1_4 = {bb 00 10 40 00 [0-48] 8b 03 [0-48] bb [0-64] 81 c3 [0-64] 39 18 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_Fareit_B_2147806890_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.B!MTB"
        threat_id = "2147806890"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = {31 34 24 eb ff 00 ff (31|37) [0-255] 31 34 24 [0-255] 8b 0c 24 [0-255] 89 0c 18 [0-255] 83 c4 04 [0-255] 83 (c7|c2) 04}  //weight: 1, accuracy: Low
        $x_1_3 = {31 34 24 3d ff 00 ff (31|37) [0-255] 31 34 24 [0-255] 8b 0c 24 [0-255] 89 0c 18 [0-255] 83 c4 04 [0-255] 83 (c7|c2) 04}  //weight: 1, accuracy: Low
        $x_1_4 = {31 34 24 e9 ff 00 ff 37 [0-255] 31 34 24 [0-255] 8b 0c 24 [0-255] 83 c4 04 [0-255] 83 c2 04}  //weight: 1, accuracy: Low
        $x_1_5 = {31 34 24 85 ff 00 ff (31|37) [0-255] 31 34 24 [0-255] 8f 04 (10|18) [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
        $x_1_6 = {31 34 24 e9 ff 00 ff (31|37) [0-255] 31 34 24 [0-255] 8f 04 (10|18) [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
        $x_1_7 = {31 34 24 66 ff 00 ff (31|37) [0-255] 31 34 24 [0-255] 8f 04 (10|18) [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
        $x_1_8 = {31 34 24 3d ff 00 ff (31|37) [0-255] 31 34 24 [0-255] 8f 04 (10|18) [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
        $x_1_9 = {31 34 24 81 ff 00 ff (31|37) [0-255] 31 34 24 [0-255] 8f 04 (10|18) [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
        $x_1_10 = {31 34 24 eb ff 00 ff (31|37) [0-255] 31 34 24 [0-255] 8f 04 (10|18) [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_Fareit_C_2147806891_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.C!MTB"
        threat_id = "2147806891"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cf b2 59 8a 03 32 c2 88 01 c3}  //weight: 1, accuracy: Low
        $x_1_2 = "GCNu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_C_2147806891_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.C!MTB"
        threat_id = "2147806891"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {68 41 41 41 41 [0-16] 46 [0-16] 8b 17 [0-16] 31 f2 [0-16] 39 ca 75}  //weight: 20, accuracy: Low
        $x_5_2 = {b9 f0 5f 00 00 [0-16] 49 [0-32] 8b 14 0f [0-16] 33 14 24 [0-16] 09 14 08 [0-16] 83 f9 00 7f}  //weight: 5, accuracy: Low
        $x_5_3 = {b9 f0 5f 00 00 [0-16] 49 [0-32] 8b 14 0f [0-16] 31 f2 [0-16] 09 14 08 [0-16] 83 f9 00 7f}  //weight: 5, accuracy: Low
        $x_5_4 = {b9 f0 5f 00 00 [0-16] 83 e9 04 [0-32] 8b 14 0f [0-16] 33 14 24 [0-16] 89 14 08 [0-16] 83 f9 00 7f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Fareit_C_2147806891_2
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.C!MTB"
        threat_id = "2147806891"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = {31 34 24 85 ff 00 ff 37 [0-255] 31 34 24 [0-255] 8b 0c 24 [0-255] (01|11) 0c 18}  //weight: 1, accuracy: Low
        $x_1_3 = {31 34 24 81 ff 00 ff 37 [0-255] 31 34 24 [0-255] 8b 0c 24 [0-255] (01|11) 0c 18}  //weight: 1, accuracy: Low
        $x_1_4 = {31 34 24 66 ff 00 ff 37 [0-255] 31 34 24 [0-255] 8b 0c 24 [0-255] (01|11) 0c 18}  //weight: 1, accuracy: Low
        $x_1_5 = {31 34 24 8b ff 00 ff 37 [0-255] 31 34 24 [0-255] 8b 0c 24 [0-255] (01|11) 0c 18}  //weight: 1, accuracy: Low
        $x_1_6 = {31 34 24 e9 ff 00 ff 37 [0-255] 31 34 24 [0-255] 8b 0c 24 [0-255] (01|11) 0c 18}  //weight: 1, accuracy: Low
        $x_1_7 = {31 34 24 eb ff 00 ff 37 [0-255] 31 34 24 [0-255] 8b 0c 24 [0-255] (01|11) 0c 18}  //weight: 1, accuracy: Low
        $x_1_8 = {31 34 24 81 ff 00 00 00 00 00 00 ff 00 ff 37 [0-255] 00 00 00 00 00 [0-255] 31 34 24 [0-255] 8b 0c 24 [0-255] 01 0c 18 [0-255] 83 c4 04 [0-255] 83 c2 04}  //weight: 1, accuracy: Low
        $x_1_9 = {31 34 24 81 ff 00 00 00 00 00 00 ff 00 ff 37 [0-255] 00 00 00 00 00 [0-255] 31 34 24 [0-255] 8b 0c 24 [0-255] 85 ff [0-255] 01 0c 18 [0-255] 83 c4 04 [0-255] 83 c2 04}  //weight: 1, accuracy: Low
        $x_1_10 = {8b 0c 24 66 ff 00 31 34 24 [0-255] 01 0c 18 [0-255] 83 c4 04 [0-255] 83 c2 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_Fareit_N_2147806892_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.N!MTB"
        threat_id = "2147806892"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PQRVW=M" ascii //weight: 1
        $x_1_2 = "PQRVW9" ascii //weight: 1
        $x_1_3 = "PQRVW=" ascii //weight: 1
        $x_1_4 = "PQRVW=C" ascii //weight: 1
        $x_1_5 = "PQRVW=/" ascii //weight: 1
        $x_1_6 = "PQRVW=n1" ascii //weight: 1
        $x_1_7 = "imagehlp.dll" ascii //weight: 1
        $x_1_8 = "shell32.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_N_2147806892_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.N!MTB"
        threat_id = "2147806892"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = {31 34 24 85 ff 00 ff 37 [0-255] 31 34 24 [0-255] 85 d2 [0-255] 8b 0c 24 [0-48] 01 0c 18 [0-255] 83 c4 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_O_2147806893_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.O!MTB"
        threat_id = "2147806893"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = {ff 34 0f d9 [0-32] 31 34 24 [0-32] 8f 04 08 [0-32] 49}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 34 0f 85 [0-32] 31 34 24 [0-32] 8f 04 08 [0-32] 49}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 34 0f 3d [0-32] 31 34 24 [0-32] 8f 04 08 [0-32] 49}  //weight: 1, accuracy: Low
        $x_1_5 = {ff 34 0f 86 [0-32] 31 34 24 [0-32] 8f 04 08 [0-32] 49}  //weight: 1, accuracy: Low
        $x_1_6 = {ff 34 0f 78 [0-32] 31 34 24 [0-32] 8f 04 08 [0-32] 49}  //weight: 1, accuracy: Low
        $x_1_7 = {ff 34 0f 79 [0-32] 31 34 24 [0-32] 8f 04 08 [0-32] 49}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_Fareit_Q_2147806894_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.Q!MTB"
        threat_id = "2147806894"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = {31 34 24 33 ff 00 ff 37 [0-255] 31 34 24 [0-255] 8b 0c 24 [0-255] 01 0c 18 [0-255] 83 c4 04}  //weight: 1, accuracy: Low
        $x_1_3 = {31 34 24 3d ff 00 ff 37 [0-255] 31 34 24 [0-255] 8b 0c 24 [0-255] 01 0c 18 [0-255] 83 c4 04}  //weight: 1, accuracy: Low
        $x_1_4 = {31 34 24 66 ff 00 ff 37 [0-255] 31 34 24 [0-255] 8b 0c 24 [0-255] 85 c0 [0-255] 01 0c 18 [0-255] 83 c4 04 [0-255] 83 c2 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_Fareit_R_2147806895_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.R!MTB"
        threat_id = "2147806895"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = {31 34 24 66 ff 00 ff 37 [0-255] 31 34 24 [0-255] 8b 0c 24 [0-255] 00 00 00 00 00 00 00 [0-255] 01 0c 18 [0-255] 83 c4 04 [0-255] 83 c2 04}  //weight: 1, accuracy: Low
        $x_1_3 = {31 34 24 e9 ff 00 ff 37 [0-255] 31 34 24 [0-255] 8b 0c 24 [0-255] 00 00 00 00 00 00 00 [0-255] 01 0c 18 [0-255] 83 c4 04 [0-255] 83 c2 04}  //weight: 1, accuracy: Low
        $x_1_4 = {31 34 24 85 ff 00 ff 37 [0-255] 31 34 24 [0-255] 8b 0c 24 [0-255] 00 00 00 00 00 00 00 [0-255] 01 0c 18 [0-255] 83 c4 04 [0-255] 83 c2 04}  //weight: 1, accuracy: Low
        $x_1_5 = {31 34 24 85 ff 00 ff 37 [0-255] 31 34 24 [0-255] 8b 0c 24 [0-255] 85 (ff|d2) [0-255] 01 0c 18 [0-255] 83 c4 04 [0-255] 83 c2 04}  //weight: 1, accuracy: Low
        $x_1_6 = {31 34 24 66 ff 00 ff 37 [0-255] 31 34 24 [0-255] 89 0c 10 [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
        $x_1_7 = {31 34 24 85 ff 00 ff 37 [0-255] 31 34 24 [0-255] 89 0c 10 [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_Fareit_S_2147806896_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.S!MTB"
        threat_id = "2147806896"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 34 1f 71 [0-64] 58 [0-160] 35 [0-160] 89 04 1f [0-160] 43 [0-160] 43 [0-160] 43 [0-160] 43 [0-160] 39 d3 (75|0f 85)}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 34 1f eb [0-64] 58 [0-160] 35 [0-160] 89 04 1f [0-160] 43 [0-160] 43 [0-160] 43 [0-160] 43 [0-160] 39 d3 (75|0f 85)}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 34 1f 71 [0-64] 58 [0-160] 35 [0-160] 89 04 1f [0-160] 83 c3 04 [0-160] 39 d3 03 01 02 02 75 0f 85 75 c9}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 34 1f eb [0-64] 58 [0-160] 35 [0-160] 89 04 1f [0-160] 83 c3 04 [0-160] 39 d3 03 01 02 02 75 0f 85 75 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Fareit_T_2147806897_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.T!MTB"
        threat_id = "2147806897"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = {31 34 24 66 ff 00 ff 37 [0-255] 31 34 24 [0-255] (8b|89) 0c 10 [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
        $x_1_3 = {31 34 24 e9 ff 00 ff 37 [0-255] 31 34 24 [0-255] (8b|89) 0c 10 [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
        $x_1_4 = {31 34 24 85 ff 00 ff 37 [0-255] 31 34 24 [0-255] (8b|89) 0c 10 [0-255] 83 c2 04 [0-255] 83 c7 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_Fareit_W_2147806898_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.W!MTB"
        threat_id = "2147806898"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = {31 34 24 eb 50 00 ff 37 [0-255] 31 34 24 [0-255] e8 [0-255] [0-255] 83 c2 04 [0-255] 83 d7 04 [0-255] 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {31 34 24 85 50 00 ff 37 [0-255] 31 34 24 [0-255] e8 [0-255] [0-255] 83 c2 04 [0-255] 83 d7 04 [0-255] 0f 85}  //weight: 1, accuracy: Low
        $x_1_4 = {31 34 24 66 50 00 ff 37 [0-255] 31 34 24 [0-255] e8 [0-255] [0-255] 83 c2 04 [0-255] 83 d7 04 [0-255] 0f 85}  //weight: 1, accuracy: Low
        $x_1_5 = {83 c2 04 66 ff 00 31 f1 [0-255] e8 [0-255] 83 c2 04 [0-255] 83 d7 04 [0-255] 0f 85 [0-255] 51 [0-255] 8f 04 18}  //weight: 1, accuracy: Low
        $x_1_6 = {83 c2 04 85 ff 00 31 f1 [0-255] e8 [0-255] 83 c2 04 [0-255] 83 d7 04 [0-255] 0f 85 [0-255] 51 [0-255] 8f 04 18}  //weight: 1, accuracy: Low
        $x_1_7 = {83 c2 04 eb ff 00 31 f1 [0-255] e8 [0-255] 83 c2 04 [0-255] 83 d7 04 [0-255] 0f 85 [0-255] 51 [0-255] 8f 04 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_Fareit_X_2147806899_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.X!MTB"
        threat_id = "2147806899"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = {83 c7 04 66 [0-64] e9 ff 00 83 ?? 04 40 00 01 0b 40 00 01 d3 60 00 5b 30 00 50 ff 00 31 f1 30 00 8b 09}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c7 04 eb [0-64] e9 ff 00 83 ?? 04 40 00 01 0b 40 00 01 d3 60 00 5b 30 00 50 ff 00 31 f1 30 00 8b 09}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c7 04 85 [0-64] e9 ff 00 83 ?? 04 40 00 01 0b 40 00 01 d3 60 00 5b 30 00 50 ff 00 31 f1 30 00 8b 09}  //weight: 1, accuracy: Low
        $x_1_5 = {83 d7 04 66 [0-64] e9 ff 00 83 ?? 04 40 00 01 0b 40 00 01 d3 60 00 5b 30 00 50 ff 00 31 f1 30 00 8b 09}  //weight: 1, accuracy: Low
        $x_1_6 = {83 d7 04 eb [0-64] e9 ff 00 83 ?? 04 40 00 01 0b 40 00 01 d3 60 00 5b 30 00 50 ff 00 31 f1 30 00 8b 09}  //weight: 1, accuracy: Low
        $x_1_7 = {83 d7 04 85 [0-64] e9 ff 00 83 ?? 04 40 00 01 0b 40 00 01 d3 60 00 5b 30 00 50 ff 00 31 f1 30 00 8b 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_Fareit_Y_2147806900_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.Y!MTB"
        threat_id = "2147806900"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 34 24 3d 50 00 ff 37 [0-255] 31 34 24 [0-255] 59 [0-255] (83|83) [0-255] 51 [0-255] 8f 04 18}  //weight: 1, accuracy: Low
        $x_1_2 = {31 34 24 85 50 00 ff 37 [0-255] 31 34 24 [0-255] 59 [0-255] (83|83) [0-255] 51 [0-255] 8f 04 18}  //weight: 1, accuracy: Low
        $x_1_3 = {31 34 24 eb 50 00 ff 37 [0-255] 31 34 24 [0-255] 59 [0-255] (83|83) [0-255] 51 [0-255] 8f 04 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Fareit_AA_2147806901_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.AA!MTB"
        threat_id = "2147806901"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c1 04 eb ff 02 (14 14 14|00 00 00) ff 02 8f 04 08 ff 02 81 34 24 ff 02 ff 34 08}  //weight: 1, accuracy: Low
        $x_1_2 = {14 83 c1 04 ff 02 (14 14 14|00 00 00) ff 02 8f 04 08 ff 02 81 34 24 ff 02 ff 34 08}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c1 04 14 ff 02 (14 14 14|00 00 00) ff 02 8f 04 08 ff 02 81 34 24 ff 02 ff 34 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Fareit_AB_2147806902_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.AB!MTB"
        threat_id = "2147806902"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 0c 24 eb [0-64] 31 34 24 [0-64] 59 [0-64] 89 0c 18 [0-64] 83 c2 04 [0-64] 83 c7 04}  //weight: 1, accuracy: Low
        $x_1_2 = {89 0c 24 8b [0-64] 31 34 24 [0-64] 59 [0-64] 89 0c 18 [0-64] 83 c2 04 [0-64] 83 c7 04}  //weight: 1, accuracy: Low
        $x_1_3 = {89 0c 24 66 [0-64] 31 34 24 [0-64] 59 [0-64] 89 0c 18 [0-64] 83 c2 04 [0-64] 83 c7 04}  //weight: 1, accuracy: Low
        $x_1_4 = {89 0c 24 85 [0-64] 31 34 24 [0-64] 59 [0-64] 89 0c 18 [0-64] 83 c2 04 [0-64] 83 c7 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Fareit_AC_2147806903_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.AC!MTB"
        threat_id = "2147806903"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 0c 18 66 ff 00 8b 0f [0-255] 31 f1 [0-255] 11 0c 18 [0-255] 83 (c2|d2) 04 [0-255] 83 (d7|c7) 04}  //weight: 1, accuracy: Low
        $x_1_2 = {11 0c 18 81 ff 00 8b 0f [0-255] 31 f1 [0-255] 11 0c 18 [0-255] 83 (c2|d2) 04 [0-255] 83 (d7|c7) 04}  //weight: 1, accuracy: Low
        $x_1_3 = {11 0c 18 85 ff 00 8b 0f [0-255] 31 f1 [0-255] 11 0c 18 [0-255] 83 (c2|d2) 04 [0-255] 83 (d7|c7) 04}  //weight: 1, accuracy: Low
        $x_1_4 = {01 0c 18 85 ff 00 8b 0f [0-255] 31 f1 [0-255] 11 0c 18 [0-255] 83 (c2|d2) 04 [0-255] 83 (d7|c7) 04}  //weight: 1, accuracy: Low
        $x_1_5 = {11 0c 18 eb ff 00 8b 0f [0-255] 31 f1 [0-255] 11 0c 18 [0-255] 83 (c2|d2) 04 [0-255] 83 (d7|c7) 04}  //weight: 1, accuracy: Low
        $x_1_6 = {11 0c 18 83 ff 00 8b 0f [0-255] 31 f1 [0-255] 11 0c 18 [0-255] 83 (c2|d2) 04 [0-255] 83 (d7|c7) 04}  //weight: 1, accuracy: Low
        $x_1_7 = {11 0c 18 3d 00 02 8b 0f [0-255] 00 00 00 00 00 00 [0-255] 31 f1 [0-255] 11 0c 18 [0-255] 83 (c2|d2) 04 [0-255] 83 (d7|c7) 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Fareit_AF_2147806904_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.AF!MTB"
        threat_id = "2147806904"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 0c 24 eb 40 00 8b 0f [0-160] 31 34 24 [0-80] 59 [0-80] 89 0c 18 [0-80] 83 c2 04 [0-80] 83 d7 04 [0-80] eb}  //weight: 1, accuracy: Low
        $x_1_2 = {89 0c 24 81 40 00 8b 0f [0-160] 31 34 24 [0-80] 59 [0-80] 89 0c 18 [0-80] 83 c2 04 [0-80] 83 d7 04 [0-80] eb}  //weight: 1, accuracy: Low
        $x_1_3 = {89 0c 24 85 40 00 8b 0f [0-160] 31 34 24 [0-80] 59 [0-80] 89 0c 18 [0-80] 83 c2 04 [0-80] 83 d7 04 [0-80] eb}  //weight: 1, accuracy: Low
        $x_1_4 = {89 0c 24 66 40 00 8b 0f [0-160] 31 34 24 [0-80] 59 [0-80] 89 0c 18 [0-80] 83 c2 04 [0-80] 83 d7 04 [0-80] eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Fareit_AG_2147806905_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.AG!MTB"
        threat_id = "2147806905"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 34 08 81 [0-64] 81 34 24 [0-64] 8f 04 08 [0-64] 83 c1 04}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 34 08 3d [0-64] 81 34 24 [0-64] 8f 04 08 [0-64] 83 c1 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Fareit_AH_2147806906_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.AH!MTB"
        threat_id = "2147806906"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 34 24 0f ff 00 ff 37 [0-255] 59 [0-255] 89 0c 18 [0-255] 83 (d2|c2) 04 [0-255] 83 (c7|d7) 04}  //weight: 1, accuracy: Low
        $x_1_2 = {31 34 24 f2 ff 00 ff 37 [0-255] 59 [0-255] 89 0c 18 [0-255] 83 (d2|c2) 04 [0-255] 83 (d7|c7) 04}  //weight: 1, accuracy: Low
        $x_1_3 = {31 34 24 66 ff 00 ff 37 [0-255] 59 [0-255] 89 0c 18 [0-255] 83 (d2|c2) 04 [0-255] 83 (d7|c7) 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Fareit_AI_2147806907_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.AI!MTB"
        threat_id = "2147806907"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c7 04 81 ff 00 83 c2 04 ff 00 31 0b ff 00 31 f1 ff 00 8b 09}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c7 04 66 ff 00 83 c2 04 ff 00 31 0b ff 00 31 f1 ff 00 8b 09}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c7 04 85 ff 00 83 c2 04 ff 00 31 0b ff 00 31 f1 ff 00 8b 09}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c7 04 eb ff 00 83 c2 04 ff 00 31 0b ff 00 31 f1 ff 00 8b 09}  //weight: 1, accuracy: Low
        $x_1_5 = {83 c7 04 66 ff 00 83 c2 04 ff 00 31 0b 00 02 31 f1 ff 00 8b 09}  //weight: 1, accuracy: Low
        $x_1_6 = {83 c7 04 eb ff 00 83 c2 04 ff 00 (09|31) 0c 10 ff 00 31 f1 ff 00 59 ff 00 ff 31}  //weight: 1, accuracy: Low
        $x_1_7 = {83 c7 04 81 ff 00 83 c2 04 ff 00 (09|31) 0c 10 ff 00 31 f1 ff 00 59 ff 00 ff 31}  //weight: 1, accuracy: Low
        $x_1_8 = {83 c7 04 66 ff 00 83 c2 04 ff 00 (09|31) 0c 10 ff 00 31 f1 ff 00 59 ff 00 ff 31}  //weight: 1, accuracy: Low
        $x_1_9 = {83 c7 04 85 ff 00 83 c2 04 ff 00 (09|31) 0c 10 ff 00 31 f1 ff 00 59 ff 00 ff 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Fareit_AJ_2147806908_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.AJ!MTB"
        threat_id = "2147806908"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 62 3c 0a 75 [0-255] 81 f7 [0-255] 31 3c 08 [0-255] 49 [0-64] 49 [0-64] 49 [0-64] 49}  //weight: 1, accuracy: Low
        $x_1_2 = {38 62 3c 0a eb [0-255] 81 f7 [0-255] 31 3c 08 [0-255] 49 [0-64] 49 [0-64] 49 [0-64] 49}  //weight: 1, accuracy: Low
        $x_1_3 = {38 62 3c 0a 71 [0-255] 81 f7 [0-255] 31 3c 08 [0-255] 49 [0-64] 49 [0-64] 49 [0-64] 49}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Fareit_AK_2147806909_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.AK!MTB"
        threat_id = "2147806909"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 34 24 0f 40 00 ff 37 [0-255] 59 [0-255] (89|09) 0c 18 [0-255] 83 (c2|d2) 04 [0-255] 83 (d7|c7) 04}  //weight: 1, accuracy: Low
        $x_1_2 = {31 34 24 66 40 00 ff 37 [0-255] 59 [0-255] (89|09) 0c 18 [0-255] 83 (c2|d2) 04 [0-255] 83 (d7|c7) 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Fareit_AM_2147806910_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.AM!MTB"
        threat_id = "2147806910"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1a 80 f3 ?? 8b f9 03 f8 73 05 [0-10] 88 1f [0-32] 40 42 3d [0-16] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_AQ_2147806911_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.AQ!MTB"
        threat_id = "2147806911"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 34 01 7e [0-64] 41 [0-80] 39 d9 [0-64] 75 [0-80] 05 ?? ?? 00 00 [0-80] ff e1}  //weight: 1, accuracy: Low
        $x_1_2 = {89 c9 80 34 01 [0-64] 41 [0-80] 39 d9 [0-64] 75 [0-80] 05 ?? ?? 00 00 [0-80] ff e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Fareit_AM_2147806912_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.AM"
        threat_id = "2147806912"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 6a 40 68 78 59 00 00 57 e8 aa 2e fa ff [0-4] 33 d2 33 c0 89 04 24 b8 [0-5] 8b f7 03 f2 [0-3] 8a 08 [0-3] 80 f1 4e [0-3] 88 0e [0-13] ff 04 24 40 81 3c 24 79 59 00 00 75 d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_BA_2147806913_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.BA!MTB"
        threat_id = "2147806913"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 49 00 6e 00 73 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 56 00 4c 00 43 00}  //weight: 1, accuracy: High
        $x_1_2 = {4c 00 65 00 67 00 61 00 6c 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 49 00 6e 00 73 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 56 00 4c 00 43 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_K_2147806914_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.K!MTB"
        threat_id = "2147806914"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QQPCRealTimeSpeedup.exe" wide //weight: 1
        $x_1_2 = "Dognaping" ascii //weight: 1
        $x_1_3 = "Hallowell" ascii //weight: 1
        $x_1_4 = "Dreyfuss7" ascii //weight: 1
        $x_1_5 = "Precuneus6" ascii //weight: 1
        $x_1_6 = "Hokeypokey4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_K_2147806914_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.K!MTB"
        threat_id = "2147806914"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b9 77 00 00 00 6a 00 e2 fc 68 ?? ?? ?? ?? 6a 00 68 e8 01 00 00 89 65 10 81 c4 e8 01 00 00 e9 ?? ?? 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {0f 31 49 29 c2 50 5a 83 f9 02 75 f4 01 cb 02 5d 64 ff d3 e8 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_1_3 = "shell32" ascii //weight: 1
        $n_1_4 = "shell32.dll" ascii //weight: -1
        $x_1_5 = "kernel32" ascii //weight: 1
        $n_1_6 = "kernel32.dll" ascii //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Fareit_E_2147806915_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.E!MTB"
        threat_id = "2147806915"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 33 c2 8b 8d ?? ff ff ff 8b 15 ?? ?? ?? 00 89 04 8a c7 45 fc 06 00 00 00 a1 ?? ?? ?? 00 99 6a 01 59 f7 f9 83 f2 01 89 55 84 c7 85 7c ff ff ff 03 00 00 00 8d 95 7c ff ff ff 8d 4d 9c e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_F_2147806916_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.F!MTB"
        threat_id = "2147806916"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shareit.exe" wide //weight: 1
        $x_1_2 = "MiusyLaTroio009" wide //weight: 1
        $x_1_3 = "NOMELMOZO" wide //weight: 1
        $x_1_4 = "CallWindowProcW" wide //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_I_2147806917_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.I!MTB"
        threat_id = "2147806917"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 34 1f 52 81 f2 ?? ?? ?? ?? 5a 68 ?? ?? ?? ?? 68}  //weight: 1, accuracy: Low
        $x_1_2 = {89 14 18 52 81 f2 ?? ?? ?? ?? 5a [0-255] 83 c4 08 83 fb 00 0f 85 ?? ?? ff ff eb}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 54 24 04}  //weight: 1, accuracy: High
        $x_1_4 = {58 31 f2 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_L_2147806918_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.L!MTB"
        threat_id = "2147806918"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wbrowsers_passwords.log" wide //weight: 1
        $x_1_2 = "%s\\%sPasswords.log" ascii //weight: 1
        $x_1_3 = "SELECT origin_url, username_value, password_value FROM logins" ascii //weight: 1
        $x_1_4 = "password:%ls" wide //weight: 1
        $x_1_5 = "file%d.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_M_2147806919_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.M!MTB"
        threat_id = "2147806919"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dumbstruckfg" wide //weight: 1
        $x_1_2 = "Afstemningsresultater" ascii //weight: 1
        $x_1_3 = "wheelbarrower" ascii //weight: 1
        $x_1_4 = "Dyrehospitalets4" ascii //weight: 1
        $x_1_5 = "Alderssukkersyge9" ascii //weight: 1
        $x_1_6 = "SPACIEST" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_P_2147806920_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.P!MTB"
        threat_id = "2147806920"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 44 24 18 46 a3 ?? ?? ?? ?? c1 e8 ?? 30 44 3e ff 3b f3 7c 1b 00 a1 ?? ?? ?? ?? c7 44 24 18 ?? ?? ?? ?? 81 44 24 18 ?? ?? ?? ?? 69 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {03 04 24 8b c8 a3 ?? ?? ?? ?? 8b 44 24 08 c1 e9 ?? 30 08 19 00 a1 ?? ?? ?? ?? c7 04 24 ?? ?? ?? ?? 81 04 24 ?? ?? ?? ?? 69 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Fareit_P_2147806920_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.P!MTB"
        threat_id = "2147806920"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0c 28 0f b6 54 28 01 88 4c 24 11 0f b6 4c 28 02 8a 44 28 03 88 54 24 12 8d 54 24 11 52 8d 74 24 17 8d 7c 24 16 88 4c 24 17 e8 ?? ?? ?? ?? 0f b6 4c 24 15 8b 44 24 18 0f b6 54 24 16 88 0c 03 0f b6 4c 24 17 88 54 03 01 8b 54 24 20 88 4c 03 02 83 c5 ?? 83 c4 ?? 83 c3 ?? 3b 2a 72 05 00 a1}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 0c 01 44 24 04 89 0c 24 c1 24 24 04 01 14 24 03 4c 24 10 89 4c 24 10 8b 44 24 10 31 04 24 8b 44 24 04 31 04 24 8b 04 24 83 c4 ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_AE_2147806921_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.AE!MTB"
        threat_id = "2147806921"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 6e fe 85 [0-21] 0f 6e da [0-21] 31 f2 [0-21] c3}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 6e fe 83 [0-21] 0f 6e da [0-21] 31 f2 [0-21] c3}  //weight: 1, accuracy: Low
        $x_1_3 = {0f 6e fe 3d [0-21] 0f 6e da [0-21] 31 f2 [0-21] c3}  //weight: 1, accuracy: Low
        $x_1_4 = {0f 6e fe 81 [0-21] 0f 6e da [0-21] 31 f2 [0-21] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Fareit_VB_2147806922_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.VB!MTB"
        threat_id = "2147806922"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "kfmjNRKLVcMKWpD4wgrGQ4XBWxy1g8qJuzYKFz114" wide //weight: 1
        $x_1_3 = "hKrFWwZEtJj9MBrGB4tzk0y240" wide //weight: 1
        $x_1_4 = "dMjHvgR9YEG82Dmj2luAy01y7cbe02kXuQnE9Vcd22" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_DEA_2147806923_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.DEA!MTB"
        threat_id = "2147806923"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mSZPba2fBf7bodjzEtJ4b9eagShyMG7A99" wide //weight: 1
        $x_1_2 = "Selvantndelsernes5" wide //weight: 1
        $x_1_3 = "Tekstmarkeringerne7" wide //weight: 1
        $x_1_4 = "Mentalundersgende6" wide //weight: 1
        $x_1_5 = "udlgstidspunkters" wide //weight: 1
        $x_1_6 = "Sammentrngninger7" wide //weight: 1
        $x_1_7 = "Salpetersyrefabrikker9" wide //weight: 1
        $x_1_8 = "CrEpGaXlFaqMZpcbXqN79" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Fareit_DEB_2147806924_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.DEB!MTB"
        threat_id = "2147806924"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SVOVLDIOXIDUDSENDELSENS" ascii //weight: 1
        $x_1_2 = "Flugtskydningsbanen5" ascii //weight: 1
        $x_1_3 = "Agerhnsjagten2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_RP_2147806925_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.RP!MTB"
        threat_id = "2147806925"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cfokp982Bfu" ascii //weight: 1
        $x_1_2 = "http://butterchoco.net/admin/bull/gate.php" ascii //weight: 1
        $x_1_3 = "YUIPWDFILE0YUIPKDFILE0YUICRYPTED0YUI1.0" ascii //weight: 1
        $x_1_4 = "{74FF1730-B1F2-4D88-926B-1568FAE61DB7}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_RT_2147806926_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.RT!MTB"
        threat_id = "2147806926"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@shell32.dll,-21813" wide //weight: 1
        $x_1_2 = "emgkgtgnnmnmninigthkgogggvmkhinjggnvm" wide //weight: 1
        $x_1_3 = "Arvi@Sehmi.org.uk" wide //weight: 1
        $x_1_4 = "www.Arvinder.co.uk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_RTU_2147806927_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.RTU!MTB"
        threat_id = "2147806927"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://akdoganevdeneve.net/wp-content/Panel/gate.php" ascii //weight: 10
        $x_10_2 = "YUIPWDFILE0YUIPKDFILE0YUICRYPTED0YUI1.0" ascii //weight: 10
        $x_10_3 = "Oguqcogtkec" ascii //weight: 10
        $x_1_4 = "GetNativeSystemInfo" ascii //weight: 1
        $x_1_5 = "outlook account manager passwords" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Fareit_MR_2147806928_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.MR!MTB"
        threat_id = "2147806928"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1a 80 f3 ?? 88 5d [0-6] 8b 5d ?? 8b fb 8a 5d ?? 88 1f [0-4] 83 c6 ?? 73 ?? e8 [0-12] 42 49 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_MS_2147806929_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.MS!MTB"
        threat_id = "2147806929"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Data\\AccCfg\\Accounts.tdat" wide //weight: 1
        $x_1_2 = "Software\\Microsoft\\Internet Explorer\\TypedURLs" wide //weight: 1
        $x_1_3 = "SELECT encryptedUsername, encryptedPassword, formSubmitURL, hostname FROM moz_logins" ascii //weight: 1
        $x_1_4 = "%s\\signons.sqlite" wide //weight: 1
        $x_1_5 = "%s\\K-Meleon\\profiles.ini" wide //weight: 1
        $x_1_6 = {25 00 73 00 5c 00 38 00 70 00 65 00 63 00 78 00 73 00 74 00 75 00 64 00 69 00 6f 00 73 00 5c 00 43 00 79 00 62 00 65 00 72 00 66 00 6f 00 78 00 5c 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 73 00 2e 00 69 00 36 45 00 69 00}  //weight: 1, accuracy: High
        $x_1_7 = "%s\\NETGATE\\Black Hawk" wide //weight: 1
        $x_1_8 = "form_password_control" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win32_Fareit_2147806930_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.MT!MTB"
        threat_id = "2147806930"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c0 8a 45 ?? 30 45 ?? 89 db 89 db 8b 45 ?? 8a 55 ?? 88 10 06 00 8a 45 ?? 88 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_MU_2147806931_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.MU!MTB"
        threat_id = "2147806931"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c6 03 c7 [0-1] a3 [0-6] 88 15 [0-5] 8b 0d [0-4] a0 [0-4] 88 01 [0-3] 47 81 ff [0-4] 75 12 00 8b c7 [0-4] 8a [0-5] 32 d3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_MW_2147806932_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.MW!MTB"
        threat_id = "2147806932"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 cb 83 c3 ?? 8d 0b c1 c1 ?? d1 c9 6a ?? 8f 02 01 1a 8d 52 ?? 83 ef ?? ?? ?? ?? 8d 1d ?? ?? ?? ?? 8d 9b 09 00 83 ee ?? 83 c3 ?? c1 cb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_SC_2147806933_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.SC!MTB"
        threat_id = "2147806933"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JTnK2dZsBI4C6tgWKWZ219" wide //weight: 1
        $x_1_2 = "E6ig8Y2hHCbKHG918" wide //weight: 1
        $x_1_3 = "Hopelesslydepotindehave" wide //weight: 1
        $x_2_4 = "Hospitatorkidnaperssubconcession" wide //weight: 2
        $x_1_5 = {89 0b eb 08}  //weight: 1, accuracy: High
        $x_1_6 = {83 c2 04 66 85 d2 66 81 fb 25 d3}  //weight: 1, accuracy: High
        $x_1_7 = {66 81 fb 15 18 85 ff 81 fa 0c bb 00 00 eb 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Fareit_SW_2147806934_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.SW!MTB"
        threat_id = "2147806934"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZJ2EB7lCm504Pq1bjLMM7Nxc2JZn7Xe8F4QMA158" wide //weight: 1
        $x_1_2 = "BuH7JuRy0edXBcaIH0Jm2rieRQHu3Fnh95" wide //weight: 1
        $x_1_3 = "VanWV197" wide //weight: 1
        $x_1_4 = "DiDaESkZHn5bQ0js2" wide //weight: 1
        $x_1_5 = "No800gc2ts6ZP5oQpdFjm38" wide //weight: 1
        $x_1_6 = "HiiAKrixjKBfFtg34V73DRMYsYTo3OHfYOHu112" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_SI_2147806935_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.SI!MTB"
        threat_id = "2147806935"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 0b 85 ff 66 81 ff d3 c7 eb 03 00 00 00 83 c2 04 66 81 fb f7 9a 3d a3 a2 5f 1e eb 08 00 00 00 00 00 00 00 00 83 c7 04 66 3d 0f f5 66 81 fb 22 65 eb 09 00 00 00 00 00 00 00 00 00 81 fa f4 b9 00 00 74 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_HL_2147806936_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.HL!MTB"
        threat_id = "2147806936"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 f3 51 b9 00 00 00 00 01 d9 31 01 59 5b 51 b9 ?? ?? ?? ?? 01 f1 68 ?? ?? ?? ?? 89 04 24 b8 ?? ?? ?? ?? 01 c8 01 18 58 59 55 89 04 24 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_JK_2147806937_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.JK!MTB"
        threat_id = "2147806937"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 e8 f9 fe ?? ?? ba ?? ?? ?? ?? b8 ?? ?? ?? ?? 31 c9 80 34 01 fd 41 89 c9 39 d1 [0-2] 75 ?? 05 ?? ?? ?? ?? ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_MK_2147806938_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.MK!MTB"
        threat_id = "2147806938"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_2_2 = "SMSvcHost_Perf_lock" wide //weight: 2
        $x_2_3 = "SMSvcHost_UAC_lock" wide //weight: 2
        $x_1_4 = "Software\\classes\\mscfile\\shell\\open\\command" wide //weight: 1
        $x_1_5 = "mshta.exe" wide //weight: 1
        $x_10_6 = "Software\\Microsoft\\SMSvcHost" wide //weight: 10
        $x_2_7 = "SELECT * FROM CIM_OperatingSystem" wide //weight: 2
        $x_2_8 = "SELECT * FROM CIM_Processor" wide //weight: 2
        $x_2_9 = "SELECT * FROM CIM_DiskDrive" wide //weight: 2
        $x_2_10 = "SELECT * FROM AntiVirusProduct" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_SMBD_2147806939_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.SMBD!MTB"
        threat_id = "2147806939"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 14 71 8d 7a bf 83 ff 19 0f 87 03 00 00 00 83 c2 20 66 89 14 71 46 3b f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_ZT_2147806940_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.ZT!MTB"
        threat_id = "2147806940"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 43 8b 32 42 42 42 42 8a 06 88 07 46 47 49 75 f7 0f b7 0b 81 f9 7a 17 00 00 72 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_VBB_2147806941_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.VBB!MTB"
        threat_id = "2147806941"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0b ff ab 4a 0b ff ab 4a 0c ff ab 4a 0b ff ab 4a 0c ff ab 4a 0b ff ab 4a 0b ff ab 49 0c ff ab 4a 0b ff ab 4a 0c ff ab 4a 0b ff ab 4a 0b ff ab 4a 0c ff ab 4a 0b ff ab 4a 0c ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_STEF_2147806942_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.STEF!MTB"
        threat_id = "2147806942"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AlienRunPE.AlienRunPE" ascii //weight: 1
        $x_1_2 = "ConvertFromUtf32" ascii //weight: 1
        $x_1_3 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_4 = "WriteByte" ascii //weight: 1
        $x_1_5 = "DownloadString" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
        $x_1_7 = "StringComparison" ascii //weight: 1
        $x_1_8 = "PooledStringBuilder" ascii //weight: 1
        $x_1_9 = "LoopTimer" ascii //weight: 1
        $x_1_10 = "Roslyn.Utilities" ascii //weight: 1
        $x_1_11 = "VirtualProtect" ascii //weight: 1
        $x_1_12 = "WebClient" ascii //weight: 1
        $x_1_13 = "ResumeLayout" ascii //weight: 1
        $x_1_14 = "get_Assembly" ascii //weight: 1
        $x_1_15 = "RtlMoveMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fareit_Fareit_2147806943_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit!!Fareit.gen!A"
        threat_id = "2147806943"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/gate.php" ascii //weight: 1
        $x_2_2 = "PWDFILE0YUIPKDFILE0YUICRYPTED" ascii //weight: 2
        $x_1_3 = "Software\\WinRAR" ascii //weight: 1
        $x_1_4 = "Software\\Far2\\SavedDialogHistory\\FTPHost" ascii //weight: 1
        $x_1_5 = {48 57 49 44 [0-5] 7b 25 30 38 58 2d 25 30 34 58 2d 25 30 34 58 2d 25 30 32 58 25 30 32 58 2d 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Fareit_E_2147806944_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.gen!E!!Fareit.gen!E"
        threat_id = "2147806944"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "Fareit: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "E: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Far2\\SavedDialogHistory\\FTPHost" ascii //weight: 1
        $x_1_2 = "\\VanDyke\\Config\\Sessions" ascii //weight: 1
        $x_2_3 = {00 6f 69 64 2e 62 61 74 00}  //weight: 2, accuracy: High
        $x_2_4 = {00 61 62 63 64 2e 62 61 74 00}  //weight: 2, accuracy: High
        $x_10_5 = {80 3f 09 74 19 80 3f 0d 74 14 80 3f 0a 74 0f 80 3f 5b 74 0a 80 3f 5d 74 05 80 3f 60 75 03 c6 07 20 47 80 3f 00 75 d9}  //weight: 10, accuracy: High
        $x_10_6 = {eb 2d 8b 17 8b 45 08 25 ff 7f ff ff 39 42 04 75 1b 6a 00 8d 42 08 50 68 ?? ?? ?? ?? ff 32 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Fareit_G_2147806945_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fareit.gen!G!!Fareit.gen!G"
        threat_id = "2147806945"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "Fareit: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "G: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 00 6a 02 ff 75 f8 6a 00 ff 73 04 ff 15 ?? ?? ?? ?? 0b c0 74 ?? ff 75 f8 e8 ?? ?? ?? ?? eb ?? ff 75 f8 e8 ?? ?? ?? ?? bf ?? ?? ?? ?? c7 45 fc 00 00 00 00 8d 45 fc 50 6a 00 6a 02 57 6a 00 ff 73 04 ff 15 ?? ?? ?? ?? 0b c0 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = "PKDFILE0YUICRYPTED0YUI1.0" ascii //weight: 1
        $x_1_3 = "PWDFILE0YUI" ascii //weight: 1
        $x_1_4 = {00 43 6c 69 65 6e 74 20 48 61 73 68 00 53 54 41 54 55 53 2d 49 4d 50 4f 52 54 2d 4f 4b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

