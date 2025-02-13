rule Rogue_Win32_FakePowav_129024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePowav"
        threat_id = "129024"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePowav"
        severity = "21"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {59 47 48 65 6c 70 65 72 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_2 = "YGHelper.SearchHelper" ascii //weight: 1
        $x_1_3 = "1F2D9C47-6AC9-4872-AACC-E1CD494F040C" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakePowav_129024_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePowav"
        threat_id = "129024"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePowav"
        severity = "21"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {67 6f 6f 67 6c 69 6e 61 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 10, accuracy: High
        $x_1_2 = "44d6897b-66fb-4d19-8f5a-5caf3665c13f" ascii //weight: 1
        $x_1_3 = "b6681c49-c882-4484-b59e-329f6fc5a3b7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePowav_129024_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePowav"
        threat_id = "129024"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePowav"
        severity = "21"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rapidantivirus.com" ascii //weight: 1
        $x_1_2 = "[Spyware.CyberAlert2;" ascii //weight: 1
        $x_1_3 = "ProcessesToKill=1" ascii //weight: 1
        $x_1_4 = "RegKeysValueToDelete=1" ascii //weight: 1
        $x_1_5 = "Description:" ascii //weight: 1
        $x_1_6 = "Advice:" ascii //weight: 1
        $x_1_7 = "Alert level:" ascii //weight: 1
        $x_1_8 = "Windows\\CurrentVersion\\Run\\\"Default\"" ascii //weight: 1
        $x_1_9 = "support@eurekalog.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Rogue_Win32_FakePowav_129024_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePowav"
        threat_id = "129024"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePowav"
        severity = "21"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_10_2 = "HowToBuy.txt" ascii //weight: 10
        $x_10_3 = "C:\\Documents and Settings\\JohnDoe\\Deskto" ascii //weight: 10
        $x_10_4 = "Are you sure you want to uninstall" ascii //weight: 10
        $x_1_5 = "\\Rapid Antivirus" ascii //weight: 1
        $x_1_6 = {57 69 6e 58 20 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_7 = "\\Win Antivir 2008" ascii //weight: 1
        $x_1_8 = "WinXDefender" ascii //weight: 1
        $x_1_9 = "WinXProtector" ascii //weight: 1
        $x_1_10 = "Power-Antivirus-2009" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePowav_129024_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePowav"
        threat_id = "129024"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePowav"
        severity = "21"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 5a 59 59 64 89 10 68 ?? ?? ?? ?? 8d 45 ?? ba ?? 00 00 00 e8 ?? ?? ?? ?? c3 e9 ?? ?? ?? ?? eb eb 5b e8 [0-32] 55 6e 69 6e 73 74 61 6c 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = "HowToBuy.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakePowav_129024_5
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePowav"
        threat_id = "129024"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePowav"
        severity = "21"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7c c6 8b 41 50 8b 49 34 8b 15}  //weight: 1, accuracy: High
        $x_1_2 = {c6 04 29 68 8b 08 8d 14 2b 89 54 29 01 8b 10 6a 01 c6 44 2a 05 c3}  //weight: 1, accuracy: High
        $x_2_3 = "softwares required for virus" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePowav_129024_6
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePowav"
        threat_id = "129024"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePowav"
        severity = "21"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 ff ff ff 00 52 ff 15 ?? ?? ?? ?? 8b 06 68 00 00 aa 00 50 ff 15}  //weight: 2, accuracy: Low
        $x_1_2 = "to delete a virus" ascii //weight: 1
        $x_1_3 = {57 41 52 4e 49 4e 47 5f 56 49 52 55 53 5f 44 45 54 45 43 54 45 44 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePowav_129024_7
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePowav"
        threat_id = "129024"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePowav"
        severity = "21"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb eb 5f 5e 5b e8 ?? ?? ?? ?? 00 ff ff ff ff 20 00 00 00 38 33 32 31 37 32 41 30 41 43 39 45 46 32 37 35 35 44 41 46 44 30 35 45 37 37 45 33 35 41 32 34 00 00 00 00 ff ff ff ff 0a 00 00 00 2d 75 6e 69 6e 73 74 61 6c 6c 00 00 ff ff ff ff 0a 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakePowav_129024_8
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePowav"
        threat_id = "129024"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePowav"
        severity = "21"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 70 79 20 50 72 6f 74 65 63 74 6f 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {6c 73 61 73 63 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_2_3 = {8b f0 6a 00 6a 1a 56 6a 00 e8 ?? ?? ff ff 8d 45 f8 8b d6 e8 ?? ?? fe ff 8b 45 f8 8d 55 fc e8 ?? ?? fe ff 8b 55 fc 8b c3 b9 ?? ?? ?? ?? e8 ?? ?? fe ff 8b c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakePowav_129024_9
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePowav"
        threat_id = "129024"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePowav"
        severity = "21"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2f 69 6e 73 74 61 6c 6c 6f 6b 3f 72 65 66 5f 69 64 3d 00}  //weight: 2, accuracy: High
        $x_2_2 = {26 73 75 62 5f 69 64 3d 00}  //weight: 2, accuracy: High
        $x_1_3 = {2f 69 6e 73 74 61 6c 6c 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {45 72 72 6f 72 20 72 75 6e 6e 69 6e 67 20 65 78 65 63 75 74 61 62 6c 65 2e 20 50 6c 65 61 73 65 20 74 72 79 20 61 67 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = {73 79 73 74 65 6d 5f 70 72 6f 74 65 63 74 6f 72 00}  //weight: 1, accuracy: High
        $x_1_6 = "Installing System Protector..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePowav_129024_10
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePowav"
        threat_id = "129024"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePowav"
        severity = "21"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "System will be restored in %d seconds." ascii //weight: 1
        $x_1_2 = "*** STOP: 0x00000019 (0x00000000,0xc00E0FF0,0xFFFFEFD4,0xC0000000)" ascii //weight: 1
        $x_2_3 = {42 41 44 5f 46 4f 4f 4c 5f 48 45 41 44 45 52 00}  //weight: 2, accuracy: High
        $x_2_4 = "Dll Base DAteStmp - Name" ascii //weight: 2
        $x_4_5 = {75 02 b3 01 84 db 75 ?? 6a 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 e8}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePowav_129024_11
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePowav"
        threat_id = "129024"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePowav"
        severity = "21"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 01 00 00 00 e8 ?? ?? ?? ?? 8b 45 ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 75 0a e8 ?? ?? ?? ?? e9 ?? ?? 00 00 8d 55 ?? b8 01 00 00 00 e8 ?? ?? ?? ?? 8b 45 ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 75 0a}  //weight: 2, accuracy: Low
        $x_1_2 = {2d 75 6e 69 6e 73 74 61 6c 6c 00 00 ff ff ff ff 05 00 00 00 2d 68 65 6c 70 00 00 00 ff ff ff ff 04 00 00 00 2d 62 75 79 00 00 00 00 ff ff ff ff [0-32] 5f 41 70 70 4d 61 6e 61 67 65 72}  //weight: 1, accuracy: Low
        $x_1_3 = "/order.php?lang=en&aid=" ascii //weight: 1
        $x_1_4 = {2f 63 68 65 63 6b 75 70 64 61 74 65 2e 70 68 70 3f 78 3d 31 32 33 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePowav_129024_12
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePowav"
        threat_id = "129024"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePowav"
        severity = "21"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Spy Protector" ascii //weight: 1
        $x_1_2 = "System Protector" ascii //weight: 1
        $x_2_3 = {61 73 00 00 ff ff ff ff 02 00 00 00 63 73 00 00 ff ff ff ff 04 00 00 00 2e 65 78 65 00}  //weight: 2, accuracy: High
        $x_2_4 = {61 73 00 00 ff ff ff ff 06 00 00 00 63 73 2e 65 78 65 00}  //weight: 2, accuracy: High
        $x_3_5 = {6a 00 6a 1a (53|56) 6a 00 e8 ?? ?? ?? ?? 8d 45 ?? 8b (d3|d6) e8 ?? ?? ?? ?? 8b 45 ?? 8d 55 ?? e8 ?? ?? ?? ?? ff 75 ?? 68 ?? ?? ?? ?? 68}  //weight: 3, accuracy: Low
        $x_3_6 = {6a 00 6a 00 68 00 0c 00 00 8d 46 02 50 53 e8 ?? ?? ?? ?? 6a 00 8b 87 28 01 00 00 8b 10 ff 52 64 50 68 00 04 00 00 [0-48] 53 63 61 6e 20 77 69 74 68 20}  //weight: 3, accuracy: Low
        $x_2_7 = {c7 06 f4 00 00 00 33 c0 89 46 08 33 c0 89 46 0c 6a 02 a1 ?? ?? ?? ?? 50 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePowav_129024_13
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePowav"
        threat_id = "129024"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePowav"
        severity = "21"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Spy Protector" ascii //weight: 1
        $x_1_2 = "System Protector" ascii //weight: 1
        $x_4_3 = {6a 00 6a 1a 56 6a 00 e8 ?? ?? ?? ?? 8d 45 ?? 8b d6 e8 ?? ?? ?? ?? 8b 45 ?? 8d 55 ?? e8 ?? ?? ?? ?? 8b 55 ?? 8b c3 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b c3 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? e9 ?? ?? 00 00 b2 01}  //weight: 4, accuracy: Low
        $x_4_4 = {6a 00 6a 1a 56 6a 00 e8 ?? ?? ?? ?? 8d 45 ?? 8b d6 e8 ?? ?? ?? ?? 8b 45 ?? 8d 55 ?? e8 ?? ?? ?? ?? ff 75 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b c3 ba 03 00 00 00 e8}  //weight: 4, accuracy: Low
        $x_4_5 = {6a 00 6a 1a 53 6a 00 e8 ?? ?? ?? ?? 8d 45 ?? 8b d3 e8 ?? ?? ?? ?? 8b 45 ?? 8d 55 ?? e8 ?? ?? ?? ?? 8b 55 ?? 8d 45 ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 01 8b 45 ?? e8 ?? ?? ?? ?? 50 e8}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePowav_129024_14
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePowav"
        threat_id = "129024"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePowav"
        severity = "21"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 6f 77 00 ff ff ff ff 06 00 00 00 4d 65 64 69 75 6d 00 00 ff ff ff ff 04 00 00 00 48 69 67 68 00 00 00 00 ff ff ff ff 08 00 00 00 43 72 69 74 69 63 61 6c}  //weight: 2, accuracy: High
        $x_2_2 = "WINXDEFENDER_BASE" ascii //weight: 2
        $x_2_3 = "/order.php?lang=en&aid=" ascii //weight: 2
        $x_1_4 = "Description: W32.Spybot.AQGF is a worm that spreads through mIRC and to network" ascii //weight: 1
        $x_1_5 = "Description: Trojan.Goldun.G is a Trojan horse program that steals passwords" ascii //weight: 1
        $x_2_6 = {53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 5f 41 70 70 4d 61 6e 61 67 65 72 5f 73 65 72 76 65 72 5f 6d 75 74 65 78 00}  //weight: 2, accuracy: High
        $x_2_7 = {53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 5f 41 70 70 4d 61 6e 61 67 65 72 5f 73 65 6e 64 5f 65 76 65 6e 74 00}  //weight: 2, accuracy: High
        $x_1_8 = {65 78 74 72 61 61 6e 74 69 76 69 72 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_9 = {4d 61 6c 77 61 72 65 52 65 6d 6f 76 61 6c 00}  //weight: 1, accuracy: High
        $x_6_10 = {32 c2 50 8b c7 e8 ?? ?? ?? ?? 5a 88 14 18 43 4e 75 06 00 8a 92}  //weight: 6, accuracy: Low
        $x_6_11 = {8a 04 10 32 c8 51 8b c7 e8 ?? ?? ?? ?? 5a 88 14 18 43 4e 75}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*))) or
            ((2 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePowav_129024_15
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePowav"
        threat_id = "129024"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePowav"
        severity = "21"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 01 00 00 00 e8 ?? ?? ?? ?? 8b 45 ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 14 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e9 ?? ?? 00 00 68 ?? ?? ?? ?? 6a 00 68 01 00 1f 00 e8}  //weight: 2, accuracy: Low
        $x_2_2 = {b8 01 00 00 00 e8 ?? ?? ?? ?? 8b 45 ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 10 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 68 01 00 1f 00 e8}  //weight: 2, accuracy: Low
        $x_2_3 = {b8 01 00 00 00 e8 ?? ?? ?? ?? 8b 45 ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 10 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 50 6a 00 68 01 00 1f 00 e8}  //weight: 2, accuracy: Low
        $x_1_4 = {75 6e 69 6e 73 74 61 6c 6c 00 00 00 7b 43 34 41 43 37 34 32 33 2d 30 31 37 43 2d 34 37 45 41 2d}  //weight: 1, accuracy: High
        $x_1_5 = {72 65 67 69 73 74 72 61 74 69 6f 6e 00 00 00 00 7b 43 34 41 43 37 34 32 33 2d 30 31 37 43 2d 34 37 45 41 2d}  //weight: 1, accuracy: High
        $x_1_6 = {53 79 73 74 65 6d 20 73 6c 6f 77 64 6f 77 6e 20 6f 72 20 6e 6f 74 20 73 74 61 72 74 69 6e 67 20 75 70 00}  //weight: 1, accuracy: High
        $x_1_7 = {49 6e 66 65 63 74 69 6e 67 20 6f 74 68 65 72 20 63 6f 6d 70 75 74 65 72 73 20 69 6e 20 79 6f 75 72 20 6e 65 74 77 6f 72 6b 00}  //weight: 1, accuracy: High
        $x_1_8 = {73 65 63 75 72 69 74 79 73 74 61 74 75 73 32 00 ff ff ff ff 0f 00 00 00 73 65 63 75 72 69 74 79 73 74 61 74 75 73 33 00}  //weight: 1, accuracy: High
        $x_1_9 = {7b 43 34 41 43 37 34 32 33 2d 30 31 37 43 2d 34 37 45 41 2d 39 32 31 39 2d 30 30 44 34 31 39 32 43 37 44 37 36 7d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

