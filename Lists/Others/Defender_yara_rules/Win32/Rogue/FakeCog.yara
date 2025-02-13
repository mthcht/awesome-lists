rule Rogue_Win32_FakeCog_140896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeCog"
        threat_id = "140896"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeCog"
        severity = "61"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "%s/readdatagateway.php?type=stats&affid=%s&subid=%s&uninstall&version=%s" ascii //weight: 3
        $x_2_2 = {43 6f 72 65 45 78 74 2e 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_2_3 = "%s/email-support/esubmit.php?name=delete&email=" ascii //weight: 2
        $x_2_4 = {50 6c 65 61 73 65 2c 20 6d 61 72 6b 20 74 68 65 20 72 65 61 73 6f 6e 20 66 6f 72 20 72 65 6d 6f 76 65 20 61 6e 74 69 76 69 72 75 73 20 73 6f 66 74 77 61 72 65 21 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeCog_140896_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeCog"
        threat_id = "140896"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeCog"
        severity = "61"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "type=stats&affid=%s&subid=%s&installruns" ascii //weight: 2
        $x_2_2 = "unauthorized antivirus software detected on your computer." ascii //weight: 2
        $x_2_3 = "Uninstall Coreguard Antivirus " ascii //weight: 2
        $x_1_4 = "plus_circle.png" ascii //weight: 1
        $x_1_5 = "tick.png" ascii //weight: 1
        $x_1_6 = "unreg.html" ascii //weight: 1
        $x_1_7 = "blacklist.cga" ascii //weight: 1
        $x_1_8 = "support.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeCog_140896_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeCog"
        threat_id = "140896"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeCog"
        severity = "61"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {61 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 25 00 32 00 30 00 32 00 30 00 30 00 39 00 00 00}  //weight: 3, accuracy: High
        $x_2_2 = {72 00 75 00 6e 00 3a 00 2f 00 2f 00 78 00 79 00 7a 00 00 00}  //weight: 2, accuracy: High
        $x_2_3 = "Your computer is not protected from virus attacks at visiting popular websites" ascii //weight: 2
        $x_1_4 = "0CB66BA8-5E1F-4963-93D1-E1D6B78FE9A2" ascii //weight: 1
        $x_1_5 = "A8954909-1F0F-41A5-A7FA-3B376D69E226" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeCog_140896_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeCog"
        threat_id = "140896"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeCog"
        severity = "61"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "6da54105-146e-4eea-9b09-b1ca3a54b726" wide //weight: 3
        $x_1_2 = "7ac311a7-47af-45aa-95a4-3e96f12ce9ce" wide //weight: 1
        $x_1_3 = "Downloading antivirus executable..." wide //weight: 1
        $x_1_4 = "Downloading uninstaller..." wide //weight: 1
        $x_1_5 = "Downloading URL blacklist..." wide //weight: 1
        $x_1_6 = "Downloading firewall extension..." wide //weight: 1
        $x_3_7 = "%s/readdatagateway.php?type=stats&affid=%s&subid=%s&installruns&version=%s" ascii //weight: 3
        $x_1_8 = {62 6c 61 63 6b 6c 69 73 74 2e 63 67 61 00}  //weight: 1, accuracy: High
        $x_1_9 = {63 6f 72 65 65 78 74 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeCog_140896_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeCog"
        threat_id = "140896"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeCog"
        severity = "61"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 4c 24 4c 6a 00 51 6a 01 6a 04 ff 15 ?? ?? ?? ?? 6a 00 ff d6 50}  //weight: 2, accuracy: Low
        $x_2_2 = {7e 0c 80 7c 0c 18 5c 74 05 49 85 c9 7f f4 8b 94 24 20 11 00 00 8d 44 0c 19}  //weight: 2, accuracy: High
        $x_1_3 = "coreguard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeCog_140896_5
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeCog"
        threat_id = "140896"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeCog"
        severity = "61"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {b8 47 39 00 00 8b 4a 1c eb 1a 8b 54 24 64 b8 07 11 00 00 8b 4a 20 eb 0c}  //weight: 3, accuracy: High
        $x_2_2 = "make your PC full scanning.</br" ascii //weight: 2
        $x_1_3 = {d8 3d 87 88 0a 00 3f 00 00 00 3f 08 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeCog_140896_6
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeCog"
        threat_id = "140896"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeCog"
        severity = "61"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5f 66 61 76 64 61 74 61 2e 64 61 74 00 00 00 00 76 65 72 00 73 75 62 69 64 00 00 00 61 66 66 69 64 00}  //weight: 2, accuracy: High
        $x_1_2 = "User Protection Support.lnk" ascii //weight: 1
        $x_1_3 = {75 73 72 65 78 74 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {75 73 72 70 72 6f 74 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeCog_140896_7
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeCog"
        threat_id = "140896"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeCog"
        severity = "61"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 00 53 00 5c 00 25 00 53 00 2e 00 6c 00 6e 00 6b 00 00 00 [0-64] 25 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "Single User License Grant: GuardSoft, Ltd. (\"GuardSoft\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeCog_140896_8
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeCog"
        threat_id = "140896"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeCog"
        severity = "61"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {33 c0 8b 44 24 0c be ?? ?? ?? ?? b9 0f 00 00 00 f3 a6 74 07 83 c2 01}  //weight: 4, accuracy: Low
        $x_1_2 = {50 61 6c 61 64 69 6e 20 41 6e 74 69 76 69 72 75 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {4d 61 6c 77 61 72 65 20 44 65 66 65 6e 73 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {44 72 2e 20 47 75 61 72 64 00}  //weight: 1, accuracy: High
        $x_2_5 = "948048601436" ascii //weight: 2
        $x_1_6 = {20 50 72 6f 74 65 63 74 69 6f 6e 00 (10 00 59 6f|13 00 44 69 67 69 74)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeCog_140896_9
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeCog"
        threat_id = "140896"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeCog"
        severity = "61"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "948048601436" ascii //weight: 1
        $x_1_2 = "e:\\Working Copies\\Bundles\\Defense Center" ascii //weight: 1
        $x_1_3 = {63 00 68 00 72 00 6f 00 6d 00 65 00 2e 00 65 00 78 00 65 00 00 00 00 00 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 00 00 00 00 63 00 6f 00 64 00 65 00 63 00 70 00 61 00 63 00 6b 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeCog_140896_10
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeCog"
        threat_id = "140896"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeCog"
        severity = "61"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Please, mark the reason for remove antivirus software!" ascii //weight: 1
        $x_1_2 = {5f 66 61 76 64 61 74 61 2e 64 61 74 00 00 00 00 76 65 72 00 73 75 62 69 64 00 00 00 61 66 66 69 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 66 69 72 65 77 61 6c 6c 2e 64 6c 6c 00 [0-10] 65 78 74 2e 64 6c 6c 00 [0-3] 55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeCog_140896_11
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeCog"
        threat_id = "140896"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeCog"
        severity = "61"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "24d1ca9a-a864-4f7b-86fe-495eb56529d8" ascii //weight: 2
        $x_1_2 = "puter are damaged. Please, re" wide //weight: 1
        $x_1_3 = "Windows Security Alert" ascii //weight: 1
        $x_1_4 = "\\_favdata.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeCog_140896_12
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeCog"
        threat_id = "140896"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeCog"
        severity = "61"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 f2 03 00 00 8b ce e8 ?? ?? ?? ?? 8b c8 e8 ?? ?? ?? ?? 68 8c 00 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 75 fc 57 68 f0 03 00 00 8b ce e8 ?? ?? ?? ?? 8b c8 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 74 18 68 ?? ?? ?? ?? 68 f3 03 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = "res://resdll.dll" wide //weight: 1
        $x_1_4 = "Attacks porn sites" wide //weight: 1
        $x_1_5 = "cgupdate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeCog_140896_13
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeCog"
        threat_id = "140896"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeCog"
        severity = "61"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Attacks porn sites" wide //weight: 1
        $x_1_2 = "Software\\Active Security" ascii //weight: 1
        $x_1_3 = "cgupdate" ascii //weight: 1
        $x_1_4 = {63 6f 72 65 67 75 61 72 64 00}  //weight: 1, accuracy: High
        $x_1_5 = "|EXEPATH|" wide //weight: 1
        $x_1_6 = {4d 00 69 00 64 00 64 00 6c 00 65 00 20 00 52 00 69 00 73 00 6b 00 00 00 48 00 69 00 67 00 68 00 20 00 52 00 69 00 73 00 6b 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_FakeCog_140896_14
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeCog"
        threat_id = "140896"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeCog"
        severity = "61"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "CoreGuard Antivirus" ascii //weight: 2
        $x_2_2 = "Scan items with " ascii //weight: 2
        $x_2_3 = "Scan with " ascii //weight: 2
        $x_1_4 = "5E2121EE-0300-11D4-8D3B-444553540000" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved" ascii //weight: 1
        $x_1_6 = {83 38 64 75 08 8b 45 ?? 83 c0 1c eb 06 8b 45 ?? 83 c0 24}  //weight: 1, accuracy: Low
        $x_2_7 = "Defense Center extension" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeCog_140896_15
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeCog"
        threat_id = "140896"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeCog"
        severity = "61"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f6 c4 05 7b 12 8b ?? ec 8b ?? (bc|c0) 3b ?? (88|90 90) 00 00 00 0f 8e ?? ?? 00 00 6a 00}  //weight: 2, accuracy: Low
        $x_1_2 = "SecStatus_" wide //weight: 1
        $x_1_3 = "full functional version" wide //weight: 1
        $x_1_4 = "the tools marked green" wide //weight: 1
        $x_1_5 = "Please, make full checking" wide //weight: 1
        $x_1_6 = "HOTSPOT=" ascii //weight: 1
        $x_1_7 = "%s/core.cga" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeCog_140896_16
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeCog"
        threat_id = "140896"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeCog"
        severity = "61"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "948048601436" ascii //weight: 1
        $x_1_2 = "/readdatagateway.php" ascii //weight: 1
        $x_1_3 = "computer are damaged" ascii //weight: 1
        $x_1_4 = "|TEXTXP|" ascii //weight: 1
        $x_1_5 = "|EXEPATH|" ascii //weight: 1
        $x_1_6 = "about:buy" ascii //weight: 1
        $x_1_7 = "_favdata.dat" ascii //weight: 1
        $x_1_8 = "spam001.exe" wide //weight: 1
        $x_1_9 = "an incorrect turn off" ascii //weight: 1
        $x_2_10 = {83 c6 04 83 fe 0c 7c 95 5f}  //weight: 2, accuracy: High
        $x_1_11 = {33 45 10 ff 45 fc 66 89 06 46 46 ff d7 39 45 fc 7c e6}  //weight: 1, accuracy: High
        $x_2_12 = "d8bb5910-2d85-489b-8403-803ed25e73bc" ascii //weight: 2
        $x_1_13 = "http://%s/any2/%s-direct.ex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeCog_140896_17
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeCog"
        threat_id = "140896"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeCog"
        severity = "61"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "coreguard" ascii //weight: 1
        $x_1_2 = "%s/buy.php?id=%s&subid=%s" ascii //weight: 1
        $x_1_3 = "t8RBtVR0f1tQq9ra" ascii //weight: 1
        $x_1_4 = "4otjesjty.mof" ascii //weight: 1
        $x_1_5 = "/readdatagateway.php" ascii //weight: 1
        $x_1_6 = "that steals your pass" ascii //weight: 1
        $x_1_7 = "SecStatus_" ascii //weight: 1
        $x_1_8 = "unauthorized antivirus" ascii //weight: 1
        $x_1_9 = "scan.ico" ascii //weight: 1
        $x_1_10 = "Buy.lnk" ascii //weight: 1
        $x_1_11 = "buy.ico" ascii //weight: 1
        $x_1_12 = "Protection\\About.lnk" ascii //weight: 1
        $x_1_13 = {8a 1c 29 32 d8 8b 02 2b 44 24 1c 83 f8 01 77 06}  //weight: 1, accuracy: High
        $x_1_14 = {76 22 8a 04 1f 8d 4d e0 32 45 10 88 45}  //weight: 1, accuracy: High
        $x_1_15 = "948048601436" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

