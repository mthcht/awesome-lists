rule Rogue_Win32_FakeRean_124161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/httpss/setup.php?action=" ascii //weight: 1
        $x_1_2 = "\\setup.exe -p\"15:30\" -y -o\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeRean_124161_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/logs2/log.php?hostid=" ascii //weight: 1
        $x_1_2 = "Spread finished" ascii //weight: 1
        $x_1_3 = "CMultiKeyAutorun" ascii //weight: 1
        $x_1_4 = "report url [%s]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeRean_124161_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@$&%04\\defender.exe" ascii //weight: 1
        $x_1_2 = "Smart Install Maker" ascii //weight: 1
        $x_1_3 = {43 6f 70 79 72 69 67 68 74 20 a9 20 32 30 31 30 2c 20 50 72 69 76 61 63 79 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "SHGetSpecialFolderLocation" ascii //weight: 1
        $x_1_5 = {74 65 73 74 00 00 00 00 2e 2e 5c 73 69 6d 2e 65 78 65 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeRean_124161_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.win-pc-anti" wide //weight: 1
        $x_1_2 = "WinPC Antivirus" wide //weight: 1
        $x_1_3 = "Lighty Compressor" ascii //weight: 1
        $x_1_4 = "WinPC Defender" ascii //weight: 1
        $x_1_5 = "FastMM Borland Edition" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeRean_124161_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "{FBD69E67-C708-47be-B49F-33D4200B8" ascii //weight: 3
        $x_2_2 = {56 69 72 75 73 20 66 72 65 65 00}  //weight: 2, accuracy: High
        $x_2_3 = {73 70 6f 6f 6c 73 76 2e 65 78 65 00 74 61 73 6b 6d 67 72 2e 65 78 65 00 63 74 66 6d 6f 6e 2e 65 78 65 00}  //weight: 2, accuracy: High
        $x_1_4 = {73 65 63 75 72 69 74 79 63 65 6e 74 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_3_5 = "87A41642-C9CD-4785-9D7C-12A5A8B66E6E" ascii //weight: 3
        $x_2_6 = "Software\\AntiVirus AntiSpyware" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRean_124161_5
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\XPSecurityCenter.exe" ascii //weight: 5
        $x_5_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 5
        $x_5_3 = "Program Files\\XPSecurityCenter" ascii //weight: 5
        $x_5_4 = "http://www.xpsecuritycenter.com/XPSecurityCenter/" ascii //weight: 5
        $x_1_5 = "Binaries1.zip" ascii //weight: 1
        $x_1_6 = "InternetReadFile" ascii //weight: 1
        $x_1_7 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeRean_124161_6
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "Security Alert!" ascii //weight: 1
        $x_1_4 = "Are you sure? Your PC will not be protected againts spyware." ascii //weight: 1
        $x_1_5 = "Antivirus uninstall is not success." ascii //weight: 1
        $x_1_6 = "if exist \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeRean_124161_7
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " has detected a leak of your files though the Internet." ascii //weight: 1
        $x_1_2 = "Malicious program has been detected." ascii //weight: 1
        $x_1_3 = "Malicious code has been detected in your system. It can replicate itself if no action is taken." ascii //weight: 1
        $x_1_4 = "Hidden file transfer to remote host has been detected" ascii //weight: 1
        $x_1_5 = "Security Central has detected a leak of your files though the Internet. We strongly recommend that you block the attack immediately" ascii //weight: 1
        $x_1_6 = "DWinPC Defender has detected that new threat database is available." ascii //weight: 1
        $x_1_7 = "Serious threats were detected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_FakeRean_124161_8
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 54 04 14}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 4c 14 14}  //weight: 1, accuracy: High
        $x_1_3 = {8a 4c 04 14}  //weight: 1, accuracy: High
        $x_1_4 = {68 00 6e 3f 00}  //weight: 1, accuracy: High
        $x_1_5 = {05 c0 0f 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_FakeRean_124161_9
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 7f 05 75 05 51 04 05 89 05 2b 8e 05 89 79 04 8d 8c 44 0e 08 d0 6c c7 45 dc 81 6d c7 24 45 e0}  //weight: 1, accuracy: High
        $x_1_2 = {89 79 04 8d 8c 0e 22 08 d0 6c c7 45 dc 81 6d c7 45 92 e0 51 2a eb 23 60 06 89 d6 21 37 82 f2 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Rogue_Win32_FakeRean_124161_10
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 09 30 08 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 48 41 3b 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 7f d7 8b 0d ?? ?? ?? ?? 40}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 09 30 08 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 48 41 3b 05 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? a3 ?? ?? ?? ?? 7f d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Rogue_Win32_FakeRean_124161_11
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 54 1f ff 88 54 18 ff 43 4e 75 e9}  //weight: 1, accuracy: High
        $x_1_2 = {8b 40 18 b9 73 00 00 00 ba a0 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "Accordingly to technical reason" ascii //weight: 1
        $x_1_4 = "Please purchase" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_FakeRean_124161_12
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 10 ff 15 ?? ?? ?? 00 83 65 fc 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? 00 83 f8 57 75 ?? 6a 00 68 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 85 c0 75 ?? 68}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 6a 1f 59 f7 f1 6a 1f 59 2b ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeRean_124161_13
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 44 52 5f 00 00 00 00 68 74 74 70 64 73 63 6f 6e 66 69 67 2e 63 6f 6d 00 00 00 00 68 74 74 70 73 68 69 67 68 2e 69 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 2e 32 00 4f 4b 00 00 31 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 63 70 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {44 69 61 6c 65 72 69 42 6c 6f 63 6b 65 72 74 72 61 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeRean_124161_14
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "%s/httpss/v=%d&step=%d&hostid=%s" ascii //weight: 3
        $x_1_2 = {4d 44 35 00 4d 41 43 48 49 4e 45 00 4f 50 00}  //weight: 1, accuracy: High
        $x_1_3 = {26 70 3d 00 3d 25 64 00 3f [0-4] 2e 70 68 70 [0-4] 2f 67 65 74 66 69 6c 65}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 44 52 5f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRean_124161_15
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1b 83 c4 0c 80 fb e8 74 05 80 fb e9 75 0b}  //weight: 1, accuracy: High
        $x_1_2 = {2b cf 83 e8 05 83 e9 05 c6 86 ?? ?? ?? 00 e9 89 8e ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 14 10 30 94 0d fc fe ff ff 40 83 f8 14}  //weight: 1, accuracy: High
        $x_1_4 = {6a 06 8b fa be ?? ?? ?? ?? 59 33 db f3 a6 74 ?? 83 c2 28 ff 45 fc 66 39 45 fc 72 e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Rogue_Win32_FakeRean_124161_16
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 70 79 77 61 72 65 20 50 72 6f 74 65 63 74 69 6f 6e 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {57 69 6e 44 65 66 65 6e 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 64 65 66 65 6e 64 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 71 75 69 74 20 57 69 6e 44 65 66 65 6e 64 65 72 3f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeRean_124161_17
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "%s/httpss/v=%d&step=%d&hostid=%s" ascii //weight: 3
        $x_2_2 = "/getfile.php?" ascii //weight: 2
        $x_1_3 = {4d 44 35 00 4d 41 43 48 49 4e 45 00 4f 50 00}  //weight: 1, accuracy: High
        $x_1_4 = {26 70 3d 00 72 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = "SOFTWARE\\Microsoft\\MediaPlayer\\Setup\\Files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRean_124161_18
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 3c 41 72 06 3c 5a 77 02 04 20 aa e2 f2 81 7d ?? 6b 65 72 6e 75 c7 81 7d ?? 65 6c 33 32 75 be 81 7d ?? 2e 64 6c 6c 75}  //weight: 1, accuracy: Low
        $x_1_2 = "fileblobDestroy: %s not saved: report to http://bugs.clamav.net" ascii //weight: 1
        $x_1_3 = {6c 69 62 43 6c 61 6d 41 56 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeRean_124161_19
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 61 63 65 62 6f 6f 6b 2e 63 6f 6d 2f 65 78 74 65 72 6e 2f 6c 6f 67 69 6e 5f 73 74 61 74 75 73 2e 00}  //weight: 2, accuracy: High
        $x_2_2 = {25 73 2c 20 25 2e 32 69 20 25 73 20 25 2e 32 69 20 25 2e 32 69 3a 25 2e 32 69 3a 25 2e 32 69 20 47 4d 54 00}  //weight: 2, accuracy: High
        $x_2_3 = {3a 53 47 3d 00 00 00 00 3a 46 46 3d 00 00 00 00 3a 4e 57 3d 00 00 00 00 3a 53 3d 00 3a 53 47 3d 00}  //weight: 2, accuracy: High
        $x_1_4 = {77 65 62 68 70 3f 00}  //weight: 1, accuracy: High
        $x_1_5 = {73 6f 75 72 63 65 3d 68 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRean_124161_20
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 0f be 88 00 e0 40 00 8b 55 fc 83 c2 01 33 55 f8 2b ca 8b 45 fc 88 88 00 e0 40 00 8b 4d fc 83 c1 01 89 4d fc}  //weight: 1, accuracy: High
        $x_1_2 = {70 61 75 73 65 00 00 00 45 6e 74 65 72 20 74 65 78 74 2e 20 49 6e 63 6c 75 64 65 20 61 20 64 6f 74 20 28 27 2e 27 29 20 69 6e 20 61 20 73 65 6e 74 65 6e 63 65 20 74 6f 20 65 78 69 74 3a 00 00 43 68 61 72 61 63 74 65 72 73 3a 20 25 63 20 25 63 20 0a 00 44 65 63 69 6d 61 6c 73 3a 20 25 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeRean_124161_21
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2f 67 65 74 00 [0-4] 66 69 6c 65 00 [0-4] 68 74 74 00 [0-2] 70 3a 2f 2f 00 30 00 26 70 3d 00 3f 00 [0-3] 00 2e 70 68 70 00}  //weight: 2, accuracy: Low
        $x_3_2 = "%s/httpss/v=%d&step=%d&hostid=%s" ascii //weight: 3
        $x_1_3 = {4c 44 52 5f 00}  //weight: 1, accuracy: High
        $x_1_4 = {6d 2e 32 00 49 00 00 00 44 00 00 00 4d 44 35 00}  //weight: 1, accuracy: High
        $x_1_5 = {4d 41 00 00 47 49 43 00 4d 41 43 48 49 4e 45 00}  //weight: 1, accuracy: High
        $x_1_6 = {2e 63 70 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRean_124161_22
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b 41 6e 74 69 76 69 72 75 73 2e 6d 73 69 5d 0d 0a 54 79 70 65 3d 32 0d 0a 4c 6f 63 61 74 69 6f 6e 3d 68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e [0-37] 2f 65 6e 2f 50 45 2f 41 6e 74 69 76 69 72 75 73 2e 6d 73 69 0d 0a 43 61 63 68 65 52 6f 6f 74 3d 32 38 0d 0a 43 61 63 68 65 46 6f 6c 64 65 72 3d 44 6f 77 6e 6c 6f 61 64 65 64 20 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 73 0d 0a 5b 53 65 74 75 70 2e 62 6d 70 5d 0d 0a 54 79 70 65 3d 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeRean_124161_23
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 65 63 75 72 69 74 79 43 65 6e 74 65 72 00 00 53 65 63 75 72 69 74 79 43 65 6e 74 65 72}  //weight: 1, accuracy: High
        $x_1_2 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1" ascii //weight: 1
        $x_1_3 = "worm that relies on the Microsoft Windows Server Service RPC Handling" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeRean_124161_24
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 85 10 fe ff ff 03 04 00 00 89 b5 14 fe ff ff 33 c0 8a 88 ?? ?? ?? ?? 88 8c 05 18 fe ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {74 15 33 c0 80 b0 ?? ?? ?? ?? ?? 40 83 f8}  //weight: 1, accuracy: Low
        $x_1_3 = {38 37 41 34 31 36 34 32 2d 43 39 43 44 2d 34 37 38 35 2d 39 44 37 43 2d 31 32 41 35 41 38 42 36 36 45 36 45}  //weight: 1, accuracy: Low
        $x_1_4 = {53 65 63 75 72 69 74 79 20 53 6f 6c 75 74 69 6f 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = "Software\\Security Solution" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_FakeRean_124161_25
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 26 6a 00 c6 44 24 ?? 00 c7 44 24 ?? 00 04 00 00 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {68 05 00 00 20 55 c7 44 24 ?? 04 00 00 00 ff 15}  //weight: 2, accuracy: Low
        $x_1_3 = {44 69 61 6c 65 72 69 42 6c 6f 63 6b 65 72 74 72 61 79 00}  //weight: 1, accuracy: High
        $x_1_4 = "FSSYNC" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\NetDDE\\DDE Trusted Shares\\Trusted files" ascii //weight: 1
        $x_1_6 = "Player\\Setup\\Files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRean_124161_26
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 0d 00 (00 49 45 41 64 64 6f 6e 2e 44|73 68 65 6c 6c 65 78 74 2e 64)}  //weight: 5, accuracy: Low
        $x_5_2 = "{427dbde0-7799-4611-9789-deb36156d1ad}" ascii //weight: 5
        $x_5_3 = "UnVirex" ascii //weight: 5
        $x_5_4 = "CAntivirusBaseDownload" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Rogue_Win32_FakeRean_124161_27
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Software\\Desktop Security 201" ascii //weight: 5
        $x_5_2 = "CSecurityCenterApp@" ascii //weight: 5
        $x_1_3 = "polymorphics sequences wich held in the decryption" ascii //weight: 1
        $x_1_4 = {61 6c 65 72 33 66 61 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = "*CRITICAL_VIRUS_ERROR" ascii //weight: 1
        $x_1_6 = {43 46 61 6b 65 42 53 4f 44 00}  //weight: 1, accuracy: High
        $x_1_7 = {25 25 73 2f 62 75 79 2f 69 6e 64 65 78 2f 25 73 2f 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRean_124161_28
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 54 4d 4c 5f 4d 41 49 4e 5f 52 45 47 49 53 54 45 52 45 44 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 66 69 72 65 77 61 6c 6c 2e 63 70 6c 22 2c 57 69 6e 64 6f 77 73 20 46 69 72 65 77 61 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 77 75 61 75 63 70 6c 2e 63 70 6c 22 2c 41 75 74 6f 6d 61 74 69 63 20 55 70 64 61 74 65 73 00}  //weight: 1, accuracy: High
        $x_1_4 = "installed antispyware softwares on your computer." ascii //weight: 1
        $x_3_5 = {83 c9 ff f2 ae f7 d1 49 83 f9 08 72 1a 8d ?? 24 ?? 6a 2f ?? e8 ?? ?? ?? ?? 83 c4 08 85 c0 74 07 b8 01 00 00 00 eb 02}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRean_124161_29
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 24 32 54 1f ff 88 54 18 ff 43 4e 75 e9}  //weight: 1, accuracy: High
        $x_1_2 = "Antivirus uninstall is not success. Please try again..." ascii //weight: 1
        $x_1_3 = {00 61 76 62 61 73 65 2e 64 61 74 00 [0-16] 4f 70 74 69 6f 6e 73 00}  //weight: 1, accuracy: Low
        $x_1_4 = "Hogdbude;!" ascii //weight: 1
        $x_1_5 = "iuuq;.." ascii //weight: 1
        $x_1_6 = {50 6c 65 61 73 65 20 63 6c 69 63 6b 20 93 41 63 74 69 76 61 74 65 20 6e 6f 77 94 20 74 6f 20 63 6f 6e 74 69 6e 75 65 20 77 69 74 68 20 61 20 73 65 63 75 72 65 20 70 75 72 63 68 61 73 65 20 6f 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_FakeRean_124161_30
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "AntiVirus Studio" ascii //weight: 10
        $x_1_2 = "Are you wish to keep this ILLEGAL FILE on your computer ? This can lead to private data steal such as passwords," ascii //weight: 1
        $x_1_3 = "s&orderid=%d&key=%s" ascii //weight: 1
        $x_1_4 = "Scan system on startup" ascii //weight: 1
        $x_1_5 = "Security Center" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRean_124161_31
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {70 70 2f 3f 69 64 3d 00}  //weight: 2, accuracy: High
        $x_2_2 = "installed.pl?bid=" ascii //weight: 2
        $x_2_3 = {49 6e 73 74 61 6c 6c 65 72 5f 41 56 00}  //weight: 2, accuracy: High
        $x_1_4 = {43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 64 6f 6e 27 74 20 6c 6f 61 64 5c 73 63 75 69 2e 63 70 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 64 6f 6e 27 74 20 6c 6f 61 64 5c 77 73 63 75 69 2e 63 70 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = "Security Alert!" ascii //weight: 1
        $x_1_7 = {41 72 65 20 79 6f 75 20 73 75 72 65 3f 20 59 6f 75 72 20 50 43 20 77 69 6c 6c 20 6e 6f 74 20 62 65 20 70 72 6f 74 65 63 74 65 64 20 61 67 61 69 6e 74 73 20 73 70 79 77 61 72 65 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRean_124161_32
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "87A41642-C9CD-4785-9D7C-12A5A8B66E6E" ascii //weight: 2
        $x_1_2 = {53 6f 66 74 77 61 72 65 5c 41 6e 74 69 56 69 72 75 73 20 53 79 73 74 65 6d 20 32 30 [0-6] 5c 41 6e 74 69 56 69 72 75 73 5f 53 79 73 74 65 6d 5f 32 30 ?? ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {53 6f 66 74 77 61 72 65 5c 41 6e 74 69 56 69 72 75 73 5f 41 6e 74 69 53 70 79 77 61 72 65 5f 32 30 02 00 00 5c 41 6e 74 69 56 69 72 75 73 20 41 6e 74 69 53 70 79 77 61 72 65 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_2_4 = {42 00 00 00 44 00 00 00 4d 00 00 00 53 00 00 00 (53 65 63 75 72 69 74 79 20 6d 61 6e 61 67|41 6e 74 69 56 69 72)}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRean_124161_33
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Malware Protection.lnk" ascii //weight: 1
        $x_1_2 = "%04\\defender.exe" ascii //weight: 1
        $x_1_3 = "Welcome to installer Security Essentials" ascii //weight: 1
        $x_1_4 = {41 20 70 61 73 73 77 6f 72 64 20 69 73 20 72 65 71 75 69 72 65 64 20 74 6f 20 62 65 67 69 6e 20 74 68 65 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 6f 66 20 53 65 63 75 72 69 74 79 20 45 73 73 65 6e 74 69 61 6c 73 [0-2] 2e 20 54 79 70 65 20 74 68 65 20 70 61 73 73 77 6f 72 64}  //weight: 1, accuracy: Low
        $x_1_5 = {49 6e 73 74 61 6c 6c 20 53 65 63 75 72 69 74 79 20 45 73 73 65 6e 74 69 61 6c 73 [0-2] 20 69 73 20 62 72 65 61 6b 69 6e 67 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_FakeRean_124161_34
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "%s/httpss/ldr123.php?v=%d&step=%d&hostid=%s" ascii //weight: 3
        $x_2_2 = {2f 67 65 74 66 69 6c 65 2e 70 68 70 3f 00}  //weight: 2, accuracy: High
        $x_2_3 = {6d 2e 32 00 49 44 00}  //weight: 2, accuracy: High
        $x_2_4 = {4c 44 52 5f 00}  //weight: 2, accuracy: High
        $x_1_5 = {61 66 66 69 64 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = {4e 4f 43 46 47 00}  //weight: 1, accuracy: High
        $x_1_7 = {25 73 3a 5a 6f 6e 65 2e 49 64 65 6e 74 69 66 69 65 72 00}  //weight: 1, accuracy: High
        $x_1_8 = {52 55 4e 41 00}  //weight: 1, accuracy: High
        $x_1_9 = {52 55 4e 55 00}  //weight: 1, accuracy: High
        $x_3_10 = {6d 2e 32 00 4f 4b 00 00 31 00}  //weight: 3, accuracy: High
        $x_1_11 = "DialeriBlockertray" ascii //weight: 1
        $x_1_12 = "httpconfig.com" ascii //weight: 1
        $x_3_13 = {2e 65 78 65 00 00 00 00 6d 2e 32 00}  //weight: 3, accuracy: High
        $x_3_14 = {2e 65 78 65 00 00 00 00 5c 4f 72 69 67 69 6e 61 6c 46 69 6c 65 6e 61 6d 65 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRean_124161_35
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "leave unwanted software or viruses on you PC?" ascii //weight: 1
        $x_1_2 = "All threats has been succesfully removed." ascii //weight: 1
        $x_1_3 = "Antivirus uninstall is not success. Please try again..." ascii //weight: 1
        $x_1_4 = "This version of %pn% is for trial purpose only. Threats" ascii //weight: 1
        $x_1_5 = "Warning! You computer in danger." ascii //weight: 1
        $x_1_6 = "imlRemoveTrojanBtnh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_FakeRean_124161_36
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {25 00 73 00 2f 00 69 00 6d 00 61 00 67 00 65 00 73 00 2f 00 25 00 75 00 2f 00 25 00 73 00 2f 00 25 00 73 00 2e 00 67 00 69 00 66 00 00 00}  //weight: 3, accuracy: High
        $x_3_2 = "%s/httpss/start.php?id=%d&mid=%hs&aid=%s&type=%d" wide //weight: 3
        $x_2_3 = {25 00 73 00 2f 00 70 00 69 00 63 00 74 00 75 00 72 00 65 00 73 00 2f 00 70 00 72 00 65 00 73 00 65 00 6e 00 74 00 2e 00 67 00 69 00 66 00 00 00}  //weight: 2, accuracy: High
        $x_1_4 = "Software\\Microsoft\\Software Notifier" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRean_124161_37
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 69 6e 61 72 69 65 73 31 2e (7a|63) 00}  //weight: 1, accuracy: Low
        $x_1_2 = {42 69 6e 61 72 69 65 73 32 2e (7a|63) 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 69 6e 61 72 69 65 73 33 2e (7a|63) 00}  //weight: 1, accuracy: Low
        $x_1_4 = {42 69 6e 61 72 69 65 73 ?? ?? [0-1] 2e 63 61 62 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2f 66 69 72 73 74 00}  //weight: 1, accuracy: High
        $x_1_6 = "/update_inst.php?" ascii //weight: 1
        $x_1_7 = {5c 77 73 63 75 69 2e 63 70 6c 00}  //weight: 1, accuracy: High
        $x_3_8 = {5c 5f 73 63 75 69 2e 63 70 6c 00}  //weight: 3, accuracy: High
        $x_1_9 = {43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 64 6f 6e 27 74 20 6c 6f 61 64 00}  //weight: 1, accuracy: High
        $x_1_10 = {46 6f 72 63 65 43 6c 61 73 73 69 63 43 6f 6e 74 72 6f 6c 50 61 6e 65 6c 00}  //weight: 1, accuracy: High
        $x_6_11 = {68 00 00 00 80 50 ff 15 ?? ?? ?? ?? 8b ?? 83 ?? ff [0-3] (74 ??|0f 84 ?? ?? ?? ??) 53 ?? ff 15 ?? ?? ?? ?? 83 e8 70 53 53 50 ?? ff 15 ?? ?? ?? ?? 6a 1b}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRean_124161_38
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 00 00 00 00 22 00 20 00 2d 00 61 00 20 00 22 00 25 00 31 00 22 00 20 00 25 00 2a 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {57 00 69 00 6e 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 00 00 5c 00}  //weight: 1, accuracy: High
        $x_1_3 = "A8A80426-F161-4fbc-8EDC-A51BA546C5F1" wide //weight: 1
        $x_1_4 = "Enable Smart Proactive Defense technology" wide //weight: 1
        $x_1_5 = "Detected ttems" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_FakeRean_124161_39
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/update_inst.php?wmid=%d&subid=%s&pid=%d&lid=%d&hs=%s" ascii //weight: 2
        $x_1_2 = {2f 42 69 6e 61 72 69 65 73 31 2e 63 61 62 00}  //weight: 1, accuracy: High
        $x_1_3 = {42 69 6e 61 72 69 65 73 55 70 64 2e 63 61 62 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 77 73 63 75 69 2e 63 70 6c 00}  //weight: 1, accuracy: High
        $x_2_5 = {5c 5f 73 63 75 69 2e 63 70 6c 00}  //weight: 2, accuracy: High
        $x_1_6 = {43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 64 6f 6e 27 74 20 6c 6f 61 64 00}  //weight: 1, accuracy: High
        $x_2_7 = "Are you sure you want to completely remove the AntiSpywareXP 20" ascii //weight: 2
        $x_2_8 = "You already have AntiSpywareXP 20" ascii //weight: 2
        $x_1_9 = "Please wait, downloading..." ascii //weight: 1
        $x_1_10 = {2f 66 69 72 73 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRean_124161_40
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2f 69 6e 73 74 61 6c 6c 65 64 2e 70 68 70 3f 69 64 3d 00}  //weight: 2, accuracy: High
        $x_2_2 = {2f 74 6e 78 2e 70 68 70 3f 65 6d 61 69 6c 3d 00}  //weight: 2, accuracy: High
        $x_2_3 = "and UNWANTED files on your computer!" ascii //weight: 2
        $x_1_4 = "Security Alert!" ascii //weight: 1
        $x_1_5 = "Protection level: low" ascii //weight: 1
        $x_2_6 = " has detected a leak of your files though the Internet." ascii //weight: 2
        $x_1_7 = " items are critical privacy compromising content" ascii //weight: 1
        $x_1_8 = " items is medium privacy threats" ascii //weight: 1
        $x_1_9 = " is infected by W32/Blaster.worm" ascii //weight: 1
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

rule Rogue_Win32_FakeRean_124161_41
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 69 6e 64 6f 77 73 20 72 65 63 6f 6d 6d 65 6e 64 20 41 63 74 69 76 61 74 65 20 25 31 00}  //weight: 1, accuracy: High
        $x_1_2 = {4f 42 4e 4f 56 49 54 20 2d 20 21 3f 00}  //weight: 1, accuracy: High
        $x_1_3 = {61 00 76 00 70 00 3a 00 73 00 63 00 61 00 6e 00 00 00 00 00 25 00 31 00 35 00 32 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {4e 00 69 00 73 00 53 00 72 00 76 00 2e 00 65 00 78 00 65 00 00 00 00 00 6d 00 73 00 73 00 65 00 63 00 65 00 73 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {4e 6f 2c 20 43 6f 6e 74 69 6e 75 65 20 75 6e 70 72 6f 74 65 63 74 65 64 20 28 44 61 6e 67 65 72 6f 75 73 29 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 31 20 72 69 67 68 74 20 6e 6f 77 20 61 6e 64 20 73 74 6f 70 20 77 6f 72 72 79 69 6e 67 20 61 62 6f 75 74 20 50 43 20 73 65 63 75 72 69 74 79 20 66 6f 72 65 76 65 72 21 00}  //weight: 1, accuracy: High
        $x_1_7 = {50 6c 65 61 73 65 20 77 72 69 74 65 20 69 74 20 66 6f 72 20 66 75 74 75 72 65 20 75 73 69 6e 67 20 61 6e 64 20 73 75 70 70 6f 72 74 20 72 65 71 75 65 73 74 73 2e 00}  //weight: 1, accuracy: High
        $x_1_8 = {53 6f 6d 65 20 6f 66 20 73 65 63 75 72 65 20 63 6f 6d 70 6f 6e 65 6e 74 73 20 69 6e 61 63 74 69 76 65 2e 20 50 6c 65 61 73 65 20 63 68 65 63 6b 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_FakeRean_124161_42
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "a.innerText = \"Click here to get \" + product_name + \" License\"" ascii //weight: 2
        $x_2_2 = {57 69 6e 64 6f 77 73 20 68 61 73 20 64 65 74 65 63 74 65 64 [0-16] 69 6e 73 74 61 6c 6c 65 64 20 61 6e 74 69 73 70 79 77 61 72 65 20 73 6f 66 74 77 61 72 65 73 20 6f 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 2e}  //weight: 2, accuracy: Low
        $x_2_3 = "Greetings to Sunbelt - only they know my name! ;)" ascii //weight: 2
        $x_2_4 = {aa e2 f2 81 7d ?? 6b 65 72 6e 75 ?? 81 7d ?? 65 6c 33 32 75 ?? 81 7d ?? 2e 64 6c 6c 75}  //weight: 2, accuracy: Low
        $x_1_5 = "VirusProtText" wide //weight: 1
        $x_1_6 = "WinSecurityCenter.cpl" ascii //weight: 1
        $x_1_7 = "Mystic Compressor" ascii //weight: 1
        $x_1_8 = "Your system might be at risk now." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRean_124161_43
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 64 6f 6e 27 74 20 6c 6f 61 64 [0-4] 73 63 75 69 2e 63 70 6c}  //weight: 1, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Security Center\\AntiVirusDisableNotify" ascii //weight: 1
        $x_1_3 = {2f 70 70 2f 3f 69 64 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {66 73 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5f 00 55 00 70 00 64 00 61 00 74 00 65 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_3_6 = {b3 01 eb 66 6a 0a e8 ?? ?? ?? ?? b3 01 eb 5b 6a 0a e8 ?? ?? ?? ?? b3 01 eb 50 6a 0a}  //weight: 3, accuracy: Low
        $x_2_7 = "Agent.arpt is a Spyware program that records keystrokes" wide //weight: 2
        $x_1_8 = "Do you want to block this suspicious software?" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRean_124161_44
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {5c 5f 73 63 75 69 2e 63 70 6c 22 00}  //weight: 3, accuracy: High
        $x_3_2 = {2f 72 65 67 5f 70 72 6f 64 75 63 74 2e 70 68 70 3f 73 6b 65 79 3d 25 73 26 68 73 3d 25 73 00}  //weight: 3, accuracy: High
        $x_3_3 = {2f 72 65 67 5f 70 72 6f 64 75 63 74 2e 70 68 70 3f 65 6d 61 69 6c 3d 25 73 26 6b 65 79 3d 25 73 26 68 73 3d 25 73 00}  //weight: 3, accuracy: High
        $x_1_4 = "dialog-spywarescan" ascii //weight: 1
        $x_1_5 = "dialog-antispyware" ascii //weight: 1
        $x_1_6 = "dialog-firewall" ascii //weight: 1
        $x_1_7 = "dialog-privacy" ascii //weight: 1
        $x_1_8 = {73 74 61 74 69 63 2d 69 6e 66 65 63 74 69 6f 6e 73 5f 66 6f 75 6e 64 00}  //weight: 1, accuracy: High
        $x_1_9 = {48 54 4d 4c 5f 53 50 59 57 41 52 45 53 43 41 4e 5f 44 49 41 4c 4f 47 00}  //weight: 1, accuracy: High
        $x_1_10 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 65 78 69 74 20 74 68 65 20 57 69 6e 41 6e 74 69 4d 61 6c 77 61 72 65 3f 00}  //weight: 1, accuracy: High
        $x_1_11 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 6c 65 61 76 65 20 74 68 65 20 6f 70 74 69 6f 6e 73 20 77 69 74 68 6f 75 74 20 73 61 76 69 6e 67 3f 00}  //weight: 1, accuracy: High
        $x_1_12 = {2f 64 61 69 6c 79 2e 63 76 64 00}  //weight: 1, accuracy: High
        $x_1_13 = {2f 6d 61 69 6e 2e 63 76 64 00}  //weight: 1, accuracy: High
        $x_4_14 = "/Antivirus PC 2009.lnk" ascii //weight: 4
        $x_3_15 = "avpc2009.exe" ascii //weight: 3
        $x_1_16 = "/data/self.hdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRean_124161_45
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 72 00 65 00 63 00 6f 00 6d 00 6d 00 65 00 6e 00 64 00 20 00 41 00 63 00 74 00 69 00 76 00 61 00 74 00 65 00 20 00 25 00 31 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {00 00 77 00 73 00 63 00 75 00 69 00 5f 00 63 00 6c 00 61 00 73 00 73 00 00 00}  //weight: 2, accuracy: High
        $x_2_3 = {22 00 20 00 2f 00 47 00 41 00 56 00 20 00 00 00}  //weight: 2, accuracy: High
        $x_1_4 = {53 00 6f 00 6d 00 65 00 20 00 6f 00 66 00 20 00 73 00 65 00 63 00 75 00 72 00 65 00 20 00 63 00 6f 00 6d 00 70 00 6f 00 6e 00 65 00 6e 00 74 00 73 00 20 00 69 00 6e 00 61 00 63 00 74 00 69 00 76 00 65 00 2e 00 20 00 50 00 6c 00 65 00 61 00 73 00 65 00 20 00 63 00 68 00 65 00 63 00 6b 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {43 00 6f 00 6e 00 74 00 69 00 6e 00 75 00 65 00 20 00 73 00 75 00 72 00 66 00 69 00 6e 00 67 00 20 00 77 00 69 00 74 00 68 00 6f 00 75 00 74 00 20 00 61 00 6e 00 79 00 20 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 6d 00 65 00 61 00 73 00 75 00 72 00 65 00 73 00 20 00 28 00 44 00 41 00 4e 00 47 00 45 00 52 00 4f 00 55 00 53 00 29 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "System security ALERT!" wide //weight: 1
        $x_1_7 = "Attention: DANGER!" wide //weight: 1
        $x_1_8 = {66 00 75 00 63 00 6b 00 69 00 6e 00 67 00 20 00 66 00 75 00 63 00 6b 00 20 00 2e 00 2e 00 00 00}  //weight: 1, accuracy: High
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

rule Rogue_Win32_FakeRean_124161_46
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {57 65 6c 63 6f 6d 65 20 74 6f 20 69 6e 73 74 61 6c 6c 65 72 20 57 69 6e [0-5] 44 65 66 65 6e 64 65 72}  //weight: 2, accuracy: Low
        $x_2_2 = {57 69 6e 64 6f 77 73 [0-1] 44 65 66 65 6e 64 65 72 20 32 30 31 32 20 55 6e 69 6e 73 74 61 6c 6c}  //weight: 2, accuracy: Low
        $x_2_3 = "@$&%04\\defender.exe" ascii //weight: 2
        $x_1_4 = {53 70 79 77 61 72 65 [0-1] 50 72 6f 74 65 63 74 69 6f 6e [0-9] 2e 6c 6e 6b}  //weight: 1, accuracy: Low
        $x_1_5 = "Welcome to the WindowsDefender Setup Wizard" ascii //weight: 1
        $x_2_6 = {57 65 6c 63 6f 6d 65 20 74 6f 20 69 6e 73 74 61 6c 6c 65 72 20 53 65 63 75 72 69 74 79 [0-1] 45 73 73 65 6e 74 69 61 6c 73}  //weight: 2, accuracy: Low
        $x_2_7 = {57 69 6e 64 6f 77 73 [0-3] 44 65 66 65 6e 64 65 72 ?? 32 30 31 31}  //weight: 2, accuracy: Low
        $x_2_8 = {57 65 6c 63 6f 6d 65 20 74 6f 20 69 6e 73 74 61 6c 6c 65 72 20 53 65 63 75 72 65 20 45 73 73 65 6e 74 69 61 6c 73 00}  //weight: 2, accuracy: High
        $x_1_9 = "Secure Essentials is breaking" ascii //weight: 1
        $x_2_10 = {57 65 6c 63 6f 6d 65 20 74 6f 20 69 6e 73 74 61 6c 6c 65 72 20 64 66 67 68 66 64 67 68 66 64 67 68 67 00}  //weight: 2, accuracy: High
        $x_1_11 = "Install dfghfdghfdghg is breaking" ascii //weight: 1
        $x_2_12 = {57 65 6c 63 6f 6d 65 20 74 6f 20 69 6e 73 74 61 6c 6c 65 72 20 57 69 6e 64 6f 77 73 20 37 00}  //weight: 2, accuracy: High
        $x_1_13 = "Install Windows 7 is breaking" ascii //weight: 1
        $x_1_14 = "Antispyware Protection.lnk" ascii //weight: 1
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

rule Rogue_Win32_FakeRean_124161_47
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 64 00 2e 00 70 00 68 00 70 00 3f 00 69 00 64 00 3d 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {2f 00 74 00 6e 00 78 00 2e 00 70 00 68 00 70 00 3f 00 6d 00 61 00 69 00 6c 00 3d 00 00 00}  //weight: 2, accuracy: High
        $x_2_3 = "and UNWANTED files on your computer!" wide //weight: 2
        $x_1_4 = {2f 00 70 00 70 00 2f 00 3f 00 69 00 64 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "Security Alert!" wide //weight: 1
        $x_1_6 = {50 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 20 00 6c 00 65 00 76 00 65 00 6c 00 3a 00 20 00 4c 00 4f 00 57 00 00 00}  //weight: 1, accuracy: High
        $x_3_7 = ".php?version=%aff%&email=%email%&os=%os%" wide //weight: 3
        $x_2_8 = "/payment/index.php?version=%aff%" wide //weight: 2
        $x_2_9 = "iexplore.exe;calc.exe;WinWord.exe" wide //weight: 2
        $x_1_10 = "Email-Worm.VBS.Peach#This internet worm spreads via e-mail" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeRean_124161_48
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WIN32.Annex.Worm" ascii //weight: 1
        $x_1_2 = "and UNWANTED files on your computer!" ascii //weight: 1
        $x_1_3 = "Please write it for future using and support requests." ascii //weight: 1
        $x_1_4 = {53 00 70 00 79 00 77 00 61 00 72 00 65 00 20 00 61 00 6c 00 61 00 72 00 6d 00 21 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "All malware objects was remove" wide //weight: 1
        $x_1_6 = "<title> Reported Insecure Browsing: Navigation blocked" wide //weight: 1
        $x_1_7 = "Are you sure to stay unprot" wide //weight: 1
        $x_1_8 = "Are you really want to keep infe" wide //weight: 1
        $x_1_9 = "Windows hangovers and crashes without limitations" ascii //weight: 1
        $x_1_10 = {75 72 6e 20 66 69 72 65 77 61 6c 6c 20 6f 6e 2c 20 73 6f 20 74 68 61 74 20 6e 6f 20 6f 6e 65 20 63 6f 75 6c 64 20 61 74 74 61 63 6b 20 69 74 20 66 72 6f 6d 20 74 68 65 20 49 6e 74 65 72 6e 65 0c}  //weight: 1, accuracy: High
        $x_1_11 = ">Insecure Internet activity. Threat of virus attack<" wide //weight: 1
        $x_1_12 = "Advanced Security Tool 20" wide //weight: 1
        $x_1_13 = "return add('Continue to this website unprotected (not recommended).')\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_FakeRean_124161_49
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeRean"
        threat_id = "124161"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeRean"
        severity = "163"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "{427dbde0-7799-4611-9789-deb36156d1ad}" ascii //weight: 3
        $x_3_2 = "http://%s/httpss/setup.php?action=4&mk=%s&aid=%s" ascii //weight: 3
        $x_3_3 = "/setup.php?v=%s&action=%s&mk=%s&aid=%s" ascii //weight: 3
        $x_2_4 = "http://www.%domain%/buy/" ascii //weight: 2
        $x_1_5 = "RunDll32.exe shell32.dll,Control_RunDLL wscui.cpl" ascii //weight: 1
        $x_1_6 = {5c 62 75 79 70 61 67 65 2e 68 74 6d 6c 00}  //weight: 1, accuracy: High
        $x_2_7 = "Are you wish to keep this ILLEGAL FILE on your computer?" ascii //weight: 2
        $x_2_8 = "The \"viral code\" (1436 B) will receive the execution inside the infected file." ascii //weight: 2
        $x_1_9 = "Pigax.gen.a!921565b7f6" ascii //weight: 1
        $x_2_10 = {68 74 74 70 3a 2f 2f 77 77 77 2e [0-1] 25 73 2f 62 75 79 2f 69 6e 64 65 78 2f 25 73 2f 25 73}  //weight: 2, accuracy: Low
        $x_1_11 = "Your computer WILL BE DISCONNECTED FORM INTERNET BECAUSE SPAMMING OTHER PCs" ascii //weight: 1
        $x_3_12 = "%s/httpss/setup.php?v=%d&action=4&mk=%s&aid=%s" ascii //weight: 3
        $x_2_13 = {25 73 25 73 3f 70 3d ?? 26 61 69 64 3d 25 73}  //weight: 2, accuracy: Low
        $x_2_14 = "{FBD69E67-C708-47be-B49F-33D4200B818C}" ascii //weight: 2
        $x_1_15 = "/buy/?affiliate_id=" wide //weight: 1
        $x_3_16 = {65 6e 74 72 79 20 70 6f 69 6e 74 20 69 74 73 20 61 6c 73 6f 20 72 65 70 6c 65 61 63 65 64 20 77 69 74 68 [0-2] 70 6f 6c 79 6d 6f 72 70 68 69 63 73 20 73 65 71 75 65 6e 63 65 73}  //weight: 3, accuracy: Low
        $x_2_17 = "http://%s%s?p=2&aid=%" ascii //weight: 2
        $x_2_18 = "s&orderid=%d&key=%s" ascii //weight: 2
        $x_1_19 = "By destroying the BIOS many times you end up buying" ascii //weight: 1
        $x_1_20 = "CAttackDlg" ascii //weight: 1
        $x_1_21 = {73 65 63 75 72 69 74 79 63 65 6e 74 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_22 = {61 6c 65 72 33 66 61 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_2_23 = "http://www.[:||||:]/buy/" ascii //weight: 2
        $x_1_24 = "%s\\How to Activate %s.lnk" ascii //weight: 1
        $x_2_25 = "proxy-relay trojan server with new and danger \"SpamBots\"." ascii //weight: 2
        $x_2_26 = "(ISP) for YOU personal computer is on some major blackl" ascii //weight: 2
        $x_2_27 = "private data steal such as passwords" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

