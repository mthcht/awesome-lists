rule Rogue_Win32_FakePlus_134332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePlus"
        threat_id = "134332"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePlus"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 35 44 21 41 00 56 ff 75 fc e8 53 bc ff ff 4f 75 ee 8b 4d fc 8d 81 b4 15 00 00 81 c1 64 31 00 00 33 08 6a 43 81 f1 87 d2 e3 f3 89 08 5f}  //weight: 1, accuracy: High
        $x_1_2 = {a3 34 1d 41 00 8b 45 0c ff 30 e8 28 0a 00 00 33 06 5f 35 d7 d5 e3 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakePlus_134332_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePlus"
        threat_id = "134332"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePlus"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "uid=%s&v=%u&aid=%s" ascii //weight: 2
        $x_2_2 = "/cb/exe_in_db.php" ascii //weight: 2
        $x_1_3 = "/cmd.php" ascii //weight: 1
        $x_1_4 = "AVDownloadAndExecuteCommand" ascii //weight: 1
        $x_2_5 = {75 69 64 5f 6d 75 74 61 6e 74 00}  //weight: 2, accuracy: High
        $x_1_6 = {41 70 70 49 6e 69 74 5f 44 4c 4c 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePlus_134332_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePlus"
        threat_id = "134332"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePlus"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "SuperMegaForce" ascii //weight: 1
        $x_5_3 = {54 6a 06 68 ?? ?? ?? ?? a1 ?? ?? ?? ?? 50 6a ff e8 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 68 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? c3 54 6a 06 68 ?? ?? ?? ?? a1 ?? ?? ?? ?? 50 6a ff e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePlus_134332_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePlus"
        threat_id = "134332"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePlus"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TTIEAdvBHO" ascii //weight: 1
        $x_2_2 = "antivirusplus2009.com" ascii //weight: 2
        $x_2_3 = "antivirus-plus-2009.com" ascii //weight: 2
        $x_2_4 = "secure-plus-payments.com" ascii //weight: 2
        $x_5_5 = {49 6e 74 65 72 6e 65 74 45 78 70 6c 6f 72 65 72 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00}  //weight: 5, accuracy: High
        $x_6_6 = {3f 75 72 6c 3d 00 00 00 ff ff ff ff 04 00 00 00 26 69 64 3d 00}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePlus_134332_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePlus"
        threat_id = "134332"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePlus"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {51 68 e2 00 00 00 57 56 ff 15 ?? ?? ?? ?? 85 c0 74 19 81 7c 24 08 e2 00 00 00 75 0f}  //weight: 2, accuracy: Low
        $x_2_2 = {30 1c 01 42 3b d7 7c 02 33 d2 41 81 f9 ?? ?? 00 00 7c}  //weight: 2, accuracy: Low
        $x_1_3 = "uid=%s&v=%u&aid=%s" wide //weight: 1
        $x_1_4 = "%s%s?url=%s&id=%s" wide //weight: 1
        $x_1_5 = "exe_in_db.php" wide //weight: 1
        $x_1_6 = "my-antivirusplus.org" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakePlus_134332_5
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakePlus"
        threat_id = "134332"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePlus"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 73 79 73 74 65 6d 33 32 5c 61 76 70 2e 69 64 00}  //weight: 1, accuracy: High
        $x_1_2 = "Activating. Please Wait. This may take a few minutes..." ascii //weight: 1
        $x_1_3 = " serious threats are found while scanning your files and registry!" ascii //weight: 1
        $x_1_4 = "It is strongly recomended to entirely clean your PC in order to protect the system against future intrusions!" ascii //weight: 1
        $x_2_5 = "Infects executable files with BS-worm, corrupts MS Office documents and spreadsheets." ascii //weight: 2
        $x_2_6 = {41 6e 74 69 76 69 72 75 73 20 50 6c 75 73 00}  //weight: 2, accuracy: High
        $x_2_7 = "Antivirus Plus is already running in system tray." ascii //weight: 2
        $x_2_8 = "Your cookies and temporary files were deleted successfully!" ascii //weight: 2
        $x_3_9 = "install/AntivirusPlus.grn" ascii //weight: 3
        $x_3_10 = "cfg/dmns.cfg" ascii //weight: 3
        $x_4_11 = {63 62 2f 72 65 61 6c 2e 70 68 70 3f 69 64 3d 00}  //weight: 4, accuracy: High
        $x_3_12 = "{D032570A-5F63-4812-A094-87D007C23012}" ascii //weight: 3
        $x_3_13 = {57 61 72 6e 69 6e 67 21 20 00 00 00 ff ff ff ff 0f 00 00 00 20 74 68 72 65 61 74 73 20 66 6f 75 6e 64 21}  //weight: 3, accuracy: High
        $x_1_14 = "Regular antivirus software updates are necessary" ascii //weight: 1
        $x_6_15 = {6a 01 6a 00 6a 02 6a 00 6a ff e8 ?? ?? ?? ?? 8b d8 e8 ?? ?? ?? ?? 3d b7 00 00 00 75 1b 68 10 00 04 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 e8}  //weight: 6, accuracy: Low
        $x_3_16 = {69 6e 73 74 61 6c 6c 2f 61 76 70 6c 75 73 2e 64 6c 6c 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
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
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

