rule TrojanClicker_Win32_Clikug_A_2147686054_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Clikug.A"
        threat_id = "2147686054"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Clikug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {47 6c 6f 62 61 6c 5c 47 43 5f 43 6f 6e 74 72 6f 6c 6c 65 72 00}  //weight: 2, accuracy: High
        $x_2_2 = "SOFTWARE\\GigaClicks Crawler" ascii //weight: 2
        $x_1_3 = "Chrome Worker Failed, %s" ascii //weight: 1
        $x_1_4 = "Click To x: %d y: %d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Clikug_A_2147686054_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Clikug.A"
        threat_id = "2147686054"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Clikug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GigaClicks Crawler" wide //weight: 2
        $x_1_2 = "Chrome Worker Failed, %s" ascii //weight: 1
        $x_2_3 = "Click To x: %d y: %d" ascii //weight: 2
        $x_2_4 = "%s/stat/uid/%s/sid/%d/a/%s/" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Clikug_B_2147686108_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Clikug.B"
        threat_id = "2147686108"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Clikug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Hyper Browser" wide //weight: 2
        $x_1_2 = "Chrome Worker Failed, %s" ascii //weight: 1
        $x_2_3 = "Click To x: %d y: %d" ascii //weight: 2
        $x_2_4 = "%s/stat/uid/%s/sid/%d/a/%s/" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Clikug_C_2147687018_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Clikug.C"
        threat_id = "2147687018"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Clikug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "IdleCrawler" wide //weight: 2
        $x_1_2 = "Chrome Worker Failed, %s" ascii //weight: 1
        $x_2_3 = "Click To x: %d y: %d" ascii //weight: 2
        $x_2_4 = "%s/stat/uid/%s/sid/%d/a/%s/" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Clikug_D_2147688545_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Clikug.D"
        threat_id = "2147688545"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Clikug"
        severity = "8"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "IdleCrawler" ascii //weight: 10
        $x_1_2 = "Chrome Worker Failed, %s" ascii //weight: 1
        $x_1_3 = ".?AVProfileInstallerWrapper@@" ascii //weight: 1
        $x_1_4 = "Main PID: %d Handle: 0x%x TID: %d Handle: 0x%x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Clikug_D_2147688545_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Clikug.D"
        threat_id = "2147688545"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Clikug"
        severity = "8"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"%s\" -Profile \"%s\" -no-remote" wide //weight: 1
        $x_1_2 = "Chrome Worker Failed, %s" ascii //weight: 1
        $x_1_3 = {53 75 70 70 53 72 76 33 00}  //weight: 1, accuracy: High
        $x_1_4 = {50 61 72 73 69 6e 67 20 43 4d 44 3a 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {2f 53 75 70 70 53 72 76 32 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_6 = {63 64 6e 00 49 64 6c 65 43 72 61 77 6c 65 72 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_7 = {63 64 6e 2e 25 73 2f 25 73 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_8 = {63 64 6e 2e 63 6f 6d 00 2f 00 00 00 2e 70 68 00}  //weight: 1, accuracy: High
        $x_2_9 = {59 00 64 00 72 00 53 00 75 00 70 00 70 00 00 00}  //weight: 2, accuracy: High
        $x_1_10 = {8b 08 68 26 98 00 00 8b 01 8d 54 24 ?? 52 ff 50}  //weight: 1, accuracy: Low
        $x_1_11 = "schtasks /Stop /F /TN \"Idle~Crawler Runner\"" wide //weight: 1
        $x_1_12 = "schtasks /Stop /F /TN \"Idle-Crawler Runner\"" wide //weight: 1
        $x_1_13 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 47 00 69 00 67 00 61 00 43 00 6c 00 69 00 63 00 6b 00 73 00 5c 00 43 00 72 00 61 00 77 00 6c 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_14 = "schtasks /Create /TN \"Microsoft\\Windows\\Maintenance\\Idle" wide //weight: 1
        $x_1_15 = "GC_Scheduler Run:" wide //weight: 1
        $x_1_16 = "GC_Scheduler Create:" wide //weight: 1
        $x_1_17 = "schtasks /Create /TN \"Microsoft\\Windows\\Maintenance\\IC Updater" wide //weight: 1
        $x_1_18 = "\\SvcSupport.exe\" --SendInstLogs \"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_Win32_Clikug_E_2147689651_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Clikug.E"
        threat_id = "2147689651"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Clikug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4e 00 61 00 76 00 53 00 75 00 70 00 70 00 00 00 43 00 6d 00 6e 00 55 00 74 00 6c 00 73 00 00 00 59 00 64 00 72 00 53 00 75 00 70 00 70 00 00 00 50 00 72 00 66 00 49 00 6e 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 00 61 00 6e 00 58 00 65 00 63 00 00 00 00 00 43 00 6d 00 64 00 50 00 72 00 6f 00 63 00 00 00 43 00 6d 00 6c 00 50 00 72 00 6f 00 63 00 00 00 43 00 68 00 72 00 6f 00 6d 00 65 00 2d 00 62 00 69 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {2d 00 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00 20 00 00 00 2d 00 6e 00 6f 00 2d 00 72 00 65 00 6d 00 6f 00 74 00 65 00 00 00 00 00 2d 00 2d 00 75 00 73 00 65 00 72 00 2d 00 64 00 61 00 74 00 61 00 2d 00 64 00 69 00 72 00 3d 00 00 00 00 00 2d 00 2d 00 75 00 73 00 65 00 72 00 2d 00 61 00 67 00 65 00 6e 00 74 00 3d 00 00 00 22 00 25 00 73 00 22 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {2d 00 2d 00 75 00 73 00 65 00 72 00 2d 00 64 00 61 00 74 00 61 00 2d 00 64 00 69 00 72 00 3d 00 00 00 22 00 25 00 73 00 22 00 00 00 00 00 20 00 2d 00 2d 00 75 00 73 00 65 00 72 00 2d 00 61 00 67 00 65 00 6e 00 74 00 3d 00 00 00 00 00 2d 00 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00 00 00 00 00 20 00 2d 00 6e 00 6f 00 2d 00 72 00 65 00 6d 00 6f 00 74 00 65 00 00 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 3a 00 20 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {2d 00 2d 00 45 00 72 00 72 00 00 00 2d 00 2d 00 53 00 75 00 70 00 70 00 00 00 00 00 2d 00 2d 00 56 00 65 00 72 00 00 00 2d 00 2d 00 55 00 69 00 64 00 00 00 2d 00 2d 00 44 00 6f 00 77 00 6e 00 4e 00 61 00 76 00 00 00 2d 00 2d 00 43 00 69 00 64 00 00 00 2d 00 2d 00 4d 00 6f 00 64 00 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {4e 6f 74 20 44 6f 77 6e 6c 6f 61 64 65 64 00 00 76 3d 31 00 26 74 69 64 3d 55 41 2d 35 36 38 33 38 36 36 32 2d 31 26 63 69 64 3d 00 26 74 3d 65 76 65 6e 74 26 65 63 3d}  //weight: 1, accuracy: High
        $x_1_7 = "schtasks /Stop /F /TN \"I.C. Runner Procedure\"" wide //weight: 1
        $x_1_8 = "schtasks /Stop /F /TN \"IC Running Procedure\"" wide //weight: 1
        $x_1_9 = "schtasks /Stop /F /TN \"IC Runner Procedure\"" wide //weight: 1
        $x_1_10 = "schtasks /Stop /F /TN \"GB Runner\"" wide //weight: 1
        $x_1_11 = "schtasks /Create /TN \"Microsoft\\Windows\\Maintenance\\I.C. Update Procedure\" /XML" wide //weight: 1
        $x_1_12 = "schtasks /Create /TN \"Microsoft\\Windows\\Maintenance\\IC Update Procedure\" /XML" wide //weight: 1
        $x_1_13 = "\\ExtHelper.exe\" --SendInstLogs \"" wide //weight: 1
        $x_1_14 = "\\AdvHelper.exe\" --SendInstLogs \"" wide //weight: 1
        $x_1_15 = "\\ExtRun.exe\" --SendInstLogs \"" wide //weight: 1
        $x_1_16 = "\\RtHelp.exe\" --SendInstLogs \"" wide //weight: 1
        $x_1_17 = "SOFTWARE\\I. d. l. e . C. r. a. w. l. e. r" wide //weight: 1
        $x_1_18 = "SOFTWARE\\I.d.l.e  C.r.a.w.l.e.r" wide //weight: 1
        $x_1_19 = "SOFTWARE\\Idle  Crawler" wide //weight: 1
        $x_1_20 = "SOFTWARE\\Idle Crawler" wide //weight: 1
        $x_1_21 = {00 00 69 00 64 00 6c 00 65 00 63 00 72 00 61 00 77 00 6c 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 2f 00 62 00 6c 00 6f 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_22 = {63 64 6e 00 49 64 6c 65 43 72 61 77 6c 65 72 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_23 = {68 74 74 70 3a 2f 2f 00 63 64 6e 00 67 62 6f 74 2e 75 6b 2e 63 6f 6d}  //weight: 1, accuracy: High
        $x_1_24 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 47 00 69 00 67 00 61 00 43 00 6c 00 69 00 63 00 6b 00 73 00 5c 00 43 00 72 00 61 00 77 00 6c 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_25 = "http://idlecrawler.com" wide //weight: 1
        $x_1_26 = "\\gigaclick\\Release\\Modules\\" ascii //weight: 1
        $x_1_27 = {2d 00 2d 00 53 00 65 00 6e 00 64 00 49 00 6e 00 73 00 74 00 4c 00 6f 00 67 00 73 00 00 00 00 00 2d 00 2d 00 50 00 72 00 65 00 43 00 68 00 65 00 63 00 6b 00 00 00 00 00 2d 00 2d 00 49 00 6e 00 73 00 74 00 53 00 75 00 70 00 70 00 00 00 00 00 2d 00 2d 00 55 00 70 00 4e 00 61 00 76 00 00 00 2d 00 2d 00 47 00 6f 00 41 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_28 = "aDeGigaForZaClicksoRwdewQQol==" wide //weight: 1
        $x_1_29 = "Idle Crawler Setup" wide //weight: 1
        $x_1_30 = {5c 00 55 00 70 00 64 00 48 00 65 00 6c 00 70 00 65 00 72 00 2e 00 64 00 6c 00 6c 00 00 00 43 00 72 00 65 00 61 00 74 00 65 00 54 00 61 00 73 00 6b 00 00 00 2d 00 2d 00 55 00 70 00 64 00 61 00 74 00 65 00}  //weight: 1, accuracy: High
        $x_1_31 = "\\RtHelp.exe\" --PreCheck" wide //weight: 1
        $x_1_32 = "VG9CZU9yOverTm90VG9UaLookGlzSXNUaGVRdWVzdGlvbg==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanClicker_Win32_Clikug_F_2147707204_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Clikug.F"
        threat_id = "2147707204"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Clikug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\InstSupp.dll\",CmdProc --Res " wide //weight: 1
        $x_1_2 = "\\InstSupp.dll\",CmdProc --Level --Supp" wide //weight: 1
        $x_1_3 = "SOFTWARE\\Ninja Loader" wide //weight: 1
        $x_1_4 = "Software\\Google\\Chrome\\Extensions\\cmlhbjpgeogifjnmlajdaealbdlfonah" wide //weight: 1
        $x_1_5 = "\\ists.dll\",CmdProc --Res " wide //weight: 1
        $x_1_6 = "\\ists.dll\",CmdProc --Level --Supp" wide //weight: 1
        $x_1_7 = "SOFTWARE\\Games Bot" wide //weight: 1
        $x_1_8 = "SELECT companyName,displayName,pathToSignedProductExe,versionNumber FROM AntiSpywareProduct" wide //weight: 1
        $x_1_9 = "--Tid UA-56838662-1" wide //weight: 1
        $x_1_10 = "D0E8C4-8D98-B742-BEA7-6B" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanClicker_Win32_Clikug_G_2147707246_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Clikug.G"
        threat_id = "2147707246"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Clikug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Runner IC" wide //weight: 1
        $x_1_2 = "\\UpdHelper.dll" wide //weight: 1
        $x_1_3 = "http://idlecrawler.com" wide //weight: 1
        $x_1_4 = "The reason you have Idle Crawler at your computer, is you installed sponsored software" wide //weight: 1
        $x_1_5 = "We're organization, which utilizes your unused computer power and broadband connection to crawl the web. To do so, we sponsor" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanClicker_Win32_Clikug_H_2147707247_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Clikug.H"
        threat_id = "2147707247"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Clikug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\WinHelp.exe\" --PreCheck" wide //weight: 1
        $x_1_2 = "XE1pY3Jvc29mdFxXaW5kb3dzXE1haW50ZW5hbmNl" wide //weight: 1
        $x_1_3 = "LiBQbGVhc2UgZG8gbm90IHN0b3AgdGhpcyB0YXNrIGluIG9yZGVyIHRvIGFsbG93IA==" wide //weight: 1
        $x_1_4 = "IHVwZGF0ZXIuIFBsZWFzZSBkbyBub3Qgc3RvcCB0aGlzIHRhc2sgaW4gb3JkZXIgdG8gYWxsb3cg" wide //weight: 1
        $x_1_5 = "\\UpdHelper.dll" wide //weight: 1
        $x_1_6 = "\\Runner.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

