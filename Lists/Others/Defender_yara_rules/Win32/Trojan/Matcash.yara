rule Trojan_Win32_Matcash_17557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matcash"
        threat_id = "17557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wurlmon.dll" ascii //weight: 1
        $x_1_2 = "mcboo.com" ascii //weight: 1
        $x_1_3 = "WinTouch.exe" ascii //weight: 1
        $x_1_4 = "win-touch.com" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_7 = "CreateDirectoryA" ascii //weight: 1
        $x_1_8 = "GetWindowsDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Matcash_17557_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matcash"
        threat_id = "17557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "wr.mcboo.com" ascii //weight: 3
        $x_2_2 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 72 00 65 00 74 00 61 00 64 00 70 00 75 00 2e 00 65 00 78 00 65}  //weight: 2, accuracy: High
        $x_2_3 = "\\retadpu" ascii //weight: 2
        $x_1_4 = "doupdate" ascii //weight: 1
        $x_1_5 = "doupdate==%d" ascii //weight: 1
        $x_1_6 = "Downloading file..." ascii //weight: 1
        $x_1_7 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 75 00 70 00 64 00 61 00 74 00 65 00 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Matcash_17557_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matcash"
        threat_id = "17557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mcboo.com" ascii //weight: 1
        $x_1_2 = "search.com-com.ws" ascii //weight: 1
        $x_1_3 = "affiliate=" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_5 = "208.67.222.222" ascii //weight: 1
        $x_1_6 = "%sUpdateWords\\%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Matcash_17557_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matcash"
        threat_id = "17557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "InternetOpenUrlA" ascii //weight: 10
        $x_10_2 = "CreateMutexA" ascii //weight: 10
        $x_2_3 = {64 6f 77 6e 6c 6f 61 64 00 00 00 00 57 52 5c 6e 65 78 74 75 70 64 61 74 65}  //weight: 2, accuracy: High
        $x_2_4 = {70 61 69 64 00 00 00 00 57 52 5c 63 6f 6e 66 69 67 76 65 72 73 69 6f 6e}  //weight: 2, accuracy: High
        $x_2_5 = {65 72 31 00 6e 6e 00 00 75 6e}  //weight: 2, accuracy: High
        $x_1_6 = {76 65 72 73 69 6f 6e 00 6e 65 77 75 70 64 61 74 65 72}  //weight: 1, accuracy: High
        $x_1_7 = {77 61 69 74 00 00 00 00 65 78 65 63 75 74 65 00 68 69 64 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Matcash_17557_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matcash"
        threat_id = "17557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Global\\{F9CD854B-2C8B-412f-8F13-B0BF8DDEB229}" ascii //weight: 10
        $x_10_2 = "/wtd.php?uid={" ascii //weight: 10
        $x_3_3 = "Impossible de lire le fichier de sortie" ascii //weight: 3
        $x_3_4 = "mcboo.com" ascii //weight: 3
        $x_3_5 = {6d 63 2d 00 74 65 2d 00}  //weight: 3, accuracy: High
        $x_1_6 = "Software\\Classes\\CLSID\\{" ascii //weight: 1
        $x_1_7 = "SystemBiosDate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Matcash_17557_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matcash"
        threat_id = "17557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "79"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "{C1B4DEC2-2623-438e-9CA2-C9043AB28508}" ascii //weight: 20
        $x_10_2 = "Software\\Microsoft\\Internet Explorer\\Toolbar" ascii //weight: 10
        $x_10_3 = "ToolBar.DLL" ascii //weight: 10
        $x_10_4 = "UrlEscapeA" ascii //weight: 10
        $x_10_5 = "BandToolBarReflectorCtrl" ascii //weight: 10
        $x_10_6 = "BandToolBarCtrl" ascii //weight: 10
        $x_3_7 = "http://babelfish.altavista.com/" ascii //weight: 3
        $x_3_8 = "http://finance.yahoo.com/" ascii //weight: 3
        $x_3_9 = "http://casinotropez.com/" ascii //weight: 3
        $x_3_10 = "http://www.comfm.com" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_10_*) and 3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Matcash_17557_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matcash"
        threat_id = "17557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2f 63 61 70 74 75 72 65 [0-2] 2f [0-6] 2f 6d 63 61 73 68 2f 00 68 74 74 70 3a 2f 2f 00 63 6f 6d}  //weight: 10, accuracy: Low
        $x_2_2 = {6e 61 6d 65 00 00 00 00 63 61 70 74 75 72 65 [0-2] 2e 6a 73}  //weight: 2, accuracy: Low
        $x_2_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 00 00 66 69 72 73 74}  //weight: 2, accuracy: High
        $x_2_4 = {5c 54 65 6d 70 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e}  //weight: 2, accuracy: High
        $x_1_5 = "%2.2X-%2.2X-%2.2X-%2.2X-%2.2X-%2.2X" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_7 = "check.php?mac=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Matcash_C_98631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matcash.gen!C"
        threat_id = "98631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Global\\{F9CD854B-2C8B-412f-8F13-B0BF8DDEB229}" ascii //weight: 10
        $x_10_2 = "/wtd.php?uid={" ascii //weight: 10
        $x_3_3 = "Impossible de lire le fichier de sortie" ascii //weight: 3
        $x_3_4 = "mcboo.com" ascii //weight: 3
        $x_3_5 = {6d 63 2d 00}  //weight: 3, accuracy: High
        $x_1_6 = "Software\\Classes\\CLSID\\{" ascii //weight: 1
        $x_1_7 = "SystemBiosDate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Matcash_D_98632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matcash.gen!D"
        threat_id = "98632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "79"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "{C1B4DEC2-2623-438e-9CA2-C9043AB28508}" ascii //weight: 20
        $x_10_2 = "Software\\Microsoft\\Internet Explorer\\Toolbar" ascii //weight: 10
        $x_10_3 = "ToolBar.DLL" ascii //weight: 10
        $x_10_4 = "UrlEscapeA" ascii //weight: 10
        $x_10_5 = "BandToolBarReflectorCtrl" ascii //weight: 10
        $x_10_6 = "BandToolBarCtrl" ascii //weight: 10
        $x_3_7 = "http://babelfish.altavista.com/" ascii //weight: 3
        $x_3_8 = "http://finance.yahoo.com/" ascii //weight: 3
        $x_3_9 = "http://casinotropez.com/" ascii //weight: 3
        $x_3_10 = "http://www.comfm.com" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_10_*) and 3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Matcash_E_98633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matcash.gen!E"
        threat_id = "98633"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" ascii //weight: 2
        $x_1_2 = "cpv.lbann.com" ascii //weight: 1
        $x_1_3 = {43 50 56 36 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_4 = "-487E-B399-3F191AC0FE23" wide //weight: 1
        $x_1_5 = {75 70 6c 2e 6c 62 00 00 63 70 76}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Matcash_KU_117584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matcash.KU"
        threat_id = "117584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mcboo.com/ack.php?uid=00000000-0000-1033--ss0000&version=16&actionname=_regcheck&action=CheckBundle" ascii //weight: 10
        $x_10_2 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_3 = "CreateDirectoryA" ascii //weight: 10
        $x_10_4 = "GetWindowsDirectoryA" ascii //weight: 10
        $x_1_5 = "kernInstall.exe" ascii //weight: 1
        $x_1_6 = "kernInst.exe" ascii //weight: 1
        $x_1_7 = "wininstall.exe" ascii //weight: 1
        $x_1_8 = "Installeur.exe" ascii //weight: 1
        $x_1_9 = "install_words" ascii //weight: 1
        $x_1_10 = "InetGet2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Matcash_I_126530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matcash.gen!I"
        threat_id = "126530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c7 45 8c 01 00 00 00 c6 45 90 32 c7 45 94 02 00 00 00 c6 45 98 33 c7 45 9c 03 00 00 00 c6 45 a0 34 c7 45 a4 04 00 00 00 c6 45 a8 35 c7 45 ac 05 00 00 00 c6 45 b0 36 c7 45 b4 06 00 00 00 c6 45 b8 37 c7 45 bc 07 00 00 00 c6 45 c0 38 c7 45 c4 08 00 00 00 c6 45 c8 39 c7 45 cc 09 00 00 00 c6 45 d0 41 c7 45 d4 0a 00 00 00 c6 45 d8 42 c7 45 dc 0b 00 00 00 c6 45 e0 43 c7 45 e4 0c 00 00 00 c6 45 e8 44 c7 45 ec 0d 00 00 00 c6 45 f0 45}  //weight: 10, accuracy: High
        $x_1_2 = "0BA755B680DD77564DDB6D0817BB4D92" ascii //weight: 1
        $x_1_3 = "0BA755B680DD775641C76715278140BD96DF77" ascii //weight: 1
        $x_1_4 = "0BA755B680DD775650CE690204A04DB6" ascii //weight: 1
        $x_1_5 = "35A04FBA9CD6660C66C764" ascii //weight: 1
        $x_1_6 = "789B44A397D2662F08CF6D0A62EB04A0D0BE184B648B6D1E2BBA55F3D09661002" ascii //weight: 1
        $x_1_7 = "2CC67122DE973B682D673560FA17A0B26A053F3D09661000FA16C032EE903F681" ascii //weight: 1
        $x_1_8 = "http://ksn.a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Matcash_J_127504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matcash.gen!J"
        threat_id = "127504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c6 45 98 33 c7 45 9c 03 00 00 00 c6 45 a0 34 c7 45 a4 04 00 00 00 c6 45 a8 35 c7 45 ac 05 00 00 00 c6 45 b0 36 c7 45 b4 06 00 00 00 c6 45 b8 37 c7 45 bc 07 00 00 00 c6 45 c0 38 c7 45 c4 08 00 00 00 c6 45 c8 39 c7 45 cc 09 00 00 00 c6 45 d0 41 c7 45 d4 0a 00 00 00 c6 45 d8 42 c7 45 dc 0b 00 00 00 c6 45 e0 43 c7 45 e4 0c 00 00 00 c6 45 e8 44 c7 45 ec 0d 00 00 00 c6 45 f0 45 c7 45 f4 0e 00 00 00 c6 45 f8 46 c7 45 fc 0f 00 00 00}  //weight: 10, accuracy: High
        $x_1_2 = "0BA755B680DD775641C76715278140BD96DF77" ascii //weight: 1
        $x_1_3 = "0BA755B680DD775650CE690204A04DB6" ascii //weight: 1
        $x_1_4 = "35A04FBA9CD6660C66C764" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Matcash_K_127902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matcash.gen!K"
        threat_id = "127902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 0a 5f f7 f7 80 c2 30 88 54 35 e8 46 85 c0 75 ed 3b ce 7e 1e 2b ce 89 4d 7c 8b d1 c1 e9 02 8d 7c 35 e8 b8 30 30 30 30}  //weight: 1, accuracy: High
        $x_1_2 = {83 7d f0 00 74 1a 80 7d 13 0a 75 05 c6 06 0a eb 1c 6a 01 6a ff ff 75 14 e8 e0 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Matcash_G_133074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matcash.gen!G"
        threat_id = "133074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matcash"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2f 6d 63 61 73 68 [0-4] 68 74 74 70 3a 2f 2f [0-14] 2e 63 6f 6d}  //weight: 10, accuracy: Low
        $x_10_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 10
        $x_2_3 = {70 72 6f 66 69 6c 65 [0-2] 2e 6a 73}  //weight: 2, accuracy: Low
        $x_2_4 = {74 6d 70 00 53 74 61 72 74 20 50 61 67 65 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e}  //weight: 2, accuracy: High
        $x_1_5 = {62 6f 6f 74 2e 70 68 70 3f 6d 61 63 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = "%02X%02X%02X%02X%02X%02X" ascii //weight: 1
        $x_1_7 = "InternetShortcut.W" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

