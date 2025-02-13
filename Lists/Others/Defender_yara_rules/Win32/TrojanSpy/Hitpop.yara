rule TrojanSpy_Win32_Hitpop_Z_2147601297_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hitpop.Z"
        threat_id = "2147601297"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hitpop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AVP.Button" ascii //weight: 1
        $x_1_2 = "winlk.ini" ascii //weight: 1
        $x_1_3 = "mydown" ascii //weight: 1
        $x_1_4 = "hitpop" ascii //weight: 1
        $x_1_5 = "sysdn.ini" ascii //weight: 1
        $x_1_6 = "md5_ver" ascii //weight: 1
        $x_1_7 = "?reg=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_Win32_Hitpop_AB_2147601329_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hitpop.AB!dll"
        threat_id = "2147601329"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hitpop"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {43 6f 6d 6d 6f 6e 20 53 74 61 72 74 75 70 00 00 ff ff ff ff [0-37] 2e 6c 6e 6b}  //weight: 5, accuracy: Low
        $x_5_2 = {45 78 70 6c 6f 72 65 72 5c 72 75 6e [0-32] 2e 69 6e 69}  //weight: 5, accuracy: Low
        $x_5_3 = {52 55 4e 49 45 50 2e 45 58 45 00 00 ff ff ff ff 0a 00 00 00 4b 52 65 67 45 78 2e 65 78 65 00 00 ff ff ff ff 08 00 00 00 4b 56 58 50 2e 6b 78 70 00 00 00 00 ff ff ff ff 0b 00 00 00 33 36 30 74 72 61 79 2e 65 78 65}  //weight: 5, accuracy: High
        $x_10_4 = {64 ff 30 64 89 20 8b 45 08 e8 ?? ?? fe ff 8d 45 f0 50 8b 45 f8 e8 ?? ?? fe ff 50 8b 45 fc 50 e8 ?? ?? fe ff 85 c0}  //weight: 10, accuracy: Low
        $x_1_5 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_6 = "HinnerHTML" ascii //weight: 1
        $x_1_7 = "Htarget" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Hitpop_AE_2147604881_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hitpop.AE!dll"
        threat_id = "2147604881"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hitpop"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {74 3d 6a 00 6a 00 8d 55 ?? 8b 45 ?? 8b 04 c5 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d ?? 8d 45 ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 6a 00 6a 00 e8 ?? ?? ?? ?? ff 45 f8 83 7d f8 0b 75 ?? 33 c0 5a 59 59 64 89 10 68 ?? ?? ?? ?? 8d 45 ?? ba ?? 00 00 00}  //weight: 10, accuracy: Low
        $x_5_2 = {6e 20 53 74 61 72 74 75 70 [0-112] 2e 6c 6e 6b}  //weight: 5, accuracy: Low
        $x_1_3 = "\\Explorer\\run" ascii //weight: 1
        $x_1_4 = "KVXP.kxp" ascii //weight: 1
        $x_1_5 = "RUNIEP.EXE" ascii //weight: 1
        $x_1_6 = "KRegEx.exe" ascii //weight: 1
        $x_1_7 = "360tray.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Hitpop_A_2147605193_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hitpop.gen!A"
        threat_id = "2147605193"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hitpop"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {be 01 00 00 00 47 83 ff 10 7e 05 bf 01 00 00 00 8d 45 d8 8b 55 ec 8a 54 3a ff e8 ?? ?? ?? ?? 8b 45 d8 e8 ?? ?? ?? ?? 8b 55 f0 0f b6 54 32 ff 33 c2 89 45 f4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 75 a7}  //weight: 5, accuracy: Low
        $x_2_2 = {6d 79 64 6f 77 6e 00}  //weight: 2, accuracy: High
        $x_1_3 = {6d 79 6d 61 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Hitpop_B_2147605194_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hitpop.gen!B"
        threat_id = "2147605194"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hitpop"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 67 5f 78 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {67 67 5f 63 6f 75 6e 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {67 67 5f 6a 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {64 78 5f 6a 67 00}  //weight: 1, accuracy: High
        $x_1_5 = {70 6d 5f 74 69 6d 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {70 6d 5f 63 6f 75 6e 74 00}  //weight: 1, accuracy: High
        $x_6_7 = {eb 25 6a 10 68 90 01 00 00 68 90 01 00 00 e8 ?? ?? ff ff 83 c0 64 50 68 60 f0 ff ff 6a fe 8b 45 f8 50 e8}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Hitpop_C_2147605195_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hitpop.gen!C"
        threat_id = "2147605195"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hitpop"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 54 0a ff e8 ?? ?? ff ff 8b 45 e0 e8 ?? ?? ff ff 8b 55 f0 0f b6 54 3a ff 33 c2 89 45 f8 8d 45 dc 8b 55 f8 e8 ?? ?? ff ff 8b 55 dc 8b c6 e8 ?? ?? ff ff 47 4b 75 b0}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 54 3a ff e8 ?? ?? ff ff 8b 45 e0 e8 ?? ?? ff ff 8b 55 f0 0f b6 54 32 ff 33 c2 89 45 f4 8d 45 dc 8b 55 f4 e8 ?? ?? ff ff 8b 55 dc 8b 45 f8 e8 06 e9 ff ff 8b 45 f8 46 4b 75 b4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanSpy_Win32_Hitpop_D_2147605196_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hitpop.gen!D"
        threat_id = "2147605196"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hitpop"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b ca d1 f9 79 03 83 d1 00 03 ca 51 8b 55 ?? 8b 45 ?? 2b d0 d1 fa 79 03 83 d2 00 03 d0 52 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {d1 f8 79 03 83 d0 00 03 45 ?? 50 8b 45 ?? 8b 7d ?? 2b c7 d1 f8 79 03 83 d0 00 03 c7 50 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_3_3 = {68 01 02 00 00 56 e8 ?? ?? ff ff 6a 00 6a 00 68 02 02 00 00 56 e8 ?? ?? ff ff}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Hitpop_AF_2147605504_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hitpop.AF!dll"
        threat_id = "2147605504"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hitpop"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "del %0" ascii //weight: 1
        $x_1_2 = "34373137373130383033303435333438273433303031" ascii //weight: 1
        $x_1_3 = "383631323833383836303138363231304143D7B6D8D3B9ABBDA4" ascii //weight: 1
        $x_1_4 = "ydown" ascii //weight: 1
        $x_1_5 = "c:\\downf.ba" ascii //weight: 1
        $x_1_6 = "c:\\mycjjk" ascii //weight: 1
        $x_1_7 = "windll16.dll" ascii //weight: 1
        $x_1_8 = "mymain" ascii //weight: 1
        $x_10_9 = {55 8b ec 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 b8 ?? ?? ?? ?? b9 28 00 00 00 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0 5a 59 59 64 89 10 68 ?? ?? ?? ?? c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Hitpop_AG_2147607883_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hitpop.AG"
        threat_id = "2147607883"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hitpop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d f8 00 0f 84 ?? ?? 00 00 8b 45 f8 8a 18 80 fb 25 0f 85 ?? ?? 00 00 8b 45 f8 80 78 01 75 75 7d 8d 45 f4 50 b9 06 00 00 00 ba 01 00 00 00 8b 45 f8 e8 07 00 6a 01 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 54 3a ff 33 c2 89 45 f8 8d 45 dc 8b 55 f8 e8 ?? ?? ?? ?? 8b 55 dc 8b c6 e8 ?? ?? ?? ?? 47 4b 75 b0}  //weight: 1, accuracy: Low
        $x_2_3 = {70 7a 6a 67 00}  //weight: 2, accuracy: High
        $x_2_4 = {06 00 00 00 6d 79 64 6f 77 6e 00}  //weight: 2, accuracy: High
        $x_2_5 = {06 00 00 00 66 6e 5f 65 78 65 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Hitpop_AH_2147611461_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hitpop.AH"
        threat_id = "2147611461"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hitpop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hitpop" ascii //weight: 2
        $x_2_2 = "webhitlogtmp.dat" ascii //weight: 2
        $x_1_3 = "gg_count" ascii //weight: 1
        $x_1_4 = "pm_count" ascii //weight: 1
        $x_1_5 = "AVP.Button" ascii //weight: 1
        $x_1_6 = "active.asp?ver=" ascii //weight: 1
        $x_1_7 = "&address=" ascii //weight: 1
        $x_1_8 = "KRegEx.exe" ascii //weight: 1
        $x_1_9 = "KVXP.kxp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Hitpop_AI_2147617743_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hitpop.AI"
        threat_id = "2147617743"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hitpop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 54 3a ff 33 c2 89 45 f8 8d 45 dc 8b 55 f8 e8 ?? ?? ?? ?? 8b 55 dc 8b c6 e8 ?? ?? ?? ?? 47 4b 75 b0}  //weight: 10, accuracy: Low
        $x_10_2 = "lljyndf32" ascii //weight: 10
        $x_10_3 = {6d 79 64 6f 77 6e 2e 61 73 70 3f 76 65 72 3d [0-6] 26 74 67 69 64 3d [0-16] 26 61 64 64 72 65 73 73 3d 30 30 2d 30 30 2d 30 30 2d 30 30 2d 30 30 2d 30 30}  //weight: 10, accuracy: Low
        $x_1_4 = "8kaka.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Hitpop_AJ_2147619590_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hitpop.AJ"
        threat_id = "2147619590"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hitpop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 55 bf 01 00 00 00 ff 45 f4 83 7d f4 10 7e 07 c7 45 f4 01 00 00 00 8d 45 e0 8b 55 ec 8b 4d f4 8a 54 0a ff e8 ?? ?? fe ff 8b 45 e0 e8 ?? ?? ff ff 8b 55 f0 0f b6 54 3a ff 33 c2 89 45 f8}  //weight: 2, accuracy: Low
        $x_1_2 = {eb 9a 46 83 c3 24 83 fe 15 0f 85 3d ff ff ff}  //weight: 1, accuracy: High
        $x_2_3 = "/active.asp?tgid=myself" ascii //weight: 2
        $x_1_4 = "/cc.txt HTTP/1.1" ascii //weight: 1
        $x_1_5 = "C:\\WINDOWS\\cc.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Hitpop_AK_2147623437_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hitpop.AK"
        threat_id = "2147623437"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hitpop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "&ver=" ascii //weight: 1
        $x_1_2 = "&tgid=" ascii //weight: 1
        $x_1_3 = "&address=" ascii //weight: 1
        $x_1_4 = "?address=" ascii //weight: 1
        $x_1_5 = "&url=" ascii //weight: 1
        $x_1_6 = "mydown" ascii //weight: 1
        $x_1_7 = "nongmin32.ini" ascii //weight: 1
        $x_1_8 = "nongmin16.ini" ascii //weight: 1
        $x_1_9 = "WinExec" ascii //weight: 1
        $x_1_10 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_11 = {6a 00 6a 00 8b 45 e4 e8 ?? ?? ff ff 50 8b 45 f4 e8 ?? ?? ff ff 50 6a 00 e8 ?? ?? ff ff 8b 45 e4 50 e8 ?? ?? ff ff 84 c0 75 0b 8b 55 e4 8b 45 f4 e8 ?? ?? ff ff 8b 45 f4 e8 ?? ?? ff ff 8b 45 e4 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Hitpop_AM_2147623607_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hitpop.AM"
        threat_id = "2147623607"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hitpop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 6e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 79 64 6f 77 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {6f 6c 64 5f 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {66 6e 5f 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_3_5 = {68 ff 00 00 00 6a 0c 8b 45 f8 50 e8 ?? ?? ff ff 6a 01 6a 0d 68 00 01 00 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

