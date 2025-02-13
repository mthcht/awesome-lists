rule TrojanDownloader_Win32_Clagger_A_2147573997_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Clagger.gen!A"
        threat_id = "2147573997"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Clagger"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "TZtUfN]dVssFouDpoUspmTfu]tFswjDfT]TIbs" ascii //weight: 4
        $x_4_2 = {05 39 58 f8 7e 18 8a 04 06 8d 4d e4 fe c8 50 56 e8 ?? ?? 00 00 8b 45 e4 46 3b 70 f8 7c e8 8d 4d}  //weight: 4, accuracy: Low
        $x_3_3 = {40 00 8d 44 24 54 6a 4b 50 e8 ?? ?? ff ff 8a 44 24 5c 83 c4 10 3c 68 74 08 3c 48 0f 85}  //weight: 3, accuracy: Low
        $x_2_4 = {67 6f 74 6f 20 31 00 69 66 20 65 78 69 73 74 20}  //weight: 2, accuracy: High
        $x_2_5 = {00 00 3d f4 01 00 00 8d 4d c8 73 54 e8}  //weight: 2, accuracy: High
        $x_2_6 = {53 8a 1c 08 80 f3 58 88 1c 08 40 3b c2 7c f2 5b c3 90 64 a1 00 00 00 00 6a ff 68 e8 23 40 00 50}  //weight: 2, accuracy: High
        $x_1_7 = {70 68 70 00 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Clagger_B_2147573998_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Clagger.gen!B"
        threat_id = "2147573998"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Clagger"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ControlSet\\Control\\Lsa" ascii //weight: 1
        $x_1_2 = ".php?new=1" ascii //weight: 1
        $x_1_3 = "Acrobat Reader ERROR " ascii //weight: 1
        $x_1_4 = {57 69 6e 55 70 64 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_5 = "Software\\ODBC\\" ascii //weight: 1
        $x_1_6 = "dwlcounter" ascii //weight: 1
        $x_1_7 = "%s;%d;%sv" ascii //weight: 1
        $x_1_8 = "%s \"%s\"" ascii //weight: 1
        $x_2_9 = {4c 61 73 74 55 70 64 61 74 65 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63}  //weight: 2, accuracy: High
        $x_2_10 = {ff 45 fc 88 0c 02 40 8a 08 80 f9 2e 75 f2}  //weight: 2, accuracy: High
        $x_4_11 = {74 12 56 0f b6 f3 [0-4] 33 c6 41 8a 1c 11 84 db 75 f0 5e}  //weight: 4, accuracy: Low
        $x_3_12 = {ff 45 f4 8b 45 f4 8b 4d 08 c1 e0 02}  //weight: 3, accuracy: High
        $x_3_13 = {8b 70 78 03 f7 89 45 e4 8b 46 20}  //weight: 3, accuracy: High
        $x_1_14 = {50 6a 01 68 00 00 10 00 ff 15}  //weight: 1, accuracy: High
        $x_2_15 = {48 89 45 d8 50 8b 45 f4 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 8 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Clagger_H_2147608486_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Clagger.H"
        threat_id = "2147608486"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Clagger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {7e 27 8b 4d ec 0f be c0 8b 49 f8 2b c8 51 50 8d 4d ec e8 ?? ?? 00 00 68 ?? ?? 40 00 68 ?? ?? 40 00 8d 4d ec e8 ?? ?? 00 00 8d ?? ec 8d 4d e8 ?? e8 ?? ?? 00 00 68 00 00 00 04}  //weight: 3, accuracy: Low
        $x_3_2 = {99 6a 17 68 ff e7 76 48 52 50 e8 ?? ?? 00 00 05 0f 27 00 00}  //weight: 3, accuracy: Low
        $x_1_3 = {70 68 70 00 65 78 65 00 3f}  //weight: 1, accuracy: High
        $x_1_4 = "del c:\\1.bat" ascii //weight: 1
        $x_1_5 = ":*:Enabled:zx" ascii //weight: 1
        $x_1_6 = "r=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

