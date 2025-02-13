rule TrojanClicker_Win32_Zirit_B_2147600927_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Zirit.B"
        threat_id = "2147600927"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Zirit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Domains" ascii //weight: 1
        $x_1_2 = "FeedUrl" ascii //weight: 1
        $x_2_3 = "ToFeed" ascii //weight: 2
        $x_2_4 = {5f 73 65 6c 66 00}  //weight: 2, accuracy: High
        $x_2_5 = "clicktime" ascii //weight: 2
        $x_4_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelay" ascii //weight: 4
        $x_10_7 = {25 6c 64 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_8 = "/%s?pid=%04d&" ascii //weight: 10
        $x_20_9 = {57 ff d6 8b f8 ff d6 2b c7 3d 30 75 00 00 73 2b 8b 6c 24 14 8b 1d ?? ?? ?? 10 6a 00 6a 01 55 ff 15 ?? ?? ?? 10 85 c0 75 19 68 e8 03 00 00 ff d3 ff d6 2b c7 3d 30 75 00 00 72}  //weight: 20, accuracy: Low
        $x_20_10 = {83 fe ff 74 4b 8d 44 24 10 50 56 ff 15 ?? ?? ?? 10 6a 00 83 c0 da 6a 00 50 56 ff 15 ?? ?? ?? 10 8d 4c 24 0c 6a 00 51 6a 26 68 60 64 00 10 56 ff 15}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_20_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_Win32_Zirit_C_2147601208_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Zirit.C"
        threat_id = "2147601208"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Zirit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "209"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Domains" ascii //weight: 1
        $x_1_2 = "FeedUrl" ascii //weight: 1
        $x_1_3 = "ToFeed" ascii //weight: 1
        $x_1_4 = "clicks" ascii //weight: 1
        $x_1_5 = "clicktime" ascii //weight: 1
        $x_4_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelay" ascii //weight: 4
        $x_100_7 = {50 6a 00 6a 00 68 ?? ?? ?? 10 6a 00 6a 00 ff d7 8b 1d ?? ?? ?? 10 be 0a 00 00 00 8d 4c 24 0c 51 6a 00 6a 00 68 ?? ?? ?? 10 6a 00 6a 00 ff d7 68 ?? ?? ?? ?? ff d3}  //weight: 100, accuracy: Low
        $x_100_8 = {53 83 c0 da 53 50 56 ff 15 ?? ?? ?? 10 8d ?? ?? ?? 53 51 6a 26 68 ?? ?? ?? 10 56 ff 15 ?? ?? ?? 10}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Zirit_J_2147602250_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Zirit.J"
        threat_id = "2147602250"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Zirit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 8b d8 ff 15 58 d0 00 10 50 8d 4c 24 74 68 2c f2 00 10}  //weight: 1, accuracy: High
        $x_1_2 = {76 33 2e 6d 61 69 6e 66 65 65 64 68 65 72 65 2e 63 6f 6d 00 65 78 65 63 00 00 00 00 63 6c 69 63 6b 73 00 00 75 72 6c 00 64 6e 73}  //weight: 1, accuracy: High
        $x_1_3 = "%ld.exe" ascii //weight: 1
        $x_1_4 = "pid=%s&s=%s&v=11&user=%s&date=%s&q=%s" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad" ascii //weight: 1
        $x_1_6 = {8b f0 83 fe ff 74 ?? 8d 44 24 10 50 56 ff 15 ?? ?? ?? 10 [0-2] 83 c0 da [0-2] 50 56 ff 15 ?? ?? ?? 10 8d 4c 24 0c [0-2] 51 6a 26 68 ?? ?? ?? 10 56 ff 15 ?? ?? ?? 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanClicker_Win32_Zirit_X_2147603283_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Zirit.X"
        threat_id = "2147603283"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Zirit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "151"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "Domains" ascii //weight: 3
        $x_3_2 = "FeedUrl" ascii //weight: 3
        $x_3_3 = "ToFeed" ascii //weight: 3
        $x_3_4 = {5f 73 65 6c 66 00}  //weight: 3, accuracy: High
        $x_3_5 = "clicktime" ascii //weight: 3
        $x_3_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelay" ascii //weight: 3
        $x_3_7 = "?pid=%04d&" ascii //weight: 3
        $x_1_8 = "bot.dll" ascii //weight: 1
        $x_1_9 = "Resources.dll" ascii //weight: 1
        $x_3_10 = "setup.jobusiness.org" ascii //weight: 3
        $x_30_11 = {2b c7 3d 30 75 00 00 73 2b 8b 6c 24 14 8b 1d ?? ?? 00 10 6a 00 6a 01 55 ff 15 ?? ?? 00 10 85 c0 75 ?? 68 e8 03 00 00 ff d3 ff d6 2b c7 3d 30 75 00 00 72}  //weight: 30, accuracy: Low
        $x_100_12 = {6a 01 68 00 00 00 80 68 [0-14] ff 15 ?? ?? 00 10 8b f0 83 fe ff 74 ?? 8d 44 24 10 50 56 ff 15 ?? ?? 00 10 [0-2] 83 c0 da [0-2] 50 56 ff 15 ?? ?? 00 10 8d 4c 24 0c [0-2] 51 6a 26 68 ?? ?? 00 10 56 ff 15 ?? ?? 00 10 85 c0 74}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_30_*) and 7 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_Win32_Zirit_Y_2147606945_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Zirit.Y"
        threat_id = "2147606945"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Zirit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c7 33 d2 bd ff 00 00 00 f7 f5 32 54 31 01 88 14 31 41 47 3b cb 72 e8 5d 6a 3b 56 c6 44 1e ff 00 e8}  //weight: 1, accuracy: High
        $x_1_2 = {76 23 0f b6 c0 53 89 45 08 8b 45 08 33 d2 bb ff 00 00 00 f7 f3 32 54 31 01 88 14 31 41 ff 45 08 3b cf 72 e5 5b 80 64 3e ff 00 6a 3b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanClicker_Win32_Zirit_Z_2147608915_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Zirit.Z"
        threat_id = "2147608915"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Zirit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "67"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "domains" ascii //weight: 3
        $x_3_2 = "FeedUrl" ascii //weight: 3
        $x_3_3 = "ToFeed" ascii //weight: 3
        $x_3_4 = {5f 73 65 6c 66 00}  //weight: 3, accuracy: High
        $x_3_5 = "ObjectDelay" ascii //weight: 3
        $x_3_6 = "?pid=%04d&" ascii //weight: 3
        $x_3_7 = "CLSID\\%s\\I" ascii //weight: 3
        $x_3_8 = "Resources.dll" ascii //weight: 3
        $x_3_9 = "URLDownloadToFileA" ascii //weight: 3
        $x_3_10 = "setup.mspublik.com" ascii //weight: 3
        $x_3_11 = "setup.jobusiness.org" ascii //weight: 3
        $x_20_12 = {2b c7 3d 30 75 00 00 73 2b 8b 6c 24 14 8b 1d ?? ?? 00 10 6a 00 6a 01 55 ff 15 ?? ?? 00 10 85 c0 75 ?? 68 e8 03 00 00 ff d3 ff d6 2b c7 3d 30 75 00 00 72}  //weight: 20, accuracy: Low
        $x_20_13 = {8b f0 83 fe ff 74 [0-24] 83 c0 da}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 9 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_Win32_Zirit_D_2147642410_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Zirit.D"
        threat_id = "2147642410"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Zirit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CurrentVersion\\Run" ascii //weight: 1
        $x_2_2 = "firstclick" ascii //weight: 2
        $x_3_3 = "minclicktime" ascii //weight: 3
        $x_2_4 = "execurl" ascii //weight: 2
        $x_2_5 = "execfile" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

