rule TrojanDownloader_Win32_Nonaco_C_2147803792_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nonaco.C"
        threat_id = "2147803792"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nonaco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "900"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "0123456789ABCDEF" ascii //weight: 100
        $x_100_2 = "9999-99-99" ascii //weight: 100
        $x_100_3 = "ClickTime" ascii //weight: 100
        $x_100_4 = "FeedUrl" ascii //weight: 100
        $x_100_5 = "Internet Explorer" ascii //weight: 100
        $x_100_6 = "InternetCheckConnectionA" ascii //weight: 100
        $x_100_7 = "Microsoft\\" ascii //weight: 100
        $x_50_8 = "SOFTWARE\\" ascii //weight: 50
        $x_50_9 = "ToFeed" ascii //weight: 50
        $x_50_10 = "UpdateUrl" ascii //weight: 50
        $x_50_11 = "%s?pid=%04d&dt=%s" ascii //weight: 50
        $x_10_12 = "http://zero.allgreathost.com" ascii //weight: 10
        $x_10_13 = "http://zero.sisdotnet.com" ascii //weight: 10
        $x_10_14 = "http://zero.bestmanage1.org" ascii //weight: 10
        $x_10_15 = "http://zero.bestmanage2.org" ascii //weight: 10
        $x_10_16 = "http://zero.bestmanage3.org" ascii //weight: 10
        $x_10_17 = "http://zero.xujace.com" ascii //weight: 10
        $x_10_18 = "http://setup.theoreon.com" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_100_*) and 3 of ($x_50_*) and 5 of ($x_10_*))) or
            ((7 of ($x_100_*) and 4 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Nonaco_B_2147803839_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nonaco.B"
        threat_id = "2147803839"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nonaco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 4c 4c 00 25 66 00 00 5f 73 65 6c 66}  //weight: 1, accuracy: High
        $x_1_2 = {44 4c 4c 00 25 66 00 00 25 64 00 00 5f 73 65 6c 66}  //weight: 1, accuracy: High
        $x_1_3 = {2f 3f 6e 61 6d 65 3d 25 73 00 [0-4] 25 73 5c 25}  //weight: 1, accuracy: Low
        $x_1_4 = {54 69 6d 65 00 00 00 00 54 6f 46 65 65 64 00 00 79 65 73 00 4b 69 6c 6c 00 00 00 00 25 30 32 58}  //weight: 1, accuracy: High
        $x_1_5 = {6a 06 99 59 f7 f9 8b da e8 ?? ?? 00 00 99 b9 8c 00 00 00 f7 f9 8b f2 46}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Nonaco_G_2147803922_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nonaco.G"
        threat_id = "2147803922"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nonaco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iSecurity.dll" ascii //weight: 1
        $x_1_2 = "wscui.cpl" ascii //weight: 1
        $x_1_3 = "promo.s2fnew.com" ascii //weight: 1
        $x_1_4 = "A8311E8F-E459-4D22-89B4-CB9DCF10A425" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_7 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Nonaco_G_2147803922_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nonaco.G"
        threat_id = "2147803922"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nonaco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 74 12 68 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 85 c0 74 02 ff e0}  //weight: 1, accuracy: Low
        $x_2_2 = {69 53 65 63 75 72 69 74 79 2e 63 70 6c 00 00 00 76 25 73 5c 00 00 00 00 5c 69 53 65 63 75 72 69}  //weight: 2, accuracy: High
        $x_1_3 = {c6 45 ff 01 6a 07 ff 75 0c ff d7 5f 5e 8a 45 ff 5b c9 c3}  //weight: 1, accuracy: High
        $x_2_4 = {45 58 45 00 72 75 6e 64 6c 6c 33 32 20 22 25 73 22 2c 53 65 63 75 72 69 74 79 4d 6f 6e 69 74 6f 72 00}  //weight: 2, accuracy: High
        $x_1_5 = {8d 78 0d 8d 04 0f bb ff 00 00 00 99 f7 fb 32 55 0f 88 16 8a 41 01 46 41 84 c0 88 45 0f 75 e4}  //weight: 1, accuracy: High
        $x_1_6 = {69 53 65 63 75 72 69 74 79 2e 63 70 6c 2c 53 65 63 75 72 69 74 79 4d 6f 6e 69 74 6f 72 00}  //weight: 1, accuracy: High
        $x_1_7 = "recommeded to install anti" ascii //weight: 1
        $x_1_8 = {72 00 75 00 6e 00 2d 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 00 00 65 00 78 00 65 00 2d 00 75 00 72 00 6c 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Nonaco_I_2147803936_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nonaco.I"
        threat_id = "2147803936"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nonaco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "UserId" ascii //weight: 1
        $x_1_2 = "live." ascii //weight: 1
        $x_1_3 = "rds.yahoo." ascii //weight: 1
        $x_1_4 = "yahoo." ascii //weight: 1
        $x_1_5 = "google." ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Internet Explorer" ascii //weight: 1
        $x_2_7 = "bho=1&v=29&se=%s&user=%s&lang=%s" ascii //weight: 2
        $x_1_8 = "Content-Type: bin%set-stream" ascii //weight: 1
        $x_1_9 = "User-Agent: %s" ascii //weight: 1
        $x_1_10 = "Invoke dispid = %d" ascii //weight: 1
        $x_10_11 = "CLSID\\e405.e405mgr" ascii //weight: 10
        $x_10_12 = {46 47 83 fe 03 75 ?? 8a 45 ?? 8a cb c0 e8 02 88 ?? 0c 8a 45 ?? 24 03 c0 e0 04 c0 e9 04 02 c1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Nonaco_F_2147803983_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nonaco.F"
        threat_id = "2147803983"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nonaco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 4d f8 50 c6 45 ?? 75 c6 45 ?? 72 c6 45 ?? 6c c6 45 ?? 63 c6 45 ?? 6c c6 45 ?? 69}  //weight: 2, accuracy: Low
        $x_2_2 = {89 4d f4 50 c6 45 ?? 75 c6 45 ?? 72 c6 45 ?? 6c c6 45 ?? 63 c6 45 ?? 6c c6 45 ?? 69}  //weight: 2, accuracy: Low
        $x_1_3 = {39 45 08 59 73 12 8b 45 08 6a 03 5b 8d 8c 05 ?? ?? ff ff 99 f7 fb 28 11 ff 45 08}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 78 0d 8d 04 0f bb ff 00 00 00 99 f7 fb 32 55 0f 88 16 8a 41 01 46 41 84 c0 88 45 0f 75 e4}  //weight: 1, accuracy: High
        $x_1_5 = {74 04 6a 01 eb 19 8d 85 00 fc ff ff 68 ?? ?? ?? ?? 50 e8 ?? ?? ff ff 59 84 c0 59 74 05 6a 02 58 eb 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Nonaco_H_2147803986_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nonaco.H"
        threat_id = "2147803986"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nonaco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 03 5f 8d 8c 05 ?? ?? ff ff 99 f7 ff 28 11 ff 45 05 00 73 12 8b 45}  //weight: 2, accuracy: Low
        $x_2_2 = {8d 55 e6 8b c1 8b f7 8b fa c6 45 ?? 75 c1 e9 02 c6 45 ?? 72 c6 45 ?? 6c c6 45 ?? 63}  //weight: 2, accuracy: Low
        $x_2_3 = {74 04 6a 01 eb 19 8d 85 00 fc ff ff 68 ?? ?? ?? ?? 50 e8 ?? ?? ff ff 59 84 c0 59 74 05 6a 02 58 eb 03}  //weight: 2, accuracy: Low
        $x_1_4 = "pid=%s&s=%s&v=%s&user=%s" ascii //weight: 1
        $x_1_5 = "Invoke dispid = %d" ascii //weight: 1
        $x_1_6 = {65 34 30 35 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Nonaco_J_2147803995_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nonaco.J"
        threat_id = "2147803995"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nonaco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b c1 8b f7 8b fa c6 44 24 ?? 75 c1 e9 02 c6 44 24 ?? 72 c6 44 24 ?? 6c c6 44 24 ?? 63}  //weight: 3, accuracy: Low
        $x_2_2 = {f7 fb 8b 45 10 32 11 46 3b 75 0c 88 54 30 fe 7c e1}  //weight: 2, accuracy: High
        $x_1_3 = "Invoke dispid = %d" ascii //weight: 1
        $x_1_4 = {67 67 67 67 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00}  //weight: 1, accuracy: High
        $x_1_5 = "mainfeedthere.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

