rule TrojanDownloader_Win32_Tonick_2147599761_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tonick"
        threat_id = "2147599761"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tonick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " Goto S" wide //weight: 1
        $x_1_2 = " Goto T" wide //weight: 1
        $x_1_3 = " Goto O" wide //weight: 1
        $x_1_4 = " Goto I" wide //weight: 1
        $x_1_5 = " Goto G" wide //weight: 1
        $x_1_6 = "del ggg.bat" wide //weight: 1
        $x_1_7 = "del c:\\*.exe" wide //weight: 1
        $x_1_8 = "del d:\\*.exe" wide //weight: 1
        $x_1_9 = " Goto H" wide //weight: 1
        $x_1_10 = " Goto D" wide //weight: 1
        $x_1_11 = " Goto P" wide //weight: 1
        $x_1_12 = " Goto X" wide //weight: 1
        $x_1_13 = " Goto J" wide //weight: 1
        $x_1_14 = " Goto K" wide //weight: 1
        $x_5_15 = "vkmhjan&lrn" wide //weight: 5
        $x_5_16 = "C:\\Documents and Settings\\tonck\\" wide //weight: 5
        $x_5_17 = "C:\\Documents and Settings\\Renca\\" wide //weight: 5
        $x_5_18 = "vkmhjah" wide //weight: 5
        $x_5_19 = "hlppdjk&lrn" wide //weight: 5
        $x_5_20 = "ivwt?)(" wide //weight: 5
        $x_5_21 = ")(elgii" wide //weight: 5
        $x_5_22 = "qwvt{t0zXD" wide //weight: 5
        $x_10_23 = {66 33 45 d0 0f bf d0 52 ff 15 ?? ?? ?? ?? 8b d0 8d 4d c8 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b d0 8d 4d d4 ff 15}  //weight: 10, accuracy: Low
        $x_10_24 = {66 33 45 d0 0f bf c0 50 e8 ?? ?? ?? ?? 8b d0 8d 4d c8 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b d0 8d 4d d4 e8}  //weight: 10, accuracy: Low
        $x_10_25 = {6b 70 ff fb 12 e7 0b ?? 00 04 00 23 44 ff 2a 31 74 ff 32 04 00 48 ff 44 ff 35 4c ff 00 0c 6b 70 ff f3 ff 00 c6 1c ?? ?? 00 07 f4 01 70 70 ff 1e ?? ?? 00 0b 6b 70 ff f4 01 a9 70 70 ff 00 0a 04 72 ff 64 6c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((14 of ($x_1_*))) or
            ((1 of ($x_5_*) and 9 of ($x_1_*))) or
            ((2 of ($x_5_*) and 4 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Tonick_A_2147605743_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tonick.gen!A"
        threat_id = "2147605743"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tonick"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6b 70 ff fb 12 e7 0b ?? 00 04 00 23 44 ff 2a 31 74 ff 32 04 00 48 ff 44 ff 35 4c ff 00 0c 6b 70 ff f3 ff 00 c6 1c ?? ?? 00 07 f4 01 70 70 ff 1e ?? ?? 00 0b 6b 70 ff f4 01 a9 70 70 ff 00 0a 04 72 ff 64 6c}  //weight: 10, accuracy: Low
        $x_10_2 = {66 33 45 d0 0f bf c0 50 ff 15 ?? ?? ?? ?? 8b d0 8d 4d c8 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b d0 8d 4d d8 ff 15}  //weight: 10, accuracy: Low
        $x_1_3 = "Codec Installed" wide //weight: 1
        $x_1_4 = "Missing Codec Loaded" wide //weight: 1
        $x_1_5 = "Missing Files Installed!" wide //weight: 1
        $x_5_6 = "jwpu<('" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Tonick_B_2147608902_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tonick.gen!B"
        threat_id = "2147608902"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tonick"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 33 45 d0 0f bf d0 52 ff 15 ?? ?? ?? ?? 8b d0 8d 4d c8 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b d0 8d 4d d4 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {66 33 45 d0 0f bf c0 50 e8 ?? ?? ?? ?? 8b d0 8d 4d c8 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b d0 8d 4d d4 e8}  //weight: 10, accuracy: Low
        $x_10_3 = {6b 70 ff fb 12 e7 0b ?? 00 04 00 23 44 ff 2a 31 74 ff 32 04 00 48 ff 44 ff 35 4c ff 00 0c 6b 70 ff f3 ff 00 c6 1c ?? ?? 00 07 f4 01 70 70 ff 1e ?? ?? 00 0b 6b 70 ff f4 01 a9 70 70 ff 00 0a 04 72 ff 64 6c}  //weight: 10, accuracy: Low
        $x_2_4 = "WriteProcessMemory" ascii //weight: 2
        $x_1_5 = "]qugmit|'osi" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Tonick_C_2147623530_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tonick.gen!C"
        threat_id = "2147623530"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tonick"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "lq`kk`no'osi" wide //weight: 1
        $x_1_2 = "rgqrleb{'osi" wide //weight: 1
        $x_5_3 = "InternetReadFile" ascii //weight: 5
        $x_10_4 = {6b 70 ff fb 12 e7 0b ?? 00 04 00 23 44 ff 2a 31 74 ff 32 04 00 48 ff 44 ff 35 4c ff 00 0c 6b 70 ff f3 ff 00 c6 1c ?? ?? 00 07 f4 01 70 70 ff 1e ?? ?? 00 0b 6b 70 ff f4 01 a9 70 70 ff 00 0a 04 72 ff 64 6c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

