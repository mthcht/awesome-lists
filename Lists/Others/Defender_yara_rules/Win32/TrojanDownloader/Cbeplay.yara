rule TrojanDownloader_Win32_Cbeplay_B_2147599377_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cbeplay.gen!B"
        threat_id = "2147599377"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cbeplay"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "58"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Microsoft Corporation" wide //weight: 10
        $x_10_2 = "Microsoft Visual C++ Runtime Library" ascii //weight: 10
        $x_10_3 = "D7EB6085-E70A-4f5a-9921-E6BD244A8C17" ascii //weight: 10
        $x_10_4 = "cantandoconadriana.com" wide //weight: 10
        $x_10_5 = "%SystemRoot%\\System32\\CbEvtSvc.exe -k netsvcs" ascii //weight: 10
        $x_1_6 = "%s\\%d.exe" ascii //weight: 1
        $x_1_7 = "explorer.exe" ascii //weight: 1
        $x_1_8 = "CbEvtSvc.exe" ascii //weight: 1
        $x_1_9 = "WinHttpOpen" ascii //weight: 1
        $x_1_10 = "WinHttpConnect" ascii //weight: 1
        $x_1_11 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_12 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_13 = "netsvcs" wide //weight: 1
        $x_1_14 = "SYSTEM\\CurrentControlSet\\Services\\CbEvtSvc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Cbeplay_B_2147601552_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cbeplay.B"
        threat_id = "2147601552"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cbeplay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "56"
        strings_accuracy = "Low"
    strings:
        $x_40_1 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 43 [0-3] 45 76 74 53 76 63 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73}  //weight: 40, accuracy: Low
        $x_5_2 = "&ver=%s&idx=%s&user=%s" ascii //weight: 5
        $x_5_3 = "%s&ioctl=%d&data=%s" ascii //weight: 5
        $x_3_4 = "URLDownloadToFileA" ascii //weight: 3
        $x_3_5 = "StartServiceA" ascii //weight: 3
        $x_3_6 = "GetCurrentHwProfileW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_40_*) and 2 of ($x_5_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Cbeplay_D_2147607923_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cbeplay.D"
        threat_id = "2147607923"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cbeplay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 c2 be 19 33 01 81 ff 02 21 00 00 74 78 76 15 89 f1 81 fe 56 ae 6f 02 4d be e7 37 8c 02 3a f4 f7 da 3b e9 f8 c1 d6 1c 33 cf f7 d1 f7 d9 33 f0 d6 c1 0b 1f b8 ac d7 43 00 f7 dd 85 c2 84 c4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Cbeplay_A_2147610965_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cbeplay.gen!A"
        threat_id = "2147610965"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cbeplay"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "os=%d&ver=%s&idx=%s&user=%s" ascii //weight: 2
        $x_2_2 = "%s&ioctl=%d&data=%s" ascii //weight: 2
        $x_1_3 = {2e 70 68 70 00 50 4f 53 54 20 2f 25 73 20 48 54 54 50 2f 31 2e 31}  //weight: 1, accuracy: High
        $x_6_4 = {44 37 45 42 36 30 38 35 2d 45 37 30 41 2d 34 66 35 61 2d 39 39 32 31 2d 45 36 42 44 32 34 34 41 38 43 31 37 00}  //weight: 6, accuracy: High
        $x_10_5 = {6a 01 6a 1a 8d 4c 24 ?? 51 6a 00 ff 15 ?? ?? ?? ?? 85 c0 75 ?? ff 15 ?? ?? ?? ?? 8b f8 (eb ??|e9 ?? ?? ?? ??) 8b 96 34 02 00 00 52}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 2 of ($x_2_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Cbeplay_L_2147647422_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cbeplay.L"
        threat_id = "2147647422"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cbeplay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "geo=%s&os=%d&ver=%S&idx=%s&user=%S" ascii //weight: 1
        $x_1_2 = "D7EB6085-E70A-4f5a-9921-E6BD244A8C17" ascii //weight: 1
        $x_1_3 = "%s&ioctl=%d&data=%s" ascii //weight: 1
        $x_1_4 = "/q /c for /l %%i in (1,1,4000000000) do if not exist \"%s\" (exit)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Cbeplay_M_2147648055_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cbeplay.M"
        threat_id = "2147648055"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cbeplay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 bf 10 04 00 00 00 8d b7 14 04 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {ff b7 08 02 00 00 8d 44 ?? ?? 50 68 ?? ?? 40 00 8d 87 04 01 00 00 68 04 01 00 00 50 e8 ?? ?? 00 00 83 c4 14}  //weight: 1, accuracy: Low
        $x_2_3 = {8b 83 14 0c 00 00 [0-4] 83 bb 18 0c 00 00 00 74 ?? 50 68 08 01 00 00 e8}  //weight: 2, accuracy: Low
        $x_1_4 = {b9 4d 5a 00 00 8b 45 08 66 39 08}  //weight: 1, accuracy: High
        $x_2_5 = "%s&ctl=%d&data=%s" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Cbeplay_O_2147649024_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cbeplay.O"
        threat_id = "2147649024"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cbeplay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s&q8=%d&payload=%s" ascii //weight: 1
        $x_1_2 = "%s&ver=%u.%u.%u.%u&os=%u&idx=%u" ascii //weight: 1
        $x_1_3 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 [0-5] 73 76 63 68 6f 73 74 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Cbeplay_P_2147649464_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cbeplay.P"
        threat_id = "2147649464"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cbeplay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 54 0b 01 46 88 51 01}  //weight: 1, accuracy: High
        $x_1_2 = {74 69 8b 44 24 14 8d 54 24 0c 52 68 ?? ?? ?? ?? 50 57 56 68 02 01 00 00 c7 44 24 24 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {75 26 56 6a 00 6a 00 68 1a 80 00 00 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {25 73 3f 75 69 64 3d 25 75 26 69 70 3d 25 73 26 6c 6f 63 61 74 69 6f 6e 3d 25 73 26 69 73 70 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_5 = "/q /c for /l %%i in (1,1,4000000000) do if not exist \"%s\" (exit)" ascii //weight: 1
        $x_1_6 = {53 41 4d 50 4c 45 00 00 56 58 00 00 56 49 52 55 53 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Cbeplay_Q_2147657637_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cbeplay.Q"
        threat_id = "2147657637"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cbeplay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 4d 5a 00 00 8b 45 08 66 39 08}  //weight: 1, accuracy: High
        $x_1_2 = {74 69 8b 44 24 14 8d 54 24 0c 52 68 ?? ?? ?? ?? 50 57 56 68 02 01 00 00 c7 44 24 24 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 [0-5] 73 76 63 68 6f 73 74 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {53 41 4d 50 4c 45 00 00 56 58 00 00 56 49 52 55 53 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Cbeplay_R_2147679386_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cbeplay.R"
        threat_id = "2147679386"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cbeplay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/q /c for /l %%i in (1,1,4000000000) do if not exist" ascii //weight: 1
        $x_1_2 = {0f b7 0f 8b c1 25 00 f0 00 00 3d 00 30 00 00 75 14 81 e1 ff 0f 00 00 03 0a 3b 4e 50 77 ?? 8b 44 24 10 01 04 29 8b 4a 04 83 e9 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

