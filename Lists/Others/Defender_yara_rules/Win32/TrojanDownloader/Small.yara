rule TrojanDownloader_Win32_Small_2147799827_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small"
        threat_id = "2147799827"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "%s\\drivers\\pcihdd2.sys" ascii //weight: 10
        $x_10_2 = {68 74 74 70 3a 2f 2f [0-32] 2e 74 78 74}  //weight: 10, accuracy: Low
        $x_10_3 = "_uninsep.bat" ascii //weight: 10
        $x_1_4 = "if exist \"%s\" goto" ascii //weight: 1
        $x_1_5 = "del \"%s\"" ascii //weight: 1
        $x_1_6 = "ntoskrnl.exe" ascii //weight: 1
        $x_1_7 = "winexec" ascii //weight: 1
        $x_1_8 = "E:\\Other\\SecEdit\\Sedisk\\objfre_w2K_x86\\i386\\Sedisk.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_CBA_2147800877_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.CBA"
        threat_id = "2147800877"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "99"
        strings_accuracy = "Low"
    strings:
        $x_99_1 = {00 4c 6f 61 64 4c 69 62 72 61 72 79 41 00 58 c6 40 fc (68 54 54|66 6a 00) 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 e8 0d 00 00 00 43 72 65 61 74 65 54 68 72 65 61 64 00 55 ff d6 ff d0 (50|89) e8 0c 00 00 00 43 6c 6f 73 65 48 61 6e 64 6c 65 00 55 ff d6 ff d0 [0-128] 43 3a 5c 62 6f 6f 74 2e 69 6e 69}  //weight: 99, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AABJ_2147800987_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AABJ"
        threat_id = "2147800987"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%%%%%%%%%%PKPK AV %%%%%%%%%%" ascii //weight: 1
        $x_1_2 = {5c 64 6f 77 6e 2e 74 78 74 [0-32] 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}  //weight: 1, accuracy: Low
        $x_1_3 = "\\systemInfomations.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AABH_2147801546_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AABH"
        threat_id = "2147801546"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 00 6a 00 [0-5] 6a 00 6a 00 e8 ?? 00 00 00 83 c4 04 eb 1c 83 7d 0c 00 75 16 ff 35 ?? ?? 00 10 e8 ?? 00 00 00 ff 35 ?? ?? 00 10}  //weight: 5, accuracy: Low
        $x_2_2 = {64 61 69 6c 75 70 [0-3] 6c 61 6e [0-3] 75 6e 6b 6e 6f 77 00}  //weight: 2, accuracy: Low
        $x_1_3 = "ver=%lu&uid=%lu&conn=%s&os=%s&socks=%lu&ip=%s" ascii //weight: 1
        $x_1_4 = "/get.cgi?data=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_AABK_2147801547_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AABK"
        threat_id = "2147801547"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 68 74 6d 00 2e 61 73 70 00 2e 70 68 70 00 2e 61 73 70 78 00 2e 6a 73 70 00 2e 68 74 6d 6c 00 3c 69 66 72 61 6d 65 20 73 72 63 3d [0-48] 3e 3c 2f 69 66 72 61 6d 65 3e}  //weight: 1, accuracy: Low
        $x_1_2 = {53 76 63 68 6f 73 74 2e 65 78 65 [0-32] 2a 2e 2a [0-4] 63 3a 5c [0-16] 2e 73 79 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_C_2147801639_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.C"
        threat_id = "2147801639"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 02 c6 45 ?? 55 c6 45 ?? 52 c6 45 ?? 4c c6 45 ?? 44}  //weight: 10, accuracy: Low
        $x_10_2 = {00 5f 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_1_3 = {68 74 74 70 3a 2f 2f [0-8] 2e 63 6f 6d 2f 66 69 6c 65 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 00 00 00 00 4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 00 00 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_ZZ_2147802357_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.ZZ"
        threat_id = "2147802357"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ollydbg.exe" wide //weight: 1
        $x_1_2 = "filemon.exe" wide //weight: 1
        $x_1_3 = "whireshark.exe" wide //weight: 1
        $x_1_4 = "C:\\file.exe" wide //weight: 1
        $x_1_5 = "*\\AE:\\Stuff\\Lilith Premium\\Start\\Projekt1.vbp" wide //weight: 1
        $x_1_6 = "regmon.exe" wide //weight: 1
        $x_1_7 = "VB!CRYPT.LILITH!" wide //weight: 1
        $x_1_8 = "procmon.exe" wide //weight: 1
        $x_1_9 = "DECRYPT: *$" wide //weight: 1
        $x_1_10 = "gmkgldfgfdgo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_NCA_2147802614_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.NCA"
        threat_id = "2147802614"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 84 84 00 00 00 48 74 5e 48 74 4c 48 74 3a 48 74 28 48 74 16 48 0f}  //weight: 1, accuracy: High
        $x_1_2 = {53 8b 5c 24 0c 56 57 6a 40 33 c0 33 f6 39 74 24 1c 59 8b fb f3 ab 7e 19 8b 7c 24 10 33 c0 8a 07 47 50 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_NCC_2147802615_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.NCC"
        threat_id = "2147802615"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "WriteProcessMemory" ascii //weight: 10
        $x_10_2 = "CreateRemoteThread" ascii //weight: 10
        $x_10_3 = {55 8b ec 83 c4 ec e8 ?? ?? 00 00 8d 4d fc 51 6a 20 50 e8 ?? ?? 00 00 c7 45 ec 01 00 00 00 8d 45 f0 50 68 ?? ?? 40 00 6a 00 e8 ?? ?? 00 00 c7 45 f8 02 00 00 00 6a 00 6a 00 6a 10}  //weight: 10, accuracy: Low
        $x_1_4 = "id=%s&p=%s&mb=%d&j1=%s.&z1=%s&d1=%s&srv=%s" ascii //weight: 1
        $x_1_5 = "id=%s&p=%s&lck=%s&mb=%s&q=%s&srv=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_NCM_2147803295_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.NCM"
        threat_id = "2147803295"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "services.exe" ascii //weight: 10
        $x_10_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_3 = "\\gkjnr.conf" ascii //weight: 10
        $x_10_4 = "WriteProcessMemory" ascii //weight: 10
        $x_10_5 = {5c 6f 75 74 00 25 73 25 73}  //weight: 10, accuracy: High
        $x_1_6 = "WinMedia" ascii //weight: 1
        $x_1_7 = "WinUpgrade" ascii //weight: 1
        $x_1_8 = "unexpand.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_AABF_2147803692_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AABF"
        threat_id = "2147803692"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c3 76 89 d8 e8 ?? ?? 00 00 ff 35 ?? ?? 41 00 8b 1d ?? ?? 41 00 83 c3 69 89 d8 e8 ?? ?? 00 00 58 ff 35 ?? ?? 41 00 8b 1d ?? ?? 41 00 83 c3 64 89 d8 e8 ?? ?? 00 00 58 ff 35 ?? ?? 41 00 8b 1d ?? ?? 41 00 83 c3 3d 89 d8}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c3 6b 89 d8 e8 ?? ?? 00 00 ff 35 ?? ?? 41 00 8b 1d ?? ?? 41 00 83 c3 69 89 d8 e8 ?? ?? 00 00 58 ff 35 ?? ?? 41 00 8b 1d ?? ?? 41 00 83 c3 6c 89 d8 e8 ?? ?? 00 00 58 ff 35 ?? ?? 41 00 8b 1d ?? ?? 41 00 83 c3 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c3 26 89 d8 e8 ?? ?? 00 00 ff 35 ?? ?? 41 00 8b 1d ?? ?? 41 00 83 c3 75 89 d8 e8 ?? ?? 00 00 58 ff 35 ?? ?? 41 00 8b 1d ?? ?? 41 00 83 c3 6e 89 d8 e8 ?? ?? 00 00 58 ff 35 ?? ?? 41 00 8b 1d ?? ?? 41 00 83 c3 71}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Small_AABG_2147803693_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AABG"
        threat_id = "2147803693"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/get.php?" ascii //weight: 1
        $x_1_2 = {74 65 78 74 2f 2a [0-5] 69 6d 61 67 65 2f 2a [0-5] 61 70 70 6c 69 63 61 74 69 6f 6e 2f 2a [0-5] 2a 2f 2a}  //weight: 1, accuracy: Low
        $x_2_3 = {c7 45 e0 04 00 00 00 6a 00 8d 45 e0 50 8d 45 d8 50 68 13 00 00 20 ff 75 f4 e8 ?? ?? 00 00 85 c0 75 07 c7 45 d8 ea 01 00 00 81 7d d8 c8 00 00 00 0f 85 ?? ?? 00 00 c7 45 e0 04 00 00 00 6a 00 8d 45 e0 50 8d 45 e8 50 68 05 00 00 20 ff 75 f4}  //weight: 2, accuracy: Low
        $x_2_4 = {33 d2 c1 e8 07 b9 06 00 00 00 f7 f1 c1 e2 0a 52 e8 ?? ?? 00 00 33 c0}  //weight: 2, accuracy: Low
        $x_2_5 = {85 c0 0f 84 91 00 00 00 83 7d e0 00 74 71 8b 45 e0 03 45 dc 3b 45 e8 7e 42 81 45 e8 00 00 02 00 ff 75 e8 6a 00 ff 75 f0 e8 ?? ?? ff ff 85 c0 74 68 89 45 e4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_NCB_2147803764_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.NCB"
        threat_id = "2147803764"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 72 69 76 65 72 73 5c 75 73 62 ?? 65 2e 73 79 73}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 53 56 57 8b 75 08 8b fe ac 0a c0 74 06 32 45 0c aa eb f5 5f 5e 5b c9}  //weight: 1, accuracy: High
        $x_1_3 = "TIMPlatform.exe" ascii //weight: 1
        $x_1_4 = "id=%s&p=%s&mb=%d&j1=%s.&z1=%s&d1=%s&srv=%s" ascii //weight: 1
        $x_1_5 = "jl)@gmlylgmlg})K`}dhy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Small_NCD_2147803765_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.NCD"
        threat_id = "2147803765"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 00 6a 00 68 00 00 02 00 e8 ?? ?? 00 00 83 f8 00 0f ?? ?? ?? ?? ?? 68 ?? ?? 40 00 6a 00 68 ?? ?? 40 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "/c del %s.exe" ascii //weight: 1
        $x_1_3 = "CreateMutex" ascii //weight: 1
        $x_1_4 = "WinExec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_NCE_2147803766_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.NCE"
        threat_id = "2147803766"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "memtest32.sys" ascii //weight: 1
        $x_1_2 = "Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Internet Explorer\\TypedUrls" ascii //weight: 1
        $x_1_4 = "SpywareGuardPlus" ascii //weight: 1
        $x_1_5 = "[InternetShortcut]" ascii //weight: 1
        $x_1_6 = "acaowieub=1; expires=" ascii //weight: 1
        $x_1_7 = "system32\\favico.dat" ascii //weight: 1
        $x_1_8 = "Explorer\\iexplore.exe" ascii //weight: 1
        $x_1_9 = {89 78 1a 50 54 51 56 50 68 00 10 00 00 51 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_BPN_2147803796_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.BPN"
        threat_id = "2147803796"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 63 3a 5c 6d 75 6d 61 2e 65 78 65 00 63 3a 5c 31 32 33 2e 65 78 65 00 00 68 74 74 70 3a 2f}  //weight: 1, accuracy: High
        $x_1_2 = {74 6f 72 75 6e 2e 69 6e 66 00 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 3d 76 69 72 75 73 2e 65 78 65 00 00 00 00 5b 41 75 74 6f 52 75 6e 5d 00 00 00 5c 76 69 72 75 73 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = {72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 00 5c 75 73 62 76 69 72 75 73 2e 65 78 65 00 00 00 54 65 73 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_GS_2147803798_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.GS"
        threat_id = "2147803798"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {64 3a 5c 4d 79 44 6f 63 75 6d 65 6e 74 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 50 72 6f 6a 65 63 74 73 5c 44 6f 77 6e 6c 6f 61 64 65 72 20 20 50 72 6f 6a 65 63 74 20 59 55 ?? 5c 44 6f 77 6e 6c 6f 61 64 65 72 4d 61 69 6e 5c 44 6f 77 6e 6c 6f 61 64 65 72 44 6c 6c 2e 70 64 62 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {4d 79 20 42 65 61 75 74 69 66 75 6c 20 67 69 72 6c 21 21 21 00 00}  //weight: 2, accuracy: High
        $x_1_3 = "http://o1a.cn/Counter/NewCounter.asp?Param=" ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 2f 2f 6f 31 2e 6f 31 77 79 2e 63 6f 6d 2f 6d 69 73 73 2f [0-8] 2e 67 69 66}  //weight: 1, accuracy: Low
        $x_1_5 = {5c 73 79 73 74 65 6d 2e 64 61 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_OZ_2147803799_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.OZ"
        threat_id = "2147803799"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 6e 6f 2e 73 69 6e 61 62 63 2e 6e 65 74 2f 61 62 63 2e 65 78 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {7e 2e 65 78 65 00 00 00 55}  //weight: 1, accuracy: High
        $x_1_3 = {65 66 32 36 65 76 2e 64 6c 6c 00 00 ff}  //weight: 1, accuracy: High
        $x_1_4 = {61 62 63 2e 65 78 65 20 31 39 37 39 30 32 30 35 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AAAA_2147803815_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AAAA"
        threat_id = "2147803815"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0b b8 20 20 20 20 0b c8 81 f9 65 78 70 6c 0f 85 ?? ?? 00 00 8b 4b 04 0b c8 81 f9 6f 72 65 72 0f 85 ?? ?? 00 00 8b 4b 08 0b c8 81 f9 2e 65 78 65 0f 85 ?? ?? 00 00 8b 45 0c 48 0f 85 ?? ?? 00 00 6a 08 59 6a 0c ?? 08 52 40 00 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 0b b8 20 20 20 20 0b c8 81 f9 65 78 70 6c 0f 85 ?? ?? 00 00 8b 4b 04 0b c8 81 f9 6f 72 65 72 0f 85 ?? ?? 00 00 8b 4b 08 0b c8 81 f9 2e 65 78 65 0f 85 ?? ?? 00 00 8b 84 24 ?? ?? 00 00 48 0f 85 f3 00 00 00 6a 08 59 6a 0c ?? 08 52 40 00 33 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {0b d0 81 fa 65 78 70 6c 0f 85 ?? ?? 00 00 8b 51 04 0b d0 81 fa 6f 72 65 72 0f 85 ?? ?? 00 00 8b 49 08 0b c8 81 f9 2e 65 78 65 0f 85 ?? ?? 00 00 8b 45 0c 48 0f 85 ?? ?? 00 00 6a 08 59 6a 0c ?? 08 52 40 00 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Small_AAAB_2147803816_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AAAB"
        threat_id = "2147803816"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "B5AC49A2-94F3-42BD-F434-2604812C897D" ascii //weight: 10
        $x_2_2 = "bensorty.dll" ascii //weight: 2
        $x_1_3 = {68 74 74 70 3a 2f 2f 67 69 63 69 61 2e 69 6e 66 6f 2f 63 64 2f 63 64 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d 67 ?? 31}  //weight: 1, accuracy: Low
        $x_1_4 = {68 74 74 70 3a 2f 2f 6d 61 73 67 69 4f 2e 69 6e 66 6f 2f 63 64 2f 63 64 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d 67 ?? 31}  //weight: 1, accuracy: Low
        $x_1_5 = {68 74 74 70 3a 2f 2f 66 31 76 69 73 61 2e 69 6e 66 6f 2f 63 64 2f 63 64 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d 67 ?? 31}  //weight: 1, accuracy: Low
        $x_1_6 = "OpenProcess" ascii //weight: 1
        $x_1_7 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_AAAC_2147803817_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AAAC"
        threat_id = "2147803817"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "winlogan.exe" ascii //weight: 2
        $x_1_2 = {68 74 74 70 3a 2f 2f 67 69 63 69 61 2e 69 6e 66 6f 2f 63 64 2f 63 64 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d 67 ?? 31}  //weight: 1, accuracy: Low
        $x_1_3 = {68 74 74 70 3a 2f 2f 6d 61 73 67 69 4f 2e 69 6e 66 6f 2f 63 64 2f 63 64 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d 67 ?? 31}  //weight: 1, accuracy: Low
        $x_1_4 = {68 74 74 70 3a 2f 2f 66 31 76 69 73 61 2e 69 6e 66 6f 2f 63 64 2f 63 64 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d 67 ?? 31}  //weight: 1, accuracy: Low
        $x_1_5 = "OpenProcess" ascii //weight: 1
        $x_1_6 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_7 = "\\drivers\\etc\\hosts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_XJ_2147803821_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.XJ"
        threat_id = "2147803821"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 56 57 8d 45 fc 68 1c 11 a0 2a 89 45 fc ff 15 10 10 a0 2a 8b 1d 44 10 a0 2a 68 00 11 a0 2a 50 ff d3 8d 4d f8 51 6a 04 ff 75 fc a3 44 22 a0 2a 6a 0b ff d0 3d 04 00 00 c0}  //weight: 1, accuracy: High
        $x_1_2 = {43 55 52 52 45 4e 54 5f 55 53 45 52 00 00 00 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 00 00 00 00 6e 74 64 6c 6c 00 00 00 4e 74 4f 70 65 6e 53 65 63 74 69 6f 6e 00 00 00 4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65}  //weight: 1, accuracy: High
        $x_1_3 = {73 76 63 68 6f 73 74 2e 65 78 65 00 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 29}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_HD_2147803822_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.HD"
        threat_id = "2147803822"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c cacls %s /e /p everyone:f" ascii //weight: 1
        $x_1_2 = {6b 69 6c 6c 72 64 6f 67 00 00 00 00 6b 69 6c 6c 65 72 64 6f 67 00 00 00 6b 69 6c 6c 64 6f 67}  //weight: 1, accuracy: High
        $x_1_3 = "CreateServiceA" ascii //weight: 1
        $x_1_4 = "%ProgramFiles%\\Outlook Express\\msoeres2.dll" ascii //weight: 1
        $x_1_5 = "WinExec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_HH_2147803823_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.HH"
        threat_id = "2147803823"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 58 45 00 72 65 67 73 76 72 33 32 20 2f 73 20 22 25 73 22}  //weight: 1, accuracy: High
        $x_1_2 = "geturl.php?version=%s&fid=%s&mac=%s&lversion=%s&wversion=%s&day=%d&name=%s&recent=%d" ascii //weight: 1
        $x_1_3 = "Software\\Classes\\CLSID\\{C86488AF-13D5-4FEF-9DDF-9FB88698CFC1}" ascii //weight: 1
        $x_1_4 = "Mozilla/4.0 (compatible; )" ascii //weight: 1
        $x_1_5 = "dlloadtime" ascii //weight: 1
        $x_1_6 = {6d 61 63 00 25 73 5c 5f 69 6e 69 6d 61 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_HI_2147803824_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.HI"
        threat_id = "2147803824"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%ComSpec% /c ERASE /F " ascii //weight: 1
        $x_1_2 = {73 65 63 00 25 74 65 6d 70 25 00 53 74 75 62 50 61 74 68 00 25 77 69 6e 64 69 72 25 00 73 76 63 68 6f 73 74 2e 65 78 65 00 4d 6f 7a 69 6c 6c 61 2f 35 2e 30}  //weight: 1, accuracy: High
        $x_1_3 = "SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\" ascii //weight: 1
        $x_1_4 = {6a 00 ff 55 0c 8d 3d ad 18 14 13 68 04 01 00 00 57 68 c9 1a 14 13 ff 55 5c 48 03 f8 8d 35 3a 1b 14 13 ac 0a c0 aa 75 fa 68 ad 18 14 13 68 b1 19 14 13 ff 55 50 0b c0 74 76 6a 00 68 ad 18 14 13 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_VE_2147803826_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.VE"
        threat_id = "2147803826"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 25 64 25 64 2e 65 78 65 00 00 55 52 4c 00 25 64 00 00 63 3a 5c 7a 2e 62 69 6e}  //weight: 1, accuracy: High
        $x_1_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 41 63 74 69 76 65 20 53 65 74 75 70 5c 49 6e 73 74 61 6c 6c 65 64 20 43 6f 6d 70 6f 6e 65 6e 74 73 5c 25 73 00 7b 25 73 2d 25 73 2d 25 73 2d 25 73 2d 25 73 7d 00 00 00 00 5c 6c 73 61 73 73 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_OAG_2147803834_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.OAG"
        threat_id = "2147803834"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 2f 00 10 15 6a 02 e8 ?? ?? ff ff 83 c4 08 6a 00 6a 00 6a 00 6a 00 6a 00 68 ?? 20 40 00 68 ?? 20 40 00 55 ff d0}  //weight: 10, accuracy: Low
        $x_10_2 = "loads.php" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AI_2147803846_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.gen!AI"
        threat_id = "2147803846"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "MUTEX_KISSKA" ascii //weight: 3
        $x_3_2 = {5c 72 74 32 35 2e 65 78 65 00 00 00 5c 72 74 32 36 2e 65 78 65 00 00 00 5c 72 74 32 37 2e 65 78 65 00 00 00 5c 72 74 32 38 2e 65 78 65 00 00 00 5c 72 74 32 39 2e 65 78 65}  //weight: 3, accuracy: High
        $x_2_3 = {5c 64 65 6c 73 65 6c 66 2e 62 61 74 00 00 00 00 40 65 63 68 6f 20 6f 66 66 0a 3a 74 72 79 0a 64 65 6c 20}  //weight: 2, accuracy: High
        $x_3_4 = "://as.ru/new2/get_exe.php?l=" wide //weight: 3
        $x_2_5 = "http://58.65.235.3/up/get_exa.php?l=" wide //weight: 2
        $x_2_6 = "http://365well.org/zload/get_exe.php?l=" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_AJ_2147803847_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.gen!AJ"
        threat_id = "2147803847"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://bestbsd.info/cd/cd.php?id=ERROR&ver=ig1" ascii //weight: 3
        $x_2_2 = {46 69 6e 64 4e 65 78 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 41 00 00 7b 00 49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6e 6e 65 63 74 65 64 53 74 61 74 65 00 77 69 6e 69 6e 65 74 2e 64 6c 6c 00 31 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00 00 75 72 6c 6d 6f 6e 2e 64 6c 6c}  //weight: 2, accuracy: High
        $x_3_3 = {68 74 74 70 3a 2f 2f 62 65 73 74 62 73 64 2e 69 6e 66 6f 2f 63 64 2f 63 64 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d 69 67 31 00 68 74 74 70 3a 2f 2f 72 65 7a 75 6c 74 73 64 2e 69 6e 66 6f 2f 63 64 2f 63 64 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d 69 67 31 00 68 74 74 70 3a 2f 2f 63 61 72 72 65 6e 74 61 6c 68 65 6c 70 2e 6f 72 67 2f 63 64 2f 63 64 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d 69 67 31 00 52 45 47 5f 53 5a 00 43 4c 53 49 44 00}  //weight: 3, accuracy: High
        $x_3_4 = {25 6c 75 2e 65 78 65 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 00 69 64 73 74 72 66 00 45 52 52 4f 52 00 25 6c 64 2d 25 6c 58 25 6c 58 00 43 4c 53 49 44 5c 25 73}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_AK_2147803848_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.gen!AK"
        threat_id = "2147803848"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 00 0a 49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 00 0a 49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 00 0a 49 6e 74 65 72 6e 65 74 43 6c 6f 73 65 48 61 6e 64 6c 65 00 0a 49 6e 74 65 72 6e 65 74 43 68 65 63 6b 43 6f 6e 6e 65 63 74 69 6f 6e 41 00 0a 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 00 0a 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e}  //weight: 3, accuracy: High
        $x_3_2 = {57 69 6e 64 6f 77 73 20 53 79 73 4e 6f 74 69 66 79 00 0a 68 74 74 70 3a 2f 2f 00 0a 6f 70 65 6e 00 0a 4d 61 6c 77 61 72 65 44 65 73 74 72 75 63 74 6f 72 00 0a 4d 61 6c 77 61 72 65 44 65 73 74 72 75 63 74 6f 72 2e 65 78 65 00 0a 68 74 74 70 3a 2f 2f 6d 61 6c 77 61 72 65 64 65 73 74 72 75 63 74 6f 72 2e 63 6f 6d 2f 3f 61 69 64 3d 33 34 37}  //weight: 3, accuracy: High
        $x_3_3 = {68 74 74 70 3a 2f 2f 6d 61 6c 77 61 72 65 64 65 73 74 72 75 63 74 6f 72 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 61 69 64 3d 33 34 37 00 0a 54 68 65 20 74 72 61 63 65 73 20 6f 66 20 6d 61 6c 69 63 69 6f 75 73 20 73 6f 66 74 77 61 72 65 20 61 63 74 69 76 69 74 79 20 77 61 73 20 64 65 74 65 63 74 65 64 20 61 74 20 79 6f 75 72 20 50 43 2e}  //weight: 3, accuracy: High
        $x_3_4 = {41 63 74 69 76 65 20 73 70 79 77 61 72 65 20 64 65 74 65 63 74 65 64 21 00 0a 53 65 63 75 72 69 74 79 20 41 6c 65 72 74 21}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Small_ZYB_2147803851_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.ZYB"
        threat_id = "2147803851"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 04 8a 01 84 c0 74 0c 04 06 88 01 8a 41 01 41 84 c0 75 f4 c3}  //weight: 1, accuracy: High
        $x_1_2 = "_StartRun@16" ascii //weight: 1
        $x_1_3 = "]4VJ>IM?LL(>;N" ascii //weight: 1
        $x_1_4 = "bnnj4))qqq(\\[c^o(]ig" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AU_2147803865_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.gen!AU"
        threat_id = "2147803865"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "urldownloadtofilea" ascii //weight: 1
        $x_1_2 = "%lu.exe" ascii //weight: 1
        $x_1_3 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_4 = "winlogan.exe" ascii //weight: 1
        $x_1_5 = {68 74 74 70 3a 2f 2f [0-32] 2f 63 64 2f 63 64 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_DBB_2147803871_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.DBB"
        threat_id = "2147803871"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\a.exe" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f 79 67 73 6f 6e 64 68 65 6b 73 2e 69 6e 66 6f 2f 63 2f ?? ?? ?? ?? 2f 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "WinExec" ascii //weight: 1
        $x_1_4 = {8b ec 6a 00 ff 15 08 31 40 00 6a 00 6a 00 6a 00 6a 04 6a 02 6a 00 6a 00 6a ff 6a 00 ff 15 04 31 40 00 6a 00 6a 2e 68 9f 30 40 00 68 a8 30 40 00 e8 15 00 00 00 6a 05 68 9f 30 40 00 ff 15 e8 30 40 00 6a 00 ff 15 e4 30 40 00 55 8b ec 83 c4 d4 eb 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AK_2147803885_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AK"
        threat_id = "2147803885"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_2 = "WinExec" ascii //weight: 1
        $x_1_3 = "Netbios" ascii //weight: 1
        $x_1_4 = {53 56 8b 74 24 0c 57 8b fe 83 c9 ff 33 c0 33 db f2 ae f7 d1 49 74 2e 55 bd 60 22 40 00 6a 00 55 55 6a ff e8}  //weight: 1, accuracy: High
        $x_1_5 = {6a 10 33 c0 59 8d 7d c0 f3 ab 6a 3f 8d bd a0 fe ff ff 59 c6 45 c0 37 f3 ab 66 ab aa 8d 85 a0 fe ff ff 66 c7 45 c8 ff 00 89 45 c4 8d 45 c0 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_LZ_2147803886_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.LZ"
        threat_id = "2147803886"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ec 68 01 00 00 56 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 a3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 a3 ?? ?? ?? ?? ff d0 8d 84 24 08 01 00 00 50 6a 64 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 4c 24 48 8b f0 51 68 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 83 c4 14 83 f8 01 0f 85 8f 00 00 00 57 8b 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_OG_2147803889_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.OG"
        threat_id = "2147803889"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f [0-64] 2f [0-22] 2e (65|6a)}  //weight: 1, accuracy: Low
        $x_1_2 = "http://www.youtube.com/watch?v=" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_4 = "Shell32.dll" wide //weight: 1
        $n_4_5 = "www.zhangmen.nl Professional Acupuncture Software by F-ACT" wide //weight: -4
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_RS_2147803891_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.RS"
        threat_id = "2147803891"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a 01 6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 01 00 00 00 60 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_LL_2147803896_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.LL"
        threat_id = "2147803896"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {be 03 00 00 00 b4 70 88 a6 ?? ?? ?? ?? be 1d 00 00 00 b4 70 88 a6 ?? ?? ?? ?? be 08 00 00 00 b4 61 88 a6 ?? ?? ?? ?? be 1c 00 00 00 b4 68 88 a6 ?? ?? ?? ?? be 00 00 00 00 b4 68 88 a6 ?? ?? ?? ?? be 01 00 00 00 b4 74 88 a6 ?? ?? ?? ?? be 07 00 00 00 b4 68 88 a6 ?? ?? ?? ?? be 09 00 00 00 b4 70 88 a6 ?? ?? ?? ?? be 17 00 00 00 b4 2f 88 a6 ?? ?? ?? ?? be 0b 00 00 00 b4 79}  //weight: 10, accuracy: Low
        $x_10_2 = {be 02 00 00 00 b4 6e 88 a6 ?? ?? ?? ?? be 04 00 00 00 b4 78 88 a6 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? ff d0 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 05 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? ff d0 6a 04 6a 00 68}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AT_2147803900_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.gen!AT"
        threat_id = "2147803900"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 62 00 65 00 65 00 70 00 2e 00 73 00 79 00 73 00 00 00 00 00 73 66 63 5f}  //weight: 1, accuracy: High
        $x_1_2 = {74 20 45 78 70 6c 6f 72 65 72 5c 32 2e 65 78 65 00 00 00 00 6f 70 65 6e 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {65 72 5c 31 2e 65 78 65 00 00 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00 00 53 68 65 6c 6c 45 78 65 63 75 74 65 41 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_2147803905_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small!inf"
        threat_id = "2147803905"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "inf: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a3 20 30 03 01 68 44 30 03 01 ff 15 14 30 03 01 a3 08 30 03 01 68 88 30 03 01 ff 35 08 30 03 01 ff 15 10 30 03 01 a3 24 30 03 01 68 30 30 03 01 ff 15 14 30 03 01 a3 0c 30 03 01 68 68 30 03 01 ff 35 0c 30 03 01 ff 15 10 30 03 01 a3 28 30 03 01 68 9b 30 03 01 ff 35 0c 30 03 01 ff 15 10 30 03 01 a3 2c 30 03 01 e8 43 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {65 54 68 72 65 61 64 00 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 73 76 63 68 6f 73 74 2e 65 78 65 00 68 74 74 70 3a 2f 2f 75 73 64 2e 38 38 31 35 31 35 2e 6e 65 74 2f 64 6f 77 6e 2f 31 2e 65 78 65 00 90 90 90 90 90 eb 0e 90 90 90 e8 14 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_DBA_2147803912_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.DBA"
        threat_id = "2147803912"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "URLDownloadToFileA" ascii //weight: 10
        $x_1_3 = {63 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 20 68 74 74 70 3a 2f 2f [0-64] 2f 66 6f 74 6f 73 2e 68 74 6d}  //weight: 1, accuracy: Low
        $x_1_4 = {68 74 74 70 3a 2f 2f [0-32] 2f 73 77 66 2f 64 6f 77 6e 2f 69 67 73 67 61 74 65 73 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = "C:\\WINDOWS\\athyxlnvx.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_AAAF_2147803926_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AAAF"
        threat_id = "2147803926"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "theinstalls.com" ascii //weight: 1
        $x_1_2 = "ldinfo.ldr" ascii //weight: 1
        $x_1_3 = "ldcore_download" ascii //weight: 1
        $x_1_4 = "ldcore_guard" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" ascii //weight: 1
        $x_1_6 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_7 = "HttpSendRequestA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_BKU_2147803929_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.BKU"
        threat_id = "2147803929"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 35 8a 3e 00 10 e8 ?? 08 00 00 c3 55 8b ec 68 e8 03 00 00 e8 ?? 08 00 00 6a 00 6a 00 e8 ?? 09 00 00 0b c0 74 30 6a ?? 6a 01 e8 ?? 02 00 00 0b c0 74 0c 68 00 50 00 10 e8 ?? 05 00 00 eb 17 6a ?? 6a 02 e8 ?? 02 00 00 0b c0 74 0a 68 ?? 50 00 10 e8 ?? 05 00 00 e8 ?? 06 00 00 68 c0 27 09 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "SOFTWARE\\Classes\\CLSID\\%s\\InProcServer32" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\%s" ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 2f 2f [0-48] 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d}  //weight: 1, accuracy: Low
        $x_1_5 = "bensorty.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_BPM_2147803932_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.BPM"
        threat_id = "2147803932"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "36"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%SystemRoot%\\system32\\drivers\\puid.sys" ascii //weight: 1
        $x_1_2 = "\\drivers\\DeepFrz.sys" ascii //weight: 1
        $x_1_3 = "\\.\\PhysicalDrive0" ascii //weight: 1
        $x_1_4 = "\\.\\PhysicalHardDisk0" ascii //weight: 1
        $x_1_5 = "\\DosDevices\\PhysicalHardDisk0" ascii //weight: 1
        $x_1_6 = "\\Device\\Harddisk0\\DR0" ascii //weight: 1
        $x_1_7 = "antiarp.exe" ascii //weight: 1
        $x_1_8 = "360tray.exe" ascii //weight: 1
        $x_1_9 = "360Safe.exe" ascii //weight: 1
        $x_1_10 = "\\msgqueuelist.exe" ascii //weight: 1
        $x_1_11 = "userinit.exe" ascii //weight: 1
        $x_1_12 = "\\spoolsv.exe" ascii //weight: 1
        $x_1_13 = "ntfs.dll" ascii //weight: 1
        $x_1_14 = "ntoskrnl.exe" ascii //weight: 1
        $x_1_15 = "ShellExecuteA" ascii //weight: 1
        $x_1_16 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\run" ascii //weight: 1
        $x_1_17 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_10_18 = {8d 85 f4 fb ff ff 50 e8 ?? ?? ff ff 8d 85 f4 fb ff ff c7 04 24 ?? ?? 40 00 50 e8 ?? ?? 00 00 59 8d 85 f4 fb ff ff 59 53 50 8d 85 e8 f8 ff ff 50 ff 15 ?? ?? ?? ?? 8d 85 e8 f8 ff ff 50 ff 15 ?? ?? ?? ?? 8d 45 f8 50 68 ?? ?? 40 00 68 02 00 00 80 ff 15 ?? ?? ?? ?? 85 c0 75 27 8d 85 f4 fb ff ff 50 e8 ?? ?? 00 00 59 40 50 8d 85 f4 fb ff ff 50 6a 01 53}  //weight: 10, accuracy: Low
        $x_10_19 = {eb 00 b9 00 01 00 00 ba b1 c9 ec cc 8d 41 ff 51 b9 08 00 00 00 d1 e8 73 02 33 c2 49 75 f7 59 89 04 8d ?? ?? 40 00 49 75 e3 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 16 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_JF_2147803933_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.JF"
        threat_id = "2147803933"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "130"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "GetSystemDirectoryA" ascii //weight: 20
        $x_20_2 = "CreateFileA" ascii //weight: 20
        $x_20_3 = "URLDownloadToFileA" ascii //weight: 20
        $x_20_4 = "WinExec" ascii //weight: 20
        $x_20_5 = "%s\\updatax.exe" ascii //weight: 20
        $x_20_6 = "HDDGuard.dll" ascii //weight: 20
        $x_5_7 = "KvTrust.dll" ascii //weight: 5
        $x_5_8 = "UrlGuard.dll" ascii //weight: 5
        $x_5_9 = "antispy.dll" ascii //weight: 5
        $x_5_10 = "safemon.dll" ascii //weight: 5
        $x_5_11 = "ieprot.dll" ascii //weight: 5
        $x_20_12 = {83 c4 1c 85 c0 74 7e 8d 85 dc fd ff ff 50 ff 75 f0 e8 ad 00 00 00 59 85 c0 59 75 69 ff 75 f0 ff 15 10 20 00 10 3d 00 c7 00 00 7d 59 8d 85 dc fd ff ff 50 ff 75 f0 ff 15 30 20 00 10 ff 75 f4 8d 85 d0 fa ff ff 50 8d 85 d8 fc ff ff 68 38 30 00 10 50 ff d6 8d 85 d8 fc ff ff 50 8d 85 dc fd ff ff 50 e8 3b 00 00 00 83 c4 18 85 c0 75 17 8d 85 d8 fc ff ff 6a 05 50 ff 15 1c 20 00 10 60 90 b8 03 00 00 00 61 ff 45 f4 83 7d f4 64 0f 8e 3e ff ff ff 68 c0 27 09 00 ff 15 24 20 00 10 e9}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_20_*) and 2 of ($x_5_*))) or
            ((7 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_AAAI_2147803954_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AAAI"
        threat_id = "2147803954"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://69.31.84.223/" ascii //weight: 1
        $x_1_2 = "http://trackhits.cc/cnt" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AAAJ_2147803955_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AAAJ"
        threat_id = "2147803955"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 c4 f0 53 33 c9 89 4d f4 89 4d f0 89 55 f8 89 45 fc 8b 45 fc e8 cf af ff ff 8b 45 f8 e8 c7 af ff ff 33 c0 55 68 bf 70 00 10 64 ff 30 64 89 20 8d 55 f4 8b 45 f8 e8 de d3 ff ff 8b 45 f4 e8 b6 af ff ff 50 8d 55 f0 8b 45 fc e8 ca d3 ff ff 8b 45 f0 e8 a2 af ff ff 50 e8 f4 9f ff ff 50 e8 1a ba ff ff 8b d8 33 c0 5a 59 59 64 89 10 68 c6 70 00 10 8d 45 f0 ba 04 00 00 00 e8 42 ab ff ff c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_BG_2147803961_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.gen!BG"
        threat_id = "2147803961"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SYSTEM\\CurrentControlSet\\Services\\" ascii //weight: 10
        $x_10_2 = {2e 65 78 65 00 02 00 00 [0-6] [0-144] 20 2f 63 20 20 64 65 6c 20}  //weight: 10, accuracy: Low
        $x_1_3 = {68 74 74 70 3a 2f 2f [0-48] 2f [0-12] 2f 30 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {68 74 74 70 3a 2f 2f [0-48] 2f [0-12] 2f 31 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = {68 74 74 70 3a 2f 2f [0-48] 2f [0-12] 2f 32 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_6 = {68 74 74 70 3a 2f 2f [0-48] 2f [0-12] 2f 33 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_7 = {68 74 74 70 3a 2f 2f [0-48] 2f [0-12] 2f 34 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_8 = {68 74 74 70 3a 2f 2f [0-48] 2f [0-12] 2f 35 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_9 = {68 74 74 70 3a 2f 2f [0-48] 2f [0-12] 2f 36 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_10 = {68 74 74 70 3a 2f 2f [0-48] 2f [0-12] 2f 37 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_11 = {68 74 74 70 3a 2f 2f [0-48] 2f [0-12] 2f 38 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_12 = {68 74 74 70 3a 2f 2f [0-48] 2f [0-12] 2f 39 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_AAAZ_2147803964_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AAAZ"
        threat_id = "2147803964"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%TEMP%\\iexplorer.exe" ascii //weight: 1
        $x_1_2 = {8b d0 59 33 c0 59 85 d2 74 ?? 8b fa 83 c9 ff f2 ae f7 d1 49 83 f9 05 72 [0-7] 8d ?? 05 6a 2e}  //weight: 1, accuracy: Low
        $x_1_3 = {57 57 68 01 02 00 00 50 ff d6 57 57 55 ff 74 24 ?? ff d6 68 ?? ?? ?? ?? 57 ff 15 ?? ?? ?? ?? 3b c7 74 25 68 ?? ?? ?? ?? 57 57 50 ff d3}  //weight: 1, accuracy: Low
        $x_5_4 = {57 ff d6 83 c4 0c 83 bd 7c ff ff ff 02 0f 85 a5 00 00 00 6a 3f 68 ?? ?? ?? ?? 57 ff d6 e9 93 00 00 00 83 f8 0a 75 09 6a 3f 68 ?? ?? ?? ?? eb 7a 83 f8 5a 75 45 6a 3f 68 ?? ?? ?? ?? eb 6c 83 f9 05 75 29 85 c0 75 09 6a 3f 68 ?? ?? ?? ?? eb 5a 83 f8 01 75 09 6a 3f 68 ?? ?? ?? ?? eb 4c 83 f8 02 75 17 6a 3f 68 ?? ?? ?? ?? eb 3e 83 f9 06 75 09 6a 3f 68 ?? ?? ?? ?? eb 30}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_B_2147804026_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.gen!B"
        threat_id = "2147804026"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 73 68 65 6c 00 6b 6c 6f 70}  //weight: 1, accuracy: High
        $x_1_2 = {75 72 6c 6d 6f 6e 2e 64 6c 6c 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00 63 3a 5c 74 73 6b 6d 67 72 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = {2e 63 6f 6d [0-3] 2f 32 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AN_2147804036_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.gen!AN"
        threat_id = "2147804036"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_2 = "TerminateThread" ascii //weight: 1
        $x_1_3 = "urlmon.dll" ascii //weight: 1
        $x_1_4 = "http://bestbsd.info/cd/cd.php?id=%s&ver=ig1" ascii //weight: 1
        $x_1_5 = "http://rezultsd.info/cd/cd.php?id=%s&ver=ig1" ascii //weight: 1
        $x_1_6 = "http://carrentalhelp.org/cd/cd.php?id=%s&ver=ig1" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Classes\\CLSID\\%s\\InProcServer32" ascii //weight: 1
        $x_1_8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 1
        $x_1_9 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_CCC_2147804052_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.CCC"
        threat_id = "2147804052"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 20 20 20 20 0b ?? 81 ?? 65 78 70 6c 0f 85 ?? 00 00 00 8b ?? 04 0b ?? 81 ?? 6f 72 65 72 0f 85 ?? 00 00 00 8b ?? 08 0b ?? 81 ?? 2e 65 78 65 0f 85 ?? 00 00 00}  //weight: 10, accuracy: Low
        $x_1_2 = "explorer.exe" ascii //weight: 1
        $x_1_3 = "psapi.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_NCK_2147804053_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.NCK"
        threat_id = "2147804053"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shell\\open\\command" ascii //weight: 1
        $x_1_2 = "mcboo.com/retadpu.exe" ascii //weight: 1
        $x_1_3 = "name for %s" ascii //weight: 1
        $x_1_4 = "affID" ascii //weight: 1
        $x_1_5 = "GetWindowsDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_JU_2147804071_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.JU"
        threat_id = "2147804071"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%shtml/%s_plus.js" ascii //weight: 1
        $x_1_2 = "%s:\\Program Files\\Internet Explorer\\IEXPLORE.EXE %s" ascii //weight: 1
        $x_1_3 = {68 e8 03 00 00 ff d3 51 8d 55 e4 8b cc 89 ?? ?? ff ff ff 52 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 68 20 4e 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_KS_2147804072_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.KS"
        threat_id = "2147804072"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 31 6e 74 30 75 63 68 31 6e 73 74 40 6c 6c 33 72 00}  //weight: 1, accuracy: High
        $x_1_2 = "http://www.win-touch.com" ascii //weight: 1
        $x_1_3 = "%s%s.exe" ascii //weight: 1
        $x_1_4 = "mutexWTRec" ascii //weight: 1
        $x_1_5 = "sacc/feedback.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_KX_2147804074_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.KX"
        threat_id = "2147804074"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 1
        $x_1_2 = "cmd /c shutdown -r -f -t 15 -c \"Erro Interno do Windows" ascii //weight: 1
        $x_1_3 = "nogui C:\\systemX86.txt" ascii //weight: 1
        $x_1_4 = "msnmsgsgrs.exe" ascii //weight: 1
        $x_1_5 = "7CEF75A538FF4FF85F8EDF" wide //weight: 1
        $x_1_6 = {b9 00 00 00 00 e8 ?? ?? fe ff 8b 45 ?? e8 ?? ?? fe ff 8b f0 8d 45 ?? e8 ?? ?? ff ff 8d 45 ?? 50 8d 4d ?? ba ?? ?? 41 00 b8 ?? ?? 41 00 e8 ?? ?? ff ff 8b 55 ?? 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_KY_2147804075_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.KY"
        threat_id = "2147804075"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://www.speedapps.com/adspace_bc_ref_1.htm" ascii //weight: 1
        $x_1_2 = {8d 7e 74 6a 68 56 8b cf e8 ?? ?? ff ff 68 ?? ?? 40 00 8d 4c 24 14 e8 ?? ?? 00 00 8b 44 ?? ?? 8b cf 50 c7 84 ?? ?? ?? 00 00 00 00 00 00 e8 ?? ?? ff ff 8d 4c ?? ?? 68 08 02 00 00 51 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_KZ_2147804076_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.KZ"
        threat_id = "2147804076"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "www.360haowan.cn" ascii //weight: 1
        $x_1_2 = "matc6" ascii //weight: 1
        $x_1_3 = {83 c4 48 33 c9 80 ?? ?? ?? 00 8d ?? ?? ?? 75 03 c6 00 30 41 83 f9 0c 7c ec}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c4 1c 85 c0 75 21 68 88 13 00 00 ff 15 ?? ?? 40 00 8d 45 ?? 50 8d 85 ?? ?? ff ff 56 50 e8 ?? ?? ff ff 83 c4 0c eb db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_LA_2147804080_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.LA"
        threat_id = "2147804080"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.promt.cc/ring" ascii //weight: 1
        $x_1_2 = "/c del >c:" ascii //weight: 1
        $x_1_3 = {b9 20 00 00 00 f3 a5 8b 54 24 28 8b 4d 04 8a 44 24 2c 8b 74 24 30 89 4c 95 38 8d 7d 18 b9 08 00 00 00 88 45 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_NO_2147804081_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.NO"
        threat_id = "2147804081"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd /c shutdown -r -t 0" ascii //weight: 1
        $x_1_2 = "urlm0n.dll" ascii //weight: 1
        $x_1_3 = {83 f8 08 7d 13 8b 4d dc 8a 0c 08 81 f1 8a 00 00 00 88 ?? ?? ?? 40 eb e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_LD_2147804082_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.LD"
        threat_id = "2147804082"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 6c 80 7d 08 00 57 74 0d bf ?? ?? ?? ?? c1 ef 10 c1 e7 10 eb 03 8b 7b 34}  //weight: 1, accuracy: Low
        $x_1_2 = {53 56 c7 05 ?? ?? ?? ?? c0 66 00 00 c7 05 ?? ?? ?? ?? 90 5b 00 00 81 05 ?? ?? ?? ?? dc 0f 00 00 c7 05 ?? ?? ?? ?? 83 07 00 00 81 05 ?? ?? ?? ?? fc 6e 00 00 c7 05 ?? ?? ?? ?? 42 09 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_SN_2147804091_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.SN"
        threat_id = "2147804091"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 00 8b d0 d1 e0 33 c2 83 c0 21 5a 89 02 c1 e8 18 5a c3 ba 05 02 40 00 b9 bb 06 00 00 e8 d7 ff ff ff 30 02 42 e2 f6 e9 58 fc ff ff ff 25}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_GX_2147804100_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.GX"
        threat_id = "2147804100"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 38 5b 01 00 8b 15 ?? ?? 40 00 52 ff d6 68 b8 22 00 00 ff 15 ?? ?? 40 00 43 89 9d ?? ?? ff ff eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_HK_2147804139_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.HK"
        threat_id = "2147804139"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 7a 74 2e 61 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 70 3f 75 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {65 72 6e 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_HW_2147804158_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.HW"
        threat_id = "2147804158"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "del %%0" ascii //weight: 2
        $x_2_2 = "\\dek.bat" ascii //weight: 2
        $x_2_3 = "del \"%s\"" ascii //weight: 2
        $x_1_4 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_2_5 = "%windir%\\Tasks\\pig.vbs" ascii //weight: 2
        $x_2_6 = "rs.run \\x22%%windir%%\\Tasks\\kav32.exe\",0" ascii //weight: 2
        $x_1_7 = "{645FF040-5081-101B-9F08-00AA002F954E}\\kav32.exe" ascii //weight: 1
        $x_2_8 = "Virus" ascii //weight: 2
        $x_2_9 = "AUTORUN.INF" ascii //weight: 2
        $x_1_10 = "TrojanHunter.exe" ascii //weight: 1
        $x_1_11 = "shell\\open\\Command" ascii //weight: 1
        $x_1_12 = "InternetOpenA" ascii //weight: 1
        $x_1_13 = "ZwQuerySystemInformation" ascii //weight: 1
        $x_1_14 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((7 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_IM_2147804159_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.IM"
        threat_id = "2147804159"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {66 81 3b 4d 5a 74 1a 81 eb 00 00 01 00 66 81 3b 4d 5a 74 0d 81 eb 00 00 01 00 66 81 3b 4d 5a 75 f3 89 5c 24 1c 61 c3}  //weight: 10, accuracy: High
        $x_10_2 = "%TEMP%\\\\svhost.exe" ascii //weight: 10
        $x_1_3 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_4 = "ZoneAlarm Security Alert" ascii //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
        $x_1_6 = "CreateRemoteThread" ascii //weight: 1
        $x_1_7 = "ZwQuerySystemInformation" ascii //weight: 1
        $x_1_8 = "NtQueryInformationProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_CAA_2147804160_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.CAA"
        threat_id = "2147804160"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {75 72 6c 6d 6f 6e 2e 64 6c 6c 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00 00 43 3a 5c 00 25 58 00 00 55 8b ec 83 ec 48}  //weight: 20, accuracy: High
        $x_1_2 = "GetVolumeInformationA" ascii //weight: 1
        $x_1_3 = "NSPStartup" ascii //weight: 1
        $x_10_4 = {73 1e 8b 45 ?? 03 45 ?? 0f b6 00 8b 4d ?? 83 c1 58 33 4d ?? 33 c1 8b 4d ?? 03 4d ?? 88 01 eb d3}  //weight: 10, accuracy: Low
        $x_10_5 = "%s\\lsp%c%c%c.dll" wide //weight: 10
        $x_1_6 = "WSCInstallNameSpace" ascii //weight: 1
        $x_1_7 = "GetTempFileNameW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_MM_2147804161_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.MM"
        threat_id = "2147804161"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "info=%s" ascii //weight: 1
        $x_10_2 = "POST /interface.asp HTTP/1.1" ascii //weight: 10
        $x_10_3 = "User-Agent: (CustomSpy)" ascii //weight: 10
        $x_10_4 = "GET /qvod.txt HTTP/1.1" ascii //weight: 10
        $x_1_5 = "%s\\baidu" ascii //weight: 1
        $x_10_6 = "%s\\baidu\\%s" ascii //weight: 10
        $x_10_7 = "Projects\\xNetInstaller\\Release\\xNetInstaller.pdb" ascii //weight: 10
        $x_1_8 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_AHL_2147804163_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AHL"
        threat_id = "2147804163"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 65 72 00 75 75 00 00 2e 6c 6f 67 00 00 00 00 47 6c 6f 62 61 6c 5c 5f 5f 73 74 6f 70 [0-16] 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 29 [0-16] 68 74 74 70 3a 2f 2f 64 2e 72 6f 62 69 6e 74 73 2e 75 73 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "URLDownloadToCacheFileA" ascii //weight: 1
        $x_1_3 = "GetPrivateProfileStringA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_RG_2147804164_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.RG"
        threat_id = "2147804164"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {26 76 65 72 3d 00 00 00 63 6c 63 6f 75 6e 74 2f 63 6f 75 6e 74 2e 61 73 70 3f 6d 61 63 3d 00 00 47 4f 4f 47 4c 45}  //weight: 10, accuracy: High
        $x_1_2 = "SkyMon.exe" ascii //weight: 1
        $x_1_3 = "ALYac.aye" ascii //weight: 1
        $x_1_4 = "AyAgent.aye" ascii //weight: 1
        $x_1_5 = "\\systemInfo.ini" ascii //weight: 1
        $x_10_6 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_7 = {44 4c 4c 2e 64 6c 6c 00 43 4f 4d 52 65 73 4d 6f 64 75 6c 65 49 6e 73 74 61 6e 63 65 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_RK_2147804165_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.RK"
        threat_id = "2147804165"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 53 6c 69 63 68 69 63 65 5c 48 61 6b 6f 76 61 6e 6a 65 5c [0-240] 2e 70 64 62}  //weight: 10, accuracy: Low
        $x_5_2 = "S_Norton5.My.Resources" ascii //weight: 5
        $x_5_3 = "FacebookHack.exe" wide //weight: 5
        $x_5_4 = "Executioner.exe" ascii //weight: 5
        $x_5_5 = "firewall set opmode disable" wide //weight: 5
        $x_2_6 = "\\derahS\\eriWemiL\\" wide //weight: 2
        $x_2_7 = "\\gnimocni\\0002yeknoDe\\" wide //weight: 2
        $x_2_8 = "\\redlof derahs ym\\" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_SJ_2147804166_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.SJ"
        threat_id = "2147804166"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "setup_RV42XPIsewo.exe" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f [0-32] 2f 4c 64 72 57 65 62 44 72 6f 70 41 70 70 7a 2f [0-64] 2f 52 56 34 32 58 50 49 73 65 77 6f 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "/SP- /suppressmsgboxes /verysilent /noicons /norestart" ascii //weight: 1
        $x_1_4 = "http://174.122.240.164/Kc/2331" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AIP_2147804168_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AIP"
        threat_id = "2147804168"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 3b c1 72 f3 38 5d 0b 75 16 80 bd ?? ?? ?? ?? 4d 75 38 80 bd ?? ?? ?? ?? 5a 75 2f c6 45 0b 01}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f 6d 66 65 65 64 2e 69 66 2e 75 61 2f 73 6c 2f 67 65 74 2e 70 68 70 [0-3] 74 6d 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_QQ_2147804188_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.QQ"
        threat_id = "2147804188"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://alfredo.myphotos.cc/scripts/view.asp" ascii //weight: 3
        $x_4_2 = "~DFBA17.tmp" ascii //weight: 4
        $x_3_3 = "%s?sid=%08X%08X" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_SO_2147804189_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.SO"
        threat_id = "2147804189"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 68 1a 20 40 00 68 10 20 40 00 6a 00 6a 00 e8 0d 00 00 00 6a 00 e8 00 00 00 00 ff 25}  //weight: 1, accuracy: High
        $x_2_2 = {6d 73 68 74 61 2e 65 78 65 00 68 74 74 70 3a 2f 2f [0-21] 2e 63 6e 2f [0-20] 2e 70 68 70}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_TS_2147804190_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.TS"
        threat_id = "2147804190"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Windows Help Engine application file" wide //weight: 3
        $x_3_2 = "Content-Type:multipart/form-data;   boundary=77fcd2ncos33a816d302b6" ascii //weight: 3
        $x_2_3 = "/install.asp" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_WY_2147804193_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.WY"
        threat_id = "2147804193"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "winrar_config.tmp" ascii //weight: 2
        $x_3_2 = "http://kp.9" ascii //weight: 3
        $x_2_3 = "C:\\Program Files\\FreeRapid\\4.bat" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_WX_2147804199_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.WX"
        threat_id = "2147804199"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 68 80 00 00 00 6a 02 55 6a 04 68 ff 01 1f 00 53 ff 15 ?? ?? ?? ?? 8b d8 8d 44 24 20 55 50 57 56 53 89 6c 24 34 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {b8 00 00 00 80 be 02 00 00 00 bd 04 00 00 00 eb 0f b8 00 00 00 c0 be 04 00 00 00 bd 06 00 00 00 6a 00 6a 00 6a 03 6a 00 6a 01 50 8b 44 24 2c 50 ff 15 ?? ?? ?? ?? 8b f8 83 ff ff}  //weight: 2, accuracy: Low
        $x_1_3 = "\\down.txt" ascii //weight: 1
        $x_1_4 = "clcount/count.asp?mac=" ascii //weight: 1
        $x_1_5 = "Global\\EVENT_bossisruning" ascii //weight: 1
        $x_1_6 = "Global\\EVENT_DOG_DOG_XXX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_UN_2147804210_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.UN"
        threat_id = "2147804210"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 20 49 6e 74 (61|6f) 72 6e (61|65|6f) 74 20 45 78 70 6c 61 72 65 72 20 2e 6c 6e 6b}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 74 61 6e 63 68 75 2e 65 78 65 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: High
        $x_1_3 = {5c 68 61 6e 6b 6f 6e 67 2e 65 78 65 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: High
        $x_1_4 = {2e 65 78 65 00 68 74 74 70 3a 2f 2f 07 00 5c 70 69 ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39)}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 65 78 65 00 68 74 74 70 3a 2f 2f 07 00 5c 78 69 ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39)}  //weight: 1, accuracy: Low
        $x_1_6 = {5c 64 69 61 6e 78 69 6e ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 65 78 65 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_7 = {5c 65 71 78 69 ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 65 78 65 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_8 = {5c 67 6f 75 ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 65 78 65 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_9 = {5c 67 75 61 ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 65 78 65 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_10 = {5c 67 75 61 64 5f ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 65 78 65 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_11 = {5c 4d 61 6f ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 65 78 65 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_12 = {5c 6e 61 71 ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 65 78 65 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_13 = {5c 4e 65 77 46 75 ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 65 78 65 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_14 = {5c 70 70 65 76 ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 65 78 65 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_15 = {5c 70 70 76 ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 65 78 65 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_16 = {5c 70 79 69 ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 65 78 65 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_17 = {5c 72 69 73 ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 65 78 65 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_18 = {5c 73 61 69 ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 65 78 65 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_19 = {5c 73 65 74 75 70 5f ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 65 78 65 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_20 = {5c 73 6f 66 74 ?? ?? ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 5c (73|77) 5f ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 65 78 65 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_21 = {5c 78 67 73 ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 65 78 65 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_22 = {5c 79 75 6c 65 ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39) 2e 65 78 65 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Small_AII_2147804216_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AII"
        threat_id = "2147804216"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 10 8a 54 24 14 53 55 8b c1 2b f1 8b ef 8a 1c 06 32 da 88 18 40 4d 75 f5 5d c6 04 0f 00}  //weight: 1, accuracy: High
        $x_1_2 = "NefkheU<>8HM==1$8O?0$=>m<$HLJ8$M<LH;;:==90K" ascii //weight: 1
        $x_1_3 = "1=><'>>9:9=8;:'jg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AII_2147804216_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AII"
        threat_id = "2147804216"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "plmd;$ipoiwsxsdf" ascii //weight: 1
        $x_1_2 = "\\sysoption.ini" ascii //weight: 1
        $x_1_3 = "\\_uninstall" ascii //weight: 1
        $x_1_4 = "\\tmp.exe.tmp" ascii //weight: 1
        $x_1_5 = "2.tmp" ascii //weight: 1
        $x_1_6 = "ktv.lnk" ascii //weight: 1
        $x_1_7 = {4d 53 43 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 74 6d 70 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AIM_2147804217_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AIM"
        threat_id = "2147804217"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "999999999999.url" ascii //weight: 1
        $x_1_2 = "tazbao.com" ascii //weight: 1
        $x_1_3 = "\\fie.exe" ascii //weight: 1
        $x_1_4 = "%s\\Google%c%c.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AHY_2147804218_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AHY"
        threat_id = "2147804218"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "microsoft_lock" ascii //weight: 10
        $x_10_2 = {4d 53 43 46 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (62|70) 2e 64 6c 6c 2e 7a 67 78}  //weight: 10, accuracy: Low
        $x_10_3 = "%ssysoption.ini" ascii //weight: 10
        $x_1_4 = ".dll.zgx.tmp" ascii //weight: 1
        $x_1_5 = "\\s.exe.tmp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_AHY_2147804218_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AHY"
        threat_id = "2147804218"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MaskPic.bmp" ascii //weight: 1
        $x_1_2 = "3b7e555a765536a7" ascii //weight: 1
        $x_1_3 = "%d^^%d^^%d^^%d^^%d^^%d^^%d^^%d^^%d^^%lu^^%d^^%d" ascii //weight: 1
        $x_1_4 = "rt.netki" ascii //weight: 1
        $x_1_5 = {40 77 65 6e 23 25 25 25 36 6e 00 00 26 63 68 74 3d ?? ?? ?? 26 75 69 64 3d ?? ?? ?? 26 6f 73 3d ?? ?? ?? ?? 26 61 76 3d ?? ?? ?? ?? 26 74 6d 3d ?? ?? ?? ?? 26 72 31 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Small_AHY_2147804218_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AHY"
        threat_id = "2147804218"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\window%d.tmp" wide //weight: 1
        $x_1_2 = "id=3013&7788251" wide //weight: 1
        $x_1_3 = "/YoudaoToolbar_tb.tuzi.exe|" wide //weight: 1
        $x_1_4 = "115.238.252.113/seemao_setup.exe|" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_XW_2147804223_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.XW"
        threat_id = "2147804223"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 00 68 00 72 00 74 00 65 00 6e 00 67 00 22 00 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_2 = "iring4u.co.kr/ad79down/stipsetup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_XF_2147804226_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.XF"
        threat_id = "2147804226"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 64 61 74 22 ba 2c 55 70 64 89 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? c7 04 18 5c 73 79 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_ZI_2147804227_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.ZI"
        threat_id = "2147804227"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 76 68 6f 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "/cry/" ascii //weight: 1
        $x_1_3 = {8a 04 0a 2c 7a 88 01 41 4e 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AIT_2147804229_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AIT"
        threat_id = "2147804229"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 2b 8d 4c 24 34 68 ?? 80 40 00 51 e8 ?? ?? 00 00 83 c4 08 85 c0 74 0d 8d 54 24 10 52 56 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {b0 0a c6 44 24 ?? 41 c6 44 24 ?? 65 c6 44 24 ?? 70 c6 44 24 ?? 74 c6 44 24 ?? 3a c6 44 24 ?? 20 c6 44 24 ?? 2f 88 4c 24 04 00 88 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_CAK_2147804234_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.CAK"
        threat_id = "2147804234"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "caogame.3322.org" ascii //weight: 1
        $x_1_2 = "360tray.exe" ascii //weight: 1
        $x_1_3 = "drivers\\fakedisk" ascii //weight: 1
        $x_1_4 = "/c ping 0 & del" ascii //weight: 1
        $x_1_5 = "avNum=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Small_QB_2147804243_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.QB"
        threat_id = "2147804243"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".hkdos.com:800/tongji/count.asp" ascii //weight: 1
        $x_1_2 = ".rouji520.org:81/down.txt" ascii //weight: 1
        $x_1_3 = "baidud page" ascii //weight: 1
        $x_1_4 = "\\hhwn.txt" ascii //weight: 1
        $x_1_5 = {c0 c7 d1 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Small_AGT_2147804244_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AGT"
        threat_id = "2147804244"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".niudoudou.com/web/download/" ascii //weight: 1
        $x_1_2 = "SSLDeskTop" ascii //weight: 1
        $x_1_3 = "IEFrame" ascii //weight: 1
        $x_1_4 = "%sclick_log.asp?ad_url=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AHM_2147804245_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AHM"
        threat_id = "2147804245"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Program Files\\DownTemp\\*.*" ascii //weight: 1
        $x_1_2 = {63 3a 5c 53 61 76 65 54 78 74 61 [0-3] 2e 74 78 74 [0-4] 77 ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c9 ff 33 c0 c6 45 a8 68 c6 45 a9 74 c6 45 aa 74 c6 45 ab 70 c6 45 ac 3a c6 45 ad 2f c6 45 ae 2f c6 45 af 61 c6 45 b0 61 c6 45 b1 61 c6 45 b2 2e c6 45 b3 77 c6 45 b4 64 c6 45 b5 6a c6 45 b6 70 c6 45 b7 71 c6 45 b8 2e c6 45 b9 6e c6 45 ba 65 c6 45 bb 74 c6 45 bc 2f}  //weight: 1, accuracy: High
        $x_1_4 = {88 45 c8 c6 45 c9 74 c6 45 ca 74 c6 45 cb 6e c6 45 cc 65 c6 45 ce 63 88 ?? cf c6 45 d0 44 88 45 d1 [0-4] c6 45 d3 65 c6 45 d4 6c c6 45 d5 69 c6 45 d6 46 c6 45 d7 20 c6 45 d9 61 c6 45 db 67 88 ?? dc c6 45 de 50 88 45 df c6 45 e0 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AHN_2147804246_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AHN"
        threat_id = "2147804246"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ABCD413BA8A2-BEF0-434a-931C-6BADCBE2E81D" wide //weight: 1
        $x_1_2 = "%s\\window%d.tmp" wide //weight: 1
        $x_1_3 = {64 00 31 00 2e 00 64 00 6f 00 77 00 6e 00 78 00 69 00 61 00 2e 00 6e 00 65 00 74 00 2f 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 73 00 2f 00 30 00 ?? ?? ?? ?? ?? ?? 2f 00 38 00 2f 00 49 00 45 00 50 00 72 00 6f 00 74 00 5f 00 32 00 2e 00 31 00 2e 00 ?? ?? ?? ?? ?? ?? 2e 00 31 00 5f 00 33 00 30 00 ?? ?? ?? ?? 5f 00 53 00 65 00 74 00 75 00 70 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {66 83 f9 2d 74 06 66 83 f9 2f 75 28 0f b7 48 02 66 83 f9 6f 74 17 66 83 f9 4f 74 11 66 83 f9 72 75 12 83 c0 04 89 44 24 0c 8b f8 eb 07 8d 70 04 85 f6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AHO_2147804247_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AHO"
        threat_id = "2147804247"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Loader_jieku_977.exe" wide //weight: 1
        $x_1_2 = "haozip_tiny.200629.exe" wide //weight: 1
        $x_1_3 = {64 00 6c 00 2e 00 6b 00 61 00 6e 00 6c 00 ?? ?? ?? ?? ?? ?? ?? ?? 69 00 6e 00 6b 00 2e 00 63 00 6e 00 3a 00 31 00 32 00 ?? ?? ?? ?? ?? ?? 38 00 37 00 2f 00 43 00 50 00 41 00 64 00 6f 00 77 00 6e 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_4 = {11 62 84 76 56 00 42 00 5c 00 a9 8b 7e 76 a6 5e 1c 64 22 7d d3 7e 9c 67 bb 53 07 63 9a 5b 30 57 40 57 5c 00 0b 4e 7d 8f 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 00 4e 74 65 57 59 d2 63 f6 4e 5c 00 0b 4e 7d 8f 89 5b c5 88 ba 4e b6 5b d2 63 f6 4e 5c 00 e5 5d 0b 7a 31 00 2e 00 76 00 62 00 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AHQ_2147804248_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AHQ"
        threat_id = "2147804248"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s?mac=%s&ver=%s&os=WinXP&ip=%s" ascii //weight: 1
        $x_1_2 = "X963A78F0000-DBC9-2d11-707B-BA3TFOS" ascii //weight: 1
        $x_1_3 = {5c 4e 65 74 4d 65 65 ?? 69 6e 67 5c 55 6e 69 6e ?? 74 61 6c 6c 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {69 75 75 71 3b 30 30 [0-3] 2f 79 79 38 2f 6a 6f 30 [0-3] 30 64 70 76 6f 75 2f 62 74 71}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AHR_2147804249_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AHR"
        threat_id = "2147804249"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ddd.ip33033.com" ascii //weight: 1
        $x_1_2 = "NY07HkTJltpvsMa1HmXOGc5lFm+2WURMHckNOW0WHwwf" ascii //weight: 1
        $x_1_3 = "%sOneG%d.exe" ascii //weight: 1
        $x_1_4 = {85 c0 75 69 8d 45 a8 c6 45 f0 43 50 8d 85 a4 fe ff ff 50 8d 45 ac 50 8d 45 f0 53 50 ff 75 b0 c6 45 f1 6f c6 45 f2 6d c6 45 f3 70 c6 45 f4 75 c6 45 f5 74 c6 45 f6 65 c6 45 f7 72 c6 45 f8 4e c6 45 f9 61 c6 45 fa 6d c6 45 fb 65 88 5d fc ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AHS_2147804250_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AHS"
        threat_id = "2147804250"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\setup_klxyx_2.5.14.277_cn.exe" ascii //weight: 1
        $x_1_2 = "119.147.242.75/setup_klxyx_2.5.14.277_cn.exe" ascii //weight: 1
        $x_1_3 = "C:\\setup_klxyx_2.5.14.277_cn.exe" wide //weight: 1
        $x_1_4 = "119.147.242.75/setup_klxyx_2.5.14.277_cn.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AHU_2147804251_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AHU"
        threat_id = "2147804251"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\FlashGameSetup.exe" ascii //weight: 1
        $x_1_2 = "119.147.242.75/FlashGameSetup.exe" ascii //weight: 1
        $x_1_3 = "C:\\FlashGameSetup.exe" wide //weight: 1
        $x_1_4 = "119.147.242.75/FlashGameSetup.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AHV_2147804252_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AHV"
        threat_id = "2147804252"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\kuwo_jm9.exe" ascii //weight: 1
        $x_1_2 = "down.kuwo.cn/mbox/kuwo_jm9.exe" ascii //weight: 1
        $x_1_3 = "C:\\kuwo_jm9.exe" wide //weight: 1
        $x_1_4 = "down.kuwo.cn/mbox/kuwo_jm9.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AHW_2147804253_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AHW"
        threat_id = "2147804253"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 1c 06 32 da 88 18 40 4d 75 f5}  //weight: 1, accuracy: High
        $x_1_2 = {53 75 70 70 65 72 54 4d 00 00 00 00 53 6f 66 74 77 61 72 65 5c 41 44 00}  //weight: 1, accuracy: High
        $x_1_3 = "NefkheU<>8HM==1$8O?0$=>m<$HLJ8$M<LH;;:==90K" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AHX_2147804254_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AHX"
        threat_id = "2147804254"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "qd.netkill.com.cn" ascii //weight: 1
        $x_1_2 = "a}}y3&&xm'gl}b`ee'jfd'jg&y~'}q}" ascii //weight: 1
        $x_1_3 = {6f 73 6f 66 74 5f 6c 6f 63 6b 00 00 25 75 00 00 43 3a 5c 08 00 6d 69 63 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AHZ_2147804255_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AHZ"
        threat_id = "2147804255"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aW5mb3NhcGkuZGxs" ascii //weight: 1
        $x_1_2 = "UHJvZ3JhbUZpbGVz" ascii //weight: 1
        $x_1_3 = "SW50ZXJuZXQgRXhwbG9yZXJ," ascii //weight: 1
        $x_1_4 = "IiBHT1RPIERFTEFQUCBFTFNFIEdPVE8gREVMQkFU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AHZ_2147804255_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AHZ"
        threat_id = "2147804255"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TcwnFA2XjlWgUo8V" wide //weight: 1
        $x_1_2 = "fbInBe12/FFy/hK8wLoEtJIUWRd1WFXlelGrpWbYjPAzv+A1tC" wide //weight: 1
        $x_1_3 = "+9b/fBsxnVKd3pqL" wide //weight: 1
        $x_1_4 = "jInDb/YTFfoFq1bhXdFPhLdW0YKOeF0K1o0Xnx8NKZ3BOQJF" wide //weight: 1
        $x_1_5 = ".fotofolia01.net/file.aspx?file=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AIA_2147804256_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AIA"
        threat_id = "2147804256"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s\\Google%c%c.exe" ascii //weight: 1
        $x_1_2 = "!@#$r#@%@#$@#" ascii //weight: 1
        $x_1_3 = {83 c9 ff 33 c0 c6 [0-3] 44 c6 [0-3] 65 c6 [0-3] 6e c6 [0-3] 67}  //weight: 1, accuracy: Low
        $x_1_4 = {b0 0a c6 44 24 1c 41 c6 44 24 1f 65 c6 44 24 20 70 c6 44 24 21 74 c6 44 24 22 3a c6 44 24 23 20 c6 44 24 25 2f 88 4c 24 27}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AID_2147804257_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AID"
        threat_id = "2147804257"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c0 ea 04 08 10 40 c0 e1 04 88 08 ba 02 00 00 00 eb 19}  //weight: 1, accuracy: High
        $x_1_2 = {c0 ea 02 08 10 40 c0 e1 06 88 08 ba 03 00 00 00 eb 05 08 08}  //weight: 1, accuracy: High
        $x_1_3 = "%s\\app%d.tmp" wide //weight: 1
        $x_1_4 = "ookefdsafdrinfdafdsaohdsafdsalnfdlsafdsa" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AIJ_2147804258_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AIJ"
        threat_id = "2147804258"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 e0 60 00 00 83 f9 04 72 1a 81 f9 82 01 00 00 73 08 81 f9 3c 01 00 00 77 02 31 03 83 c3 04 83 e9 04 eb e1}  //weight: 1, accuracy: High
        $x_1_2 = "heiying4" ascii //weight: 1
        $x_1_3 = ".fnsorfnfgsajr.com/test.htm" ascii //weight: 1
        $x_1_4 = "//home.51.com/?u=lichao3596&c=d" ascii //weight: 1
        $x_1_5 = "?u=testdown&c=diary&a=getdataview&id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_ZZS_2147804260_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.ZZS"
        threat_id = "2147804260"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 0d 8b d8 ff d7 ff d6 6a 0d 8b e8 ff d7 ff d6 8b c8 8b c3 6a 64 99}  //weight: 2, accuracy: High
        $x_1_2 = "f=__Lqir1gdw" wide //weight: 1
        $x_1_3 = "Qixi55 Video Community" wide //weight: 1
        $x_1_4 = "vip.9bic.net:883/over.html" wide //weight: 1
        $x_1_5 = {57 00 69 00 6e 00 53 00 65 00 72 00 2e 00 65 00 78 00 65 00 22 00 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_ZYN_2147804261_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.ZYN"
        threat_id = "2147804261"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 00 a4 93 d6 50 ff 15 ?? ?? ?? ?? 8b 45 f0 c6 45 fc 04 3b c3 74 06}  //weight: 1, accuracy: Low
        $x_1_2 = "%s\\1229.tmp" ascii //weight: 1
        $x_1_3 = {5c 56 4c 2e 69 6e 69 0a 00 43 3a 5c 57 49 4e 44 4f 57 53}  //weight: 1, accuracy: Low
        $x_1_4 = "jj.765321.info:3218/sms/xxx02.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_ZZR_2147804262_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.ZZR"
        threat_id = "2147804262"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ChkAndRun Begin" ascii //weight: 1
        $x_1_2 = "6469616E78696E2E64616F68616E67313233342E636F6D" ascii //weight: 1
        $x_1_3 = "687474703A2F2F646174612E64616F68616E67313233342E636F6D2F646174612E747874" ascii //weight: 1
        $x_1_4 = "687474703A2F2F6469616E78696E2E64616F68616E67313233342E636F6D2F6370612E68746D3F" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_ZZH_2147804265_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.ZZH"
        threat_id = "2147804265"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b0 63 b1 0d 88 44 24 19 88 44 24 1a b0 2a 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? b0 0a c6 44 24 1c 41 c6 44 24 1f 65 c6 44 24 20 70 c6 44 24 21 74 c6 44 24 22 3a c6 44 24 23 20 c6 44 24 25 2f 88 4c 24 27}  //weight: 2, accuracy: Low
        $x_2_2 = "F:\\Program Files\\" ascii //weight: 2
        $x_1_3 = "/ime.sogou.com/dl/sogou_pinyin_mini_5302.exe" ascii //weight: 1
        $x_1_4 = "/download.uusee.com/pop2/pc/UUSee_SEO1_Setup_10.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Small_ZZJ_2147804266_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.ZZJ"
        threat_id = "2147804266"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MPGoodStatus" ascii //weight: 1
        $x_1_2 = "%APPDATA%\\cwintool.exe" ascii //weight: 1
        $x_1_3 = "{64EE0D45-EC9B-4D8C-99D5-652B87657F54}" wide //weight: 1
        $x_1_4 = "/search.cwintool.com/search.asp?pid=%s&mac=%s&qy=" ascii //weight: 1
        $x_1_5 = {c1 a4 bb f3 c0 fb c0 b8 b7 ce 20 bb e8 c1 a6 b5 c7 be fa bd c0 b4 cf b4 d9 00 00 00 c8 ae c0 ce}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_PAA_2147804286_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.PAA!MTB"
        threat_id = "2147804286"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SYSTEM\\CurrentControlSet\\Services\\WinSysNetwork" ascii //weight: 1
        $x_1_2 = "\\\\.\\PHYSICALDRIVE" ascii //weight: 1
        $x_1_3 = "\\localsoas.dat" ascii //weight: 1
        $x_1_4 = "ShellExecuteA" ascii //weight: 1
        $x_1_5 = "winlogon.exe" ascii //weight: 1
        $x_1_6 = "HOST Value" ascii //weight: 1
        $x_1_7 = "DNS Value" ascii //weight: 1
        $x_1_8 = "IP Value" ascii //weight: 1
        $x_1_9 = "SysScnet" ascii //weight: 1
        $x_1_10 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_11 = "GetCurrentProcess" ascii //weight: 1
        $x_1_12 = "Process32First" ascii //weight: 1
        $x_1_13 = "Process32Next" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_AM_2147804298_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.AM!MSR"
        threat_id = "2147804298"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 33 db 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 80 b1 ?? ?? ?? ?? ?? 41 8b d9 3b d8 74 ?? eb f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_EG_2147804300_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.EG!MTB"
        threat_id = "2147804300"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 c0 39 44 24 0c 76 15 8b 4c 24 08 8a 0c 08 8b 54 24 04 88 0c 10 40 3b 44 24 0c 72 eb c2 0c 00 55 8b ec 81 ec 38 08}  //weight: 10, accuracy: High
        $x_3_2 = "ShellExecuteW" ascii //weight: 3
        $x_3_3 = "GetTempPathWFileSize" ascii //weight: 3
        $x_3_4 = "Updates downloader" ascii //weight: 3
        $x_3_5 = "InternetConnectW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_MA_2147836829_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.MA!MTB"
        threat_id = "2147836829"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 bc 6a 0c 2b 45 b8 59 99 f7 f9 3b f8 0f 83 ?? ?? ?? ?? 57 8d 4d b4 e8 ?? ?? ?? ?? 50 8d 4d e4 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 04 5e 8d 85 34 ff ff ff 56 53 50 8d 4d e4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_MB_2147842621_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.MB!MTB"
        threat_id = "2147842621"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 db 88 44 24 10 b2 78 88 4c 24 15 88 44 24 16 88 4c 24 17 88 44 24 19 88 44 24 1b b9 3d 00 00 00 33 c0 8d 7c 24 1d 88 54 24 11 c6 44 24 12 70 c6 44 24 13 6c c6 44 24 14 6f c6 44 24 18 2e 88 54 24 1a 88 5c 24 1c}  //weight: 5, accuracy: High
        $x_1_2 = "CreateProcessA" ascii //weight: 1
        $x_1_3 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_CAFO_2147846637_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.CAFO!MTB"
        threat_id = "2147846637"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 ab 66 ab bf ?? ?? ?? ?? 83 c9 ff 33 c0 c6 44 24 0c ?? f2 ae f7 d1 2b f9 c6 44 24 10 ?? 8b c1 8b f7 8b fa c6 44 24 14 ?? c1 e9 02 f3 a5 8b c8 33 c0 83 e1 03 c6 44 24 15 00 f3 a4 8d 7c 24 0c 83 c9 ff f2 ae}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_ARAQ_2147850736_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.ARAQ!MTB"
        threat_id = "2147850736"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b c1 6a 03 99 5f f7 ff 80 c2 02 00 91 28 41 40 00 41 3b ce 7c ea}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_B_2147889336_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.B!MTB"
        threat_id = "2147889336"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be c9 c1 e0 04 03 c1 8b c8 42 81 e1 00 00 00 f0 74 07 8b f1 c1 ee 18 33 c6 f7 d1 23 c1 8a 0a 84 c9 75 dc}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 fc 8b 14 87 03 d6 ?? ?? ?? ?? ?? 3b 45 08 74 11 ff 45 fc 8b 45 fc 3b 45 f8 72 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_C_2147889337_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.C!MTB"
        threat_id = "2147889337"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 8b ca 81 e1 03 00 00 80 79 05 49 83 c9 fc 41 0f b6 0c 31 0f b6 7c 16 04 33 cf 88 0c 02 75 e0}  //weight: 1, accuracy: High
        $x_1_2 = {33 d2 6a 1a 5f f7 f7 80 c2 61 88 14 1e 46 3b f1 7c e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_SK_2147900352_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.SK!MTB"
        threat_id = "2147900352"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 ec 8b 55 10 8b 45 f8 89 02 8b 4d f8 c1 e9 09 8b 45 f8 33 d2 be 00 02 00 00 f7 f6 f7 da 1b d2 f7 da 03 ca c1 e1 09 89 4d f4 8b 55 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Small_ASM_2147927959_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Small.ASM!MTB"
        threat_id = "2147927959"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {04 e2 23 03 00 24 5a 4c 36 4d d3 34 3e 32 26 1a 90 23 69 9a a6 59 a4 b2 c0}  //weight: 1, accuracy: High
        $x_2_2 = "freedataverification.com" wide //weight: 2
        $x_3_3 = "sellmakers.com" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

