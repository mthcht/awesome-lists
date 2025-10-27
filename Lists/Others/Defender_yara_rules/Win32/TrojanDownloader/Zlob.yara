rule TrojanDownloader_Win32_Zlob_JN_5900_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.JN"
        threat_id = "5900"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 07 32 18 8b 06 88 1c 01 41 83 f9 0b 72 ed}  //weight: 1, accuracy: High
        $x_1_2 = {10 75 2b 09 1d ?? ?? ?? 10 83 65 fc 00 8d 45 ?? 50 8d 45 ?? 50 b9 ?? ?? ?? 10 e8 ?? ?? ff ff 68 ?? ?? ?? 10 e8 ?? ?? ?? 00 83 4d fc ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_16998_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob"
        threat_id = "16998"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://z1.nf-2.net/512.txt" ascii //weight: 1
        $x_1_2 = "%s\\Temp\\edit.jpg" ascii //weight: 1
        $x_1_3 = "%SystemRoot%\\System32\\dllcache\\explorer.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_16998_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob"
        threat_id = "16998"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 64 72 49 6e 73 75 72 61 6e 63 65 45 76 65 6e 74 45 78 00}  //weight: 1, accuracy: High
        $x_1_2 = {4c 6f 61 64 65 72 53 74 61 72 74 65 64 5f 25 58 00}  //weight: 1, accuracy: High
        $x_1_3 = "/php/loader3/download.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_16998_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob"
        threat_id = "16998"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IESPlugin" ascii //weight: 1
        $x_1_2 = "ToolbarWindow32" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Internet Explorer\\Toolbar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_16998_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob"
        threat_id = "16998"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 41 43 2e 56 69 64 65 6f 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 6c 65 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = "elr" wide //weight: 1
        $x_1_4 = {46 69 6e 64 43 6c 6f 73 65 55 72 6c 43 61 63 68 65 00 00 00 46 69 6e 64 46 69 72 73 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 41 00}  //weight: 1, accuracy: High
        $x_1_5 = {47 65 74 46 69 6c 65 56 65 72 73 69 6f 6e 49 6e 66 6f 41 00 47 65 74 46 69 6c 65 56 65 72 73 69 6f 6e 49 6e 66 6f 53 69 7a 65 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Zlob_16998_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob"
        threat_id = "16998"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "420"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Attention!" ascii //weight: 100
        $x_100_2 = "Removable" ascii //weight: 100
        $x_100_3 = "reboot your computer" ascii //weight: 100
        $x_50_4 = "createtoolhelp32snapshot" ascii //weight: 50
        $x_50_5 = "del " ascii //weight: 50
        $x_10_6 = "Media-Codec" ascii //weight: 10
        $x_10_7 = ".Chl" ascii //weight: 10
        $x_10_8 = "video" ascii //weight: 10
        $n_500_9 = "SOFTWARE\\GREATIS\\REGRUN2\\" ascii //weight: -500
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((3 of ($x_100_*) and 2 of ($x_50_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_16998_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob"
        threat_id = "16998"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56}  //weight: 1, accuracy: High
        $x_1_2 = "IESPlugin" ascii //weight: 1
        $x_2_3 = {56 68 04 01 00 00 6a 00 be ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? ff 74 24 14 e8 ?? ?? ?? ?? 83 c4 10 48 78 1a 8b 4c 24 08 2b ce 8a 94 01 ?? ?? ?? ?? 32 54 24 0c 48 88 90 ?? ?? ?? ?? 79 ec 8b c6 5e c3}  //weight: 2, accuracy: Low
        $x_2_4 = {8a 08 40 84 c9 75 f9 2b c2 48 78 1c 8a 4c 24 ?? 81 ?? ?? ?? ?? ?? 8a 94 ?? ?? ?? ?? ?? 32 d1 48 88 90 ?? ?? ?? ?? 79 ee}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_16998_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob"
        threat_id = "16998"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 75 14 68 2c 01 00 00 6a 08 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 56 8b 74 24 08 8a 16 84 d2 a3 ?? ?? ?? ?? 8b c8 74 10 2b f0 32 54 24 0c 88 11 41 8a 14 0e 84 d2 75 f2 c6 01 00 5e c3}  //weight: 1, accuracy: Low
        $x_1_2 = {46 69 6e 64 43 6c 6f 73 65 55 72 6c 43 61 63 68 65 00 00 00 46 69 6e 64 46 69 72 73 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 41 00}  //weight: 1, accuracy: High
        $x_1_3 = {47 65 74 46 69 6c 65 56 65 72 73 69 6f 6e 49 6e 66 6f 41 00 47 65 74 46 69 6c 65 56 65 72 73 69 6f 6e 49 6e 66 6f 53 69 7a 65 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_16998_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob"
        threat_id = "16998"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "611"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "InternetOpenUrlA" ascii //weight: 100
        $x_100_2 = "ShellExecuteA" ascii //weight: 100
        $x_100_3 = "Shell_NotifyIconA" ascii //weight: 100
        $x_100_4 = "DisplayIcon" ascii //weight: 100
        $x_100_5 = {6c 6f 61 64 00}  //weight: 100, accuracy: High
        $x_100_6 = {61 6c 6c 65 72 74 00}  //weight: 100, accuracy: High
        $x_10_7 = {61 6e 61 6c [0-10] 6d 6f 6e 73 74 65 72 73 2e 63 6f 6d}  //weight: 10, accuracy: Low
        $x_1_8 = "system on computer is damaged." ascii //weight: 1
        $x_1_9 = "Virus" ascii //weight: 1
        $x_1_10 = "infected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_16998_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob"
        threat_id = "16998"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "611"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "InternetOpenUrlA" ascii //weight: 100
        $x_100_2 = "ShellExecuteA" ascii //weight: 100
        $x_100_3 = "Shell_NotifyIconA" ascii //weight: 100
        $x_100_4 = "DisplayIcon" ascii //weight: 100
        $x_100_5 = {6c 6f 61 64 00}  //weight: 100, accuracy: High
        $x_100_6 = {61 6c 6c 65 72 74 00}  //weight: 100, accuracy: High
        $x_10_7 = "tmxxxh.dll" ascii //weight: 10
        $x_10_8 = "blowjob." ascii //weight: 10
        $x_1_9 = "system on computer is damaged." ascii //weight: 1
        $x_1_10 = "Virus" ascii //weight: 1
        $x_1_11 = "infected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((6 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_16998_9
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob"
        threat_id = "16998"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ser helper ob" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_3 = "Start Page" ascii //weight: 1
        $x_2_4 = {56 68 04 01 00 00 6a 00 be ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? ff 74 24 14 e8 ?? ?? ?? ?? 83 c4 10 48 78 1a 8b 4c 24 08 2b ce 8a 94 01 ?? ?? ?? ?? 32 54 24 0c 48 88 90 ?? ?? ?? ?? 79 ec 8b c6 5e c3}  //weight: 2, accuracy: Low
        $x_1_5 = {59 59 68 04 01 00 00 8d 44 24 14 50 6a ff 68 ?? 00 00 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_16998_10
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob"
        threat_id = "16998"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "151"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 8b 74 24 08 a3 ?? ?? ?? ?? 8a 16 84 d2 8b c8 74 10 2b f0 32 54 24 0c 88 11 41 8a 14 0e 84 d2 75 f2}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c8 b2 b4 2b d8 90 80 f2 c0 88 11 8a 54 0b 01 41 84 d2 75 f2}  //weight: 1, accuracy: High
        $x_10_3 = ".php?qq=%s" ascii //weight: 10
        $x_10_4 = "res://%s" wide //weight: 10
        $x_10_5 = "arch.msn.com/res" wide //weight: 10
        $x_10_6 = "ll/http_4" wide //weight: 10
        $x_10_7 = "/dnse" wide //weight: 10
        $x_100_8 = "GetSystemDirectoryW" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_16998_11
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob"
        threat_id = "16998"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MyBGTransfer_1" wide //weight: 1
        $x_1_2 = "\\PC Drive Tool" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Ultimate Fixer" ascii //weight: 1
        $x_1_4 = "C:\\WINDOWS\\sysdx.dll" wide //weight: 1
        $x_1_5 = "C:\\WINDOWS\\msvb.dll" wide //weight: 1
        $x_10_6 = "ShellServiceObjectDelayLoad" wide //weight: 10
        $x_10_7 = {48 54 54 50 43 6c 69 65 6e 74 00}  //weight: 10, accuracy: High
        $x_10_8 = "software\\products" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_16998_12
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob"
        threat_id = "16998"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "640"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "winexec" ascii //weight: 100
        $x_100_2 = "writefile" ascii //weight: 100
        $x_100_3 = "SeShutdownPrivilege" ascii //weight: 100
        $x_100_4 = "yttruov" ascii //weight: 100
        $x_10_5 = "virus protection" ascii //weight: 10
        $x_10_6 = "antivirus software" ascii //weight: 10
        $x_20_7 = "antispayware software" ascii //weight: 20
        $x_20_8 = "on your system Windows Defender." ascii //weight: 20
        $x_20_9 = {25 73 20 2f 64 65 6c 00}  //weight: 20, accuracy: High
        $x_10_10 = {25 73 20 2f 64 65 6c 32 00}  //weight: 10, accuracy: High
        $x_10_11 = {2f 63 20 64 65 6c [0-5] 25 73 [0-5] 3e 3e [0-5] 6e 75 6c 6c 00}  //weight: 10, accuracy: Low
        $x_100_12 = {6a 00 6a 04 6a 02 6a 00 6a 01 68 00 00 00 40 68 ?? ?? 40 00 e8 ?? ?? ?? ?? 83 f8 ff 75 0c}  //weight: 100, accuracy: Low
        $x_100_13 = {80 3e 00 74 05 30 06 46 eb f6 c9 c2 08 00}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_100_*) and 4 of ($x_10_*))) or
            ((6 of ($x_100_*) and 1 of ($x_20_*) and 2 of ($x_10_*))) or
            ((6 of ($x_100_*) and 2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_16998_13
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob"
        threat_id = "16998"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "46"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{41F6170D-6AF8-4188-8D92-9DDAB3C71A78}" ascii //weight: 1
        $x_1_2 = "{23ED2206-856D-461A-BBCF-1C2466AC5AE3}" ascii //weight: 1
        $x_10_3 = {53 54 41 52 54 45 52 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 00}  //weight: 10, accuracy: High
        $x_10_4 = "software\\microsoft\\internet explorer\\toolbar\\webbrowser" ascii //weight: 10
        $x_10_5 = "createtoolhelp32snapshot" ascii //weight: 10
        $x_10_6 = "process32next" ascii //weight: 10
        $x_5_7 = "http" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_16998_14
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob"
        threat_id = "16998"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "86"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e3 0e 3a 28 c1 2c ab 45 82 07 b1 d7 b6 9c 7f 83}  //weight: 1, accuracy: High
        $x_1_2 = {cc 7b 8d 20 57 98 9e 4c 82 3b d0 4e 72 49 0a 67}  //weight: 1, accuracy: High
        $x_1_3 = {13 cf 12 af 3b dc 1c 46 b5 ce 89 48 06 c1 53 03}  //weight: 1, accuracy: High
        $x_1_4 = {4f 81 cf f4 0f 97 5d 40 a4 2c 0c e0 6e b9 73 73}  //weight: 1, accuracy: High
        $x_1_5 = {a3 8a 41 88 f5 16 c2 4f a9 d8 90 b1 26 6d f8 41}  //weight: 1, accuracy: High
        $x_1_6 = {c2 0c b7 3c 3f 30 6c 4a 82 4d 01 3a e8 cf db 6b}  //weight: 1, accuracy: High
        $x_1_7 = {fd 94 5a 69 d0 15 d7 4e 8f 40 d2 b3 bd c4 2c 15}  //weight: 1, accuracy: High
        $x_1_8 = {07 51 d8 ac f9 9c 9e 4c b0 b7 39 94 0a 00 17 c0}  //weight: 1, accuracy: High
        $x_1_9 = {3b b1 cb 31 4d 24 44 4c ae d5 dc ad 70 f6 62 81}  //weight: 1, accuracy: High
        $x_1_10 = {a4 a4 8f 42 ec c8 7c 42 85 de 11 c8 0f 67 89 3a}  //weight: 1, accuracy: High
        $x_1_11 = {d1 04 bd ec 33 11 80 44 8a 8c bc 9f dd 54 d6 c1}  //weight: 1, accuracy: High
        $x_1_12 = {16 bc dc 3a fa 19 59 4c 9c 22 e1 7c 71 b5 fd 7a}  //weight: 1, accuracy: High
        $x_1_13 = {bd db f4 c4 4c 4a 40 4b 97 da 2f e0 6d bb 29 01}  //weight: 1, accuracy: High
        $x_1_14 = {08 2b 27 15 fe f6 71 4e b2 bd a5 9a d2 3e be 3c}  //weight: 1, accuracy: High
        $x_1_15 = {90 98 f7 05 a6 cf 53 4d 87 bc 2f 39 0d a6 64 5e}  //weight: 1, accuracy: High
        $x_1_16 = {02 4f c5 47 28 1b f1 45 ae 46 b5 cd fb 6e 79 26}  //weight: 1, accuracy: High
        $x_1_17 = {50 7d 8b 21 37 bc a8 4f a5 7f 6e 8d e6 92 bd 79}  //weight: 1, accuracy: High
        $x_50_18 = "BhoNew.DLL" ascii //weight: 50
        $x_10_19 = "EncodePointer" ascii //weight: 10
        $x_10_20 = "InternetAttemptConnect" ascii //weight: 10
        $x_10_21 = "IsDebuggerPresent" ascii //weight: 10
        $x_5_22 = "explorer.exe" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 2 of ($x_10_*) and 16 of ($x_1_*))) or
            ((1 of ($x_50_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 11 of ($x_1_*))) or
            ((1 of ($x_50_*) and 3 of ($x_10_*) and 6 of ($x_1_*))) or
            ((1 of ($x_50_*) and 3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_16998_15
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob"
        threat_id = "16998"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "16"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "91"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e3 0e 3a 28 c1 2c ab 45 82 07 b1 d7 b6 9c 7f 83}  //weight: 1, accuracy: High
        $x_1_2 = {cc 7b 8d 20 57 98 9e 4c 82 3b d0 4e 72 49 0a 67}  //weight: 1, accuracy: High
        $x_1_3 = {13 cf 12 af 3b dc 1c 46 b5 ce 89 48 06 c1 53 03}  //weight: 1, accuracy: High
        $x_1_4 = {4f 81 cf f4 0f 97 5d 40 a4 2c 0c e0 6e b9 73 73}  //weight: 1, accuracy: High
        $x_1_5 = {a3 8a 41 88 f5 16 c2 4f a9 d8 90 b1 26 6d f8 41}  //weight: 1, accuracy: High
        $x_1_6 = {c2 0c b7 3c 3f 30 6c 4a 82 4d 01 3a e8 cf db 6b}  //weight: 1, accuracy: High
        $x_1_7 = {fd 94 5a 69 d0 15 d7 4e 8f 40 d2 b3 bd c4 2c 15}  //weight: 1, accuracy: High
        $x_1_8 = {07 51 d8 ac f9 9c 9e 4c b0 b7 39 94 0a 00 17 c0}  //weight: 1, accuracy: High
        $x_1_9 = {3b b1 cb 31 4d 24 44 4c ae d5 dc ad 70 f6 62 81}  //weight: 1, accuracy: High
        $x_1_10 = {a4 a4 8f 42 ec c8 7c 42 85 de 11 c8 0f 67 89 3a}  //weight: 1, accuracy: High
        $x_1_11 = {d1 04 bd ec 33 11 80 44 8a 8c bc 9f dd 54 d6 c1}  //weight: 1, accuracy: High
        $x_1_12 = {16 bc dc 3a fa 19 59 4c 9c 22 e1 7c 71 b5 fd 7a}  //weight: 1, accuracy: High
        $x_1_13 = {bd db f4 c4 4c 4a 40 4b 97 da 2f e0 6d bb 29 01}  //weight: 1, accuracy: High
        $x_1_14 = {08 2b 27 15 fe f6 71 4e b2 bd a5 9a d2 3e be 3c}  //weight: 1, accuracy: High
        $x_1_15 = {90 98 f7 05 a6 cf 53 4d 87 bc 2f 39 0d a6 64 5e}  //weight: 1, accuracy: High
        $x_1_16 = {02 4f c5 47 28 1b f1 45 ae 46 b5 cd fb 6e 79 26}  //weight: 1, accuracy: High
        $x_1_17 = {50 7d 8b 21 37 bc a8 4f a5 7f 6e 8d e6 92 bd 79}  //weight: 1, accuracy: High
        $x_50_18 = "BhoNew.DLL" ascii //weight: 50
        $x_10_19 = "search.msn.com/dnserror.aspx" wide //weight: 10
        $x_10_20 = "EncodePointer" ascii //weight: 10
        $x_10_21 = "InternetAttemptConnect" ascii //weight: 10
        $x_10_22 = "IsDebuggerPresent" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 3 of ($x_10_*) and 11 of ($x_1_*))) or
            ((1 of ($x_50_*) and 4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_I_70997_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.I"
        threat_id = "70997"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 24 67 6f 2d 61 76}  //weight: 1, accuracy: High
        $x_1_2 = "Addr5sLoadL" ascii //weight: 1
        $x_1_3 = {73 65 48 61 6e 64 ?? 48 74 74 70}  //weight: 1, accuracy: Low
        $x_1_4 = "ast!)garbageworldb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_88832_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!dll"
        threat_id = "88832"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 84 24 5c 05 00 00 68 ?? ?? 00 10 50 ff 15 ?? ?? 00 10 8d 44 24 28 50 c6 44 24 23 01 e8 ?? ?? ff ff 83 c4 10}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 94 24 48 04 00 00 68 ?? ?? 00 10 52 ff 15 ?? ?? 00 10 8d 44 24 24 50 c6 44 24 23 01 e8 ?? ?? ff ff 83 c4}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 84 24 58 05 00 00 68 ?? ?? 00 10 50 ff 15 ?? ?? 00 10 8d 44 24 28 50 c6 44 24 23 01 e8 ?? ?? ff ff 83 c4}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 84 24 60 05 00 00 68 ?? ?? 00 10 50 ff 15 ?? ?? 00 10 8d 44 24 2c 50 c6 44 24 23 01 e8 ?? ?? ff ff 83 c4}  //weight: 1, accuracy: Low
        $x_1_5 = {8d 8c 24 50 04 00 00 68 ?? ?? 00 10 51 ff 15 ?? ?? 00 10 8d 54 24 24 52 c6 44 24 23 01 e8 ?? ?? ff ff 83 c4}  //weight: 1, accuracy: Low
        $x_1_6 = {8d 8c 24 54 04 00 00 68 ?? ?? 00 10 51 ff 15 ?? ?? 00 10 8d 54 24 24 52 c6 44 24 23 01 e8 ?? ?? ff ff 83 c4}  //weight: 1, accuracy: Low
        $x_1_7 = {8d 94 24 4c 04 00 00 68 ?? ?? 00 10 52 ff 15 ?? ?? 00 10 8d 44 24 24 50 c6 44 24 23 01 e8 ?? ?? ff ff 83 c4}  //weight: 1, accuracy: Low
        $x_1_8 = {74 2a ff 75 f8 8b 35 ?? ?? 00 10 bf ?? ?? 00 10 8d 85 e4 ?? ff ff 57 50 ff d6 ff 75 ?? 8d 85 ?? ?? ff ff 57 50 ff d6 83 c4}  //weight: 1, accuracy: Low
        $x_1_9 = {8d 85 b8 f4 ff ff 68 ?? ?? 00 10 50 ff 15 ?? ?? 00 10 8d 45 ec 50 c6 45 ff 01 e8 ?? ?? ff ff 83 65 f4 00 83 c4 10 85 c0 89 45 ?? 0f 8e}  //weight: 1, accuracy: Low
        $x_1_10 = {8d 85 bc f4 ff ff 68 ?? ?? 00 10 50 ff 15 ?? ?? 00 10 8d 45 f0 50 c6 45 ff 01 e8 ?? ?? ff ff 83 65 f8 00 83 c4 10 85 c0 89 45 ?? 0f 8e}  //weight: 1, accuracy: Low
        $x_1_11 = {50 51 ff 15 ?? ?? 00 10 ?? 8d 94 24 54 07 00 00 68 ?? ?? 00 10 52 ff 15}  //weight: 1, accuracy: Low
        $x_1_12 = {ff 74 24 18 8d 84 24 5c 07 00 00 68 ?? ?? 00 10 50 ff 15 ?? ?? 00 10 8d 44 24 2c 50 c6 44 24 23 01 e8}  //weight: 1, accuracy: Low
        $x_1_13 = {8b 54 24 14 52 8d 84 24 58 07 00 00 68 ?? ?? 00 10 50 ff 15 ?? ?? 00 10 8d 4c 24 28 51 c6 44 24 23 01 e8}  //weight: 1, accuracy: Low
        $x_1_14 = {8d 4c 24 28 51 50 c6 44 24 30 47 c6 44 24 31 45 c6 44 24 32 54 88 5c 24 33 ff 15 ?? ?? 00 10}  //weight: 1, accuracy: Low
        $x_1_15 = {50 c6 44 24 28 47 c6 44 24 29 45 c6 44 24 2a 54 c6 44 24 2b 00 ff 15 ?? ?? 00 10}  //weight: 1, accuracy: Low
        $x_1_16 = {50 c6 44 24 30 47 c6 44 24 31 45 c6 44 24 32 54 c6 44 24 33 00 ff 15 ?? ?? 00 10}  //weight: 1, accuracy: Low
        $x_1_17 = {50 c6 85 f8 fe ff ff 47 c6 85 f9 fe ff ff 45 c6 85 fa fe ff ff 54 88 9d fb fe ff ff ff 15 ?? ?? 00 10}  //weight: 1, accuracy: Low
        $x_1_18 = {50 c6 85 fc fe ff ff 47 c6 85 fd fe ff ff 45 c6 85 fe fe ff ff 54 88 9d ff fe ff ff ff 15 ?? ?? 00 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Zlob_C_109265_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!C"
        threat_id = "109265"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ser helper ob" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_3 = "Start Page" ascii //weight: 1
        $x_1_4 = {58 54 52 45 4d 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00}  //weight: 1, accuracy: High
        $x_1_5 = {42 4c 4f 42 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_2_6 = {56 68 04 01 00 00 6a 00 be ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? ff 74 24 14 e8 ?? ?? ?? ?? 83 c4 10 48 78 1a 8b 4c 24 08 2b ce 8a 94 01 ?? ?? ?? ?? 32 54 24 0c 48 88 90 ?? ?? ?? ?? 79 ec 8b c6 5e c3}  //weight: 2, accuracy: Low
        $x_2_7 = {8a 08 40 84 c9 75 f9 2b c2 48 78 1c 8a 4c 24 ?? 81 ?? ?? ?? ?? ?? 8a 94 ?? ?? ?? ?? ?? 32 d1 48 88 90 ?? ?? ?? ?? 79 ee}  //weight: 2, accuracy: Low
        $x_1_8 = {59 59 68 04 01 00 00 8d 44 24 14 50 6a ff 68 ?? 00 00 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_D_109266_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!D"
        threat_id = "109266"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {33 00 00 00 75 73 65 72 00 00 00 00 68 72 6e 25 64 2e 63 6d 64 00 00 00 7a 75 00 00 22 25 73 22}  //weight: 3, accuracy: High
        $x_3_2 = {20 47 6f 00 69 73 74 20 22 25 73 22 00 00 00 00 20 45 78 00 49 66 00 00 65 6c 20 22 25 73 22 0d}  //weight: 3, accuracy: High
        $x_3_3 = {64 69 00 00 72 65 5c 57 65 62 4d 00 53 6f 66 74 77 61 00 00 77 65 72 00 61 56 69 65 00 00 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_ZWC_109655_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ZWC"
        threat_id = "109655"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "go.php?step=%d" wide //weight: 1
        $x_1_2 = {7d 00 00 65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72}  //weight: 1, accuracy: High
        $x_1_3 = {49 54 42 61 72 4c 61 79 6f 75 74 00 53 6f 66 74}  //weight: 1, accuracy: High
        $x_1_4 = {49 73 6f 6c 61 74 69 6f 6e 41 77 61 72 65 43 6c 65 61 6e 75 70 0a 00}  //weight: 1, accuracy: High
        $x_1_5 = "://aguardtool" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Zlob_L_112050_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!L"
        threat_id = "112050"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "36"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MyBGTransfer_1" wide //weight: 2
        $x_2_2 = "\\PC Drive Tool" ascii //weight: 2
        $x_2_3 = "SOFTWARE\\Ultimate Fixer" ascii //weight: 2
        $x_1_4 = "C:\\WINDOWS\\sysdx.dll" wide //weight: 1
        $x_1_5 = "C:\\WINDOWS\\msvb.dll" wide //weight: 1
        $x_1_6 = "C:\\WINDOWS\\hstsys.dll" ascii //weight: 1
        $x_1_7 = "C:\\WINDOWS\\hostctrl.dll" ascii //weight: 1
        $x_10_8 = "ShellServiceObjectDelayLoad" wide //weight: 10
        $x_10_9 = {48 54 54 50 43 6c 69 65 6e 74 00}  //weight: 10, accuracy: High
        $x_10_10 = "software\\products" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_M_112097_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!M"
        threat_id = "112097"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 42 c4 74 2d 2a 99 4a b0 0b cc a3 91 23 49 f3}  //weight: 1, accuracy: High
        $x_1_2 = {03 bb a3 d3 bf 15 5b 4c a0 1a 4f 37 6c 62 cb f3}  //weight: 1, accuracy: High
        $x_50_3 = {42 68 6f 4e 65 77 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00}  //weight: 50, accuracy: High
        $x_10_4 = "EncodePointer" ascii //weight: 10
        $x_10_5 = "IsDebuggerPresent" ascii //weight: 10
        $x_10_6 = "explorer.exe" wide //weight: 10
        $x_10_7 = "GetProcessWindowStation" ascii //weight: 10
        $x_10_8 = "GetActiveWindow" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_M_112097_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!M"
        threat_id = "112097"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "86"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e3 0e 3a 28 c1 2c ab 45 82 07 b1 d7 b6 9c 7f 83}  //weight: 1, accuracy: High
        $x_1_2 = {cc 7b 8d 20 57 98 9e 4c 82 3b d0 4e 72 49 0a 67}  //weight: 1, accuracy: High
        $x_1_3 = {13 cf 12 af 3b dc 1c 46 b5 ce 89 48 06 c1 53 03}  //weight: 1, accuracy: High
        $x_1_4 = {4f 81 cf f4 0f 97 5d 40 a4 2c 0c e0 6e b9 73 73}  //weight: 1, accuracy: High
        $x_1_5 = {a3 8a 41 88 f5 16 c2 4f a9 d8 90 b1 26 6d f8 41}  //weight: 1, accuracy: High
        $x_1_6 = {c2 0c b7 3c 3f 30 6c 4a 82 4d 01 3a e8 cf db 6b}  //weight: 1, accuracy: High
        $x_1_7 = {fd 94 5a 69 d0 15 d7 4e 8f 40 d2 b3 bd c4 2c 15}  //weight: 1, accuracy: High
        $x_1_8 = {07 51 d8 ac f9 9c 9e 4c b0 b7 39 94 0a 00 17 c0}  //weight: 1, accuracy: High
        $x_1_9 = {3b b1 cb 31 4d 24 44 4c ae d5 dc ad 70 f6 62 81}  //weight: 1, accuracy: High
        $x_1_10 = {a4 a4 8f 42 ec c8 7c 42 85 de 11 c8 0f 67 89 3a}  //weight: 1, accuracy: High
        $x_1_11 = {d1 04 bd ec 33 11 80 44 8a 8c bc 9f dd 54 d6 c1}  //weight: 1, accuracy: High
        $x_1_12 = {16 bc dc 3a fa 19 59 4c 9c 22 e1 7c 71 b5 fd 7a}  //weight: 1, accuracy: High
        $x_1_13 = {bd db f4 c4 4c 4a 40 4b 97 da 2f e0 6d bb 29 01}  //weight: 1, accuracy: High
        $x_1_14 = {08 2b 27 15 fe f6 71 4e b2 bd a5 9a d2 3e be 3c}  //weight: 1, accuracy: High
        $x_1_15 = {90 98 f7 05 a6 cf 53 4d 87 bc 2f 39 0d a6 64 5e}  //weight: 1, accuracy: High
        $x_1_16 = {02 4f c5 47 28 1b f1 45 ae 46 b5 cd fb 6e 79 26}  //weight: 1, accuracy: High
        $x_1_17 = {50 7d 8b 21 37 bc a8 4f a5 7f 6e 8d e6 92 bd 79}  //weight: 1, accuracy: High
        $x_1_18 = {dd 98 05 48 28 ae b7 48 82 f7 6a dd a1 aa 6b 66}  //weight: 1, accuracy: High
        $x_1_19 = {b5 64 7d c8 92 df 03 47 90 cb b4 65 b6 98 29 41}  //weight: 1, accuracy: High
        $x_50_20 = "BhoNew.DLL" ascii //weight: 50
        $x_10_21 = "EncodePointer" ascii //weight: 10
        $x_10_22 = "InternetAttemptConnect" ascii //weight: 10
        $x_10_23 = "IsDebuggerPresent" ascii //weight: 10
        $x_5_24 = "explorer.exe" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 2 of ($x_10_*) and 16 of ($x_1_*))) or
            ((1 of ($x_50_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 11 of ($x_1_*))) or
            ((1 of ($x_50_*) and 3 of ($x_10_*) and 6 of ($x_1_*))) or
            ((1 of ($x_50_*) and 3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_M_112097_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!M"
        threat_id = "112097"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "91"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e3 0e 3a 28 c1 2c ab 45 82 07 b1 d7 b6 9c 7f 83}  //weight: 1, accuracy: High
        $x_1_2 = {cc 7b 8d 20 57 98 9e 4c 82 3b d0 4e 72 49 0a 67}  //weight: 1, accuracy: High
        $x_1_3 = {13 cf 12 af 3b dc 1c 46 b5 ce 89 48 06 c1 53 03}  //weight: 1, accuracy: High
        $x_1_4 = {4f 81 cf f4 0f 97 5d 40 a4 2c 0c e0 6e b9 73 73}  //weight: 1, accuracy: High
        $x_1_5 = {a3 8a 41 88 f5 16 c2 4f a9 d8 90 b1 26 6d f8 41}  //weight: 1, accuracy: High
        $x_1_6 = {c2 0c b7 3c 3f 30 6c 4a 82 4d 01 3a e8 cf db 6b}  //weight: 1, accuracy: High
        $x_1_7 = {fd 94 5a 69 d0 15 d7 4e 8f 40 d2 b3 bd c4 2c 15}  //weight: 1, accuracy: High
        $x_1_8 = {07 51 d8 ac f9 9c 9e 4c b0 b7 39 94 0a 00 17 c0}  //weight: 1, accuracy: High
        $x_1_9 = {3b b1 cb 31 4d 24 44 4c ae d5 dc ad 70 f6 62 81}  //weight: 1, accuracy: High
        $x_1_10 = {a4 a4 8f 42 ec c8 7c 42 85 de 11 c8 0f 67 89 3a}  //weight: 1, accuracy: High
        $x_1_11 = {d1 04 bd ec 33 11 80 44 8a 8c bc 9f dd 54 d6 c1}  //weight: 1, accuracy: High
        $x_1_12 = {16 bc dc 3a fa 19 59 4c 9c 22 e1 7c 71 b5 fd 7a}  //weight: 1, accuracy: High
        $x_1_13 = {bd db f4 c4 4c 4a 40 4b 97 da 2f e0 6d bb 29 01}  //weight: 1, accuracy: High
        $x_1_14 = {08 2b 27 15 fe f6 71 4e b2 bd a5 9a d2 3e be 3c}  //weight: 1, accuracy: High
        $x_1_15 = {90 98 f7 05 a6 cf 53 4d 87 bc 2f 39 0d a6 64 5e}  //weight: 1, accuracy: High
        $x_1_16 = {02 4f c5 47 28 1b f1 45 ae 46 b5 cd fb 6e 79 26}  //weight: 1, accuracy: High
        $x_1_17 = {50 7d 8b 21 37 bc a8 4f a5 7f 6e 8d e6 92 bd 79}  //weight: 1, accuracy: High
        $x_1_18 = {dd 98 05 48 28 ae b7 48 82 f7 6a dd a1 aa 6b 66}  //weight: 1, accuracy: High
        $x_1_19 = {b5 64 7d c8 92 df 03 47 90 cb b4 65 b6 98 29 41}  //weight: 1, accuracy: High
        $x_50_20 = "BhoNew.DLL" ascii //weight: 50
        $x_10_21 = "search.msn.com/dnserror.aspx" wide //weight: 10
        $x_10_22 = "EncodePointer" ascii //weight: 10
        $x_10_23 = "InternetAttemptConnect" ascii //weight: 10
        $x_10_24 = "IsDebuggerPresent" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 3 of ($x_10_*) and 11 of ($x_1_*))) or
            ((1 of ($x_50_*) and 4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_Q_112297_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!Q"
        threat_id = "112297"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/search.php?qq=%s" ascii //weight: 5
        $x_5_2 = "/search.php?qq=%s" wide //weight: 5
        $x_10_3 = {52 45 53 54 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00}  //weight: 10, accuracy: High
        $x_5_4 = "{B499D34E-58EF-4927-AB9F-7AF52B2C4C82}" ascii //weight: 5
        $x_1_5 = "aconfidenceonline.com" wide //weight: 1
        $x_1_6 = "anydnserrors.com" wide //weight: 1
        $x_1_7 = "thesafetyfiles.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_R_112316_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!R"
        threat_id = "112316"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "38"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/search.php?qq=%s" ascii //weight: 10
        $x_10_2 = {43 4c 41 46 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00}  //weight: 10, accuracy: High
        $x_5_3 = "http://auto.search.msn.com/response.asp?MT=" wide //weight: 5
        $x_5_4 = "/search.php?qq=%s" wide //weight: 5
        $x_5_5 = "res://%s\\s%s%s%s" wide //weight: 5
        $x_1_6 = "{1C3C4699-B285-475F-BE47-0B26088CE876}" ascii //weight: 1
        $x_1_7 = "vexplorer.exe" ascii //weight: 1
        $x_1_8 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_S_112327_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!S"
        threat_id = "112327"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/search.php?qq=%s" ascii //weight: 10
        $x_10_2 = {43 4c 41 46 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00}  //weight: 10, accuracy: High
        $x_5_3 = "http://auto.search.msn.com/response.asp?MT=" wide //weight: 5
        $x_5_4 = "/search.php?qq=%s" wide //weight: 5
        $x_1_5 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_T_112639_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!T"
        threat_id = "112639"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "121"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {48 4c 45 46 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00}  //weight: 50, accuracy: High
        $x_50_2 = "/search.php?qq=%s" wide //weight: 50
        $x_10_3 = "http://auto.search.msn.com/response.asp?MT=" wide //weight: 10
        $x_10_4 = "/search.php?qq=%s" ascii //weight: 10
        $x_10_5 = "ser helper ob" ascii //weight: 10
        $x_1_6 = "{1C3C4699-B285-475F-BE47-0B26088CE876}" ascii //weight: 1
        $x_1_7 = {85 c0 75 14 68 2c 01 00 00 6a 08 ff 15 ?? ?? ?? ?? 70 ff 15 ?? ?? ?? ?? 76 8b 74 24 08 8a 16 84 d2 a3 ?? ?? ?? ?? 8b c8 74 10 2b f0 32 74 24 0c 88 11 61 8a 14 0e 84 d2 75 f2 c6 01 00 5e c3}  //weight: 1, accuracy: Low
        $x_1_8 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_9 = "res://%s\\s%s%s%s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_50_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_W_112651_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!W"
        threat_id = "112651"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "InternetReadFile" ascii //weight: 1
        $x_1_2 = "OpenEventW" ascii //weight: 1
        $x_1_3 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 2e 00 63 00 6f 00 6d 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f [0-64] 2f 00 64 00 77 00 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
        $x_2_5 = "bx18dxv.dat" wide //weight: 2
        $x_1_6 = "MyBITSTrans_new" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_AD_112882_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AD"
        threat_id = "112882"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/search.php?qq=%s" wide //weight: 1
        $x_1_2 = "asecurityassurance.com" wide //weight: 1
        $x_1_3 = {8a 16 84 d2 8b c8 74 10 2b f0 32 54 24 0c 88 11 41 8a 14 0e 84 d2 75 f2 c6 01 00 5e c3}  //weight: 1, accuracy: High
        $x_2_4 = {6a 00 6a 01 ff (15|??) [0-4] 8d ?? 24 ?? ?? 68 ?? ?? 00 10 ff 15 ?? (30|40) 00 10 68}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_AC_112883_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AC"
        threat_id = "112883"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "640"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "winexec" ascii //weight: 100
        $x_100_2 = "writefile" ascii //weight: 100
        $x_100_3 = "SeShutdownPrivilege" ascii //weight: 100
        $x_100_4 = "yttruov" ascii //weight: 100
        $x_10_5 = "virus protection" ascii //weight: 10
        $x_10_6 = "antivirus software" ascii //weight: 10
        $x_20_7 = "antispayware software" ascii //weight: 20
        $x_20_8 = "on your system Windows Defender." ascii //weight: 20
        $x_20_9 = "on your system Microsoft OneCare" ascii //weight: 20
        $x_20_10 = {25 73 20 2f 64 65 6c 00}  //weight: 20, accuracy: High
        $x_10_11 = {25 73 20 2f 64 65 6c 32 00}  //weight: 10, accuracy: High
        $x_10_12 = {2f 63 20 64 65 6c [0-5] 25 73 [0-5] 3e 3e [0-5] 6e 75 6c 6c 00}  //weight: 10, accuracy: Low
        $x_100_13 = {6a 00 6a 04 6a 02 6a 00 6a 01 68 00 00 00 40 68 ?? ?? 40 00 e8 ?? ?? ?? ?? 83 f8 ff 75 0c}  //weight: 100, accuracy: Low
        $x_100_14 = {80 3e 00 74 05 30 06 46 eb f6 c9 c2 08 00}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_100_*) and 4 of ($x_10_*))) or
            ((6 of ($x_100_*) and 1 of ($x_20_*) and 2 of ($x_10_*))) or
            ((6 of ($x_100_*) and 2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_AB_112884_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AB"
        threat_id = "112884"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "411"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "InternetOpenUrlA" ascii //weight: 100
        $x_100_2 = "ShellExecuteA" ascii //weight: 100
        $x_100_3 = "Shell_NotifyIconA" ascii //weight: 100
        $x_100_4 = "DisplayIcon" ascii //weight: 100
        $x_10_5 = "tmxxxh.dll" ascii //weight: 10
        $x_10_6 = "blowjob." ascii //weight: 10
        $x_1_7 = "system on computer is damaged." ascii //weight: 1
        $x_1_8 = "Virus" ascii //weight: 1
        $x_1_9 = "infected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_AB_112884_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AB"
        threat_id = "112884"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "411"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "InternetOpenUrlA" ascii //weight: 100
        $x_100_2 = "ShellExecuteA" ascii //weight: 100
        $x_100_3 = "Shell_NotifyIconA" ascii //weight: 100
        $x_100_4 = "DisplayIcon" ascii //weight: 100
        $x_10_5 = {61 6e 61 6c [0-10] 6d 6f 6e 73 74 65 72 73 2e 63 6f 6d}  //weight: 10, accuracy: Low
        $x_10_6 = "/mature._xe" ascii //weight: 10
        $x_1_7 = "system on computer is damaged." ascii //weight: 1
        $x_1_8 = "Virus" ascii //weight: 1
        $x_1_9 = "infected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_AA_112885_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AA"
        threat_id = "112885"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 98 1d c3 14 a3 bb 49 ba 51 7f 57 de e5 ea 34}  //weight: 1, accuracy: High
        $x_10_2 = {6c 65 6f 73 72 76 2e 64 6c 6c 00 64 6c 6c 63 61 6e 75 6e 6c 6f 61 64 6e 6f 77 00 64 6c 6c 67 65 74 63 6c 61 73 73 6f 62 6a 65 63 74 00 64 6c 6c 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 64 6c 6c 75 6e 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 00}  //weight: 10, accuracy: High
        $x_10_3 = "leosrvTOOLBAR" wide //weight: 10
        $x_10_4 = "ToolbarWindow32" wide //weight: 10
        $x_10_5 = "explorer.exe" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_AA_112885_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AA"
        threat_id = "112885"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b5 0d 5c e7 f7 5d f0 4d 97 61 8e fc d1 78 39 12}  //weight: 1, accuracy: High
        $x_10_2 = {6a 6f 6b 77 6d 70 2e 64 6c 6c 00 64 6c 6c 63 61 6e 75 6e 6c 6f 61 64 6e 6f 77 00 64 6c 6c 67 65 74 63 6c 61 73 73 6f 62 6a 65 63 74 00 64 6c 6c 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 64 6c 6c 75 6e 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 00}  //weight: 10, accuracy: High
        $x_10_3 = "jokwmpTOOLBAR" wide //weight: 10
        $x_10_4 = "ToolbarWindow32" wide //weight: 10
        $x_10_5 = "explorer.exe" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_AA_112885_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AA"
        threat_id = "112885"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 76 87 06 48 f0 d1 43 b3 3b db e6 fe 9a e7 12}  //weight: 1, accuracy: High
        $x_10_2 = {76 6f 69 70 77 65 74 2e 64 6c 6c 00 64 6c 6c 63 61 6e 75 6e 6c 6f 61 64 6e 6f 77 00 64 6c 6c 67 65 74 63 6c 61 73 73 6f 62 6a 65 63 74 00 64 6c 6c 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 64 6c 6c 75 6e 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 00}  //weight: 10, accuracy: High
        $x_10_3 = "voipwetTOOLBAR" wide //weight: 10
        $x_10_4 = "ToolbarWindow32" wide //weight: 10
        $x_10_5 = "explorer.exe" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_AA_112885_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AA"
        threat_id = "112885"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{B02534D7-8D91-49BE-A864-97DFB8E0BAB4}" ascii //weight: 1
        $x_10_2 = "optnet.ToolBar.1" ascii //weight: 10
        $x_10_3 = {6f 70 74 6e 65 74 2e 64 6c 6c 00 64 6c 6c 63 61 6e 75 6e 6c 6f 61 64 6e 6f 77 00 64 6c 6c 67 65 74 63 6c 61 73 73 6f 62 6a 65 63 74 00 64 6c 6c 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 64 6c 6c 75 6e 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 00}  //weight: 10, accuracy: High
        $x_10_4 = "optnet.dll" wide //weight: 10
        $x_10_5 = "optnetTOOLBAR" wide //weight: 10
        $x_10_6 = "writefile" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_AA_112885_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AA"
        threat_id = "112885"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{AC9BBDB2-8FCD-49C8-96F7-CC3CF7B453CD}" ascii //weight: 1
        $x_1_2 = "{61AB8A39-FCCB-47CC-BAF3-750D1834E773}" ascii //weight: 1
        $x_1_3 = "{1699137C-B90E-4488-97BC-575C896C2B5C}" ascii //weight: 1
        $x_1_4 = "{DF0ACE0C-4A3F-4A1F-8676-BA16DEB23C70}" ascii //weight: 1
        $x_1_5 = "{2106BEDE-F5E8-4DE8-A081-A7E5EAD1529B}" ascii //weight: 1
        $x_1_6 = "{7D61C1B5-86AF-439F-9ACF-D19FDB5F55CC}" ascii //weight: 1
        $x_10_7 = "nssfrch.ToolBar.1" ascii //weight: 10
        $x_10_8 = {6e 73 73 66 72 63 68 2e 64 6c 6c 00 64 6c 6c 63 61 6e 75 6e 6c 6f 61 64 6e 6f 77 00 64 6c 6c 67 65 74 63 6c 61 73 73 6f 62 6a 65 63 74 00 64 6c 6c 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 64 6c 6c 75 6e 72 65 67 69 73 74 65 72 73 65 72 76 65 72 00 00}  //weight: 10, accuracy: High
        $x_10_9 = "nssfrch.dll" wide //weight: 10
        $x_10_10 = "nssfrchTOOLBAR" wide //weight: 10
        $x_10_11 = "writefile" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_Z_112886_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!Z"
        threat_id = "112886"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "46"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{41F6170D-6AF8-4188-8D92-9DDAB3C71A78}" ascii //weight: 1
        $x_1_2 = "{23ED2206-856D-461A-BBCF-1C2466AC5AE3}" ascii //weight: 1
        $x_1_3 = "{062F3F8B-CB94-4D76-A98A-EF800A438F01}" ascii //weight: 1
        $x_10_4 = {53 54 41 52 54 45 52 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 00}  //weight: 10, accuracy: High
        $x_10_5 = "software\\microsoft\\internet explorer\\toolbar\\webbrowser" ascii //weight: 10
        $x_10_6 = "createtoolhelp32snapshot" ascii //weight: 10
        $x_10_7 = "process32next" ascii //weight: 10
        $x_5_8 = "http" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_AI_113418_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AI"
        threat_id = "113418"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1300"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" ascii //weight: 1
        $x_2_2 = "Generate Key" wide //weight: 2
        $x_2_3 = "Access code:" wide //weight: 2
        $x_1_4 = "Visit" wide //weight: 1
        $x_2_5 = "Enter Website" wide //weight: 2
        $x_2_6 = "Copy Key" wide //weight: 2
        $x_2_7 = "Shell_NotifyIconA" ascii //weight: 2
        $x_1_8 = "ProgramVersion" ascii //weight: 1
        $x_2_9 = "VC20XC00U" ascii //weight: 2
        $x_2_10 = "Site code:" wide //weight: 2
        $x_2_11 = "visited:" ascii //weight: 2
        $x_1_12 = "Shell_TrayWnd" ascii //weight: 1
        $x_10_13 = "FindFirstUrlCacheEntryA" ascii //weight: 10
        $x_10_14 = "InternetCrackUrlA" ascii //weight: 10
        $x_10_15 = "TrackPopupMenuEx" ascii //weight: 10
        $x_75_16 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" ascii //weight: 75
        $x_25_17 = "Software\\Microsoft\\Internet Explorer\\TypedURLs" ascii //weight: 25
        $x_1100_18 = "http://5starvideos.com/main/" ascii //weight: 1100
        $x_75_19 = " usage count exceeded, please download a new version." ascii //weight: 75
        $x_50_20 = "WindowClass" ascii //weight: 50
        $x_75_21 = " installation information was corrupted, please reinstall " ascii //weight: 75
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1100_*) and 1 of ($x_75_*) and 1 of ($x_50_*) and 1 of ($x_25_*) and 3 of ($x_10_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_1100_*) and 2 of ($x_75_*) and 3 of ($x_10_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_1100_*) and 2 of ($x_75_*) and 1 of ($x_25_*) and 1 of ($x_10_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_1100_*) and 2 of ($x_75_*) and 1 of ($x_25_*) and 1 of ($x_10_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_1100_*) and 2 of ($x_75_*) and 1 of ($x_25_*) and 1 of ($x_10_*) and 8 of ($x_2_*))) or
            ((1 of ($x_1100_*) and 2 of ($x_75_*) and 1 of ($x_25_*) and 2 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_1100_*) and 2 of ($x_75_*) and 1 of ($x_25_*) and 2 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_1100_*) and 2 of ($x_75_*) and 1 of ($x_25_*) and 2 of ($x_10_*) and 3 of ($x_2_*))) or
            ((1 of ($x_1100_*) and 2 of ($x_75_*) and 1 of ($x_25_*) and 3 of ($x_10_*))) or
            ((1 of ($x_1100_*) and 2 of ($x_75_*) and 1 of ($x_50_*))) or
            ((1 of ($x_1100_*) and 3 of ($x_75_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_AH_113419_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AH"
        threat_id = "113419"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "300"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" ascii //weight: 1
        $x_2_2 = "Generate Key" wide //weight: 2
        $x_2_3 = "Access code:" wide //weight: 2
        $x_1_4 = "Visit" wide //weight: 1
        $x_2_5 = "Enter Website" wide //weight: 2
        $x_2_6 = "Copy Key" wide //weight: 2
        $x_2_7 = "Shell_NotifyIconA" ascii //weight: 2
        $x_1_8 = "ProgramVersion" ascii //weight: 1
        $x_2_9 = "VC20XC00U" ascii //weight: 2
        $x_2_10 = "Site code:" wide //weight: 2
        $x_2_11 = "visited:" ascii //weight: 2
        $x_1_12 = "Shell_TrayWnd" ascii //weight: 1
        $x_10_13 = "FindFirstUrlCacheEntryA" ascii //weight: 10
        $x_10_14 = "InternetCrackUrlA" ascii //weight: 10
        $x_10_15 = "TrackPopupMenuEx" ascii //weight: 10
        $x_75_16 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\X Password Generator" ascii //weight: 75
        $x_25_17 = "Software\\Microsoft\\Internet Explorer\\TypedURLs" ascii //weight: 25
        $x_100_18 = "http://www.xpassgenerator.com/software/" ascii //weight: 100
        $x_100_19 = "http://5starvideos.com/main/" ascii //weight: 100
        $x_25_20 = "X Password Generator Error" wide //weight: 25
        $x_10_21 = "X Password Generator" ascii //weight: 10
        $x_25_22 = "X Password Generator usage count exceeded, please download a new version." ascii //weight: 25
        $x_75_23 = "XPassGeneratorWindowClass" ascii //weight: 75
        $x_25_24 = "X Password Generator installation information was corrupted, please reinstall X Password Generator." ascii //weight: 25
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_75_*) and 4 of ($x_25_*) and 3 of ($x_10_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_75_*) and 4 of ($x_25_*) and 4 of ($x_10_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_75_*) and 4 of ($x_25_*) and 4 of ($x_10_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_75_*) and 4 of ($x_25_*) and 4 of ($x_10_*) and 5 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_75_*) and 3 of ($x_25_*) and 3 of ($x_10_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_75_*) and 3 of ($x_25_*) and 4 of ($x_10_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_75_*) and 3 of ($x_25_*) and 4 of ($x_10_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_75_*) and 3 of ($x_25_*) and 4 of ($x_10_*) and 5 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_75_*) and 4 of ($x_25_*) and 1 of ($x_10_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_75_*) and 4 of ($x_25_*) and 1 of ($x_10_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_75_*) and 4 of ($x_25_*) and 1 of ($x_10_*) and 8 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_75_*) and 4 of ($x_25_*) and 2 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_75_*) and 4 of ($x_25_*) and 2 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_75_*) and 4 of ($x_25_*) and 2 of ($x_10_*) and 3 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_75_*) and 4 of ($x_25_*) and 3 of ($x_10_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 3 of ($x_10_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 4 of ($x_10_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 4 of ($x_10_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 4 of ($x_10_*) and 5 of ($x_2_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 1 of ($x_25_*) and 1 of ($x_10_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 1 of ($x_25_*) and 1 of ($x_10_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 1 of ($x_25_*) and 1 of ($x_10_*) and 8 of ($x_2_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 1 of ($x_25_*) and 2 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 1 of ($x_25_*) and 2 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 1 of ($x_25_*) and 2 of ($x_10_*) and 3 of ($x_2_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 1 of ($x_25_*) and 3 of ($x_10_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 2 of ($x_25_*))) or
            ((2 of ($x_100_*) and 2 of ($x_25_*) and 3 of ($x_10_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_100_*) and 2 of ($x_25_*) and 4 of ($x_10_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_100_*) and 2 of ($x_25_*) and 4 of ($x_10_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_100_*) and 2 of ($x_25_*) and 4 of ($x_10_*) and 5 of ($x_2_*))) or
            ((2 of ($x_100_*) and 3 of ($x_25_*) and 1 of ($x_10_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_100_*) and 3 of ($x_25_*) and 1 of ($x_10_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*) and 3 of ($x_25_*) and 1 of ($x_10_*) and 8 of ($x_2_*))) or
            ((2 of ($x_100_*) and 3 of ($x_25_*) and 2 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_100_*) and 3 of ($x_25_*) and 2 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*) and 3 of ($x_25_*) and 2 of ($x_10_*) and 3 of ($x_2_*))) or
            ((2 of ($x_100_*) and 3 of ($x_25_*) and 3 of ($x_10_*))) or
            ((2 of ($x_100_*) and 4 of ($x_25_*))) or
            ((2 of ($x_100_*) and 1 of ($x_75_*) and 1 of ($x_10_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_100_*) and 1 of ($x_75_*) and 1 of ($x_10_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*) and 1 of ($x_75_*) and 1 of ($x_10_*) and 8 of ($x_2_*))) or
            ((2 of ($x_100_*) and 1 of ($x_75_*) and 2 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_100_*) and 1 of ($x_75_*) and 2 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*) and 1 of ($x_75_*) and 2 of ($x_10_*) and 3 of ($x_2_*))) or
            ((2 of ($x_100_*) and 1 of ($x_75_*) and 3 of ($x_10_*))) or
            ((2 of ($x_100_*) and 1 of ($x_75_*) and 1 of ($x_25_*))) or
            ((2 of ($x_100_*) and 2 of ($x_75_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_AG_113420_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AG"
        threat_id = "113420"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "300"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" ascii //weight: 1
        $x_2_2 = "Generate Key" wide //weight: 2
        $x_2_3 = "Access code:" wide //weight: 2
        $x_1_4 = "Visit" wide //weight: 1
        $x_2_5 = "Enter Website" wide //weight: 2
        $x_2_6 = "Copy Key" ascii //weight: 2
        $x_2_7 = "Shell_NotifyIconA" ascii //weight: 2
        $x_1_8 = "ProgramVersion" ascii //weight: 1
        $x_2_9 = "VC20XC00U" ascii //weight: 2
        $x_2_10 = "Site code:" wide //weight: 2
        $x_2_11 = "visited:" ascii //weight: 2
        $x_1_12 = "Shell_TrayWnd" ascii //weight: 1
        $x_10_13 = "FindFirstUrlCacheEntryA" ascii //weight: 10
        $x_10_14 = "InternetCrackUrlA" ascii //weight: 10
        $x_10_15 = "TrackPopupMenuEx" ascii //weight: 10
        $x_75_16 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PornPass Manager" ascii //weight: 75
        $x_25_17 = "Software\\Microsoft\\Internet Explorer\\TypedURLs" ascii //weight: 25
        $x_100_18 = "http://www.pornpassmanager.com/" ascii //weight: 100
        $x_100_19 = "http://5starvideos.com/main/" ascii //weight: 100
        $x_25_20 = "PornPass Manager Error" ascii //weight: 25
        $x_10_21 = "PornPass Manager" ascii //weight: 10
        $x_25_22 = "PornPass Manager usage count exceeded, please download a new version." ascii //weight: 25
        $x_75_23 = "PornPassManagerWindowClass" ascii //weight: 75
        $x_25_24 = "PornPass Manager installation information was corrupted, please reinstall PornPass Manager." ascii //weight: 25
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_75_*) and 4 of ($x_25_*) and 3 of ($x_10_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_75_*) and 4 of ($x_25_*) and 4 of ($x_10_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_75_*) and 4 of ($x_25_*) and 4 of ($x_10_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_75_*) and 4 of ($x_25_*) and 4 of ($x_10_*) and 5 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_75_*) and 3 of ($x_25_*) and 3 of ($x_10_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_75_*) and 3 of ($x_25_*) and 4 of ($x_10_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_75_*) and 3 of ($x_25_*) and 4 of ($x_10_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_75_*) and 3 of ($x_25_*) and 4 of ($x_10_*) and 5 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_75_*) and 4 of ($x_25_*) and 1 of ($x_10_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_75_*) and 4 of ($x_25_*) and 1 of ($x_10_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_75_*) and 4 of ($x_25_*) and 1 of ($x_10_*) and 8 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_75_*) and 4 of ($x_25_*) and 2 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_75_*) and 4 of ($x_25_*) and 2 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_75_*) and 4 of ($x_25_*) and 2 of ($x_10_*) and 3 of ($x_2_*))) or
            ((1 of ($x_100_*) and 1 of ($x_75_*) and 4 of ($x_25_*) and 3 of ($x_10_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 3 of ($x_10_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 4 of ($x_10_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 4 of ($x_10_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 4 of ($x_10_*) and 5 of ($x_2_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 1 of ($x_25_*) and 1 of ($x_10_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 1 of ($x_25_*) and 1 of ($x_10_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 1 of ($x_25_*) and 1 of ($x_10_*) and 8 of ($x_2_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 1 of ($x_25_*) and 2 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 1 of ($x_25_*) and 2 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 1 of ($x_25_*) and 2 of ($x_10_*) and 3 of ($x_2_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 1 of ($x_25_*) and 3 of ($x_10_*))) or
            ((1 of ($x_100_*) and 2 of ($x_75_*) and 2 of ($x_25_*))) or
            ((2 of ($x_100_*) and 2 of ($x_25_*) and 3 of ($x_10_*) and 8 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_100_*) and 2 of ($x_25_*) and 4 of ($x_10_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_100_*) and 2 of ($x_25_*) and 4 of ($x_10_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_100_*) and 2 of ($x_25_*) and 4 of ($x_10_*) and 5 of ($x_2_*))) or
            ((2 of ($x_100_*) and 3 of ($x_25_*) and 1 of ($x_10_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_100_*) and 3 of ($x_25_*) and 1 of ($x_10_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*) and 3 of ($x_25_*) and 1 of ($x_10_*) and 8 of ($x_2_*))) or
            ((2 of ($x_100_*) and 3 of ($x_25_*) and 2 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_100_*) and 3 of ($x_25_*) and 2 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*) and 3 of ($x_25_*) and 2 of ($x_10_*) and 3 of ($x_2_*))) or
            ((2 of ($x_100_*) and 3 of ($x_25_*) and 3 of ($x_10_*))) or
            ((2 of ($x_100_*) and 4 of ($x_25_*))) or
            ((2 of ($x_100_*) and 1 of ($x_75_*) and 1 of ($x_10_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_100_*) and 1 of ($x_75_*) and 1 of ($x_10_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*) and 1 of ($x_75_*) and 1 of ($x_10_*) and 8 of ($x_2_*))) or
            ((2 of ($x_100_*) and 1 of ($x_75_*) and 2 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_100_*) and 1 of ($x_75_*) and 2 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*) and 1 of ($x_75_*) and 2 of ($x_10_*) and 3 of ($x_2_*))) or
            ((2 of ($x_100_*) and 1 of ($x_75_*) and 3 of ($x_10_*))) or
            ((2 of ($x_100_*) and 1 of ($x_75_*) and 1 of ($x_25_*))) or
            ((2 of ($x_100_*) and 2 of ($x_75_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_IV_113506_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!IV"
        threat_id = "113506"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "39"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "cmd.exe /c \"C:\\TEMP" ascii //weight: 5
        $x_3_2 = "HttpSendRequestW" ascii //weight: 3
        $x_3_3 = "InternetReadFile" ascii //weight: 3
        $x_3_4 = "HttpOpenRequest" ascii //weight: 3
        $x_5_5 = {69 00 65 00 2e 00 56 00 69 00 73 00 69 00 62 00 6c 00 65 00 [0-6] 66 00 61 00 6c 00 73 00 65 00}  //weight: 5, accuracy: Low
        $x_5_6 = ".Sleep(100)" wide //weight: 5
        $x_5_7 = "while (ie.Busy)" wide //weight: 5
        $x_5_8 = "set ie = WScript.CreateObject(\"InternetExplorer.Application\")" wide //weight: 5
        $x_5_9 = "cscript.exe //E:VBScript //B" wide //weight: 5
        $x_1_10 = "ie.Navigate(\"http://nmextensions.com/preconfirm.php?sid=0&aid=0&said=0\")" wide //weight: 1
        $x_1_11 = "ie.Navigate(\"http://mediabusnetwork.com/preconfirm.php?aid=" wide //weight: 1
        $x_1_12 = "ie.Navigate(\"" wide //weight: 1
        $x_1_13 = "Software\\Microsoft\\VideoExtension" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((6 of ($x_5_*) and 3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_AJ_113604_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AJ"
        threat_id = "113604"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VideoAccessCodec" ascii //weight: 1
        $x_1_2 = "/ocx/VideoAccessCodec.ocx" ascii //weight: 1
        $x_1_3 = "\\VideoAccessCodec\\VideoAccessCodec.ocx" ascii //weight: 1
        $x_1_4 = {64 65 6c 20 2f 53 20 2f 51 20 76 70 6e ?? ?? ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = "del /F /Q imex.bat" ascii //weight: 1
        $x_1_6 = "InternetOpenW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_ZWD_113621_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ZWD"
        threat_id = "113621"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\gala.dll" ascii //weight: 1
        $x_1_2 = "\\InstallOptions.dll" ascii //weight: 1
        $x_1_3 = "\\wininit.ini" ascii //weight: 1
        $x_1_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c ?? ?? ?? ?? ?? 20 41 64 64 2d 6f 6e}  //weight: 1, accuracy: Low
        $x_1_5 = "%s\\la%s%d.exe" ascii //weight: 1
        $x_1_6 = "FindFirstUrlCacheEntryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_ZWE_113718_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ZWE"
        threat_id = "113718"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "download.php?advid=" ascii //weight: 2
        $x_1_2 = "WinAntiVirus" ascii //weight: 1
        $x_1_3 = "FIREFOX.EXE" ascii //weight: 1
        $x_1_4 = "systemdoctor." ascii //weight: 1
        $x_1_5 = "stopper.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_AK_113728_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AK"
        threat_id = "113728"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}" wide //weight: 1
        $x_1_2 = "NewMediaCodecPropPage" ascii //weight: 1
        $x_1_3 = "CNewMediaCodecCtrl" ascii //weight: 1
        $x_1_4 = "Factory@CNewMediaCodec" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" wide //weight: 1
        $x_1_6 = "ForceRemove" wide //weight: 1
        $x_1_7 = "CLSID\\%1\\InProcServer32" wide //weight: 1
        $x_1_8 = "RestrictRun" wide //weight: 1
        $x_1_9 = "040904e4" wide //weight: 1
        $x_1_10 = "MediaExtension.ocx" wide //weight: 1
        $x_1_11 = "RegCreateKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_AL_113830_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AL"
        threat_id = "113830"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 75 14 68 2c 01 00 00 6a 08 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 56 8b 74 24 08 a3 ?? ?? ?? ?? 8a 16 84 d2 8b c8 74 10 2b f0 32 54 24 0c 88 11 41 8a 14 0e 84 d2 75 f2 c6 01 00 5e c3}  //weight: 1, accuracy: Low
        $x_1_2 = {80 44 24 08 64 56 8b 35 ?? ?? ?? ?? 85 f6 57 75 16 68 2c 01 00 00 6a 08 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b f0 8b 7c 24 0c 89 35 ?? ?? ?? ?? 8a 17 84 d2 8b ce 74 10 2b fe 32 54 24 10 88 11 41 8a 14 0f 84 d2 75 f2 5f 8b c6 c6 01 00 5e c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_AMM_114708_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.AMM"
        threat_id = "114708"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "It may be possible to skip this check using the /NCRC command line switch" ascii //weight: 1
        $x_1_2 = "del /F /Q imex.bat" ascii //weight: 1
        $x_1_3 = "download_quiet" ascii //weight: 1
        $x_1_4 = "Proxy-Authorization:" ascii //weight: 1
        $x_1_5 = "User-Agent:" ascii //weight: 1
        $x_1_6 = "Connecting ..." ascii //weight: 1
        $x_1_7 = "NOTICE TO USER: THIS END USER LICENSE AGREEMENT" ascii //weight: 1
        $x_1_8 = "Special Notice for Non-English Speakers:" ascii //weight: 1
        $x_1_9 = "Video Codec Software is suited primarily for the use of English" ascii //weight: 1
        $x_1_10 = "#32770" ascii //weight: 1
        $x_1_11 = "Nullsoft Install System" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule TrojanDownloader_Win32_Zlob_AM_115544_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AM"
        threat_id = "115544"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d 14 07 00 00 74 15 3d 15 07 00 00 74 0e 3d 17 07 00 00 74 07 3d 16 07 00 00 75 60 33 c0 89 45 d8 c7 05}  //weight: 1, accuracy: High
        $x_1_2 = {53 54 41 52 54 45 52 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_CCA_115572_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.CCA"
        threat_id = "115572"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {ba 7f 96 98 00 eb 0a 46 56 83 c6 10 58 48 8b f0 4a 0b d2 75 f2}  //weight: 10, accuracy: High
        $x_1_2 = {6c 6f 61 64 00 77 69 6e 64 6f 77 73 00}  //weight: 1, accuracy: High
        $x_1_3 = "explorer.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_ZWO_115786_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ZWO"
        threat_id = "115786"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c4 7c ff ff ff 33 c0 89 85 7c ff ff ff 89 45 80 89 45 84 89 45 fc 89 45 94 89 45 88 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 6a 00 8d 45 84 b9 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 84 e8 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 d4 40 ff ff 8d 4d 80 b2 9d b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 80 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 d0 40 ff ff 8d 85 7c ff ff ff b9 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 85 7c ff ff ff e8 ?? ?? ?? ?? 50 e8 a9 40 ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {f5 e9 e9 ed a7 b2 b2 ed f2 ea f8 ef f0 ed f8 fa b3 fe f2 f0 b2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_ZWP_115788_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ZWP"
        threat_id = "115788"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 61 72 61 6d 3d 25 73 00 00 00 00 25 73 2f 61 63 63 65 73 73 2f 67 6f 2e 70 68 70 00 00 00 00 32 31 36 2e 32 35 35 2e 31 38 37 2e 39 31 00 00 2f 6b 65 79 2f 73 65 63 72 65 74 6b 65 79 2e 69 6e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_ZWR_115835_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ZWR"
        threat_id = "115835"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 00 00 00 dc c0 c0 c4 8e 9b 9b d7 c6 d1 d5 c0 db da c4 c6 db de d1 d7 c0 c7 9a d7 db d9 9b d0 c6 c2 87 86 9a d0 d5 c0 d5 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 8d 45 c4 b9 68 ad 41 00 8b 15 fc 12 42 00 e8 01 9d fe ff 8b 45 c4 e8 09 9e fe ff 50 a1 fc 12 42 00 e8 fe 9d fe ff 50 e8 78 b1 fe ff 33 c0 89 45 f8 8b 45 fc 03 c0 83 c0 09 89 45 fc}  //weight: 1, accuracy: High
        $x_1_3 = {ff 35 fc 12 42 00 68 78 ad 41 00 8d 4d bc b2 b4 b8 84 ad 41 00 e8 a6 8a ff ff ff 75 bc 8d 45 c0 ba 03 00 00 00 e8 92 9b fe ff 8b 45 c0 e8 c2 d5 ff ff 33 c0 89 45 f8 8b 45 fc 03 c0 83 c0 09 89 45 fc 83 45 fc 7b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_GT_116372_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!GT"
        threat_id = "116372"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 57 53 55 e8 00 00 00 00 5d 81 ed 49 2b 40 00 e8 03 02 00 00 e8 b7 06 00 00 b8 00 00 00 00 85 c0 75 21 ff 85 5b 2b 40 00 e8 63 01 00 00 60 8d b5 40 2b 40 00 b9 f2 09 00 00 89 c7 f3 a4 61 83 c0 04 ff e0 60 8b bd 3c 30 40 00 03 bd 14 30 40 00 8d b5 e2 32 40 00 8b 8d fc 2f 40 00 68 00 10 00 00 57 e8 60 01 00 00 f3 a4 8d 85 d2 32 40 00 8b 9d 14 30 40 00 ff b5 18 30 40 00 ff b5 0c 30 40 00 6a 01 50 53 e8 7d 04 00 00 ff b5 40 30 40 00 ff b5 14 30 40 00 e8 79 00 00 00 8b 85 00 30 40 00 85 c0 74 1c}  //weight: 1, accuracy: High
        $x_1_2 = "URLDownloadA" ascii //weight: 1
        $x_1_3 = "CompareSecurityIds" ascii //weight: 1
        $x_1_4 = "DllUnregisterServer" ascii //weight: 1
        $x_1_5 = "FindFirstUrlCacheEntryW" ascii //weight: 1
        $x_1_6 = "FtpRemoveDirectoryA" ascii //weight: 1
        $x_1_7 = "FtpSetCurrentDirectoryA" ascii //weight: 1
        $x_1_8 = "ForceNexusLookupExW" ascii //weight: 1
        $x_1_9 = {00 00 00 00 63 61 60 0c 64 62 61 2b 6c 6a 69 4c 74 72 71 64 74 72 71 6e 72 70 70 6f 6b 69 69 69 5c 5b 5a 58 54 52 51 43 55 53 52 2a 5a 58 58 13 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 69 67 66 18 81 7f 7e 62 a3 a1 a0 ac bc ba b9 d6 c7 c6 c4 ee cc ca c9 fa ca c8 c7 fb cc cb ca fb ce cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_GS_116377_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!GS"
        threat_id = "116377"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 89 e5 83 ec 14 c7 45 ec 00 00 00 00 c7 45 f0 56 69 72 74 c7 45 f4 75 61 6c 50 c7 45 f8 72 6f 74 65 66 c7 45 fc 63 74 c6 45 fe 00 60 8d 45 ec 50 68 2f 01 ff ff 81 04 24 11 ff 00 00 ff 75 0c ff 75 08 8d 45 f0 e8 58 05 00 00 61 c9}  //weight: 1, accuracy: High
        $x_1_2 = "RegisterBindStatusCallback" ascii //weight: 1
        $x_1_3 = "URLDownloadA" ascii //weight: 1
        $x_1_4 = "CompareSecurityIds" ascii //weight: 1
        $x_1_5 = "DllUnregisterServer" ascii //weight: 1
        $x_1_6 = "FindFirstUrlCacheEntryW" ascii //weight: 1
        $x_1_7 = "ForceNexusLookupExW" ascii //weight: 1
        $x_1_8 = "FtpRemoveDirectoryA" ascii //weight: 1
        $x_1_9 = "CommitUrlCacheEntryW" ascii //weight: 1
        $x_1_10 = "FtpSetCurrentDirectoryA" ascii //weight: 1
        $x_1_11 = "GetUrlCacheEntryInfoW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_GU_116378_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!GU"
        threat_id = "116378"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 00 00 00 00 5d 81 ed 49 2b 40 00 e8 03 02 00 00 e8 c6 06 00 00 b8 00 00 00 00 85 c0 75 21 ff 85 5b 2b 40 00 e8 63 01 00 00 60 8d 50 2d d0 0a 71 e3 eb 03}  //weight: 1, accuracy: High
        $x_1_2 = "RegisterBindStatusCallback" ascii //weight: 1
        $x_1_3 = "URLDownloadA" ascii //weight: 1
        $x_1_4 = "CompareSecurityIds" ascii //weight: 1
        $x_1_5 = "DllUnregisterServer" ascii //weight: 1
        $x_1_6 = "FindFirstUrlCacheEntryW" ascii //weight: 1
        $x_1_7 = "ForceNexusLookupExW" ascii //weight: 1
        $x_1_8 = "FtpRemoveDirectoryA" ascii //weight: 1
        $x_1_9 = "CommitUrlCacheEntryW" ascii //weight: 1
        $x_1_10 = "FtpSetCurrentDirectoryA" ascii //weight: 1
        $x_1_11 = "GetUrlCacheEntryInfoW" ascii //weight: 1
        $x_1_12 = {28 00 00 00 20 00 00 00 40 00 00 00 01 00 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 63 61 60 0c 64 62 61 2b 6c 6a 69 4c 74 72 71 64 74 72 71 6e 72 70 70 6f 6b 69 69 69 5c 5b 5a 58 54 52 51 43 55 53 52 2a 5a 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_KG_117687_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.KG"
        threat_id = "117687"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C2A1C5CB-C0EF-4689-9436-F62CCA1C5383" wide //weight: 1
        $x_1_2 = "ssft.dll" ascii //weight: 1
        $x_1_3 = "dnsduepage.com" wide //weight: 1
        $x_1_4 = "sn.com/res" wide //weight: 1
        $x_1_5 = "puresafetyhere.com/search.php?qq=%s" wide //weight: 1
        $x_1_6 = "VirtualProtect" ascii //weight: 1
        $x_1_7 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_ANA_118134_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ANA"
        threat_id = "118134"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "allert2" ascii //weight: 10
        $x_10_2 = "The computer has been infected!!" ascii //weight: 10
        $x_10_3 = "myfirstgaysex.com/" ascii //weight: 10
        $x_10_4 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" ascii //weight: 10
        $x_1_5 = "ShellExecuteExA" ascii //weight: 1
        $x_1_6 = "InternetCloseHandle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_AV_118429_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AV"
        threat_id = "118429"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 20 53 56 57 33 f6 56 56 56 56 6a 64 6a 64 b8 00 08 00 00 50 50 68 00 00 00 10 56 68 ?? ?? 40 00 68 80 00 00 08 ff 15 ?? ?? 40 00 8b 5d 08 8b 3d ?? ?? 40 00 89 45 fc 83 c3 04 eb 14 8d 45 e0 50 ff 15 ?? ?? 40 00 8d 45 e0 50 ff 15 ?? ?? 40 00 6a 01 56 56 8d 45 e0 56 50 ff d7 85 c0 75 dd 68 ff 04 00 00 6a ff 56 53 6a 01 ff 15 ?? ?? 40 00 83 f8 01 74 db}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 63 68 6c 5c 43 4c 53 49 44 [0-4] 7b 36 42 46 35 32 41 35 32 2d 33 39 34 41 2d 31 31 44 33 2d 42 31 35 33 2d 30 30 43 30 34 46 37 39 46 41 41 36 7d}  //weight: 1, accuracy: Low
        $x_1_3 = "Software\\NetProject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_AMP_119455_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.AMP"
        threat_id = "119455"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "71"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "live." ascii //weight: 10
        $x_10_2 = "yahoo." ascii //weight: 10
        $x_10_3 = "google." ascii //weight: 10
        $x_10_4 = "Software\\Microsoft\\Internet Explorer\\SearchScopes" ascii //weight: 10
        $x_10_5 = "GetSystemDefaultLCID" ascii //weight: 10
        $x_10_6 = "HttpOpenRequestA" ascii //weight: 10
        $x_1_7 = "Software\\NetProject" ascii //weight: 1
        $x_2_8 = "#785ujthgfrw34676utyj" ascii //weight: 2
        $x_2_9 = "_REDD_" ascii //weight: 2
        $x_10_10 = {00 00 83 c4 10 85 c0 74 ?? 6a 01 68 ?? ?? ?? ?? e8 ?? ?? ff ff [0-40] 74 ?? 6a 02 68 ?? ?? ?? ?? e8 ?? ?? ff ff [0-40] 74 ?? 6a 03 68 ?? ?? ?? ?? e8 ?? ?? ff ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 1 of ($x_1_*))) or
            ((7 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_KH_119678_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.KH"
        threat_id = "119678"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6860A44B-5D3E-433D-A7B5-D517F810D0E7" ascii //weight: 1
        $x_1_2 = "dnsmserrors.com" ascii //weight: 1
        $x_1_3 = "hbvt.dll" ascii //weight: 1
        $x_1_4 = "sn.com/res" wide //weight: 1
        $x_1_5 = "securitypills.com/search.php?qq=%s" wide //weight: 1
        $x_1_6 = "VirtualProtect" ascii //weight: 1
        $x_1_7 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_AW_119939_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AW"
        threat_id = "119939"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 16 84 d2 (a3|b8) ?? ?? ?? ?? 8b c8 74 10 2b f0 32 54 24 ?? 88 11 41 8a 14 0e 84 d2 75 f2 c6 01 00 5e c3}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 17 84 d2 89 35 ?? ?? ?? ?? 8b ce 74 10 2b fe 32 54 24 ?? 88 11 41 8a 14 0f 84 d2 75 f2 5f 8b c6 c6 01 00 5e c3}  //weight: 2, accuracy: Low
        $x_2_3 = {8a 0f 84 c9 b8 ?? ?? ?? ?? 8b f0 74 10 2b f8 32 4c 24 ?? 88 0e 46 8a 0c 37 84 c9 75 f2 5f c6 06 00 5e c3}  //weight: 2, accuracy: Low
        $x_2_4 = {8a 0e 84 c9 b8 ?? ?? ?? ?? 74 (0f|13 (??|?? ??|?? ?? ??)) 2b f0 32 ca 88 08 8a 4c 06 ?? 40 84 c9 75 f3 c6 00 00 b8 ?? ?? ?? ?? 5e c3}  //weight: 2, accuracy: Low
        $x_2_5 = {8b 44 24 14 8a 04 30 32 44 24 18 [0-1] 88 06 [0-1] 46}  //weight: 2, accuracy: Low
        $x_2_6 = {2b cf 32 44 24 18 88 06 46 8a 04 31 3a c3 75 f2}  //weight: 2, accuracy: High
        $x_2_7 = {8a da 32 d9 88 1e 46 8a 0c 37 84 c9 75 f2 5b 5f c6 06 00}  //weight: 2, accuracy: High
        $x_2_8 = {8a da 32 d9 88 18 8a 4c 06 01 40 84 c9 75 f1 5b c6 00 00}  //weight: 2, accuracy: High
        $x_1_9 = {8d 49 00 32 c3 88 06 8a 44 31 01 46 84 c0 75 f3}  //weight: 1, accuracy: High
        $x_1_10 = {6a 00 6a 01 ff ?? 8d ?? 24 ?? ?? ?? ff 15 ?? (30|40) 00 10}  //weight: 1, accuracy: Low
        $x_1_11 = {83 c4 30 6a 01 8d 85 f8 fd ff ff 50 ff 15 ?? ?? 00 10 50 8d 85 f8 fd ff ff 50 ff 75 08 e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_12 = {32 ca 88 08 8a 4c 06 01 40 84 c9 75 f3 c6 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_AX_120036_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AX"
        threat_id = "120036"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {70 00 3d 00 25 00 64 00 06 00 (73 00 74 00|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 3f 00 73 00 74 00)}  //weight: 2, accuracy: Low
        $x_2_2 = {49 73 6f 6c 61 74 69 6f 6e 41 77 61 72 65 43 6c 65 61 6e 75 70 0a 00}  //weight: 2, accuracy: High
        $x_1_3 = {83 e8 46 8b ?? 14 74 ?? 83 e8 33 74 ?? 2d}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 01 00 00 03 00 6a (16|1c) (68|b8)}  //weight: 1, accuracy: Low
        $x_1_5 = {88 a6 a5 a9 a1 ea ab ae}  //weight: 1, accuracy: High
        $x_1_6 = {c8 e6 e5 e9 e1 aa eb ee}  //weight: 1, accuracy: High
        $x_2_7 = {66 67 64 79 2e 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_2_8 = {68 6c 65 6f 2e 64 6c 6c 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_AY_120052_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AY"
        threat_id = "120052"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\InprocServer32" ascii //weight: 1
        $x_1_2 = "{7C109800-A5D5-438F-9640-18D17E168B88}" ascii //weight: 1
        $x_1_3 = "#785ujthgfrw34676utyj" ascii //weight: 1
        $x_10_4 = "DllRegisterServer" ascii //weight: 10
        $x_1_5 = {8d 85 f8 fd ff ff 68 ?? ?? 00 10 50 e8 ?? ?? 00 00 8d 85 f8 fd ff ff 68 ?? ?? 00 10 50 e8 ?? ?? 00 00 8d 85 f8 fd ff ff 68 ?? ?? 00 10 50 e8 ?? ?? 00 00 8d 85 f8 fd ff ff 68 ?? ?? 00 10 50 e8 ?? ?? 00 00 8d 85 f8 fd ff ff 68 ?? ?? 00 10 50 e8 ?? ?? 00 00 8d 85 f8 fd ff ff 68 ?? ?? 00 10 50 e8 ?? ?? 00 00 83 c4 30 6a 01 8d 85 f8 fd ff ff 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_AZ_121726_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AZ"
        threat_id = "121726"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 7e 01 3a 88 9d ?? ?? ff ff b9 ff 00 00 00 8d bd ?? ?? ff ff f3 ab 66 ab 88 5d ff aa 89 5d ?? 74 31 8d 85 ?? ?? ff ff 50 53 53 6a 25 53 ff 15 ?? ?? ?? ?? 56 8d 85 ?? ?? ff ff 50 8d 85 ?? ?? ff ff 68 ?? ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {39 5d 14 5f 5e 5b 74 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_ANE_122293_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ANE"
        threat_id = "122293"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Internet Explorer\\SearchScopes" ascii //weight: 1
        $x_1_2 = "if exist \"%s\" goto Repeat" ascii //weight: 1
        $x_1_3 = "del \"%s\"" ascii //weight: 1
        $x_1_4 = "Software\\NetProject" ascii //weight: 1
        $x_1_5 = "ShellExecuteA" ascii //weight: 1
        $x_1_6 = "%s\\zf%s%d.exe" ascii //weight: 1
        $x_1_7 = "_cls%d.bat" ascii //weight: 1
        $x_1_8 = "rmdir \"%s\"" ascii //weight: 1
        $x_1_9 = "/music.php?param=" ascii //weight: 1
        $x_1_10 = ".chl\\CLSID" ascii //weight: 1
        $x_1_11 = {79 61 68 6f 6f 2e 00 00 67 6f 6f 67 6c 65 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_AMQ_122335_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.AMQ"
        threat_id = "122335"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "89"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = "Software\\NetProject" ascii //weight: 50
        $x_10_2 = "Software\\Microsoft\\Internet Explorer\\SearchScopes" ascii //weight: 10
        $x_10_3 = "GetSystemDefaultLCID" ascii //weight: 10
        $x_10_4 = "HttpOpenRequestA" ascii //weight: 10
        $x_3_5 = "#785ujthgfrw34676utyj" ascii //weight: 3
        $x_3_6 = "_REDD_" ascii //weight: 3
        $x_3_7 = "live." ascii //weight: 3
        $x_3_8 = "yahoo." ascii //weight: 3
        $x_3_9 = "google." ascii //weight: 3
        $x_3_10 = {00 00 83 c4 10 85 c0 74 ?? 6a 01 68 ?? ?? ?? ?? e8 ?? ?? ff ff [0-72] 74 ?? 6a 02 68 ?? ?? ?? ?? e8 ?? ?? ff ff [0-72] 74 ?? 6a 03 68 ?? ?? ?? ?? e8 ?? ?? ff ff}  //weight: 3, accuracy: Low
        $x_3_11 = {6a 00 c6 44 24 ?? 47 c6 44 24 ?? 45 c6 44 24 ?? 54 c6 44 24 ?? 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 2 of ($x_10_*) and 7 of ($x_3_*))) or
            ((1 of ($x_50_*) and 3 of ($x_10_*) and 3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_ANF_122543_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ANF"
        threat_id = "122543"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 85 dc fe ff ff 6a 07 50 ff 15 ?? ?? ?? ?? 8d 85 dc fe ff ff 50 e8 ?? ?? ?? ?? 59 8d 45 f0 50 c7 45 f0 ?? ?? ?? ?? c7 45 f4 ?? ?? ?? ?? 89 5d f8 89 5d fc ff 15 ?? ?? ?? ?? 85 c0 75 15 8d 85 d8 fd ff ff 50 8d 85 dc fe ff ff 50 e8 ?? ?? ?? ?? 59 59 5f 33 c0 5b c9 c2 10 00}  //weight: 1, accuracy: Low
        $x_1_2 = {56 57 6a 04 33 f6 5f c7 05 ?? ?? ?? ?? 30 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 02 00 00 00 89 3d ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 a3 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 7c 24 0c 01 7e 1d 8b 7c 24 10 39 77 04 74 14 68 d0 07 00 00 ff 15 ?? ?? ?? ?? ff 77 04 ff 15 ?? ?? ?? ?? 6a 01 56 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 0c 33 c0 5f 5e c3}  //weight: 1, accuracy: Low
        $x_1_3 = {55 8b ec 83 ec 14 8d 45 fc 57 50 8b f9 6a 28 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8d 45 f0 c7 45 ec 01 00 00 00 50 68 ?? ?? ?? ?? 6a 00 c7 45 f8 02 00 00 00 ff 15 ?? ?? ?? ?? 6a 00 6a 00 8d 45 ec 6a 10 50 6a 00 ff 75 fc ff 15 ?? ?? ?? ?? 8b c7 5f c9 c3}  //weight: 1, accuracy: Low
        $x_1_4 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_5 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_6 = "RegisterServiceCtrlHandlerA" ascii //weight: 1
        $x_1_7 = "GET /%s HTTP/1.1" ascii //weight: 1
        $x_1_8 = "GreenFlower dert" ascii //weight: 1
        $x_1_9 = "ZwSystemDebugControl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_DO_123126_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.DO"
        threat_id = "123126"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "266,129 bytes" ascii //weight: 5
        $x_5_2 = "Click OK to download antivirus software and pass full system scan to" ascii //weight: 5
        $x_5_3 = "Would you like to download latest version of antivirus software?" ascii //weight: 5
        $x_5_4 = "Click OK to donwload antispyware software." ascii //weight: 5
        $x_5_5 = "email addresses from the compromised computer." ascii //weight: 5
        $x_5_6 = "This fatal error probably occured because of a virus on your PC." ascii //weight: 5
        $x_5_7 = "Low Internet connection speed" ascii //weight: 5
        $x_5_8 = "Low system perfomance" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanDownloader_Win32_Zlob_ZWV_123330_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ZWV"
        threat_id = "123330"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {bb 65 00 00 00 e8 ?? ?? ff ff 80 3e 00 75 0f e8 ?? ?? ff ff 6a 0a e8 ?? ?? ff ff 4b 75 e7 c6 06 00 bb 11 27 00 00 e8 ?? ?? ff ff 80 3e 00 75 0a 6a 0a e8 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_2_2 = "C:\\TEMP\\budget.xpi" ascii //weight: 2
        $x_1_3 = "MozillaUIWindowClass" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Mozilla\\Mozilla Firefox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_IB_123781_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.IB"
        threat_id = "123781"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\NetProject" ascii //weight: 1
        $x_1_2 = "stereo/music.php?param=" ascii //weight: 1
        $x_1_3 = "internetsecurity" ascii //weight: 1
        $x_1_4 = "google." ascii //weight: 1
        $x_1_5 = "{6BF52A52-394A-11D3-B153-00C04F79FAA6}" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Internet Explorer\\SearchScopes" ascii //weight: 1
        $x_1_7 = "%s\\zf%s%d.exe" ascii //weight: 1
        $x_1_8 = ".chl\\CLSID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_IF_124173_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.IF"
        threat_id = "124173"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\NetProject" ascii //weight: 1
        $x_1_2 = "google." ascii //weight: 1
        $x_1_3 = {33 2d 30 30 43 30 34 46 37 39 46 41 41 36 7d 00 34 41 2d 31 31 44 33 2d 42 31 35 00 7b 36 42 46 35 32 41 35 32 2d 33 39}  //weight: 1, accuracy: High
        $x_1_4 = "Software\\Microsoft\\Internet Explorer\\SearchScopes" ascii //weight: 1
        $x_1_5 = "awer%d.bat" ascii //weight: 1
        $x_10_6 = {3a 52 65 70 65 61 74 0d 0a 64 65 6c 20 22 25 73 22 0d 0a 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 0d 0a 72 6d 64 69 72 20 22 25 73 22}  //weight: 10, accuracy: High
        $x_10_7 = "%s\\zf%s%d.exe" ascii //weight: 10
        $x_1_8 = ".chl\\CLSID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_II_124297_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.II"
        threat_id = "124297"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 50 01 8a 08 83 c0 01 84 c9 75 f7 2b c2 56 8b f0 74 0f b0 2f 38 86 ?? ?? ?? ?? 74 0a 83 ee 01 75 f3}  //weight: 10, accuracy: Low
        $x_1_2 = "InternetReadFile" ascii //weight: 1
        $x_1_3 = "IsBadWritePtr" ascii //weight: 1
        $x_1_4 = "WinExec" ascii //weight: 1
        $x_1_5 = "/confirm.php?aid=%lu&said=%lu&mac=%s&mn=%lu" ascii //weight: 1
        $x_1_6 = ".com/dw.php" ascii //weight: 1
        $x_1_7 = "winpole32.exe" ascii //weight: 1
        $x_1_8 = "/media.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_IK_124384_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.IK!dll"
        threat_id = "124384"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "atfxqogp.DLL" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "\\Implemented Categories" wide //weight: 1
        $x_1_4 = "atfxqogpTOOLBAR" wide //weight: 1
        $x_1_5 = "ForceRemove" wide //weight: 1
        $x_10_6 = {8b 4c 24 04 f7 c1 03 00 00 00 74 24 8a 01 83 c1 01 84 c0 74 4e f7 c1 03 00 00 00 75 ef 05 00 00 00 00 8d a4 24 00 00 00 00 8d a4 24 00 00 00 00 8b 01 ba ff fe fe 7e 03 d0 83 f0 ff 33 c2 83 c1 04 a9 00 01 01 81 74 e8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_BB_124788_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!BB"
        threat_id = "124788"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b f7 74 10 2b cf 32 44 24 18 88 06 46 8a 04 31 84 c0 75 f2}  //weight: 2, accuracy: High
        $x_2_2 = {8b c8 74 10 2b f0 32 54 24 0c 88 11 41 8a 14 0e 84 d2 75 f2}  //weight: 2, accuracy: High
        $x_1_3 = {c6 45 e7 01 83 65 fc 00 52 51 53 b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 e7}  //weight: 1, accuracy: High
        $x_2_4 = {51 50 c6 85 ?? fe ff ff 47 c6 85 ?? fe ff ff 45 c6 85 ?? fe ff ff 54 88 9d ?? fe ff ff ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_KA_124845_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.KA"
        threat_id = "124845"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "72"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "yahoo." ascii //weight: 10
        $x_10_2 = "google." ascii //weight: 10
        $x_10_3 = "Software\\Microsoft\\Internet Explorer\\SearchScopes" ascii //weight: 10
        $x_10_4 = "DefaultScope" ascii //weight: 10
        $x_10_5 = "GetSystemDefaultLCID" ascii //weight: 10
        $x_10_6 = "HttpOpenRequestA" ascii //weight: 10
        $x_2_7 = "_REDD_" ascii //weight: 2
        $x_2_8 = "GetUserDefaultLCID" ascii //weight: 2
        $x_10_9 = {56 8b 74 24 08 8a 16 84 d2 b8 ?? ?? ?? ?? 8b c8 74 10 2b f0 32 54 24 0c 88 11 41 8a 14 0e 84 d2 75 f2 c6 01 00 5e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_KI_125138_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.KI"
        threat_id = "125138"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE INSTALLATION: Components bundled with our software may feed back to Licensor" ascii //weight: 1
        $x_1_2 = {53 6f 66 74 77 61 72 65 5c 57 65 62 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 62 64 74 62 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = "Nullsoft Install System" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_BI_125228_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!BI"
        threat_id = "125228"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 05 6a 01 52 ff 15 ?? ?? 40 00 85 c0 75 34}  //weight: 2, accuracy: Low
        $x_1_2 = {5f 5f 49 53 41 5f 55 50 44 41 54 45 5f 5f 00}  //weight: 1, accuracy: High
        $x_1_3 = {5f 5f 43 48 45 43 4b 5f 5f 00}  //weight: 1, accuracy: High
        $x_1_4 = "/index.php?b=1&t=%d&q={searchTerms}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_BJ_125354_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!BJ"
        threat_id = "125354"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "%s\\zf%s%d.exe" ascii //weight: 2
        $x_1_2 = {8d 4c 24 14 51 68 ?? ?? 40 00 57 ff d3 83 c4 14 57 46 ff d5 83 f8 ff 75 e1}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 85 fc fe ff ff 50 68 ?? ?? 40 00 ff 75 08 ff 15 ?? ?? 40 00 83 c4 14 ff 75 08 46 ff 15 ?? ?? 40 00 83 f8 ff 75 d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_ANH_125489_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ANH"
        threat_id = "125489"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 6f 66 74 77 61 72 65 5c 57 65 62 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 00}  //weight: 2, accuracy: High
        $x_2_2 = {bf 40 4b 4c 00 [0-16] 4e c1 ee (02|03) 46 4f 75}  //weight: 2, accuracy: Low
        $x_1_3 = {c7 44 24 68 43 72 65 00 4f 8d 64 24 00 8a 47 01 47 84 c0 75 f8}  //weight: 1, accuracy: High
        $x_1_4 = {c7 44 24 10 57 61 69 00 4f 8a 47 01 47 84 c0 75 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_ANI_125504_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ANI"
        threat_id = "125504"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{E2090673-256B-4632-94EE-FEC7F551543C}" wide //weight: 1
        $x_1_2 = "%ss://%s\\shdo%s%srr%s%s" wide //weight: 1
        $x_1_3 = {26 00 73 00 72 00 63 00 68 00 3d 00 00 00 00 00 3f 00 4d 00 54 00 3d 00 00 00 00 00 65 00 2e 00 61 00 73 00 70 00 3f 00 4d 00 54 00 3d 00 00 00 70 00 6f 00 6e 00 73 00 00 00 00 00 73 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 65 00 73 00 00 00 00 00 61 00 72 00 63 00 68 00 2e 00 6d 00 00 00 00 00 61 00 75 00 74 00 6f 00 2e 00 73 00 65 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_ANJ_125505_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ANJ"
        threat_id = "125505"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 fc 50 8d 45 10 50 ?? 68 3f 00 0f 00 ?? ?? ?? 68 ?? ?? 40 00 ff 75 0c ff 15 ?? ?? 40 00 ff 75 0c 8b ?? ?? ?? 40 00 ff ?? 8d 45 fc 50 8d 45 0c 50 ?? 68 3f 00 0f 00 ?? ?? ?? 68 ?? ?? 40 00 ff 75 10}  //weight: 1, accuracy: Low
        $x_1_2 = {43 4c 53 49 44 [0-16] 4e 56 69 64 65 6f 43 6f 64 65 6b 2e 43 68 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {54 68 69 73 20 77 69 6c 6c 20 69 6e 73 74 61 6c 6c 20 56 63 6f 64 65 63 20 76 65 72 20 33 2e 31 35 2e 20 44 6f 20 79 6f 75 20 77 69 73 68 20 74 6f 20 63 6f 6e 74 69 6e 75 65 3f [0-16] 56 63 6f 64 65 63 20 76 65 72 20 33 2e 31 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_KJ_125515_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.KJ"
        threat_id = "125515"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Software\\Web Technologies" ascii //weight: 5
        $x_5_2 = {73 74 65 72 65 6f 00}  //weight: 5, accuracy: High
        $x_2_3 = "awer%d.bat" ascii //weight: 2
        $x_2_4 = "%s\\zf%s%d.exe" ascii //weight: 2
        $x_1_5 = "if exist \"%s\" goto Repeat" ascii //weight: 1
        $x_1_6 = "rmdir \"%s\"" ascii //weight: 1
        $x_1_7 = "del \"%s\"" ascii //weight: 1
        $x_5_8 = "{6BF52A52" ascii //weight: 5
        $x_5_9 = "HttpSendRequestA" ascii //weight: 5
        $x_5_10 = "ShellExecuteA" ascii //weight: 5
        $x_5_11 = "WriteFile" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((6 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_NN_125517_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.NN"
        threat_id = "125517"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6f 67 67 79 2e 64 6c 6c 00 66 6f 6f 64 00 67 72 61 62 00 70 6c 75 6d 00}  //weight: 5, accuracy: High
        $x_2_2 = "Software\\Web Technologies" ascii //weight: 2
        $x_1_3 = "Explorer\\SearchScopes" ascii //weight: 1
        $x_5_4 = "HttpOpenRequestA" ascii //weight: 5
        $x_5_5 = {73 74 65 72 65 6f 00}  //weight: 5, accuracy: High
        $x_5_6 = "%s\\zf%s%d.exe" ascii //weight: 5
        $x_5_7 = "WriteFile" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*) and 1 of ($x_1_*))) or
            ((5 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_ZF_125687_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ZF"
        threat_id = "125687"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 40 4b 4c 00 [0-16] 4f c1 ef (02|03) 47 4b 75 f1}  //weight: 1, accuracy: Low
        $x_1_2 = {57 65 62 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {61 77 65 72 25 64 2e 62 61 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_YZ_125688_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.YZ"
        threat_id = "125688"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 18 6a 00 6a 00 81 c2 96 00 00 00 52 55 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {bf 40 4b 4c 00 [0-16] 4e c1 ee (02|03) 46 4f 75}  //weight: 1, accuracy: Low
        $x_1_3 = {25 73 5c 7a 66 25 73 25 64 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_YU_125689_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.YU"
        threat_id = "125689"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {53 8a 5c 24 18 80 c3 64 2b fe 8a cb 32 c8 [0-2] 88 0e 6a 00 46}  //weight: 4, accuracy: Low
        $x_5_2 = {68 00 01 00 00 53 53 53 ff 75 0c 8d 8d f0 fe ff ff 51 50 c6 85 f0 fe ff ff 47 c6 85 f1 fe ff ff 45 c6 85 f2 fe ff ff 54 88 9d f3 fe ff ff}  //weight: 5, accuracy: High
        $x_4_3 = {00 5f 52 45 44 44 5f 00}  //weight: 4, accuracy: High
        $x_4_4 = {00 25 73 5c 7a 66 25 73 25 64 2e 65 78 65 00}  //weight: 4, accuracy: High
        $x_4_5 = {00 73 74 65 72 65 6f 00}  //weight: 4, accuracy: High
        $x_4_6 = {00 79 61 68 6f 6f 2e 00 00 67 6f 6f 67 6c 65 2e 00}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_4_*))) or
            ((1 of ($x_5_*) and 4 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_YV_125720_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.YV"
        threat_id = "125720"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "D46BEAA4-A304-40B3-A9DA-EC7F7F501F25" ascii //weight: 10
        $x_10_2 = {65 00 2e 00 61 00 73 00 70 00 3f 00 4d 00 54 00 3d 00 00 00 70 00 6f 00 6e 00 73 00}  //weight: 10, accuracy: High
        $x_2_3 = "res://%s\\s%s%s%s04.htm" wide //weight: 2
        $x_2_4 = "%ss://%s\\shdo%s%srr%s%s" wide //weight: 2
        $x_1_5 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_BK_125869_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!BK"
        threat_id = "125869"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 4e 74 ?? 83 e8 33 74 ?? 2d 90 00 00 00 (75|0f 85)}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 16 68 2d 01 00 00}  //weight: 1, accuracy: High
        $x_2_3 = {66 67 64 79 2e 64 6c 6c 00 44 6c 6c}  //weight: 2, accuracy: High
        $x_2_4 = {68 6c 65 6f 2e 64 6c 6c 00 44 6c 6c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_ANK_125899_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ANK"
        threat_id = "125899"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "Nullsoft Install System" ascii //weight: 5
        $x_2_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Online Service Tool" ascii //weight: 2
        $x_2_3 = "All video files will now be played automatically. Thank you for choosing Online Service Tool." ascii //weight: 2
        $x_2_4 = "Licensor may offer additional components through our version checking/update system." ascii //weight: 2
        $x_2_5 = {4d 61 69 6e 53 65 63 74 69 6f 6e [0-16] 5c ?? ?? ?? ?? 2e 64 6c 6c}  //weight: 2, accuracy: Low
        $x_1_6 = "C:\\Program Files\\Web Technologies" ascii //weight: 1
        $x_1_7 = "C:\\Program Files\\Applications" ascii //weight: 1
        $x_1_8 = {53 6f 66 74 77 61 72 65 5c 57 65 62 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 00}  //weight: 1, accuracy: High
        $x_1_9 = {53 6f 66 74 77 61 72 65 5c 41 70 70 6c 69 63 61 74 69 6f 6e 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_ANL_125900_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ANL"
        threat_id = "125900"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 47 01 47 3a c3 75 f8 be ?? ?? 40 00 66 a5 8d bd f0 fe ff ff 4f 8a 47 01 47 3a c3 75 f8 be ?? ?? 40 00 a5 a5 a5 a5}  //weight: 4, accuracy: Low
        $x_5_2 = "Web Technologies" ascii //weight: 5
        $x_1_3 = "awer%d.bat" ascii //weight: 1
        $x_1_4 = "%s\\ll%s%d.exe" ascii //weight: 1
        $x_1_5 = "ogle." ascii //weight: 1
        $x_1_6 = "hScopes" ascii //weight: 1
        $x_1_7 = "rmdir \"%s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_ACA_126013_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ACA"
        threat_id = "126013"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ATL:%p" wide //weight: 10
        $x_10_2 = "InterlockedPopEntrySList" ascii //weight: 10
        $x_10_3 = "CoCreateInstance" ascii //weight: 10
        $x_10_4 = "StringFromGUID2" ascii //weight: 10
        $x_1_5 = {71 6e 64 73 66 6d 61 6f 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_6 = {73 71 76 67 6e 72 70 78 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_BL_126037_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!BL"
        threat_id = "126037"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Web Technologies" ascii //weight: 10
        $x_5_2 = "{E2090673-256B-4632-94EE-FEC7F551543C}" ascii //weight: 5
        $x_5_3 = "{DAED9266-8C28-4C1C-8B58-5C66EFF1D302}" ascii //weight: 5
        $x_2_4 = "9034A523-D068-4BE8-A284-9DF278BE776E" ascii //weight: 2
        $x_2_5 = "toolforsearch.com/index" ascii //weight: 2
        $x_2_6 = "IE Anti-Spyware" ascii //weight: 2
        $x_1_7 = "Software\\Microsoft\\Internet Explorer\\SearchScopes" ascii //weight: 1
        $x_1_8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\explorer\\run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_BL_126037_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!BL"
        threat_id = "126037"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ti-Spy" ascii //weight: 2
        $x_1_2 = "Software\\Web Technologies" ascii //weight: 1
        $x_1_3 = "Software\\Applications" ascii //weight: 1
        $x_1_4 = "DAED9266-8C28-4C1C-8B58-5C66EFF1D302" ascii //weight: 1
        $x_1_5 = "9034A523-D068-4BE8-A284-9DF278BE776E" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Internet Explorer\\SearchScopes" ascii //weight: 1
        $x_1_7 = "ect.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_GZ_126376_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!GZ"
        threat_id = "126376"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "__ISA_UPDATE__" ascii //weight: 2
        $x_2_2 = "__COMPONENT_STARTED__" ascii //weight: 2
        $x_1_3 = "Software\\Applications" ascii //weight: 1
        $x_1_4 = "Software\\Web Technologies" ascii //weight: 1
        $x_1_5 = "awer%d.bat" ascii //weight: 1
        $x_1_6 = "iebtm.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_AEQ_126623_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.AEQ"
        threat_id = "126623"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 0d 8b 45 f4 46 83 c0 f8 3b f0 72 98 eb 63 53 53 81 c6 6a ff ff ff 56 ff 75 f8 ff 15}  //weight: 1, accuracy: High
        $x_5_2 = {74 15 80 c2 64 2b f8 53 8a da 32 d9 88 1e 46 8a 0c 37 84 c9 75 f2}  //weight: 5, accuracy: High
        $x_1_3 = {ff 55 f8 8b 45 fc 29 45 10 3b c6 74 c7 53 ff 15 ?? ?? ?? ?? 39 7d 10 75 05 33 c0 40 eb 02}  //weight: 1, accuracy: Low
        $x_1_4 = {72 d6 eb 52 8b 45 0c 53 53 05 74 ff ff ff 50 ff 75 14 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_VWX_126771_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.VWX"
        threat_id = "126771"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 85 fc fe ff ff 47 c6 85 fd fe ff ff 45 c6 85 fe fe ff ff 54}  //weight: 1, accuracy: High
        $x_1_2 = {83 7c 24 08 30 7c 0c 83 7c 24 08 39 7f 05}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 5c 77 67 76 25 73 25 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {6a 04 83 c7 0c 57 ff 74 24 24 ff 15 ?? ?? ?? ?? 8b 84 24 30 01 00 00 53 8d 4c 24 1c 51 83 c0 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Zlob_VWX_126774_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.VWX"
        threat_id = "126774"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 85 f0 fe ff ff 47 c6 85 f1 fe ff ff 45 c6 85 f2 fe ff ff 54}  //weight: 1, accuracy: High
        $x_1_2 = {6d 67 72 74 2e 64 6c 6c 00 63 6f 6f 6c 00 66 65 65 64 00 70 6c 65 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = {5f 52 45 44 44 5f 00}  //weight: 1, accuracy: High
        $x_1_4 = {25 73 5c 6a 65 65 25 73 25 64 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Zlob_AFM_126874_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.AFM"
        threat_id = "126874"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\{" ascii //weight: 1
        $x_1_2 = "%s/inst/index.php?affid=%s&subid=%s&guid=%s&ver=%s&key=%s" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\CMVideoPlugin" ascii //weight: 1
        $x_1_4 = "virusalerturl" wide //weight: 1
        $x_1_5 = "CMVideo.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_AFN_126930_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.AFN"
        threat_id = "126930"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c4 89 84 24 64 04 00 00 56 ff 15 ?? ?? 40 00 68 08 02 00 00 8d 84 24 64 02 00 00 50 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 68 ?? ?? 40 00 8d 8c 24 64 02 00 00 51 8d 54 24 60 68}  //weight: 10, accuracy: Low
        $x_10_2 = {6a 06 8d 4c 24 5c 51 ff 15 ?? ?? 40 00 6a 40 8d 54 24 1c 6a 00 52 c7 44 24 20 44 00 00 00 e8 ?? ?? 00 00 83 c4 0c 8d 44 24 04 50 8d 4c 24 18 51 8d 94 24 68 02 00 00 52 6a 00 6a 00 6a 00}  //weight: 10, accuracy: Low
        $x_10_3 = "MediaTubeCodec_ver" wide //weight: 10
        $x_1_4 = "//thepowerofsmith.googlepages.com/" wide //weight: 1
        $x_1_5 = "//Update.WindowsSettings.org/" wide //weight: 1
        $x_1_6 = "//freshtorrents.info/" wide //weight: 1
        $x_1_7 = "//superseedy.info/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_ANM_127079_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ANM"
        threat_id = "127079"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 c3 64 8d 50 01 8d 49 00 8a 08 40 84 c9 75 f9 2b c2 48 78 18 81 ee ?? ?? 40 00 8a 8c 06 ?? ?? 40 00 32 cb 48 88 88 ?? ?? 40 00 79 ee}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 00 4f eb 0c 00 c7 44 24 ?? 44 00 00 00 c7 44 24}  //weight: 1, accuracy: Low
        $x_1_3 = {00 73 74 65 72 65 6f 00}  //weight: 1, accuracy: High
        $x_1_4 = {78 00 65 00 00 00 00 00 2e 00 25 00 73 00 25 00 73 00 00 00 25 00 64 00 00 00 00 00 25 00 73 00 5c 00 25 00 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Zlob_BQ_127115_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!BQ"
        threat_id = "127115"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a ff b2 67 b8 ?? ?? 00 10 89 ?? ?? ?? 00 10 e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8a da 32 d9 88 1e 46 8a 0c 37 84 c9 75 f2 5b 5f c6 06 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 75 70 70 61 2e 64 6c 6c 00 44 6c 6c}  //weight: 1, accuracy: High
        $x_1_4 = "res://%s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Zlob_AMT_127445_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.AMT"
        threat_id = "127445"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 68 58 4d 56 bb 65 d4 85 86 b9 0a 00 00 00 66 ba 58 56 ed 89 5d e4 5b c7 45 fc fe ff ff ff 33 c0 81 7d e4 68 58 4d 56 0f 94 c0}  //weight: 1, accuracy: High
        $x_1_2 = {41 00 75 28 b9 ?? 00 00 00 0f 31 69 c0 35 4e 5a 01 83 c0 01 89 44 24 08 0f 31 69 c0 35 4e 5a 01 83 c0 01 89 44 24 48 e9}  //weight: 1, accuracy: Low
        $x_3_3 = {2f 63 6f 6e 66 69 72 6d 2e 70 68 70 3f 61 69 64 3d 25 6c 75 26 73 61 69 64 3d 25 6c 75 26 6d 61 63 3d 25 73 26 68 61 73 68 3d 25 73 26 6d 6e 3d 25 6c 75 00}  //weight: 3, accuracy: High
        $x_1_4 = {00 2e 6d 69 78 63 72 74 00 45 6e 63 6f 64 65 50 6f 69 6e 74 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_BS_127547_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!BS"
        threat_id = "127547"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {88 04 2e 83 c6 01 83 c4 04 83 c3 04 3b f7 72 e8 08 00 53 e8 ?? ?? ?? ?? 34}  //weight: 3, accuracy: Low
        $x_3_2 = {66 89 44 75 00 83 c6 01 83 c4 04 83 c3 04 3b f7 72 e4 0a 00 53 e8 ?? ?? ?? ?? 66 35}  //weight: 3, accuracy: Low
        $x_1_3 = {49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6e 6e 65 63 74 65 64 53 74 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 74 74 70 3a 2f 2f [0-15] 2f [0-15] 2e 70 68 70 3f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_BT_127560_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!BT"
        threat_id = "127560"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 64 69 72 00 00 00 00 2e 63 6f 6d 2f 72 00 00 6e 64 00 00 74 65 00 00 65 78 00 00 2e 69 65 00 70 3a 2f 2f 77 77 77 00 68 74 74 00 4d 65 6e 75}  //weight: 1, accuracy: High
        $x_1_2 = {55 52 4c 00 63 68 54 65 72 6d 73 7d 00 00 00 00 3d 7b 73 65 61 72 00 00 3d 25 64 26 71 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 00 00 00 25 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_AON_127586_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.AON"
        threat_id = "127586"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "beegrocks.dll" ascii //weight: 1
        $x_1_2 = "{64466B8E-20A7-4A4A-AFF4-AAD9CA68B52C}" wide //weight: 1
        $x_1_3 = {53 74 61 00 61 6e 6b 00 75 74 3a 62 6c 00 00 00 61 62 6f 00 67 65 00 00 50 61 00 00 20 00 00 00 72 74 00 00 6c 6f 72 65 72 5c 4d 61 69 6e 00 00 6e 65 74 20 45 78 70 00 74 5c 49 6e 74 65 72 00 72 6f 73 6f 66 00 00 00 61 72 65 5c 4d 69 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_AON_127586_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.AON"
        threat_id = "127586"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 69 63 68 6c 65 6e 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47}  //weight: 1, accuracy: High
        $x_1_2 = "D358-48A3-A5C7" ascii //weight: 1
        $x_1_3 = {62 65 65 67 72 6f 63 6b 73 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74}  //weight: 1, accuracy: High
        $x_10_4 = {74 15 8b 77 40 03 f0 eb 09 8b 1e 03 d8 01 03 83 c6 04 83 3e 00 75 f2 8b 74 24 24 8b de 03 f0 b9 01 00 00 00 33 c0 f0 0f b1 4f 30 75 f7 ac}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_CB_127707_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!CB"
        threat_id = "127707"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {c6 85 ec fe ff ff 47 c6 85 ed fe ff ff 45 c6 85 ee fe ff ff 54 88 9d ef fe ff ff ff 55}  //weight: 6, accuracy: High
        $x_4_2 = {fe ff ff 47 c6 85 ?? fe ff ff 45 c6 85 ?? fe ff ff 54 88 9d ?? fe ff ff ff 55}  //weight: 4, accuracy: Low
        $x_1_3 = {00 5f 52 45 44 44 5f 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 73 74 65 72 65 6f 00}  //weight: 1, accuracy: High
        $x_1_5 = "SearchScopes" ascii //weight: 1
        $x_1_6 = {00 76 65 2e 00 6c 69 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 6d 67 72 74 2e 64 6c 6c 00 63 6f 6f 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_BU_127714_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!BU"
        threat_id = "127714"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 00 00 55 52 4c 00 65 72 6d 73 7d 00 00 00 68 54 00 00 3d 7b 73 65 61 72 63 00 3d 25 64 26 71 00 00 00 3d 31 26 74 00 00 00 00 70 3f 62 00}  //weight: 1, accuracy: High
        $x_1_2 = {2d 33 00 00 7b 31 46 42 41 00 00 00 45 78 65 63 00 00 00 00 68 70 00 00 63 74 2e 70 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 61 64 76 00 00 00 00 70 3a 2f 2f 77 77 77 00 4d 65 6e 75 54 65 78 74 00 00 00 00 70 79 77 61 72 65 00 00 6e 74 69 2d 53 00 00 00 49 45 20 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_CC_127744_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!CC"
        threat_id = "127744"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {c6 84 24 40 01 00 00 47 c6 84 24 41 01 00 00 45 c6 84 24 42 01 00 00 54 88 9c 24 43 01 00 00 ff 54 24}  //weight: 6, accuracy: High
        $x_4_2 = {01 00 00 47 c6 84 24 ?? 01 00 00 45 c6 84 24 ?? 01 00 00 54 88 9c 24 ?? 01 00 00 ff 54 24}  //weight: 4, accuracy: Low
        $x_1_3 = {00 5f 52 45 44 44 5f 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 73 74 65 72 65 6f 00}  //weight: 1, accuracy: High
        $x_1_5 = "SearchScopes" ascii //weight: 1
        $x_1_6 = {00 76 65 2e 00 6c 69 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 6d 67 72 74 2e 64 6c 6c 00 63 6f 6f 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_AMU_127752_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.AMU"
        threat_id = "127752"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 4f 46 54 57 41 52 45 20 49 4e 53 54 41 4c 4c 41 54 49 4f 4e 3a [0-5] 43 6f 6d 70 6f 6e 65 6e 74 73 20 62 75 6e 64 6c 65 64 20 77 69 74 68 20 6f 75 72 20 73 6f 66 74 77 61 72 65 20 6d 61 79 [0-5] 66 65 65 64 [0-5] 62 61 63 6b 20 74 6f 20 4c 69 63 65 6e 73 6f 72}  //weight: 2, accuracy: Low
        $x_2_2 = {53 6f 66 74 77 61 72 65 5c 41 70 70 6c 69 63 61 74 69 6f 6e 73 00}  //weight: 2, accuracy: High
        $x_2_3 = "Nullsoft Install System" ascii //weight: 2
        $x_1_4 = "\\mgrt.dll" ascii //weight: 1
        $x_1_5 = "\\wdsck.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_CE_127943_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!CE"
        threat_id = "127943"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a0 66 00 10 32 4c 24 ?? 48 88 88}  //weight: 1, accuracy: Low
        $x_1_2 = {72 65 61 6c 2e 64 6c 6c 00 44 6c 6c}  //weight: 1, accuracy: High
        $x_1_3 = "res://%s" wide //weight: 1
        $x_1_4 = "r%ss://%s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Zlob_CF_127984_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!CF"
        threat_id = "127984"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 c6 84 24 ?? ?? ?? ?? (45|54) 0f 00 c6 84 24}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 47 c6 85 ?? ?? ff ff 45 05 00 c6 85 ?? ?? ff}  //weight: 1, accuracy: Low
        $x_2_3 = {6d 67 72 74 2e 64 6c 6c 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_ANN_128076_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ANN"
        threat_id = "128076"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 fb c1 ef 02 47 81 fd 80 e0 62 00 8b df 75}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4c 24 10 8a 8c 01 ?? ?? ?? ?? 32 4c 24 1c 48 88 88 ?? ?? ?? ?? 79 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {75 18 8d 84 24 ?? ?? 00 00 50 ff 74 24 14 ff 54 24 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Zlob_ANP_128228_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ANP"
        threat_id = "128228"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "missingworld" ascii //weight: 1
        $x_1_2 = "nnectA" ascii //weight: 1
        $x_1_3 = "rnetCo" ascii //weight: 1
        $x_1_4 = "DIR \"%s\"" ascii //weight: 1
        $x_1_5 = "to ag" ascii //weight: 1
        $x_1_6 = "IST \"%s\"" ascii //weight: 1
        $x_1_7 = "DEL \"%s\"" ascii //weight: 1
        $x_1_8 = "wewt%d.bat" ascii //weight: 1
        $x_1_9 = "_IEVU" ascii //weight: 1
        $x_1_10 = "_~?dumb" ascii //weight: 1
        $x_1_11 = "%dmissingworld" ascii //weight: 1
        $x_1_12 = "mgfuypuben" ascii //weight: 1
        $x_1_13 = "|DEL DIR " ascii //weight: 1
        $x_1_14 = ".tea_" ascii //weight: 1
        $x_1_15 = ":1wewt_.b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_ANQ_128262_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ANQ"
        threat_id = "128262"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 84 24 3c 01 00 00 47 c6 84 24 3e 01 00 00 54}  //weight: 1, accuracy: High
        $x_1_2 = {c6 84 24 45 01 00 00 45 88 9c 24 47 01 00 00 ff 54 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_ANR_128349_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ANR"
        threat_id = "128349"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {01 00 00 47 04 00 c6 84 24}  //weight: 3, accuracy: Low
        $x_3_2 = {01 00 00 45 04 00 c6 84 24}  //weight: 3, accuracy: Low
        $x_3_3 = {01 00 00 54 04 00 c6 84 24}  //weight: 3, accuracy: Low
        $x_1_4 = {00 67 65 6f 72 67 69 61 20 6d 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {c1 ee 02 46 3d 02 03 03 40 36 8e c0 fd 8c 00 89 74 24 ?? 75}  //weight: 1, accuracy: Low
        $x_1_6 = {00 64 75 6d 62 [0-4] 25 64 [0-4] 6d 69 73 73 69 6e 67 77 6f 72 6c 64 00}  //weight: 1, accuracy: Low
        $x_1_7 = {00 77 65 77 74 25 64 2e 62 61 74 00}  //weight: 1, accuracy: High
        $n_14_8 = {5c 4d 6d 51 54 5f 76 [0-7] 5f 73 76 6e 5c 41 64 62 44 65 76 69 63 65 4a 6f 62 54 68 72 65 61 64 2e 63 70 70}  //weight: -14, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_ANS_128363_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ANS"
        threat_id = "128363"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {5f 5f 54 48 5f 53 54 4f 50 5f 5f 00}  //weight: 3, accuracy: High
        $x_3_2 = {5f 5f 50 4d 5f 4d 4f 4e 49 54 4f 52 5f 53 54 4f 50 5f 5f 00}  //weight: 3, accuracy: High
        $x_3_3 = {5f 5f 48 49 52 45 5f 5f 00}  //weight: 3, accuracy: High
        $x_3_4 = {4c 00 4f 00 48 00 49 00 00 00}  //weight: 3, accuracy: High
        $x_1_5 = "Shell_TrayWnd" ascii //weight: 1
        $x_1_6 = "InternetOpenA" ascii //weight: 1
        $x_3_7 = "%saswe%d.ex%s" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_ANS_128363_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ANS"
        threat_id = "128363"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "rmdir \"%s\"" ascii //weight: 1
        $x_1_2 = "%d.exe" ascii //weight: 1
        $x_1_3 = "evc.php?id=dw0%d" ascii //weight: 1
        $x_1_4 = "Your system is unprotected from new version of SpyBot@MXt" ascii //weight: 1
        $x_1_5 = {53 70 79 42 6f 74 40 4d 58 74 20 69 73 20 61 20 (6d 61 6c 77 61 72 65 20 70 72 6f 67 72|74 72 6f 6a 61 6e 20 68 6f 72) 20 74 68 61 74 20 73 74 65 61 6c 73 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 61 6e 64 20 67 61 74 68 65 72 73}  //weight: 1, accuracy: Low
        $x_1_6 = "Your system is probably infected with latest version of Spyware.CyberLog-X." ascii //weight: 1
        $x_1_7 = "gatevc.php?pn=srch0p%dtotal" ascii //weight: 1
        $x_1_8 = "Your computer is infected with last version of PSW.x-Vir trojan. PSW trojans steal your private information such as: passwords, IP-address, credit card information, registration details, documents, etc." ascii //weight: 1
        $x_1_9 = "System Alert: Trojan-Spy.Win32@mx" ascii //weight: 1
        $x_1_10 = "Security Alert: NetWorm-i.Virus@fp" ascii //weight: 1
        $x_1_11 = "%d.bat" ascii //weight: 1
        $x_1_12 = "/files/get.php?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule TrojanDownloader_Win32_Zlob_ANT_128410_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ANT"
        threat_id = "128410"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 32 54 24 24 88 10 48 ff 4c 24 10 75 f0}  //weight: 1, accuracy: High
        $x_1_2 = {33 7c 24 10 c1 ef 02 47 81 fd a0 71 8e 00 89 7c 24 10 75}  //weight: 1, accuracy: High
        $x_1_3 = {33 f7 c1 ee 02 46 (81 fb|3d) a0 71 8e 00 8b fe 75}  //weight: 1, accuracy: Low
        $x_1_4 = {00 67 65 6f 72 67 69 61 20 6d 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 7a 65 72 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Zlob_AMV_128424_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.AMV"
        threat_id = "128424"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {40 89 44 24 10 [0-5] 8a ?? ?? 32 04 01 01 01 01 54 44 4c 5c 24 ?? 88 ?? 04 01 01 01 01 48 49 4a 4b ff 4c 24 10 75 f0}  //weight: 15, accuracy: Low
        $x_7_2 = {44 00 00 00 88 9c 24 ?? 01 00 00 c6 84 24 ?? 01 00 00 43}  //weight: 7, accuracy: Low
        $x_7_3 = {83 c4 08 84 c0 0f 85 ?? ?? 00 00 c6 44 24 ?? 47 c6 44 24 ?? 65 e8 ?? ?? 00 00}  //weight: 7, accuracy: Low
        $x_3_4 = {8a 44 24 29 c6 44 24 2a 72 88 44 24 2c c6 44 24 2b 6e}  //weight: 3, accuracy: High
        $x_2_5 = {67 65 6f 72 67 69 61 20 6d 64 00}  //weight: 2, accuracy: High
        $x_2_6 = {6d 69 73 73 69 6e 67 77 6f 72 6c 64 00}  //weight: 2, accuracy: High
        $x_2_7 = {7a 65 72 67 00}  //weight: 2, accuracy: High
        $x_2_8 = "__PM2_UPD__" ascii //weight: 2
        $x_2_9 = {69 65 62 74 6d 2e 65 78 65 00}  //weight: 2, accuracy: High
        $x_2_10 = {00 66 75 63 6b 00}  //weight: 2, accuracy: High
        $x_2_11 = {6d 6d 6d 00 77 74 66 00}  //weight: 2, accuracy: High
        $x_1_12 = "?N=S7P%1.1dN8K3" ascii //weight: 1
        $x_1_13 = "gate.php" ascii //weight: 1
        $x_1_14 = {64 75 6d 62 00}  //weight: 1, accuracy: High
        $x_1_15 = {25 64 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_16 = {53 6f 66 74 77 61 72 65 5c 41 70 70 6c 69 63 61 74 69 6f 6e 73 00}  //weight: 1, accuracy: High
        $x_1_17 = "__ISC" ascii //weight: 1
        $x_1_18 = "_MM_F" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 7 of ($x_1_*))) or
            ((6 of ($x_2_*) and 5 of ($x_1_*))) or
            ((7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_7_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_7_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_7_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_7_*) and 5 of ($x_2_*))) or
            ((1 of ($x_7_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_7_*) and 3 of ($x_1_*))) or
            ((2 of ($x_7_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_7_*) and 2 of ($x_2_*))) or
            ((2 of ($x_7_*) and 1 of ($x_3_*))) or
            ((1 of ($x_15_*) and 2 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_2_*))) or
            ((1 of ($x_15_*) and 1 of ($x_3_*))) or
            ((1 of ($x_15_*) and 1 of ($x_7_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_ANV_128560_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ANV"
        threat_id = "128560"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 84 24 4e 05 00 00 52 c6 84 24 4d 05 00 00 55 c6 84 24 4f 05 00 00 4c c7 44 24 24 04 01 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_ANW_128667_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ANW"
        threat_id = "128667"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 00 00 43 0b 00 88 9c 24 ?? 01 00 00 c6 84 24}  //weight: 2, accuracy: Low
        $x_2_2 = {01 00 00 65 c6 84 24 ?? 01 00 00 72 e8 04 00 c6 84 24}  //weight: 2, accuracy: Low
        $x_1_3 = {8a 04 0e 32 44 24 14 88 01 49 ff 4c 24 0c 75 f0}  //weight: 1, accuracy: High
        $x_1_4 = {00 6d 6d 6d 00 77 74 66 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_CH_129030_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!CH"
        threat_id = "129030"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 65 61 6c 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {04 00 53 00 45 00 47 00 48 00 04 00 53 00 52 00 54 00 47 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 6c 65 6f 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {04 00 52 00 45 00 46 00 53 00 00 00 00 ?? ?? ?? 28}  //weight: 1, accuracy: Low
        $x_1_5 = {6d 67 72 74 2e 64 6c 6c 00 04 00 01 00 02 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Zlob_ZXJ_130076_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ZXJ"
        threat_id = "130076"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4e 67 bd 72 fc c9 84 70 56 57 9d da 8d 28 01 ab c4 8e 23 b4 70 00 00 00 80 bf 33 29 36 7b d2 11 b2 0e 00 c0 4f 98 3e 60}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_CI_130778_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!CI"
        threat_id = "130778"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 64 6d 64 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {04 00 4d 00 55 00 44 00 41 00 04 00 53 00 52 00 54 00 47 00}  //weight: 1, accuracy: High
        $x_1_3 = {77 64 73 63 6b 2e 64 6c 6c 00 04 00 01 00 02 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6d 64 77 64 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 1, accuracy: High
        $x_1_5 = {04 00 4a 00 49 00 52 00 41 00 00 00 00 ?? ?? ?? 28}  //weight: 1, accuracy: Low
        $x_1_6 = {67 2d 61 76 61 73 74 21 00 00 00 00 67 61 72 62 61 67 65 77 6f 72 6c 64}  //weight: 1, accuracy: High
        $x_1_7 = {a2 ae a9 bf a6 e5 ae b3 ae}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Zlob_AMZ_131723_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.AMZ"
        threat_id = "131723"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 04 0a 32 44 24 20 88 01 49 ff 4c 24 10 75 f0}  //weight: 5, accuracy: High
        $x_5_2 = {25 ff 7f 00 00 c3 1d 00 a1 ?? ?? ?? ?? 69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? 33 c0 66 a1}  //weight: 5, accuracy: Low
        $x_1_3 = "gov-avast!" ascii //weight: 1
        $x_1_4 = {69 64 65 6f 00}  //weight: 1, accuracy: High
        $x_1_5 = "kingoftheworld" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_AMZ_131724_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AMZ"
        threat_id = "131724"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "gov-avast!kin" ascii //weight: 2
        $x_1_2 = "theworld" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_CK_131753_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!CK"
        threat_id = "131753"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " NAV guys" ascii //weight: 1
        $x_1_2 = "VC20XC00" ascii //weight: 1
        $x_1_3 = "Nam2" ascii //weight: 1
        $x_1_4 = "IEVU" ascii //weight: 1
        $x_3_5 = {c1 ee 02 46 [0-2] 28 61 5b 02}  //weight: 3, accuracy: Low
        $x_3_6 = {8a 14 01 32 54 24 24 88 10 48 ff 4c 24 10 75 f0}  //weight: 3, accuracy: High
        $x_3_7 = {8a 04 0a 32 44 24 20 88 01 49 ff 4c 24 10 75 f0}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_CL_131767_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!CL"
        threat_id = "131767"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "105"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 100, accuracy: High
        $x_2_2 = "814B-4839" ascii //weight: 2
        $x_2_3 = "0EBC-4D89" ascii //weight: 2
        $x_1_4 = "geList_Add" ascii //weight: 1
        $x_1_5 = "20XC00" ascii //weight: 1
        $x_1_6 = "v - nash" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_ZXK_132149_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ZXK"
        threat_id = "132149"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 76 61 73 74 21 [0-3] 6b 69 6e}  //weight: 1, accuracy: Low
        $x_1_2 = "ftheworld" ascii //weight: 1
        $x_1_3 = "394A3" ascii //weight: 1
        $x_1_4 = "VC20XC00" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_DA_132353_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!DA"
        threat_id = "132353"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 10
        $x_10_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 10
        $x_10_3 = "pyware" ascii //weight: 10
        $x_10_4 = "ool.com/re" ascii //weight: 10
        $x_1_5 = {03 c8 40 89 44 24 10 8a 04 0a 32 44 24 20 88 01 49 ff 4c 24 10 75}  //weight: 1, accuracy: High
        $x_1_6 = {33 f5 c1 ee 02 46 81 ff ?? ?? ?? 00 89 74 24 10 75 ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_7 = "{3B7AAEB1-9F3D-4491-9C06-C7165CA8D058}" ascii //weight: 1
        $x_1_8 = "{9034A523-D068-4BE8-A284-9DF278BE776E}" ascii //weight: 1
        $x_1_9 = "{DAED9266-8C28-4C1C-8B58-5C66EFF1D302}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_BAF_132360_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.BAF"
        threat_id = "132360"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "%s/test/?c=%1.1d%d%1.1d" ascii //weight: 3
        $x_3_2 = "%s/doc.php?type=file" ascii //weight: 3
        $x_2_3 = "_STARTED_" ascii //weight: 2
        $x_2_4 = "%d.bat" ascii //weight: 2
        $x_2_5 = "\\myv.ico" ascii //weight: 2
        $x_2_6 = "user_pref(\"browser.search.selectedEngine\", \"Search\")," ascii //weight: 2
        $x_2_7 = "%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Ranges\\Range%d" ascii //weight: 2
        $x_1_8 = "scanner.powerantivirus-2009.com" ascii //weight: 1
        $x_1_9 = "ieantivirus.com" ascii //weight: 1
        $x_1_10 = "onlinevideosoftex.com" ascii //weight: 1
        $x_1_11 = "codechost.com" ascii //weight: 1
        $x_1_12 = "216.239.*.*" ascii //weight: 1
        $x_1_13 = "205.188.*.*" ascii //weight: 1
        $x_1_14 = "77.92.88.*" ascii //weight: 1
        $x_1_15 = "91.203.70.*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_BAG_132363_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.BAG"
        threat_id = "132363"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c6 44 24 ?? 76 c6 44 24 ?? 64 c6 44 24 ?? 6f c6 44 24 ?? 2e 88 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {52 c6 84 24 ?? ?? 00 00 55 c6 84 24 ?? ?? 00 00 4c c7 44 24 24 04 01 00 00 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = {65 c6 44 24 ?? 73 88 5c 24 ?? c6 44 24 ?? 72 c6 44 24 ?? 6e c6 44 24 ?? 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Zlob_BAH_132640_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.BAH"
        threat_id = "132640"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {40 89 44 24 10 [0-5] 8a ?? ?? 32 04 01 01 01 01 54 44 4c 5c 24 ?? 88 ?? 04 01 01 01 01 48 49 4a 4b ff 4c 24 10 75 f0}  //weight: 8, accuracy: Low
        $x_8_2 = {49 48 75 f3 0f 00 [0-5] 40 8a 14 ?? 32 54 24 ?? 88}  //weight: 8, accuracy: Low
        $x_8_3 = {53 c6 44 24 ?? 4f c6 44 24 ?? 54 c6 44 24 ?? 5f c6 44 24 ?? 50 c6 44 24 ?? 5f}  //weight: 8, accuracy: Low
        $x_2_4 = {47 c6 44 24 ?? 65}  //weight: 2, accuracy: Low
        $x_2_5 = {65 c6 44 24 ?? 72}  //weight: 2, accuracy: Low
        $x_1_6 = {64 65 6f 50 6c 00}  //weight: 1, accuracy: High
        $x_1_7 = "%d.bat" ascii //weight: 1
        $x_2_8 = "NAV guys," ascii //weight: 2
        $x_2_9 = "SA_UPD" ascii //weight: 2
        $x_2_10 = "%1.1dN8K3" ascii //weight: 2
        $x_2_11 = {5a 45 45 44 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_8_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*))) or
            ((2 of ($x_8_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_KDA_132819_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.KDA!dll"
        threat_id = "132819"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "65CA8D05" ascii //weight: 1
        $x_1_2 = {2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_3 = "VC20X" ascii //weight: 1
        $x_1_4 = "lorer." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_AOM_132987_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.AOM"
        threat_id = "132987"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {5f c6 44 24 ?? 52 c6 44 24 ?? 45 c6 44 24 ?? 44 c6 44 24 ?? 44 c6 44 24 ?? 5f}  //weight: 4, accuracy: Low
        $x_3_2 = {47 c6 84 24 ?? 01 00 00 54 07 00 c6 84 24 ?? 01 00 00}  //weight: 3, accuracy: Low
        $x_3_3 = {45 88 9c 24 ?? 01 00 00 ff d5 07 00 c6 84 24 ?? 01 00 00}  //weight: 3, accuracy: Low
        $x_2_4 = {2e 64 6c 6c 00 67 65 6f 67 72 61 70 68 79 00 67 6f 74 6f 73 63 68 6f 6f 6c 00}  //weight: 2, accuracy: High
        $x_1_5 = "SearchScopes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_CP_133012_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!CP"
        threat_id = "133012"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {e9 29 6b 9d 69 3e ?? 35 31 b5 e4 1d 31 3d bb 39 f7 ec ea 43 06 15 a3 e8 7e bd 49 ea 69 76 21 ba ba 98 26 c8}  //weight: 3, accuracy: Low
        $x_2_2 = "A284-9DF278" ascii //weight: 2
        $x_2_3 = "DAED9266" ascii //weight: 2
        $x_1_4 = {49 45 20 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_CQ_133061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!CQ"
        threat_id = "133061"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {30 22 20 21 26 3b 20 3d 30 3b 2a 3d 22 26 21 2e 06 30}  //weight: 10, accuracy: High
        $x_10_2 = "D358-48A3-A5C7" ascii //weight: 10
        $x_1_3 = " hptr" ascii //weight: 1
        $x_1_4 = "9CA68B" ascii //weight: 1
        $x_1_5 = "GOMODRI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_CT_133062_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!CT"
        threat_id = "133062"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {35 31 00 51 75 69 63 6b 54 69 6d 65}  //weight: 10, accuracy: High
        $x_1_2 = "$s/get.php?id=" ascii //weight: 1
        $x_1_3 = "d with adwa" ascii //weight: 1
        $x_1_4 = "__PM_MINI_STO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_CU_133165_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!CU"
        threat_id = "133165"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 4c 24 10 75 f0 0a 00 8a (04|1c|0c|14) ?? 32 (44|5c|4c|54) 24 ?? 88}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 01 68 00 04 00 00 ff 15 ?? ?? ?? ?? 48 48 f7 d8 1b c0 f7 d0 23 44 24 10 3b ?? 89 44 24 10 75 18 8d 84 24 ?? ?? 00 00 50 ff 74 24 18 ff 54 24 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_AOP_133427_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.AOP"
        threat_id = "133427"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6-D358-48A3" ascii //weight: 1
        $x_1_2 = "AD9CA68B52CY" ascii //weight: 1
        $x_1_3 = "17C69-BF55-6B" ascii //weight: 1
        $x_1_4 = "get.php?id=803466417" ascii //weight: 1
        $x_1_5 = "QuickTime TaskgSOFTW" ascii //weight: 1
        $x_1_6 = "d with adwa" ascii //weight: 1
        $x_1_7 = "GOMODRIL" wide //weight: 1
        $x_1_8 = "ZVERUSHKA" wide //weight: 1
        $x_1_9 = "SAAKASHV" wide //weight: 1
        $x_10_10 = {74 15 8b 77 40 03 f0 eb 09 8b 1e 03 d8 01 03 83 c6 04 83 3e 00 75 f2 8b 74 24 24 8b de 03 f0 b9 01 00 00 00 33 c0 f0 0f b1 4f 30 75 f7 ac}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_AOS_134059_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.AOS"
        threat_id = "134059"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c6 84 24 4a 05 00 00 52 c6 84 24 49 05 00 00 55 c6 84 24 4b 05 00 00 4c c7 44 24 28 04 01 00 00 ff 15}  //weight: 5, accuracy: High
        $x_4_2 = {05 00 00 52 c6 84 24 ?? 05 00 00 55 c6 84 24 ?? 05 00 00 4c c7 44 24 ?? 04 01 00 00 ff 15}  //weight: 4, accuracy: Low
        $x_1_3 = {78 00 65 00 00 00 00 00 2e 00 25 00 73 00 25 00 73 00 00 00 25 00 64 00 00 00 00 00 25 00 73 00 5c 00 25 00 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 73 65 63 75 72 69 74 79 69 6e 74 65 72 6e 65 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 68 72 6e 25 64 2e 63 6d 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_ANP_134392_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!ANP"
        threat_id = "134392"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\lubric.dll" ascii //weight: 1
        $x_1_2 = "Software\\WebMediaViewer" ascii //weight: 1
        $x_1_3 = "{F00E59F9" ascii //weight: 1
        $x_1_4 = "Web Media Viewer Installer already installed" ascii //weight: 1
        $x_1_5 = "mutobronc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_ANQ_134393_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!ANQ"
        threat_id = "134393"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 9c fc e8 00 00 00 00 5f 81 ef ?? ?? ?? ?? 8b c7 81 c7 ?? ?? ?? ?? 3b 47 2c 75 02 eb 36 89 47 2c b9 a8 00 00 00 eb 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {6c 75 62 72 69 63 2e 64 6c 6c 00 63 61 6e 74 6f 00 6d 75 74 6f 62 72 6f 6e 63 00 70 65 79 64 65 79 72 61 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_ANO_134506_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!ANO"
        threat_id = "134506"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "govno-avast!" ascii //weight: 2
        $x_2_2 = "WebMediaViewer" ascii //weight: 2
        $x_1_3 = {70 69 64 6f 72 61 73 79 76 73 68 74 61 62 65 00 34 30 32 00}  //weight: 1, accuracy: High
        $x_2_4 = "CreateToolhelp32Snapshot" ascii //weight: 2
        $x_2_5 = "VirtualProtect" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_APB_134687_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.APB"
        threat_id = "134687"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\willower.dll" ascii //weight: 1
        $x_1_2 = "Software\\WebMediaViewer" ascii //weight: 1
        $x_1_3 = "{F00E59F9" ascii //weight: 1
        $x_1_4 = "Web Media Viewer Installer already installed" ascii //weight: 1
        $x_1_5 = "bieminteros" ascii //weight: 1
        $x_1_6 = "through our version checking/update system. These components include:" ascii //weight: 1
        $x_1_7 = "(c) Security software: A third party anti-virus/anti-spyware application." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Zlob_CV_135158_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!CV"
        threat_id = "135158"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fd 6f 0f b7 73 1e 6f 72 61 67 65 32 30 30 39 43 d6 de fe 1b 8d 62 6f 70 6c 61 79 65 72 2e c7 74}  //weight: 1, accuracy: High
        $x_1_2 = {f6 0a 5f 76 2f 76 69 64 65 6f d6 0d 7b 27 56 0a 2f 27 74 6a 1f 16 fb ff 74 2f 3f 63 3d 25 31 2e 31 64 25 64 06 ef 53 70 79 d6 fd bb db 77 61 8b}  //weight: 1, accuracy: High
        $x_1_3 = {ff 87 00 90 00 6d 79 63 2e 69 63 6f 00 25 73 be fd ff ed 2f 64 6f 0a 70 68 70 3f 74 79 70 65 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_CW_135159_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!CW"
        threat_id = "135159"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e9 67 9f ff ff 30 30 30 31 65 63 32 64 30 30 30 30 30 30 30 36 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 2d 7a 6c 6c 53 74 7d 6e 67 ab a7 d7 0c ed b7 4c 61 79 4e 61 6d ef 96 df 03 6d 8e 18 7f 46 7c}  //weight: 1, accuracy: High
        $x_1_3 = {32 34 03 34 45 45 ad 7b a1 dd 0c bf 4e 00 7b 28 93 78 65 63 1b ad e1 f7 ee 68 03 63 74 2e 70 0b 72 65 5b 69 03 6b b1 ed bb 2f 08 70 3a 2f 2f 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_AAA_135635_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AAA"
        threat_id = "135635"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tc\\svch;t\\" ascii //weight: 1
        $x_1_2 = "rb+taskmgrV" ascii //weight: 1
        $x_1_3 = "http://www.rabbitsafe.cn/test.exe" ascii //weight: 1
        $x_1_4 = "\\drivers\\svchost" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_AAB_135636_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AAB"
        threat_id = "135636"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "81.0.250.47" ascii //weight: 1
        $x_1_2 = "%s?version=%s&cn=%s&contype=%d&pid=%d" ascii //weight: 1
        $x_1_3 = "ClickNum" ascii //weight: 1
        $x_1_4 = "%s?id_num=%d&text=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_AAC_135637_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.gen!AAC"
        threat_id = "135637"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "from=P-233268&backurl=" ascii //weight: 1
        $x_1_2 = "?pid=g842329" ascii //weight: 1
        $x_1_3 = "win87rm.dll" ascii //weight: 1
        $x_1_4 = "\\ie\\realplayer10\\Hgj.pas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_APK_138198_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.APK"
        threat_id = "138198"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7d 14 8b 55 08 03 55 fc 8a 02 2c ?? 8b 4d 08 03 4d fc 88 01}  //weight: 2, accuracy: Low
        $x_2_2 = "i5i.in/xd" ascii //weight: 2
        $x_2_3 = "&guid=" wide //weight: 2
        $x_1_4 = {69 70 64 6c 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {62 69 74 73 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zlob_APK_138198_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.APK"
        threat_id = "138198"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {96 02 10 00 00 00 00 c7 05 ?? 96 02 10 00 00 00 00 c7 05 ?? 96 02 10 00 00 00 00 c7 05 ?? 96 02 10 00 00 00 00 c7 05 ?? 96 02 10 00 00 00 00 c7 05 ?? 96 02 10 00 00 00 00 c6 05 ?? 96 02 10 00 c7 05 ?? 96 02 10 00 00 00 00 c7 05 ?? 96 02 10 00 00 00 00 c6 05 ?? 96 02 10 f1 8b 0d ?? 9b 02 10 89 0d ?? 96 02 10 c7 05 ?? 96 02 10 00 00 00 00 c7 05 ?? 96 02 10 00 00 00 00 c7 05 ?? 96 02 10 00 00 00 00 c7 05 ?? 96 02 10 00 00 00 00 c7 05 ?? 96 02 10 00 00 00 00 c7 05 ?? 96 02 10 00 00 00 00 c6 05 ?? 96 02 10 00 c7 05 ?? 96 02 10 00 00 00 00 c7 05 ?? 96 02 10 00 00 00 00 c6 05 ?? 96 02 10 f2 8b 15 ?? 9b 02 10 89 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d1 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 8b 4d [0-32] 8b c1 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 8b 4d}  //weight: 1, accuracy: Low
        $x_1_3 = {00 46 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 00 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 00 00 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 00 00 00 00 47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_APM_139469_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.APM"
        threat_id = "139469"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 1c 28 40 83 f8 ?? 7c f7 c6 04 28 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 52 38 8d 4c 24 0c 51 50 ff d2 8b 44 24 0c 83 f8 06 74 1f 83 f8 04 74 05 83 f8 05 75 d8}  //weight: 1, accuracy: High
        $x_1_3 = {62 69 74 73 2e 64 6c 6c 00 41 64 64 52 65 67 69 73 74 72 79 00 44 6f 77 6e 6c 6f 61 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {7d 14 8b 55 08 03 55 fc 8a 02 2c ?? 8b 4d 08 03 4d fc 88 01 eb db}  //weight: 1, accuracy: Low
        $x_1_5 = {83 ea 05 89 55 f8 8b 45 08 89 45 fc 8b 4d fc c6 01 e9 6a 04}  //weight: 1, accuracy: High
        $x_1_6 = {69 70 64 6c 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Zlob_APN_139480_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.APN"
        threat_id = "139480"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 4f 4d 53 50 45 43 00 4f 70 65 6e 00 00 00 00 20 3e 20 6e 75 6c 00 00 2f 63 20 64 65 6c 20 00}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 8d 85 ?? fe ff ff 50 ff 75 ?? 6a 04 ff 75 ?? ff 75 ?? ff 75 ?? ff 75 ?? c3 5f 5e 5b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_BBD_142273_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.BBD"
        threat_id = "142273"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 01 c6 85 ?? ?? ff ff 52 c6 85 ?? ?? ff ff 6f c6 85 ?? ?? ff ff 6f c6 85 ?? ?? ff ff 6b c6 85 ?? ?? ff ff 49 c6 85 ?? ?? ff ff 45 c6 85 ?? ?? ff ff 2f c6 85 ?? ?? ff ff 31 c6 85 ?? ?? ff ff 2e c6 85 ?? ?? ff ff 30}  //weight: 1, accuracy: Low
        $x_1_2 = "EnumProcesses" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_4 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 00 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "CreateRemoteThread" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_APT_146072_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.APT"
        threat_id = "146072"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_AD1CompleteRemoveNow_" wide //weight: 1
        $x_1_2 = "_browser_redirect_event_" wide //weight: 1
        $x_1_3 = "/get-last-update.php?sid=0&aid=0&said=0&pn=&config=cn" wide //weight: 1
        $x_1_4 = "www.thenmnetwork.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zlob_ZXP_249573_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zlob.ZXP!bit"
        threat_id = "249573"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zlob"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 89 04 ?? e8 ?? ?? ?? ?? 39 45 ?? 73 40 8b 75 ?? 81 c6 ?? ?? ?? ?? 8b 45 08 8b 5d ?? 01 c3 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 c2 8b 45 ?? 89 d1 ba 00 00 00 00 f7 f1 0f b6 92 ?? ?? ?? ?? 0f b6 03 28 d0 88 06 8d 45 ?? ff 00 eb b0}  //weight: 1, accuracy: Low
        $x_1_2 = {74 63 c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 44 24 ?? 8b 45 ?? 89 04 ?? e8 ?? ?? ?? ?? 83 ec 08 89 45 ?? 8b 45 ?? 85 c0 74 2d c7 44 24 ?? 00 00 00 00 c7 44 24 ?? 00 00 00 00 8b 45 0c 89 44 24 ?? 8b 45 08 89 44 24 ?? c7 04 ?? 00 00 00 00 8b 45 ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

