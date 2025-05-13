rule Trojan_Win32_Small_P_2147509960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.P"
        threat_id = "2147509960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 08 83 c0 01 84 c9 75 f7 8d 7c 24 20 2b c2 83 c7 ff [0-8] 8a 4f 01 83 c7 01 84 c9 75 f6}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 07 8b 08 8b 49 04 03 c8 8b 51 10 81 e2 ff f9 ff ff 53 81 ca 00 08 00 00 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_KJ_2147593301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.KJ"
        threat_id = "2147593301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "304"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {55 89 e5 8b 45 0c 83 f8 01 75 28 8b 45 08 a3 ?? ?? 40 00 e8 23 05 00 00 a1 ?? ?? 40 00 09 c0 74 0b ff 35 ?? ?? 40 00 e8 ?? ?? 00 00 b8 01 00 00 00 eb 13 83 f8 00 75 0c e8 ?? ?? 00 00 b8 01 00 00 00 eb 02 31 c0 c9 c2 0c 00}  //weight: 100, accuracy: Low
        $x_100_2 = {55 89 e5 83 ec 08 56 8d 75 f8 56 6a 08 68 ?? ?? 40 00 ff 35 ?? ?? 40 00 6a ff ff 15 ?? ?? 40 00 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 68 ?? ?? 40 00 50 ff 15 ?? ?? 40 00 a3 ?? ?? 40 00 ff 75 1c ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff 15 ?? ?? 40 00 89 45 fc 56 6a 06 68 ?? ?? 40 00 ff 35 ?? ?? 40 00 6a ff ff 15 ?? ?? 40 00 5e 8b 45 fc c9 c2 18 00}  //weight: 100, accuracy: Low
        $x_100_3 = "SYSHOST.DLL" ascii //weight: 100
        $x_1_4 = "CallNextHookEx" ascii //weight: 1
        $x_1_5 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_1_7 = "ReadProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_SC_2147594016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.SC"
        threat_id = "2147594016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 1c 24 80 3b 43 74 0a 6a 32 59 b0 ?? 30 03 43 e2 fb 66 33 db ff 93 00 20 00 00 33 c0 40 c9 c2 0c 00}  //weight: 10, accuracy: Low
        $x_10_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 53 79 73 74 65 6d 5c 4d 53 [0-8] 2e 44 4c 4c}  //weight: 10, accuracy: Low
        $x_10_3 = "WinExec" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_BC_2147598153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.BC"
        threat_id = "2147598153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 c0 68 47 00 e8 a5 2f f9 ff 84 c0 0f 84 8c 00 00 00 b8 f0 68 47 00 e8 93 2f f9 ff 84 c0 75 7e ba c0 68 47 00 b8 ec 9f 47 00 e8 b4 d0 f8 ff b8 ec 9f 47 00 e8 46 ce f8 ff e8 71 cc f8 ff 8d 55 b8 b8 1c 69 47 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_ZDA_2147603630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.ZDA"
        threat_id = "2147603630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 6f 00 00 ff ff ff ff 04 00 00 00 6b 69 6c 6c 00 00 00 00 ff ff ff ff 04 00 00 00 6d 73 67 73 00 00 00 00 ff ff ff ff 03 00 00 00 73 79 73 00 ff ff ff ff 01 00 00 00 30 00 00 00 ff ff ff ff 04 00 00 00 78 78 6a 67 00 00 00 00 ff ff ff ff 03 00 00 00 72 75 6e 00 ff ff ff ff 03 00 00 00 6d 73 67 00 ff ff ff ff 03 00 00 00 76 65 72 00 ff ff ff ff 06 00 00 00 6d 79 64 6f 77 6e 00 00 ff ff ff ff 03 00 00 00 31 38 30 00 ff ff ff ff 04 00 00 00 70 7a 6a 67 00 00 00 00 ff ff ff ff 01 00 00 00 32 00 00 00 ff ff ff ff 05 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {64 65 6c 61 79 00 00 00 ff ff ff ff 07 00 00 00 7a 68 71 62 5f 64 66 00 ff ff ff ff 3f 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 72 75 6e 00 ff ff ff ff 07 00 00 00 53 74 61 72 74 75 70 00 ff ff ff ff 40 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 00 00 00 00 ff ff ff ff 0b 00 00 00 5c 64 66 7a 68 71 62 2e 65 78 65 00 ff ff ff ff 02 00 00 00 66 6e 00 00 ff ff ff ff 06 00 00 00 64 65 6c 65 74 65 00 00 ff ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Small_AG_2147606966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.AG"
        threat_id = "2147606966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 75 6e 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e}  //weight: 1, accuracy: High
        $x_1_2 = {57 69 6e 64 6f 77 73 20 53 65 72 76 69 63 65 00 00 00 00 20 2d 73 65 72 76 69 63 65}  //weight: 1, accuracy: High
        $x_1_3 = "%s\\ds%c%c%c.%s" ascii //weight: 1
        $x_1_4 = "SFFDJDSERY$45645" ascii //weight: 1
        $x_1_5 = "des_bot.exe" ascii //weight: 1
        $x_1_6 = "_WorkProc@4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_CD_2147607450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.CD"
        threat_id = "2147607450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GET ^%$%^&**(*((&&*^&&%%^&*(*&$%$" ascii //weight: 1
        $x_1_2 = "#%d<<<<<I@C<<<<<%s!" ascii //weight: 1
        $x_1_3 = {20 3e 20 6e 75 6c 00 00 20 2f 63 20 20 64 65 6c 20}  //weight: 1, accuracy: High
        $x_1_4 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 00 00 00 00 48 61 63 6b}  //weight: 1, accuracy: High
        $x_1_5 = "OpenSCManagerA" ascii //weight: 1
        $x_1_6 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_AM_2147609778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.AM"
        threat_id = "2147609778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 f8 e8 ?? ?? ff ff 50 e8 ?? ?? ff ff 8d 45 f4 e8 ?? ?? ff ff ff 75 f4 68 ?? ?? 40 00 6a 00 68 ?? ?? 40 00 8d 45 fc ba 04 00 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 10
        $x_10_3 = "{3FDEB171-8F86-FF11-0001-69B8DB553683}" ascii //weight: 10
        $x_5_4 = {73 79 73 74 65 6d 33 32 5c 73 79 73 74 65 6d 74 00 00 00 00 ff ff ff ff 04 00 00 00 2e 64 6c 6c 00 00 00 00 ff ff ff ff 04 00 00 00 64 6c 6c 31 00}  //weight: 5, accuracy: High
        $x_5_5 = {63 3a 5c 61 61 2e 62 61 74 00 00 00 ff ff ff ff 05 00 00 00 64 65 6c 20 22 00 00 00 ff ff ff ff 01 00 00 00 22 00 00 00 ff ff ff ff 06 00 00 00 64 65 6c 20 25 30 00 00 63 3a 5c 5c 61 61 2e 62 61 74 00 00 6f 70 65 6e 00}  //weight: 5, accuracy: High
        $x_1_6 = "FindResourceA" ascii //weight: 1
        $x_1_7 = "LoadResource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Small_CE_2147621793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.CE"
        threat_id = "2147621793"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://gpt0.ru/web/rtcom" ascii //weight: 1
        $x_1_2 = {68 c8 00 00 00 68 ?? ?? 40 00 e8 ?? ?? 00 00 68 ?? ?? 40 00 68 ?? ?? 40 00 e8 ?? ?? 00 00 68 ?? ?? 40 00 68 ?? ?? 40 00 e8 ?? ?? 00 00 83 f8 ff 74 08 6a 00 e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 01 6a 00 68 ?? ?? 40 00 ff 35 ?? ?? 40 00 e8 ?? ?? 00 00 68 ac 33 40 00 e8 ?? ?? 00 00 6a 05 68 ?? ?? 40 00 e8 ?? 00 00 00 6a 00 e8 01 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_CF_2147622759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.CF"
        threat_id = "2147622759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 6f 6f 6b 32 2e 64 6c 6c 00 48 6f 6f 6b 49 6e 69 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {56 6a 01 68 00 06 00 00 68 ?? ?? 40 00 e8 ?? ?? 00 00 56 e8 ?? ?? 00 00 83 c4 14 8d 94 24 ?? ?? 00 00 52 ff 15 ?? ?? 40 00 8d 44 24 ?? 8d 8c 24 ?? ?? 00 00 50 51 55 55 6a 03 55 55 55 8d 94 24 ?? ?? 00 00 55 52 ff 15 ?? ?? 40 00 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_3 = {ff d5 83 fb 02 7f 11 8b 84 24 ?? ?? 00 00 80 cc 01 89 84 24 ?? ?? 00 00 8b 54 24 ?? 8d 8c 24 ?? ?? 00 00 51 52 ff d7 8b 44 24 ?? 8b 4c 24 ?? 68 02 00 01 00 50 51 ff 15 ?? ?? 40 00 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_CH_2147623981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.CH"
        threat_id = "2147623981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 84 c0 75 fb 83 ee 05 81 0e 20 20 20 20 81 3e 2e 65 78 65 0f ?? ?? ?? 00 00 0f b7 46 fe 0d 20 20 00 00 3d 71 71 00 00 0f ?? ?? ?? 00 00 8b 46 f9 0d 20 20 20 20 3d 74 68 75 6e 0f ?? ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {0b c9 74 24 f7 43 24 00 00 00 20 74 1b 2b 4b 08 81 f9 24 04 00 00 76 10 81 4b 24 00 00 00 c0 81 43 08 24 04 00 00 eb 1b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_CI_2147624290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.CI"
        threat_id = "2147624290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 1b 46 0d 53 89 d1 68 3e df 4e 00 81 fe 1b 46 0d 53 75 ec 03 0d 42 94 40 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 eb 99 00 00 00 81 e9 11 54 08 7a 81 c3 b5 00 00 00 8b 1b 03 15 ?? ?? 40 00 83 c9 16 b8 28 00 00 00 83 e8 20 01 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_PU_2147624994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.PU"
        threat_id = "2147624994"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "|q=%s&client=pub-%I64u&forid=1&prog=aff&channel=%I64u&ie=UTF8&oe=UTF8&hl=zh-CN&sa=Google|client=pub-9133687207262754|client=pub-0786758448562656|gg-%s.haode81.com|c-hi|c-lo|" ascii //weight: 1
        $x_1_2 = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d [0-5] 55 52 4c 3d 68 74 74 70 3a 2f 2f 77 77 77 2e 6b 75 32 30 30 39 2e 63 6f 6d 2f 3f 46 61 76 6f 72 69 74 65 73 [0-5] 7c 55 53 45 52 50 52 4f 46 49 4c 45 7c 5c 46 61 76 6f 72 69 74 65 73 5c}  //weight: 1, accuracy: Low
        $x_1_3 = {67 6f 6f 67 6c 65 2e 7c 2e 67 6f 6f 67 6c 65 73 79 6e 64 69 63 61 74 69 6f 6e 2e 7c 2e 68 61 6f 64 65 38 31 2e 7c 65 73 65 74 2e 7c 70 61 67 65 61 64 32 2e 67 6f 6f 67 6c 65 73 79 6e 64 69 63 61 74 69 6f 6e 2e 63 6f 6d 2f 70 61 67 65 61 64 2f 73 68 6f 77 5f 73 64 6f 2e 6a 73 7c 68 74 74 70 3a 2f 2f 77 77 77 2e [0-10] 2e 63 6f 6d 2f 7c 73 65 61 72 63 68 7c 73 74 61 72 74 7c 48 6f 73 74 7c 52 65 66 65 72 65 72 7c 43 6f 6f 6b 69 65 7c 41 63 63 65 70 74 2d 45 6e 63 6f 64 69 6e 67 7c 47 45 54 20 2f 6b 2e 74 78 74 20 48 54 54 50 2f 31 2e 30 0d 0a 48 4f 53 54 3a 20 77 77 77 2e 75 6e 69 6f 6e 38 38 38 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_4 = "bholibs.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_GL_2147637767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.GL"
        threat_id = "2147637767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%USERPROFILE%\\Application Data\\~" ascii //weight: 1
        $x_1_2 = {3e 48 62 68 6f 7e 76 49 74 74 6f 3e 47 48 62 68 6f 7e 76 28 29 47 49 6e 75 7f 77 77 28 29 35 7e 63 7e}  //weight: 1, accuracy: High
        $x_1_3 = "360sd;360rp;360deepscan;DSMain;krnl360svc;egui;ekrn;kissvc;kswebshield;ZhuDongFangYu;" ascii //weight: 1
        $x_1_4 = {2e 74 78 74 00 00 00 00 ff ff ff ff 08 00 00 00 4f 48 48 62 68 50 72 6f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_GO_2147639891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.GO"
        threat_id = "2147639891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\hdp.exe" ascii //weight: 1
        $x_1_2 = ".henbang.net" ascii //weight: 1
        $x_1_3 = "%s\\henbangtemp" ascii //weight: 1
        $x_1_4 = "%s\\distributer.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_GP_2147639892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.GP!dll"
        threat_id = "2147639892"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Z8=;XjmnFdeHgjxx" ascii //weight: 1
        $x_1_2 = "XDM_\\JYNWW8=;Xjmn" ascii //weight: 1
        $x_1_3 = {c3 bc bd a3 00}  //weight: 1, accuracy: High
        $x_1_4 = {38 3d 3b 7f 79 6a 72 25 6e 73 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = {7b 41 43 43 41 45 32 44 32 2d 30 35 ?? ?? 2d ?? ?? ?? ?? 2d 41 34 33 45 2d ?? ?? 44 31 38 42 42 37 39 39 ?? ?? 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_DJ_2147642561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.DJ"
        threat_id = "2147642561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 73 61 73 73 2e 65 78 65 00 00 00 46 61 69 6c 20 54 6f 20 63 72 65 61 74 65 20 53 6e 61 70 20 53 68 6f 74}  //weight: 1, accuracy: High
        $x_1_2 = "Is GodMode:" ascii //weight: 1
        $x_1_3 = "Fail Error!" ascii //weight: 1
        $x_1_4 = "root$ " ascii //weight: 1
        $x_1_5 = {8b ca c1 e2 07 c1 e9 19 0b ca 03 cf 8b ef 23 e9 8b d1 f7 d2 23 d3 0b d5 03 50 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_DL_2147642928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.DL"
        threat_id = "2147642928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 1a 00 00 00 f7 f1 0f b7 d2 83 c2 61 8b 85 fc f7 ff ff 66 89 94 45 04 f8 ff ff eb b1}  //weight: 1, accuracy: High
        $x_1_2 = {68 49 66 73 20 8b 85 00 f8 ff ff 50 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = {66 c7 85 8e fb ff ff 6d 00 66 c7 85 90 fb ff ff 73 00 66 c7 85 92 fb ff ff 76 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Small_ZZE_2147643236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.ZZE"
        threat_id = "2147643236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/alarm.php" ascii //weight: 1
        $x_1_2 = "117.59.39.72" ascii //weight: 1
        $x_1_3 = "wbrj2009.3322.org" ascii //weight: 1
        $x_1_4 = "000006F6-BFEBFBFF-0000E19C" ascii //weight: 1
        $x_1_5 = {d6 b1 cf fa c9 cc b5 c7 c2 bd c6 f7 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_EL_2147654029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.EL"
        threat_id = "2147654029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TASKKILL /F /IM winupd.exe" ascii //weight: 1
        $x_1_2 = "p0rn0" ascii //weight: 1
        $x_1_3 = "MYFUCKINGMUTEX_" ascii //weight: 1
        $x_1_4 = "\\Documents and Settings\\Administrator\\Application Data\\winupd.exe" ascii //weight: 1
        $x_1_5 = {8a 08 40 84 c9 75 f9 2b c2 8b f0 8b 07 8b 48 04 8b 44 39 18 3b c3 7e 0d 3b c6 7e 09 2b c6 8b d8 89 45 e8 eb 03 89 5d e8 8d 55 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_EO_2147655747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.EO"
        threat_id = "2147655747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hlExe" ascii //weight: 1
        $x_1_2 = "hShel" ascii //weight: 1
        $x_2_3 = "PXherPr" ascii //weight: 2
        $x_2_4 = "PXhbugg" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_EP_2147656181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.EP"
        threat_id = "2147656181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {47 c6 44 24 ?? 61 c6 44 24 ?? 6d 88 5c 24 ?? c6 44 24 ?? 44 c6 44 24 ?? 6c c6 44 24 ?? 2e 88 5c 24 ?? c6 44 24 ?? 78 88 5c 24}  //weight: 2, accuracy: Low
        $x_2_2 = "\\vbcfg.ini" ascii //weight: 2
        $x_1_3 = "QQGameDl.exe" ascii //weight: 1
        $x_1_4 = {53 6f 25 73 5c 25 73 5c 25 73 00 00 66 74 77 61 72 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Small_FG_2147667428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.FG"
        threat_id = "2147667428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 79 73 74 65 6d 2e 44 69 61 67 6e 6f 73 74 69 63 73 00 50 72 6f 63 65 73 73 00 47 65 74 50 72 6f 63 65 73 73 65 73 42 79 4e 61 6d 65 00 53 74 61 72 74 00 45 6e 76 69 72 6f 6e 6d 65 6e 74 00 45 78 69 74 00 53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 00 54 68 72 65 61 64 00 53 6c 65 65 70}  //weight: 1, accuracy: High
        $x_1_2 = {28 03 00 00 0a 0a 06 8e 69 16 30 16 72 ?? 00 00 70 28 04 00 00 0a 26 16 28 05 00 00 0a de 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_A_2147740708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.A!MTB"
        threat_id = "2147740708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Password Cracker.exe" ascii //weight: 1
        $x_1_2 = "Hotmail Hacker.exe" ascii //weight: 1
        $x_1_3 = "NetBIOS Hacker.exe" ascii //weight: 1
        $x_1_4 = "ICQ Hacker.exe" ascii //weight: 1
        $x_1_5 = "Website Hacker.exe" ascii //weight: 1
        $x_1_6 = "Keylogger.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_SA_2147744715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.SA!MSR"
        threat_id = "2147744715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NtYRJTIWLiOzkmXGXsItIWkRTeSe" ascii //weight: 1
        $x_1_2 = "Quitting" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_PB_2147752362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.PB!MTB"
        threat_id = "2147752362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "covid-19" ascii //weight: 1
        $x_1_2 = "C:\\\\HiddenFolder\\\\" wide //weight: 1
        $x_1_3 = "http://tiny.cc/updae" wide //weight: 1
        $x_1_4 = "setupk.exe" wide //weight: 1
        $x_1_5 = "Loader-1-master\\Loader" ascii //weight: 1
        $x_1_6 = "https://iplogger.org/" wide //weight: 1
        $x_1_7 = "get_DefaultCredentials" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_ADF_2147781324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.ADF!MTB"
        threat_id = "2147781324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c6 0d 11 47 00 00 c1 e0 10 0b f0 89 35 ?? ?? ?? ?? f7 d6 89 35 ?? ?? ?? ?? 5e 5f 5b c9 c3}  //weight: 5, accuracy: Low
        $x_4_2 = "URLDownloadToFileA" ascii //weight: 4
        $x_4_3 = "DeleteUrlCacheEntry" ascii //weight: 4
        $x_3_4 = "ProcessIdToSessionId" ascii //weight: 3
        $x_3_5 = "GetTempPathA" ascii //weight: 3
        $x_2_6 = "IsDebuggerPresent" ascii //weight: 2
        $x_2_7 = "DecodePointer" ascii //weight: 2
        $x_2_8 = "WTSQueryUserToken" ascii //weight: 2
        $x_2_9 = "IsNetworkAlive" ascii //weight: 2
        $x_2_10 = "GetProcessImageFileNameA" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_SIB_2147781952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.SIB!MTB"
        threat_id = "2147781952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 2b d6 8b fb 8a 0c 02 88 08 40 83 ef 01 75 ?? 33 c9 8b c1 83 e0 ?? 8a 80 ?? ?? ?? ?? 30 04 31 41 3b cb 72 ?? 8b ce e8 ?? ?? ?? ?? 64 8b 0d 30 00 00 00 89 41 08 8b 49 0c 8b 49 14 89 41 10 8b 48 3c 8b 4c 01 28 03 c8 ff d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_PA_2147786345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.PA!MTB"
        threat_id = "2147786345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Documents and Settings\\Administrator\\Application Data\\Microsoft\\msdn\\elbicho.exe" wide //weight: 1
        $x_1_2 = "CodeBlocksWindowsApp" wide //weight: 1
        $x_1_3 = "ServicioEnPruebas" wide //weight: 1
        $x_1_4 = "www.monster.es" wide //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_ADGF_2147797365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.ADGF!MTB"
        threat_id = "2147797365"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b c8 8d 04 3e 8d 04 87 03 cf 8a 04 18 46 32 45 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_AN_2147817971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.AN!MTB"
        threat_id = "2147817971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dl.kanlink.cn" wide //weight: 1
        $x_1_2 = "haozip_tiny" wide //weight: 1
        $x_1_3 = "CPAdown" wide //weight: 1
        $x_1_4 = "wscript.shell" wide //weight: 1
        $x_1_5 = "c:\\Loader" wide //weight: 1
        $x_1_6 = "scripting.filesystemobject" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_R_2147828382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.R!MTB"
        threat_id = "2147828382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\TempDir\\mw.exe" ascii //weight: 1
        $x_1_2 = "c:\\TempDir\\e.jpg" ascii //weight: 1
        $x_1_3 = "http://www.massonne.de" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_EM_2147836902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.EM!MTB"
        threat_id = "2147836902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {83 c6 04 66 ba 31 df 39 fe 7c ef 66 bf ac e1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_EM_2147836902_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.EM!MTB"
        threat_id = "2147836902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aff.rkrurein" ascii //weight: 1
        $x_1_2 = "-LIBGCCW32-EH-" ascii //weight: 1
        $x_1_3 = "smnss.exe" ascii //weight: 1
        $x_1_4 = "fzaff.rkr" ascii //weight: 1
        $x_1_5 = "fureinaf.qyy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_AF_2147838619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.AF!MTB"
        threat_id = "2147838619"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:/Users/Public/Documents/k4.exe" ascii //weight: 1
        $x_1_2 = "C:\\Users\\Public\\Documents\\TASLoginBase.dll" ascii //weight: 1
        $x_1_3 = "0user.exe" ascii //weight: 1
        $x_1_4 = "cmd.exe /c taskkill /f /t /im k4.exe" ascii //weight: 1
        $x_1_5 = "2022060125.vbe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_MA_2147840370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.MA!MTB"
        threat_id = "2147840370"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 d8 c1 e6 12 ff 45 e4 c1 e0 0c 01 f0 8b 75 d4 c1 e6 06 01 f0 8b 75 e0 01 c8 89 c1 c1 e8 10 88 04 32 39 5d e4 73 28}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_EC_2147892109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.EC!MTB"
        threat_id = "2147892109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {b8 00 00 00 00 50 b8 00 00 00 00 50 b8 ?? ?? ?? ?? 50 b8 ?? ?? ?? ?? 50 b8 ?? ?? ?? ?? 50 b8 00 00 00 00 50 e8}  //weight: 3, accuracy: Low
        $x_2_2 = {39 c1 0f 84 2e 00 00 00 8b 45 fc 89 c1 40 89 45 fc c1 e1 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_EC_2147892109_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.EC!MTB"
        threat_id = "2147892109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DisableTaskMgr" ascii //weight: 1
        $x_1_2 = "AllowProtectedRenames" ascii //weight: 1
        $x_1_3 = "SFCDisable" ascii //weight: 1
        $x_1_4 = "DisableChangePassword" ascii //weight: 1
        $x_1_5 = "Norton AntiVirus" ascii //weight: 1
        $x_1_6 = "BACTERIA.txt" ascii //weight: 1
        $x_1_7 = "VIRUSES.txt" ascii //weight: 1
        $x_1_8 = "FUNGUS.txt" ascii //weight: 1
        $x_1_9 = "SLEEP_TEST.sys" ascii //weight: 1
        $x_1_10 = "SPOOKY.sys" ascii //weight: 1
        $x_1_11 = "VAGRANT.exe" ascii //weight: 1
        $x_1_12 = "AGENT.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_HNA_2147907878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.HNA!MTB"
        threat_id = "2147907878"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 22 00 00 00 8b d9 51 83 eb 01 6b db 04 81 c3 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 33 e8 ?? ?? ?? 00 6a 04}  //weight: 1, accuracy: Low
        $x_1_2 = {51 6a 64 e8 ?? ?? ?? ?? 59 e2 f5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_ECP_2147941299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small.ECP!MTB"
        threat_id = "2147941299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8a 0c 30 2a c8 88 0c 30 40 3b c7}  //weight: 3, accuracy: High
        $x_3_2 = {8a 0c 30 80 c1 fc ?? ?? ?? ?? 2a d1 8a 0c 30 02 ca 88 0c 30 40 3b c7}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Small_11283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small"
        threat_id = "11283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://girlracer.me.uk/language/lang_english/" ascii //weight: 5
        $x_3_2 = "http://humortadela.uol.com.br" ascii //weight: 3
        $x_2_3 = "URLDownloadToFileA" ascii //weight: 2
        $x_2_4 = "ShellExecuteA" ascii //weight: 2
        $x_1_5 = ".scr" ascii //weight: 1
        $x_1_6 = ".txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Small_11283_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small"
        threat_id = "11283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://demo.dokeos.com/courses/ERIC/work/" ascii //weight: 5
        $x_2_2 = "http://humortadela.uol.com.br" ascii //weight: 2
        $x_2_3 = "link da paguina de DISTRA" ascii //weight: 2
        $x_2_4 = "O do Infectado" ascii //weight: 2
        $x_1_5 = ".scr" ascii //weight: 1
        $x_1_6 = ".txt" ascii //weight: 1
        $x_1_7 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_8 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Small_11283_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Small"
        threat_id = "11283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc a3 68 aa 40 00 c7 45 ?? 10 00 00 00 8d 45 ?? 50 8d 85 ?? f9 ff ff 50 e8 ?? dd ff ff 8d 85 ?? f9 ff ff e8}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 81 c4 ?? f8 ff ff 53 56 57 [0-1] 31 c0 50 b9 61 72 79 41 64 03 40 30 51 68 4c 69 62 72 78 0f 8b 40 0c 31 d2 8b 40 1c 8b 00 8b 40 08 eb 0d 8b 40 34 31 d2 8d 40 7c 31 d2 8b 40 3c b9 cf 6e 61 64 83 c1 7d 51 54 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

