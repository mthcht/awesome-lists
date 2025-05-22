rule Backdoor_Win32_Poison_E_2147573853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.E"
        threat_id = "2147573853"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 e3 03 83 fb 00 75 03 83 ee 10 ad 33 07 ab 43 e2 ee}  //weight: 1, accuracy: High
        $x_1_2 = {8b 46 3c 8b 54 06 78 03 d6 8b 4a 18 8b 5a 20 03 de e3 35 49 8b 34 8b 03 75 08 33 ff 33 c0 fc ac 84 c0 74 07 c1 cf 0d 03 f8 eb f4}  //weight: 1, accuracy: High
        $x_1_3 = {8b 75 08 81 e6 00 00 ff ff 66 ad 4e 4e 3d 4d 5a 00 00 74 08 81 ee 00 00 01 00 eb ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Poison_E_2147573853_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.E"
        threat_id = "2147573853"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 1b 00 00 00 43 4f 4e 4e 45 43 54 20 25 73 3a 25 69 20 48 54 54 50 2f 31}  //weight: 1, accuracy: High
        $x_1_2 = {e8 09 00 00 00 61 64 76 61 70 69 33 32 00 ff ?? ?? ?? ?? ff (89|09) ?? ?? ?? ?? ff e8 06 00 00 00 6e 74 64 6c 6c 00 ff ?? ?? ?? ?? ff 89 ?? ?? ?? ?? ff e8 07 00 00 00 75 73 65 72 33 32 00 ff}  //weight: 1, accuracy: Low
        $x_2_3 = {81 bd 30 fa ff ff 63 6b 73 3d 75 13 c7 85 30 fa ff ff 74 74 70 3d c6 86 ef 0a 00 00 02 eb 11 c7 85 30 fa ff ff 63 6b 73 3d c6 86 ef 0a 00 00 01}  //weight: 2, accuracy: High
        $x_2_4 = {56 8d 86 6b 09 00 00 50 8d 86 45 01 00 00 50 ff 96 fd 00 00 00 e8 ?? 00 00 00 77 73 32 5f 33 32 00 58 50 ff 96 9d 00 00 00 ?? 86 c3 0a 00 00 e8 3a 00 00 00 e1 60}  //weight: 2, accuracy: Low
        $x_3_5 = {e8 08 00 00 00 61 64 76 70 61 63 6b 00 ff 95 ?? ?? ff ff 68 6b 37 04 7e 50 6a 00 e8 ?? ?? ?? ff 6a 00 6a 00 ff d0 (88|08) 85 ?? ?? ff ff 68 0e 03 e5 e6 ff b5 ?? ?? ff ff 6a 00 e8 ?? ?? ?? ff 0b c0 75 12 68 94 2c d5 87 ff b5 ?? ?? ff ff 6a 00 e8 ?? ?? ?? ff 89 85 ?? ?? ff ff}  //weight: 3, accuracy: Low
        $x_1_6 = "SOFTWARE\\Classes\\http\\shell\\open\\commandV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Poison_A_2147576657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.gen!A"
        threat_id = "2147576657"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "advpack" ascii //weight: 1
        $x_1_2 = "StubPath" ascii //weight: 1
        $x_2_3 = {68 05 0b 7e 26 ff ?? ?? ?? 40 00 68 ?? ?? 40 00 [0-5] a3 ?? ?? 40 00 68 8c ad 5d db ff}  //weight: 2, accuracy: Low
        $x_2_4 = {68 ba 36 c1 0a ff ?? ?? ?? 40 00 68 ?? ?? 40 00 [0-5] a3 ?? ?? 40 00 68 22 fc 89 da ff ?? ?? ?? 40 00 68 ?? ?? 40 00 [0-5] a3 ?? ?? 40 00 68 d5 ba 9b 0e}  //weight: 2, accuracy: Low
        $x_2_5 = {68 c4 f2 00 ec ff ?? ?? ?? 40 00 68 ?? ?? 40 00 [0-5] a3 ?? ?? 40 00 68 81 fe c3 b0 ff}  //weight: 2, accuracy: Low
        $x_1_6 = "SOFTWARE\\Classes\\http\\shell\\open\\command" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\Active Setup\\Installed Components\\" ascii //weight: 1
        $x_2_8 = {ff 96 84 00 00 00 6a 00 8d 45 fc 50 6a 00 6a 00 6a 00 6a 00 6a 00 57 68 02 00 00 80 ff 56 50 8d 45 fc 50 68 3f 00 0f 00 6a 00 57 68 02 00 00 80 ff 56 40 68 ff 00 00 00 8d 86 5d 06 00 00 50 6a 01 6a 00 8d 86 d0 03 00 00 50 ff 75 fc ff 56 48 ff 75 fc ff 56 3c}  //weight: 2, accuracy: High
        $x_2_9 = {41 9f f8 97 d0 f8 42 47 43 46 45 9f 51 04 27 c6 86 aa 28 14 14 14 17 61 18}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Poison_G_2147593553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.G"
        threat_id = "2147593553"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d 05 64 02 40 00 83 c0 04 ff d0 6a 00 e8 00 00 00 00 ff 25 f8 01 40 00}  //weight: 10, accuracy: High
        $x_10_2 = {e8 41 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 00 59 8d 45 d8 50 6a 01 6a 00 51 68 01 00 00 80 ff 56 35 e8 08 00 00 00 41 70 70 44 61 74 61}  //weight: 10, accuracy: High
        $x_1_3 = "SOFTWARE\\Classes\\http\\shell\\open\\commandV" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Poison_G_2147593553_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.G"
        threat_id = "2147593553"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {e8 1b 00 00 00 43 4f 4e 4e 45 43 54 20 25 73 3a 25 69 20 48 54 54 50 2f 31 2e 30 0d 0a 0d 0a 00 5a 8d bd 34 fb ff ff}  //weight: 10, accuracy: High
        $x_1_2 = {c5 08 00 00 ff 96 89 00 00 00 3d b7 00 00 00 75 04 c9 c2 04 00 56 8d 86 6b 09 00 00 50 8d 86 45 01 00 00 50 ff 96 fd 00 00 00 e8 07 00 00 00 77 73 32 5f 33 32 00 58 50 ff 96 9d 00 00 00 89 86 c3 0a 00 00 e8 3a 00 00 00 e1 60 b4 8e 01 00 d1 41 29 7c 15 00 1e bb ec 65 19 00 0c 58 ed ea 1d}  //weight: 1, accuracy: High
        $x_1_3 = {bd 30 fa ff ff 63 6b 73 3d 75 13 c7 85 30 fa ff ff 74 74 ?? 3d c6 86 ef 0a 00 00 02 eb 11 c7 85 30 fa ff ff 63 6b 73 3d c6 86 ef 0a 00 00 01 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_H_2147597101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.H"
        threat_id = "2147597101"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "61"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "explorer.exe" ascii //weight: 10
        $x_10_2 = "svhosters.exe" ascii //weight: 10
        $x_10_3 = "wangwang2008" ascii //weight: 10
        $x_10_4 = "cvnxus.8800.org" ascii //weight: 10
        $x_10_5 = "CONNECT %s:%i HTTP/1.0" ascii //weight: 10
        $x_10_6 = "{89BAAD42-7413-7DC4-C084-58561CA9EF0A}" ascii //weight: 10
        $x_1_7 = "SOFTWARE\\Classes\\http\\shell\\open\\command" ascii //weight: 1
        $x_1_8 = "Software\\Microsoft\\Active Setup\\Installed Components\\" ascii //weight: 1
        $x_1_9 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Poison_I_2147599678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.I"
        threat_id = "2147599678"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 bf 0a 00 00 00 99 f7 ff 83 fa 08 7c [0-4] ba ?? ?? 00 00 8a 04 16 8a 91 ?? ?? ?? ?? 32 c2 88 81 ?? ?? ?? ?? 41 81 f9 ?? ?? ?? ?? 7e d2}  //weight: 1, accuracy: Low
        $x_1_2 = {7e d2 33 c0 b1 ?? 8a 90 ?? ?? ?? ?? 32 d1 88 ?? ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 7e}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 44 24 04 56 8b 74 24 0c 8a 08 8a 16 88 10 88 0e 5e c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_I_2147599678_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.I"
        threat_id = "2147599678"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 1b 00 00 00 43 4f 4e 4e 45 43 54 20 25 73 3a 25 69 20 48 54 54 50 2f 31 2e 30 0d 0a 0d 0a 00 5a 8d bd ?? ?? ff ff 8d 9d ?? ?? ff ff 68 b6 30 0a a1 ff b6 ?? ?? 00 00 ff b6 e1 00 00 00 ff 96 dd 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {57 6a 01 57 ff 75 fc 6a 00 56 ff 96 e5 00 00 00 81 7f fd 0d 0a 0d 0a 75 02 eb 05 83 c7 01 eb e1 5f 81 3f 35 30 33 20 0f 84 9e fe ff ff 81 7f 09 32 30 30 20}  //weight: 1, accuracy: High
        $x_1_3 = {ff 96 e5 00 00 00 56 fc b9 40 00 00 00 8d b5 ?? ?? ff ff 8d bd ?? ?? ff ff f3 a7 74 0d 5e c7 85 ?? ?? ff ff 30 75 00 00 eb 7f 5e 6a 04 8d 45 f8 50 ff 75 fc 6a 00 56 ff 96 e5 00 00 00 85 c0 74 68 6a 40 68 00 10 00 00 ff 75 f8 6a 00 ff 56 21}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Poison_J_2147603170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.J"
        threat_id = "2147603170"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d5 8b f8 33 c9 8a 04 31 30 04 0a 41 83 f9 ?? 7c ?? 83 c2 ?? 4f 75 ec}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c5 2b c1 8a 14 08 80 f2 ?? 88 11 41 4e 75 ?? 5f 5e 5d 5b c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8b f5 bf 0a 00 00 00 ff d3 8b c8 b8 67 66 66 66 f7 e9 c1 fa ?? 8b c2 83 c6 ?? c1 e8 ?? 03 d0 4f 89 56 ?? 75 ?? 8b 44 24 ?? 81 c5 ?? ?? ?? ?? 48 89 44 24 ?? 75 ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_K_2147605156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.K"
        threat_id = "2147605156"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 40 8b cb 99 f7 f9 0f b6 04 3a 03 45 f8 89 55 08 8d 34 3a 99 f7 f9 89 55 f8 8d 04 3a 50 56 89 45 f4 e8 ba 00 00 00 8b 45 0c 8b 55 f4 59 0f b6 12 59 8b 4d fc 03 c8 0f b6 06 03 c2 8b f3 99 f7 fe 8a 04 3a 30 01 ff 45 fc 8b 45 fc 3b 45 10 7c ad}  //weight: 1, accuracy: High
        $x_1_2 = {33 c0 8a 14 30 30 14 01 40 83 f8 10 7c f4 83 c1 10 4f 75 ec ff 15 ?? ?? ?? ?? 8d 4b f0 85 c9 76 12 8b 44 24 18 2b e8 8a 14 28 80 f2 ?? 88 10 40 49 75 f4 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Poison_L_2147605882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.L"
        threat_id = "2147605882"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CONNECT %s:" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Active Setup\\Installed Components\\" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Classes\\http\\shell\\open\\commandV" ascii //weight: 1
        $x_1_6 = ")!VoqA.I4-" ascii //weight: 1
        $x_1_7 = "server.exe" ascii //weight: 1
        $x_1_8 = "127.0.0.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_M_2147608810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.M"
        threat_id = "2147608810"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 31 92 33 c9 69 c0 05 4b 56 ac 83 c0 01 89 84 8e d9 08 00 00 83 c1 01 83 f9 22 72 e8 d9 e8 db be 61 09 00 00 c7 86 d1 08 00 00 00 00 00 00 c7 86 d5 08 00 00 50 00 00 00 e8 5d ff ff ff 57 bf 1e 00 00 00 e8 52 ff ff ff 83 ef 01 75 f6 5f 64 a1 30 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_N_2147609621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.N"
        threat_id = "2147609621"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "140"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {41 33 f6 8d 46 01 bf ff 00 00 00 99 f7 ff 30 13 43 46 49 75}  //weight: 100, accuracy: High
        $x_10_2 = "StartServiceA" ascii //weight: 10
        $x_10_3 = "cmd /c del C:\\myapp.exe" ascii //weight: 10
        $x_10_4 = "%SystemRoot%\\system32\\svchost.exe -k netsvcs" ascii //weight: 10
        $x_10_5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_O_2147609654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.O"
        threat_id = "2147609654"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinExec" ascii //weight: 1
        $x_1_2 = "StartServiceA" ascii //weight: 1
        $x_1_3 = "RegSetValueExA" ascii //weight: 1
        $x_1_4 = "GetShortPathNameA" ascii //weight: 1
        $x_1_5 = "GetFileTime" ascii //weight: 1
        $x_1_6 = "GetFileSize" ascii //weight: 1
        $x_1_7 = "WriteFile" ascii //weight: 1
        $x_1_8 = {5d 00 00 00 5b 53 59 53 54 45 4d 33 32 5d 00 00 5c 00 00 00 25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 00 00 00 00 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 00 00 5c 50 61 72 61 6d 65 74 65 72 73 00 53 65 72 76 69 63 65 44 6c 6c 00 00 44 65 73 63 72 69 70 74 69 6f 6e 00 4c 69 6e 6b 4e 61 6d 65 00 00 00 00 63 6d 64 20 2f 63 20 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_P_2147609664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.P"
        threat_id = "2147609664"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 11 c7 85 ?? ?? ?? ?? 63 6b 73 3d c6 86 ?? ?? ?? ?? 01}  //weight: 2, accuracy: Low
        $x_1_2 = "ONnECT %s:%i HTTP/" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Classes\\http\\shell\\open\\commandv" ascii //weight: 1
        $x_1_4 = {e8 06 00 00 00 6e 74 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_2_5 = {e8 2e 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 72 75 6e 00 57 ff 96 [0-4] 80 be [0-4] 01 75 07 b9 02 00 00 80}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Poison_V_2147610284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.V"
        threat_id = "2147610284"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {52 50 8d 46 48 50 e8 ?? ?? ff ff 83 f8 ff 0f 84 08 01 00 00 89 06 66 81 7e 04 b3 d7 0f 85 c3 00 00 00 66 ff 4e 04 6a 00 ff 36 e8 ?? ?? ff ff 40}  //weight: 5, accuracy: Low
        $x_5_2 = {b9 65 00 00 00 e8 ?? ?? ff ff 66 8b 83 ?? ?? 00 00 66 89 83 ?? ?? 00 00 eb 0d e8 ?? ?? ff ff 84 c0 0f 84 ?? ?? 00 00 c6 83 ?? ?? 00 00 01 c6 83 ?? ?? 00 00 00 8b 83 ?? ?? 00 00}  //weight: 5, accuracy: Low
        $x_5_3 = {eb 08 8d 45 f8 e8 ?? ?? ff ff 8b 45 f8 e8 ?? ?? ff ff 50 68 ?? ?? 40 00 8d 45 e8 ba ?? ?? 41 00 b9 15 00 00 00 e8 ?? ?? ff ff ff 75 e8 68 ?? ?? 40 00 8d 45 ec ba 03 00 00 00 e8 ?? ?? ff ff}  //weight: 5, accuracy: Low
        $x_2_4 = "TMySvr" ascii //weight: 2
        $x_2_5 = "TMyThd" ascii //weight: 2
        $x_2_6 = "TMySpy" ascii //weight: 2
        $x_2_7 = "TMyAud" ascii //weight: 2
        $x_2_8 = "TMyCam" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_2_*))) or
            ((2 of ($x_5_*) and 3 of ($x_2_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Poison_X_2147611027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.X"
        threat_id = "2147611027"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "m_Stub" ascii //weight: 1
        $x_1_2 = "file.exe" ascii //weight: 1
        $x_1_3 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "FindResourceA" ascii //weight: 1
        $x_1_6 = "CreateMutexA" ascii //weight: 1
        $x_1_7 = {6a 40 68 00 30 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00}  //weight: 1, accuracy: High
        $x_1_9 = {81 fa 4d 5a 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {81 3a 50 45 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {b8 68 58 4d 56 bb 65 d4 85 86 b9 0a 00 00 00 66 ba 58 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_B_2147611032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.gen!B"
        threat_id = "2147611032"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 00 eb a8 81 bd 30 fa ff ff 63 6b 73 3d 75 13 d7 85 30 fa ff ff 74 74 70 3d c6 86 ef 0a 00}  //weight: 1, accuracy: High
        $x_1_2 = {e8 07 00 00 00 57 73 32 5f 33 32 00 58 50 ff 96 9d 00 00 00 89 86 c3 0a 00 00 e8 3a 00 00 00 e1}  //weight: 1, accuracy: High
        $x_1_3 = {6c 6c 65 64 20 43 6f 6d 70 6f 6e 65 6e 74 73 5c fa 0a 05 00 6b 69 6c 65 72 90 01 0d 00 09 31 32}  //weight: 1, accuracy: High
        $x_1_4 = {00 00 c1 02 04 00 ff ff ff ff 45 01 05 00 61 64 6d 69 6e fb 03 05 00 63 63 78 63 73 fa 03 01 00}  //weight: 1, accuracy: High
        $x_1_5 = "ONnECT %s:%i HTTP/1.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_C_2147611033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.gen!C"
        threat_id = "2147611033"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {04 08 00 73 74 75 62 50 61 74 68 18 04 28 00 53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c}  //weight: 1, accuracy: High
        $x_1_2 = {fa 0a 05 00 6b 69 6c 65 72 90 01 0d 00 09 31 32 37 2e 30 2e 30 2e 31 00 84 0d 8c 01 04 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 00 e8 08 00 00 00 61 64 76 70 61 63 6b 00 ff 95 21 f1 ff ff 68 6b 37 04 7e 50 6a 00 e8 5e f5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_D_2147611034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.gen!D"
        threat_id = "2147611034"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {58 50 56 53 53 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 43 75 72 72 65 6e 74 55 73 65 72 00 43 3a 5c 66 69 6c 65 2e 65 78 65 00 52 65 73 75 6d 65 54 68}  //weight: 1, accuracy: High
        $x_1_3 = {6f 63 65 73 73 41 00 00 6d 5f 53 74 75 62 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_E_2147611035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.gen!E"
        threat_id = "2147611035"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e6 11 40 00 00 30 40 00 2a 00 5c 00 41 00 44 00 3a 00 5c 00 50 00 72 00 6f 00 1f 01 72 00 61 00 6d 00 6c 00 61 00 6d 00 61 00 5c 00 74 00 73 00 74 00 20 00 63 00 72 00 79 00 70 00 74 00 65 00 72 00 20 00 31 00 2e 00 32 00 5c 00 53 00 74 00 75 00 62 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "8( Turk Siber Team ) 256" wide //weight: 1
        $x_1_3 = {00 00 00 00 06 00 00 00 74 00 6d 00 70 00 00 00 1e 00 00 00 5c 00 59 00 6f 00 75 00 20 00 53 00 65 00 72 00 76 00 65 00 72 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_Y_2147617011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.Y"
        threat_id = "2147617011"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {7e 25 bf 01 00 00 00 8d 45 f8 8b 55 fc 8a 54 3a ff 80 f2 ?? e8 ?? ?? fe ff 8b 55 f8 8b c6 e8 ?? ?? fe ff 47 4b 75 e0}  //weight: 3, accuracy: Low
        $x_2_2 = {74 58 b8 61 09 00 00 e8 ?? ?? ff ff 89 45 00 33 c0 89 07 6a 00 57 68 60 09 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = "TWebCamThread" ascii //weight: 1
        $x_1_4 = "TDownFileThread" ascii //weight: 1
        $x_1_5 = "TScreenSpy" ascii //weight: 1
        $x_1_6 = {00 2e 6b 6c 67 00}  //weight: 1, accuracy: High
        $x_1_7 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 00 00 [0-5] 2e 5c 53 4d 41 52 54 56 53 44}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Poison_AC_2147618261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.AC"
        threat_id = "2147618261"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c4 c1 1d 00 d8 11 40 00 5c 13 40 00 6e 10 40 00 74 10 40 00 14 14 40 00 50 13 40 00 84 1e 40 00 2c 14 40 00 5c 1c 40 00 98 1e 40 00 7a 10 40 00 74 00 73 00 24 36 40 00 ba 24 36 40 00 b9 aa 10}  //weight: 1, accuracy: High
        $x_1_2 = "bonibon" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_AI_2147627101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.AI"
        threat_id = "2147627101"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DoOnECt %s:%i HTTP/1.0" ascii //weight: 1
        $x_1_2 = {b8 00 04 40 00 ff d0 6a 00 e8 00 00 00 00 ff 25 00 02 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_Y_2147631176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.Y!dll"
        threat_id = "2147631176"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2e 6b 6c 67 00}  //weight: 10, accuracy: High
        $x_1_2 = "Unt_WebCam" ascii //weight: 1
        $x_1_3 = "Unt_DownFileThread" ascii //weight: 1
        $x_1_4 = "Unit_FileTrans" ascii //weight: 1
        $x_1_5 = "Unit_ScreenSpy" ascii //weight: 1
        $x_1_6 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_7 = "capGetDriverDescriptionA" ascii //weight: 1
        $x_1_8 = "MainService" ascii //weight: 1
        $x_1_9 = "MainWork" ascii //weight: 1
        $x_1_10 = "ServiceMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Poison_AP_2147632246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.AP"
        threat_id = "2147632246"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c4 0c 02 00 00 c3 [0-4] 56 8b 35 ?? ?? ?? ?? 68 7f 96 98 00 ff d6 eb f7}  //weight: 1, accuracy: Low
        $x_1_2 = "Local AppWizard-Generated Applications" ascii //weight: 1
        $x_1_3 = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces" ascii //weight: 1
        $x_1_4 = {6a 0c 6a 35 6a 2b 6a 0c c7 45 e8 2b 00 00 00 c7 45 e4 35 00 00 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Poison_AT_2147637391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.AT"
        threat_id = "2147637391"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 1a 00 00 00 f7 f9 83 c2 61}  //weight: 1, accuracy: High
        $x_1_2 = {66 c7 44 24 ?? 40 00 c6 44 24 ?? 80 c6 44 24 ?? 06 c6 44 24 ?? 50}  //weight: 1, accuracy: Low
        $x_1_3 = {99 b9 fa 00 00 00 f7 f9 42}  //weight: 1, accuracy: High
        $x_1_4 = "MD ServicesB" ascii //weight: 1
        $x_1_5 = "Svc%c%c%c%c.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Poison_AU_2147638790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.AU"
        threat_id = "2147638790"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb d4 be e0 03 00 00 8d 87 ?? ?? ?? ?? 56 50 ff 77 ?? e8 ?? ?? ?? ?? 56 ff 77 ?? e8 ?? ?? ?? ?? 8b c6 eb 03}  //weight: 1, accuracy: Low
        $x_1_2 = {41 ad 03 c5 33 db 0f be 10 38 f2 74 08 c1 cb ?? 03 da 40 eb f1}  //weight: 1, accuracy: Low
        $x_1_3 = {8b f5 8b fd b9 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? ac 34 ?? aa e2 fa}  //weight: 1, accuracy: Low
        $x_1_4 = {75 13 68 30 75 00 00 ff 95 ?? ?? ?? ?? ff 85 ?? ?? ?? ?? eb c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Poison_AW_2147638947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.AW"
        threat_id = "2147638947"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 69 6d 65 6f 75 74 20 26 20 51 55 49 54 21 21 21 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 46 47 32 45 58 54 52 00 00 00 00 4c 44 53 55 70 44 72 76 31 00 00 00 4c 44 53 55 70 44 72 76 00 00 00 00 43 46 47 45 58 54 52 00}  //weight: 1, accuracy: High
        $x_1_3 = {65 77 72 3a 6d 3a 73 3a 68 3a 70 3a 74 3a 62 3a 64 3a 6e 3a 77 3a 78 3a 67 3a 6b 3a 00}  //weight: 1, accuracy: High
        $x_1_4 = {c6 44 24 2d 63 c6 44 24 32 69 c6 44 24 33 74 c6 44 24 34 68 c6 44 24 35 4c 88 54 24 36 c6 44 24 37 67 88 54 24 38 c6 44 24 39 6e}  //weight: 1, accuracy: High
        $x_1_5 = {c6 44 24 24 43 c6 44 24 27 61 c6 44 24 28 74 c6 44 24 2a 50 c6 44 24 2c 6f c6 44 24 2d 63 88 4c 24 2f 88 4c 24 30 c6 44 24 31 57}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_AY_2147647726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.AY"
        threat_id = "2147647726"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {75 11 8b 4d ?? 51 e8 ?? ?? ?? ?? 83 c4 04 e9 ?? ?? ?? ?? 6a 03 68}  //weight: 2, accuracy: Low
        $x_1_2 = {44 4f 57 00 55 50 4c 00 44 54 4b 00 53 54 4b 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 49 52 00 50 4c 49 00 50 4c 44 00 52 55 4e 00}  //weight: 1, accuracy: High
        $x_1_4 = "%u 0 COT DATA A %u" ascii //weight: 1
        $x_1_5 = "glp.uin" wide //weight: 1
        $x_1_6 = "%s\\%u.xpl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Poison_AY_2147647726_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.AY"
        threat_id = "2147647726"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 41 58 6a 70 66 89 85 ?? ?? ?? ?? 58 6a 49 66 89 85 ?? ?? ?? ?? 66 89 85 ?? ?? ?? ?? 58 66 89 85 ?? ?? ?? ?? 6a 74 58 6a 5f 66 89 85 ?? ?? ?? ?? 58 6a 44}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 74 66 89 95 ?? ?? ?? ?? 5a 6a 5c 66 89 95 ?? ?? ?? ?? 5a 6a 57 66 89 95 ?? ?? ?? ?? 5a 66 89 95 ?? ?? ?? ?? 6a 6e 5e 8b d3 66 89 95 ?? ?? ?? ?? 8b d6 66 89 95 ?? ?? ?? ?? 6a 64}  //weight: 2, accuracy: Low
        $x_1_3 = {5c 00 73 00 79 00 73 00 [0-16] 70 00 72 00 65 00 70 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_4 = "EXPLORE.lnk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Poison_AY_2147647726_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.AY"
        threat_id = "2147647726"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 a2 00 00 00 ff d6 57 6a 02 57 6a 56 ff d6 68 e8 03 00 00 ff d3}  //weight: 1, accuracy: High
        $x_1_2 = {40 3b c7 7c f7 04 00 80 34}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 3a 89 45 ?? 58 6a 5c 66 89 85 ?? ?? ?? ?? 58 6a 77 66 89 85 ?? ?? ?? ?? 58 6a 69}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 00 6c 00 6e 00 6b 00 [0-16] 5c 00 49 00 6e 00 74 00 65 00 6c 00 5c 00 [0-16] 41 00 70 00 70 00 55 00 73 00 65 00 72 00 2e 00 64 00 61 00 74 00 [0-16] 25 00 75 00}  //weight: 1, accuracy: Low
        $x_1_5 = {5c 00 72 00 69 00 73 00 69 00 6e 00 67 00 00 00 61 00 76 00 69 00 72 00 61 00 00 00 33 00 36 00 30 00 53 00 44 00 00 00 61 00 76 00 67 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Poison_AZ_2147650397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.AZ"
        threat_id = "2147650397"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {88 84 2e 41 1e 00 00 46 83 c4 04 81 fe 41 1e 00 00 7c e7 b0 01 eb 02}  //weight: 2, accuracy: High
        $x_2_2 = {74 18 33 c0 8d 8e 81 3c 00 00 8a 11 88 14 30 40 49 3d 41 1e 00 00 7c f2 ff d6}  //weight: 2, accuracy: High
        $x_1_3 = {61 6e 74 69 2e 74 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Poison_BD_2147650469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.BD"
        threat_id = "2147650469"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c0 8a 88 ?? ?? ?? ?? 80 f1 ?? 88 8c 05 ?? ?? ?? ?? 40 83 f8 40 72 ea 33 c0 8a 88 ?? ?? ?? ?? 80 f1 ?? 88 4c 05 ?? 40 83 f8 40 72 ed}  //weight: 5, accuracy: Low
        $x_2_2 = {5c 5c 2e 5c 4c 50 52 53 00 00 00 00 5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c 90 02 10 5f 6d 61 69 6c 73 6c 6f 74}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_BE_2147650471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.BE"
        threat_id = "2147650471"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 64 3d 00 34 31 2e 70 68 70 3f 00 47 45 54 00 63 6d 64 20}  //weight: 1, accuracy: High
        $x_1_2 = {33 31 2e 70 68 70 3f 00 43 72 65 61 74 65 20 70 72 6f 63 65 73 73 20 66 61 69 6c 21 00}  //weight: 1, accuracy: High
        $x_2_3 = {6a 04 8d 44 24 14 50 6a 06 bb 30 75 00 00 55 89 5c 24 20 ff d6 6a 04 8d 4c 24 14 51 6a 05 55 89 5c 24 20 ff d6 6a 00 6a 00 6a 03 6a 00 6a 00 6a 50 57 55 ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_BE_2147650471_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.BE"
        threat_id = "2147650471"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "id=%s&id=%s&id=%s&id=%s&id=%s&id=%s" ascii //weight: 2
        $x_2_2 = {5c 77 69 6e 2e 69 6e 69 00 00 00 00 63 6f 6f 6b 69 65 73 5c}  //weight: 2, accuracy: High
        $x_2_3 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 73 00 50 4f 53 54 00 00 00 00 69 64 3d 00 34 31 2e 70 68 70 3f}  //weight: 2, accuracy: High
        $x_1_4 = "Open HOST_URL error" ascii //weight: 1
        $x_1_5 = "VST%d.%d.%d.%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Poison_BF_2147650948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.BF"
        threat_id = "2147650948"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c9 b8 25 49 92 24 f7 e1 8b c1 2b c2 d1 e8 03 c2 c1 e8 02 8d 14 c5 00 00 00 00 2b d0 8b c1 2b c2 75 09 80 b1 ?? ?? ?? ?? 0b eb 07 80 b1 ?? ?? ?? ?? 21 41 81 f9 ?? ?? ?? ?? 72 c6}  //weight: 10, accuracy: Low
        $x_10_2 = {ff 15 04 b0 40 00 33 ff 8d 49 00 56 e8 68 01 00 00 88 84 3b ?? ?? 00 00 47 83 c4 04 81 ff ?? ?? 00 00 72 e7 5f 5e b0 01 5d c3}  //weight: 10, accuracy: Low
        $x_10_3 = {8d 49 00 80 30 05 8a 10 88 54 0c 10 41 48 81 f9 ?? ?? 00 00 72 ed 55 e8}  //weight: 10, accuracy: Low
        $x_1_4 = {6f 70 68 63 72 61 63 6b 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {6e 6f 69 70 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {6c 6f 6f 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {68 61 70 70 69 6e 65 73 73 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_8 = {61 6e 74 69 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_9 = {71 75 65 72 79 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_10 = {6f 66 66 65 72 2e 74 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Poison_BG_2147651604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.BG"
        threat_id = "2147651604"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 6f 71 3d 25 73 26 69 6f 71 3d 25 73 26 69 6f 71 3d 25 73 26 69 6f 71 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 65 61 72 63 68 3f 00 26 45 72 26 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 73 00 50 4f 53 54 00}  //weight: 1, accuracy: High
        $x_1_4 = {63 6d 64 20 73 68 65 6c 6c 20 63 6c 6f 73 65 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {6d 67 65 74 20 6f 76 65 72 26 66 61 69 6c 75 72 65 0d 0a}  //weight: 1, accuracy: High
        $x_1_6 = {43 72 65 61 74 65 20 70 69 70 65 20 66 61 69 6c 21 00}  //weight: 1, accuracy: High
        $x_1_7 = {4f 70 65 6e 20 48 4f 53 54 5f 55 52 4c 20 65 72 72 6f 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Poison_BI_2147653146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.BI"
        threat_id = "2147653146"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 ff 00 00 00 33 c0 8d 7c 24 ?? c6 44 24 ?? 00 f3 ab 8b 35 ?? ?? ?? ?? 6a 00 66 ab 68 80 00 00 00 6a 03 aa}  //weight: 1, accuracy: Low
        $x_1_2 = {b0 72 b1 63 56 57 88 44 24 ?? 88 44 24 ?? 88 4c 24}  //weight: 1, accuracy: Low
        $x_1_3 = {54 c6 44 24 ?? 61 c6 44 24 ?? 65 c6 44 24 ?? 47 c6 44 24 ?? 78 c6 44 24 ?? 73}  //weight: 1, accuracy: Low
        $x_1_4 = "svchost .exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Poison_BL_2147653193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.BL"
        threat_id = "2147653193"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {56 33 c9 8b c1 be 1f 00 00 00 99 f7 fe 8a 81 ?? ?? ?? ?? 32 c2 88 81 00 41 81 f9 10 03 ?? ?? 7c df 8d 05 ?? ?? ?? ?? 50 8d 05 00 ff d0}  //weight: 2, accuracy: Low
        $x_1_2 = {32 30 32 66 89 54 24 ?? 89 5c 24 ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {6e 5c 52 75 c7 84 24 ?? 00 00 00 6e 00 00 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Poison_BN_2147655074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.BN"
        threat_id = "2147655074"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4.;7.5GF" ascii //weight: 1
        $x_1_2 = "[CREATE.NEW = USER NAME]" wide //weight: 1
        $x_1_3 = "Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "C:\\Windows\\System\\System.exe" wide //weight: 1
        $x_1_5 = "c:\\record.dat" wide //weight: 1
        $x_1_6 = "c:\\windows\\system\\keylog.txt" wide //weight: 1
        $x_1_7 = "{backspace}" wide //weight: 1
        $x_1_8 = "{ScrollLock}" wide //weight: 1
        $x_1_9 = "{PrintScreen}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_Win32_Poison_BO_2147655199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.BO"
        threat_id = "2147655199"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 f3 a5 66 c7 45 ?? 44 00 66 c7 45 ?? 74 00 66 c7 45 ?? 76 00 66 c7 45 ?? 72 00 66 c7 45 ?? 63 00 66 c7 45 ?? 75 00 66 c7 45 ?? 67 00 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {83 45 fc 02 8d 45 e8 83 c3 04 50 ff d6 39 45 fc 59 72 e9 04 00 66 83 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_BP_2147655206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.BP"
        threat_id = "2147655206"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 6f 8d 44 24 10 6a 00 50 55 53 57 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {7e 54 58 45 00 00 00 00 42 49 4e 00}  //weight: 1, accuracy: High
        $x_2_3 = {88 48 fe 80 c1 02 c0 e1 04 88 0c 3e 8a 50 ff 80 ea 1e 32 d1 88 14 3e 46 3b f3 7c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Poison_BQ_2147661225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.BQ"
        threat_id = "2147661225"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 09 00 00 00 61 64 76 61 70 69 33 32 00 ff ?? ?? ?? ?? ff (89|09) ?? ?? ?? ?? ff e8 06 00 00 00 6e 74 64 6c 6c 00 ff ?? ?? ?? ?? ff 89 ?? ?? ?? ?? ff e8 07 00 00 00 75 73 65 72 33 32 00 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 00 06 40 00 ff d0 6a 00 e8 00 00 00 00 ff 25 00 04 40 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\shell\\open\\command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_BT_2147665885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.BT"
        threat_id = "2147665885"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac c0 c0 03 34 41 c0 c0 03 34 52 c0 c0 03 34 43 c0 c0 03 34 48 c0 c0 03 34 59 (aa)}  //weight: 1, accuracy: Low
        $x_1_2 = {85 c0 74 12 8b 08 6a 01 49 5e d3 e6 0b d6 89 57 fc 8b 40 04 eb (ea)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_BU_2147672236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.BU"
        threat_id = "2147672236"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "0x1A7B4C9F" ascii //weight: 5
        $x_1_2 = {50 ad 03 c2 50 ad 03 c2 5b 50 33 c0 8b 34 83 03 f2}  //weight: 1, accuracy: High
        $x_1_3 = {b9 18 00 00 00 33 ff 33 c0 66 ad 85 c0 74 0d}  //weight: 1, accuracy: High
        $x_1_4 = {03 f2 53 50 33 db 33 c0 ac c1 c3 13 03 d8 83 f8 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Poison_BV_2147672243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.BV"
        threat_id = "2147672243"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "soft\\move.bak" ascii //weight: 1
        $x_1_2 = "t\\tempfile.bak" ascii //weight: 1
        $x_1_3 = {61 72 64 2e 65 78 65 00 [0-2] 61 76 67 75 00}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c9 ff f2 ae f7 d1 2b f9 6a 03 8b f7 8b d9 8b fa 83 c9 ff f2 ae 8b cb 4f c1 e9 02 f3 a5 8b cb 50 83 e1 03 6a 01 8d [0-6] 68 00 00 00 80 f3 a4 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_BX_2147683981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.BX"
        threat_id = "2147683981"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {39 4d 14 75 15 39 4d 0c 7e 25 8b 45 08 03 c1 80 30 32 41 3b 4d 0c 7c f2}  //weight: 1, accuracy: High
        $x_1_2 = {85 c0 59 75 0a 8a 06 3c 2e 74 04 3c 5f 75 05 8a 06 88 07 47 46 38 1e 75 ce}  //weight: 1, accuracy: High
        $x_1_3 = {83 c4 14 c6 40 fd 6c c6 40 fe 6e c6 40 ff 6b 8d 85 ec fc ff ff}  //weight: 1, accuracy: High
        $x_1_4 = "cmd /c erase /F " ascii //weight: 1
        $x_1_5 = {00 73 76 63 68 6f 73 74 20 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_BZ_2147686454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.BZ"
        threat_id = "2147686454"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 14 01 84 d2 74 0e 80 fa 28 74 09 8a 14 01 80 f2 28 88 14 01 40 4e 75 e7}  //weight: 10, accuracy: High
        $x_1_2 = {58 5a 47 4f 5a 49 45 08 00 45 5d 5b 5c 08 4a 4d 08 00 5a 5d 46 08 5d 46 4c 4d 00 5a 08 7f 41 46}  //weight: 1, accuracy: High
        $x_1_3 = {e4 21 e9 3b 06 5a 4d 44 47 e6 4b ec 16 e8 68 00 80 00 00 e9 48 ef 3a aa 00 e8 21 78 06 5a 5b 5a}  //weight: 1, accuracy: High
        $x_1_4 = {a8 2a ac e8 5d 2c a8 1b e8 a1 2e 72 75 77 c8 38 29 c9 25 ab ec d0 a3 f0 a3 d3 00 a3 1a a3 6b 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Poison_E_2147692682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.E!dha"
        threat_id = "2147692682"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 57 b9 ae 04 00 00 8d 74 24 10 8b fb f3 a5 66 a5 a4 c6 43 05 2f c6 43 04 eb ff d5 83 f8 0c}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 6a 00 6a 00 53 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b f0 ff d5 83 f8 0c 75 ?? 6a 00}  //weight: 1, accuracy: Low
        $x_1_3 = {b3 33 b1 81 b0 7e b2 3a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_CB_2147695276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.CB!dha"
        threat_id = "2147695276"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%ProgramW6432%" ascii //weight: 1
        $x_1_2 = {6b 61 73 70 65 72 73 6b 79 [0-4] 61 6c 77 69 6c}  //weight: 1, accuracy: Low
        $x_1_3 = "\\\\.\\VBoxMiniRdrDN" ascii //weight: 1
        $x_1_4 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-4] 25 73 5c 25 73 2e 6c 6e 6b}  //weight: 1, accuracy: Low
        $x_1_5 = "Hostname was found in DNS cache" ascii //weight: 1
        $x_1_6 = "DownExecute.pdb" ascii //weight: 1
        $x_1_7 = "P@$sw0rD$nd" ascii //weight: 1
        $x_1_8 = "downexecute" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Backdoor_Win32_Poison_CD_2147723378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.CD"
        threat_id = "2147723378"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "unsigned char fuckyou" ascii //weight: 1
        $x_1_2 = {56 2b c8 8d 72 01 8a 14 ?? 80 f2 ?? 88 10 40 4e 75 ?? 5e c3}  //weight: 1, accuracy: Low
        $x_1_3 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 41 00 63 00 74 00 69 00 76 00 65 00 73 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_CD_2147723378_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.CD"
        threat_id = "2147723378"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 85 f6 ?? ?? 03 cb 8a 54 07 ?? 32 14 29 40 3b c6 88 ?? ?? ?? 8b 4c 24 ?? 8b 54 24 ?? 8d 42 ?? 3b d8 ?? ?? 51 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 4c ?? ?? 8b 54 ?? ?? 83 c4 ?? 43 3b da 72}  //weight: 1, accuracy: Low
        $x_1_2 = {77 11 8a 98 ?? ?? ?? ?? 32 da 80 eb ?? 88 98 ?? ?? ?? ?? 8d bc 06 ?? ?? ?? ?? 81 ff ?? ?? ?? ?? 77 11 8a 98 ?? ?? ?? ?? 32 d9 80 eb ?? 88 98 ?? ?? ?? ?? 83 c0 ?? 3d ?? ?? ?? ?? 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Poison_CD_2147723378_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.CD"
        threat_id = "2147723378"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {eb 73 e8 2e 00 00 00 73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e 00}  //weight: 5, accuracy: High
        $x_3_2 = {73 74 75 62 70 61 74 68 ?? ?? ?? ?? 73 6f 66 74 77 61 72 65 5c 63 6c 61 73 73 65 73 5c 68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 76}  //weight: 3, accuracy: Low
        $x_1_3 = "software\\microsoft\\active setup\\installed components\\" ascii //weight: 1
        $x_1_4 = "advpack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_CE_2147730068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.CE"
        threat_id = "2147730068"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 6d 1b 00 00 77 ?? 8a 98 ?? ?? ?? ?? 32 da 80 eb 05 88 98 ?? ?? ?? 00 8d bc 06 ?? ?? ?? 00 81 ff ?? ?? ?? 00 77 ?? 8a 98 ?? ?? ?? 00 32 d9 80 eb ?? 88 98 ?? ?? ?? 00 83 c0 02 3d ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {43 81 e3 ff 00 ?? ?? 79 ?? 4b 81 cb ?? ?? ?? ?? 43 8b 44 24 ?? 33 c9 8a 0c 03 8d 3c 03 03 e9 81 e5 ?? ?? ?? ?? 79 ?? 4d 81 cd ?? ?? ?? ?? 45 03 c5 50 57 89 44 24 ?? e8 ?? ?? ?? 00 8b 4c 24 ?? 33 d2 8a 17 33 c0 8a 01 83 c4 ?? 03 d0 81 e2 ff ?? ?? ?? 79 ?? 4a 81 ca 00 ?? ?? ?? 42 8b 44 24 ?? 8a 0c 02 8b 44 24 ?? 8a 14 06 32 d1 88 14 06 8b 44 24 ?? 46 3b f0 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Poison_AM_2147819039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.AM!MTB"
        threat_id = "2147819039"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AntiAdwa.exe" ascii //weight: 1
        $x_1_2 = "222.exe" ascii //weight: 1
        $x_1_3 = {31 39 34 2e 31 34 36 00 00 00 00 00 2e 38 34 2e 33}  //weight: 1, accuracy: High
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_5 = {50 72 6f 67 72 61 00 00 00 00 00 00 00 6d 44 61 74 61 5c 73 76 63 00 00 00 00 00 00 00 68 6f 73 74 2e 74 78 74}  //weight: 1, accuracy: High
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Poison_GTZ_2147942006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poison.GTZ!MTB"
        threat_id = "2147942006"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6d 31 00 0d ?? ?? ?? ?? 53 53 59 33 32 00 19 01 00}  //weight: 10, accuracy: Low
        $x_1_2 = "svchoct.exe" ascii //weight: 1
        $x_1_3 = "taskkill /f /im  svchoct" ascii //weight: 1
        $x_1_4 = "k3ylogger.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

