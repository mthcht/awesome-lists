rule Backdoor_Win32_PcClient_Z_2147595874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.Z"
        threat_id = "2147595874"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" ascii //weight: 1
        $x_1_2 = "SYSTEM\\ControlSet001\\Services\\%s" ascii //weight: 1
        $x_1_3 = "SeShutdownPrivilege" ascii //weight: 1
        $x_1_4 = "\\svchost.exe -k" ascii //weight: 1
        $x_1_5 = "ServiceMain" ascii //weight: 1
        $x_1_6 = "PcMain.dll" ascii //weight: 1
        $x_1_7 = "image/jpeg" wide //weight: 1
        $x_1_8 = "%08x.tmp" ascii //weight: 1
        $x_1_9 = "TestFunc" ascii //weight: 1
        $x_1_10 = "winsta0" ascii //weight: 1
        $x_1_11 = "cmd.exe" ascii //weight: 1
        $x_1_12 = "LoadProfile" ascii //weight: 1
        $x_1_13 = "GdipCreateBitmapFromHBITMAP" ascii //weight: 1
        $x_1_14 = "GdipCreateBitmapFromScan0" ascii //weight: 1
        $x_1_15 = "SHEmptyRecycleBinA" ascii //weight: 1
        $x_1_16 = "ImpersonateSelf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (15 of ($x*))
}

rule Backdoor_Win32_PcClient_AY_2147596028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.AY"
        threat_id = "2147596028"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {51 8b 54 24 10 8d 44 24 00 6a 00 50 8b 44 24 14 6a 00 6a 00 52 8b 54 24 1c 50 8b 81 c4 08 00 00 52 50 c7 44 24 20 00 00 00 00 ff 15}  //weight: 3, accuracy: High
        $x_1_2 = {89 44 24 08 2d 38 44 44 24 08 2d 36 41 04 50 68 2d 31 30 00 61 25 8b ce e8}  //weight: 1, accuracy: High
        $x_1_3 = {8a 44 24 20 f6 d8 1a c0 24 01 fe c8 88 46 0c}  //weight: 1, accuracy: High
        $x_1_4 = {8a 0c 32 80 f9 30 7c 05 80 f9 39 7e 05 80 f9 2e 75 0e 42}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_YX_2147596382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.YX"
        threat_id = "2147596382"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\%s" ascii //weight: 1
        $x_1_2 = "%s\\*.*" ascii //weight: 1
        $x_1_3 = "cmd.exe" ascii //weight: 1
        $x_1_4 = "\\\\.\\%s" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Classes\\HTTP\\shell\\open\\command" ascii //weight: 1
        $x_1_6 = "\\\\.\\pipe\\" ascii //weight: 1
        $x_1_7 = "%s%s%s%s" ascii //weight: 1
        $x_1_8 = "%s%s%s%s\\Parameters" ascii //weight: 1
        $x_1_9 = "%SystemRoot%\\System32\\" ascii //weight: 1
        $x_1_10 = "%s %s %s" ascii //weight: 1
        $x_1_11 = "[%04d-%02d-%02d %02d:%02d:%02d]" ascii //weight: 1
        $x_1_12 = "%d.exe" ascii //weight: 1
        $x_1_13 = "%d.tmp" ascii //weight: 1
        $x_1_14 = "Host:" ascii //weight: 1
        $x_1_15 = "http://%s" ascii //weight: 1
        $x_1_16 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322)" ascii //weight: 1
        $x_2_17 = {8d 45 fc 50 8d 85 ec dd ff ff 68 00 20 00 00 50 ff 75 08 ff 15 00 93 00 10 85 c0 74 20 39 5d fc 74 1b 8d 45 0c 53 50 8d 85 ec dd ff ff ff 75 fc 89 5d 0c 50 56 ff 15 94 91 00 10 eb c3 56 ff 15 d8 91 00 10 6a 01 5b ff 75 08 ff 15 04 93 00 10 5f 5e ff 75 f0 ff 15 04 93 00 10}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_YX_2147596383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.YX"
        threat_id = "2147596383"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\svchost.exe" ascii //weight: 1
        $x_1_2 = "DoService" ascii //weight: 1
        $x_1_3 = ".sys" ascii //weight: 1
        $x_1_4 = "drivers\\" ascii //weight: 1
        $x_1_5 = ".pxy" ascii //weight: 1
        $x_1_6 = ".drv" ascii //weight: 1
        $x_7_7 = {8d 85 74 fe ff ff 50 ff 15 28 20 40 00 8b 3d 2c 20 40 00 8d 85 74 fe ff ff 68 58 30 40 00 50 ff d7 8d 8d 74 fe ff ff 8d 86 fe 04 00 00 51 50 89 45 e4 ff 15 10 20 40 00 8d 86 70 02 00 00 50 ff 75 e4 ff d7 68 50 30 40 00 ff 75 e4 ff d7 8d 8d 74 fe ff ff 8d 86 fe 06 00 00 51 50 ff 15 10 20 40 00 8d 86 70 02 00 00 50 8d 86 fe 06 00 00 50 ff d7 8d 86 fe 06 00 00 68 48 30 40 00 50 ff d7 8d 8d 74 fe ff ff 8d 86 fe 07 00 00 51}  //weight: 7, accuracy: High
        $x_7_8 = {50 ff 15 10 20 40 00 8d 86 70 02 00 00 50 8d 86 fe 07 00 00 50 ff d7 8d 86 fe 07 00 00 68 40 30 40 00 50 ff d7 8d 8d 74 fe ff ff 8d 86 fe 05 00 00 51 50 89 45 08 ff 15 10 20 40 00 68 34 30 40 00 ff 75 08 ff d7 8d 86 70 02 00 00 50 ff 75 08 ff d7 68 2c 30 40 00 ff 75 08 ff d7 8d 86 ec 03 00 00 50 e8 67 fb ff ff}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_7_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_CU_2147598003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.CU!dll"
        threat_id = "2147598003"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "49"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {32 30 30 20 25 73 25 73 25 73 00 [0-48] 3e 20 6e 75 6c 00 [0-48] 43 4f 4d 53 50 45 43}  //weight: 3, accuracy: Low
        $x_3_2 = "goog1e." ascii //weight: 3
        $x_3_3 = "http://%s:%d/%s%d%08d" ascii //weight: 3
        $x_3_4 = "index.asp?" ascii //weight: 3
        $x_3_5 = {5c 53 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c [0-16] 2e 73 79 73 00}  //weight: 3, accuracy: Low
        $x_20_6 = "CreateRemoteThread" ascii //weight: 20
        $x_20_7 = "WriteProcessMemory" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_D_2147598521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.gen!D"
        threat_id = "2147598521"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "drivers\\" ascii //weight: 1
        $x_1_2 = "DoService" ascii //weight: 1
        $x_10_3 = {33 c9 39 4c 24 08 76 10 8b 44 24 04 03 c1 80 30 ?? 41 3b 4c 24 08 72 f0 c3}  //weight: 10, accuracy: Low
        $x_10_4 = {83 c8 ff eb 1c 68 ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 74 03 ?? ff d0 ?? ff 15 ?? ?? ?? ?? 33 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_BV_2147598627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.BV"
        threat_id = "2147598627"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SYSTEM\\ControlSet001\\Services\\%s" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Classes\\HTTP\\shell\\open\\command" ascii //weight: 1
        $x_1_3 = "\\\\.\\pipe\\" ascii //weight: 1
        $x_1_4 = "WinSta0" ascii //weight: 1
        $x_1_5 = "\\svchost.exe -k" ascii //weight: 1
        $x_1_6 = "ServiceDll" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" ascii //weight: 1
        $x_1_8 = "[%04d-%02d-%02d %02d:%02d:%02d]" ascii //weight: 1
        $x_1_9 = "%d.exe" ascii //weight: 1
        $x_1_10 = "%d.tmp" ascii //weight: 1
        $x_1_11 = "updateevent=%s;" ascii //weight: 1
        $x_1_12 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322)" ascii //weight: 1
        $x_1_13 = "PcMain.dll" ascii //weight: 1
        $x_1_14 = "DoMainWork" ascii //weight: 1
        $x_1_15 = "DoService" ascii //weight: 1
        $x_1_16 = "ServiceMain" ascii //weight: 1
        $x_1_17 = {68 3f 00 0f 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 89 85 fc fd ff ff 83 bd fc fd ff ff 00 75 08 83 c8 ff e9 ?? ?? ?? ?? c6 85 00 fe ff ff 00 b9 7f 00 00 00 33 c0 8d bd 01 fe ff ff f3 ab 66 ab aa 68 c8 00 00 00 8d 85 00 fe ff ff 50 90 00 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 8d 00 fe ff ff 51 ff 15 ?? ?? ?? ?? 8b 55 08 52 8d 85 00 fe ff ff 50 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 00 6a 00 6a 00 8d 8d 00 fe ff ff 51 6a 01 6a 02 68 10 01 00 00 68 ff 01 0f 00 8b 55 0c 52 8b 45 08 50 8b ?? ?? ?? ?? 51 ff 15 ?? ?? ?? ?? 89 85 f8 fd ff ff 83 bd f8 fd ff ff 00 74 0d 8b 95 f8 fd ff ff 52 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_BW_2147598675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.BW"
        threat_id = "2147598675"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\svchost.exe" ascii //weight: 1
        $x_1_2 = "LoadProfile" ascii //weight: 1
        $x_1_3 = "drivers\\" ascii //weight: 1
        $x_1_4 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c ?? ?? ?? ?? ?? ?? ?? ?? 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_5 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 64 72 69 76 65 72 73 5c ?? ?? ?? ?? ?? ?? ?? ?? 2e 73 79 73}  //weight: 1, accuracy: Low
        $x_1_6 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c ?? ?? ?? ?? ?? ?? ?? ?? 2e 64 72 76}  //weight: 1, accuracy: Low
        $x_1_7 = {80 a5 d4 fe ff ff 00 6a 3f 59 33 c0 8d bd d5 fe ff ff f3 ab 66 ab aa 68 c8 00 00 00 8d 85 d4 fe ff ff 50 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 85 d4 fe ff ff 50 ff 15 ?? ?? ?? ?? 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 8d 85 d4 fe ff ff 50 ff 15 ?? ?? ?? ?? 89 45 fc 83 7d fc ff 75 0e ff 75 d4 ff 15 ?? ?? ?? ?? 6a 01 58 eb 4d 83 65 dc 00 33 c0 8d 7d e0 ab ab ab ab ab 8d 45 ec 50 8d 45 e4 50 8d 45 dc 50 ff 75 fc ff 15 ?? ?? ?? ?? 8d 45 ec 50 8d 45 e4 50 8d 45 dc 50 ff 75 d4 ff 15 ?? ?? ?? ?? ff 75 fc ff 15 ?? ?? ?? ?? ff 75 d4 ff 15 ?? ?? ?? ?? 6a 01 58 5f 5e 5b c9 c2 0c 00}  //weight: 1, accuracy: Low
        $x_1_8 = {80 a5 ec fe ff ff 00 6a 3f 59 33 c0 8d bd ed fe ff ff f3 ab 66 ab aa 68 ff 00 00 00 8d 85 ec fe ff ff 50 ff 15 ?? ?? ?? ?? 68 50 30 40 00 8d 85 ec fe ff ff 50 ff 15 ?? ?? ?? ?? 8d 85 ec fe ff ff 50 8b 45 08 05 dc 04 00 00 50 ff 15 ?? ?? ?? ?? 8b 45 08 05 6c 02 00 00 50 8b 45 08 05 dc 04 00 00 50 ff 15 ?? ?? ?? ?? 68 48 30 40 00 8b 45 08 05 dc 04 00 00 50 ff 15 ?? ?? ?? ?? 8d 85 ec fe ff ff 50 8b 45 08 05 dc 06 00 00 50 ff 15 ?? ?? ?? ?? 8b 45 08 05 6c 02 00 00 50 8b 45 08 05 dc 06 00 00 50 ff 15 ?? ?? ?? ?? 68 40 30 40 00 8b 45 08 05 dc 06 00 00 50 ff 15 ?? ?? ?? ?? 8d 85 ec fe ff ff 50 8b 45 08 05 dc 05 00 00 50 ff 15 ?? ?? ?? ?? 68 34 30 40 00 8b 45 08 05 dc 05 00 00 50 ff 15 ?? ?? ?? ?? 8b 45 08 05 6c 02 00 00 50 8b 45 08 05 dc 05 00 00 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_9 = {6a 2c 8d 85 c0 fe ff ff 50 e8 c7 04 00 00 59 59 8b 45 08 8b 8d c8 fe ff ff 89 08 8b 45 08 8b 8d cc fe ff ff 89 48 04 8b 45 08 8b 8d d0 fe ff ff 89 48 08 8b 45 08 8b 8d d4 fe ff ff 89 48 0c 8b 45 08 8b 8d d8 fe ff ff 89 48 10 0f b7 85 e4 fe ff ff 0f b7 8d de fe ff ff 03 c1 0f b7 8d dc fe ff ff 03 c1 0f b7 8d e0 fe ff ff 03 c1 0f b7 8d e8 fe ff ff 03 c1 0f b7 8d e6 fe ff ff 03 c1 0f b7 8d e2 fe ff ff 03 c1 89 45 f0 6a 02 6a 00 8b 45 f0 83 c0 2c 33 c9 2b c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_CE_2147598685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.CE"
        threat_id = "2147598685"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "141"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322)" ascii //weight: 10
        $x_10_2 = "http://%s:%d/%s%d%08d" ascii //weight: 10
        $x_10_3 = "index.asp?" ascii //weight: 10
        $x_10_4 = "CurrentControlSet\\" ascii //weight: 10
        $x_10_5 = "ControlSet003\\" ascii //weight: 10
        $x_10_6 = "ControlSet002\\" ascii //weight: 10
        $x_10_7 = "ControlSet001\\" ascii //weight: 10
        $x_10_8 = "SVCHOST.EXE" ascii //weight: 10
        $x_10_9 = "SELOADDriverPrivilege" ascii //weight: 10
        $x_10_10 = "LoadProfile" ascii //weight: 10
        $x_10_11 = "SensNotifyNetconEvent" ascii //weight: 10
        $x_10_12 = "SensNotifyRasEvent" ascii //weight: 10
        $x_10_13 = "SensNotifyWinlogonEvent" ascii //weight: 10
        $x_10_14 = "ServiceMain" ascii //weight: 10
        $x_1_15 = {8d 85 fc fe ff ff 68 20 51 00 10 50 89 7d fc ff d6 59 85 c0 59 74 0d 8d 45 fc 50 57 57 68 02 2d 00 10 eb 1f 8d 85 fc fe ff ff 68 14 51 00 10 50 ff d6 59 85 c0 59 74 13 8d 45 fc 50 57 57 68 39 2d 00 10 57 57 ff 15}  //weight: 1, accuracy: High
        $x_1_16 = {8d 85 fc fe ff ff 68 14 51 00 10 50 89 7d fc ff 15 ?? ?? ?? ?? 59 85 c0 59 74 13 8d 45 fc 50 57 57 68 98 2d 00 10 57 57 ff 15 ?? ?? ?? ?? 6a 01 58 5f 5e 5b c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((14 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_CV_2147599339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.CV"
        threat_id = "2147599339"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322)" ascii //weight: 1
        $x_1_2 = "[%04d-%02d-%02d %02d:%02d:%02d]" ascii //weight: 1
        $x_1_3 = "updateevent=%s;" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" ascii //weight: 1
        $x_1_5 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 67 64 69 70 6c 75 73 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_7 = {53 65 72 76 69 63 65 44 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_8 = {25 30 38 78 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_9 = {25 64 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_10 = "image/gif" wide //weight: 1
        $x_1_11 = "image/jpeg" wide //weight: 1
        $x_1_12 = "SYSTEM\\CurrentControlSet\\Services" ascii //weight: 1
        $x_1_13 = "Default IME" ascii //weight: 1
        $x_1_14 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_15 = "SOFTWARE\\Classes\\HTTP\\shell\\open\\command" ascii //weight: 1
        $x_1_16 = "\\\\.\\pipe\\" ascii //weight: 1
        $x_1_17 = "ControlSet003" ascii //weight: 1
        $x_1_18 = "ControlSet002" ascii //weight: 1
        $x_1_19 = "ControlSet001" ascii //weight: 1
        $x_1_20 = "%SystemRoot%\\System32\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_CW_2147599367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.CW"
        threat_id = "2147599367"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 72 76 69 63 65 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 65 6e 73 4e 6f 74 69 66 79 4e 65 74 63 6f 6e 45 76 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 65 6e 73 4e 6f 74 69 66 79 52 61 73 45 76 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 65 6e 73 4e 6f 74 69 66 79 57 69 6e 6c 6f 67 6f 6e 45 76 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {ff ff 68 c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 70 c6 85 ?? ?? ff ff 3a c6 85 ?? ?? ff ff 2f c6 85 ?? ?? ff ff 2f c6 85 ?? ?? ff ff 25 c6 85 ?? ?? ff ff 73 c6 85 ?? ?? ff ff 3a c6 85 ?? ?? ff ff 25 c6 85 ?? ?? ff ff 64 c6 85 ?? ?? ff ff 2f c6 85 ?? ?? ff ff 25 c6 85 ?? ?? ff ff 73 c6 85 ?? ?? ff ff 25 c6 85 ?? ?? ff ff 64 c6 85 ?? ?? ff ff 25 c6 85 ?? ?? ff ff 30 c6 85 ?? ?? ff ff 38 c6 85 ?? ?? ff ff 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_ZA_2147599562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.ZA"
        threat_id = "2147599562"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 00 00 00 00 44 6f 53 65 72 76 69 63 65 00 00 00 6d 79 67 75 69 64 00 00 6d 79 70 61 72 65 6e 74 74 68 72 65 61 64 69 64 00 00 00 00 25 73 3d 00 2e 73 79 73 00 00 00 00 64 72 69 76 65 72 73 5c 00 00 00 00 2e 6b 65 79 00 00 00 00 2e 65 78 65 00 00 00 00 2e 73 63 6f 00 00 00 00 2e 70 72 6f 00 00 00 00 2e 64 6c 6c 00 00 00 00 30 00 00 00 25 73 25 30 38 78 2e 69 6e 69 00 00 47 6c 6f 62 61 6c 5c 70 73 25 30 38 78 00 00 00 5c 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_CY_2147599775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.CY"
        threat_id = "2147599775"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 ff 01 0f 00 ff 75 08 ff 75 fc ff 15 ?? ?? 40 00 89 45 f8 83 7d f8 00 75 0e ff 75 fc ff 15 ?? ?? 40 00 6a 01 58 eb 26 ff 75 f8 ff 15 ?? ?? 40 00 85 c0 75 0d ff 75 fc ff 15 ?? ?? 40 00 33 c0 eb 0c ff 75 fc ff 15 ?? ?? 40 00 6a 01 58}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 08 05 74 02 00 00 50 8b 45 08 05 42 08 00 00 50 ff 15 ?? ?? 40 00 68 ?? ?? 40 00 8b 45 08 05 42 08 00 00 50 ff 15 ?? ?? 40 00 8d 85 ec fe ff ff 50 8b 45 08 05 42 06 00 00 50 ff 35 ?? ?? 40 00 68 ?? ?? 40 00 8b 45 08 05 42 06 00 00 50 ff 15 ?? ?? 40 00 8b 45 08 05 74 02 00 00 50 8b 45 08 05 42 06 00 00 50 ff 15 ?? ?? 40 00 68 3c 40 40 00 8b 45 08 05 42 06 00 00 50 ff 15 ?? ?? 40 00 8b 45 08 05 f0 03 00 00 50 e8 ?? ?? ?? ?? 59 c6 85 82 fe ff ff 08 c6 85 81 fe ff ff 08 c6 85 83 fe ff ff 04 c6 85 84 fe ff ff 02 83 65 fc 00 ff 75 08 8b 45 08 05 42 05 00 00 50 ff b5 6c fe ff ff 8d 8d 74 fe ff ff e8 ?? ?? ?? ?? 8b 85 6c fe ff ff 89 85 5c fe ff ff ff b5 5c fe ff ff}  //weight: 10, accuracy: Low
        $x_1_3 = "HipHop123" ascii //weight: 1
        $x_1_4 = "OpenServiceA" ascii //weight: 1
        $x_1_5 = "OpenSCManagerA" ascii //weight: 1
        $x_1_6 = "DoService" ascii //weight: 1
        $x_1_7 = "updateevent" ascii //weight: 1
        $x_1_8 = "drivers\\" ascii //weight: 1
        $x_1_9 = "\\svchost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_ZB_2147599776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.ZB"
        threat_id = "2147599776"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 30 30 00 68 74 74 70 3a 2f 2f 25 73 00 00 00 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 32 3b 20 53 56 31 3b 20 2e 4e 45 54 20 43 4c 52}  //weight: 1, accuracy: High
        $x_1_2 = {20 31 2e 31 2e 34 33 32 32 29 00 00 68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 73 25 64 25 30 38 64 00 00 00 69 6e 64 65 78 2e 61 73 70 3f 00 00 54 6f 44 6f 00 00 00 00 77 62 00 00 53 56 43 48 4f 53 54 2e 45 58 45 00 72 62 00 00 53 65 44 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_ZC_2147599777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.ZC"
        threat_id = "2147599777"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 69 6e 6c 6f 67 6f 6e 00 00 00 00 43 61 70 74 75 72 65 00 55 50 4a 50 47 2e 41 53 50 3f 25 64 25 73 00 00 50 55 54 00 69 6e 64 65 78 2e 61 73 70 3f 25 64 25 73 00 00 47 45 54 00 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69}  //weight: 1, accuracy: High
        $x_1_2 = {62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 32 3b 20 53 56 31 3b 20 2e 4e 45 54 20 43 4c 52 20 31 2e 31 2e 34 33 32 32 29 00 00 25 73 25 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 73 25 64 25 73 00 69 6e 64 65 78 2e 61 73 70 3f 00 00 25 75 00 00 25 64 4f 45 4d 43 50 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_ZD_2147599782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.ZD"
        threat_id = "2147599782"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 c0 83 f8 05 74 3b c6 45 b8 64 c6 45 b9 6d 90 90 90 c6 45 ba 73 c6 45 bb 65 90 c6 45 bc 72 c6 45 bd 76 c6 45 be 65 c6 45 bf 72 c6 45 c0 2e 90 c6 45 c1 64 c6 45 c2 6c c6 45 c3 6c 80 65 c4 00 eb 2e c6 45 b8 72 c6 45 b9 70 90 c6 45 ba 63 c6 45 bb 73 90 c6 45 bc 73 c6 45 bd 2e 90 90 90 c6 45 be 64 c6 45 bf 6c 90 c6 45 c0 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_CZ_2147599839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.CZ"
        threat_id = "2147599839"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SYSTEM\\ControlSet001\\Services\\%s" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" ascii //weight: 1
        $x_1_3 = "Network DDE" ascii //weight: 1
        $x_1_4 = "\\svchost.exe -k" ascii //weight: 1
        $x_1_5 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322)" ascii //weight: 1
        $x_1_6 = "PcClient.dll" ascii //weight: 1
        $x_1_7 = "LoadProfile" ascii //weight: 1
        $x_1_8 = "ServiceMain" ascii //weight: 1
        $x_1_9 = "ServiceDll" ascii //weight: 1
        $x_1_10 = "TestFunc" ascii //weight: 1
        $x_1_11 = "CallNextHookEx" ascii //weight: 1
        $x_1_12 = "image/jpeg" wide //weight: 1
        $x_10_13 = {68 7f 03 00 00 6a 00 68 ?? ?? 00 10 ff 15 ?? ?? 00 10 85 c0 74 07 50 ff 15 ?? ?? 00 10 68 cf 01 00 40 6a 00 6a 00 68 ?? ?? 00 10 ff 15 ?? ?? 00 10 85 c0 74 07 50 ff 15 ?? ?? 00 10 68 03 00 2e 00 6a 00 68 12 03 00 00 68 ff ff 00 00 ff 15 ?? ?? 00 10}  //weight: 10, accuracy: Low
        $x_10_14 = {53 56 8b 75 0c 33 db 57 39 9e 08 02 00 00 74 0d 8d 86 00 01 00 00 50 ff 15 ?? ?? 00 10 8d 4d e4 e8 ?? ?? 00 00 8d 86 00 01 00 00 53 68 01 30 00 00 50 8d 4d e4 89 5d fc 89 45 e0 e8 ?? ?? 00 00 85 c0 0f 84 a7 00 00 00 39 9e 08 02 00 00 75 18 8d 4d e4 e8 ?? ?? 00 00 85 c0 76 0c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_ZE_2147600140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.ZE"
        threat_id = "2147600140"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ServiceMain" ascii //weight: 2
        $x_2_2 = {56 8b 31 57 66 8b 7c 24 0c 66 89 3c 96 8b 31 0f b7 10 66 8b 7c 24 10 66 89 7c 96 02 66 ff 00 66 8b 00 5f 66 3d 08 00 5e 74 30 66 3d 10 00 74 2a 66 3d 20 00 74 24 66 3d 40 00 74 1e 66 3d 80 00 74 18 66 3d 00 01 74 12 66 3d 00 02 74 0c 66 3d 00 04 74 06 66 3d 00 08 75 03}  //weight: 2, accuracy: High
        $x_2_3 = {0f b6 d0 0f b6 54 0a 0d 01 51 34 8b 51 34 3b 51 28 72 16 fe c0 3c 04 88 41 0c 73 1c 0f b6 c0 0f b6 44 08 0d d1 e8 89 41 34 8b 41 38 8b 51 14 0f af 41 34 2b d0 89 51 1c}  //weight: 2, accuracy: High
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
        $x_1_5 = "CreateRemoteThread" ascii //weight: 1
        $x_1_6 = "ControlService" ascii //weight: 1
        $x_1_7 = "DeviceIoControl" ascii //weight: 1
        $x_1_8 = "InternetSetOption" ascii //weight: 1
        $x_1_9 = "InternetReadFile" ascii //weight: 1
        $x_1_10 = "SHDeleteKey" ascii //weight: 1
        $x_1_11 = "WS2_32.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_CI_2147600312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.CI"
        threat_id = "2147600312"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 ab 6a 02 6a 00 6a d0 ff b5 b8 fe ff ff ff 15 ?? ?? 40 00 83 65 ec 00 6a 00 8d 45 ec 50 6a 30 8d 85 bc fe ff ff 50 ff b5 b8 fe ff ff ff 15 ?? ?? 40 00 6a 30 8d 85 bc fe ff ff 50 e8 68 ?? ?? 00 59 59 8b 45 08 8b 8d c4 fe ff ff 89 08 8b 45 08 8b 8d c8 fe ff ff 89 48 04 8b 45 08 8b 8d cc fe ff ff 89 48 08 8b 45 08 8b 8d d0 fe ff ff 89 48 0c 8b 45 08 8b 8d d4 fe ff ff 89 48 10 0f b7 85 e0 fe ff ff 0f b7 8d da fe ff ff 03 c1 0f b7 8d d8 fe ff ff 03 c1 0f b7 8d dc fe ff ff 03 c1 0f b7 8d e4 fe ff ff 03 c1 0f b7 8d e2 fe ff ff 03 c1 0f b7 8d de fe ff ff 03 c1 0f b7 8d e6 fe ff ff 03 c1 0f b7 8d e8 fe ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c ?? ?? ?? ?? ?? ?? ?? ?? 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 64 72 69 76 65 72 73 5c ?? ?? ?? ?? ?? ?? ?? ?? 2e 73 79 73}  //weight: 1, accuracy: Low
        $x_1_4 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c ?? ?? ?? ?? ?? ?? ?? ?? 2e 64 72 76}  //weight: 1, accuracy: Low
        $x_1_5 = "software\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" ascii //weight: 1
        $x_1_6 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322)" ascii //weight: 1
        $x_1_7 = "PcMain.dll" ascii //weight: 1
        $x_1_8 = "LoadProfile" ascii //weight: 1
        $x_1_9 = "ServiceMain" ascii //weight: 1
        $x_1_10 = "ServiceDll" ascii //weight: 1
        $x_1_11 = "\\svchost.exe -k " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_E_2147600672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.gen!E"
        threat_id = "2147600672"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "520"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "GET / HTTP/1.1" ascii //weight: 100
        $x_100_2 = "POST /%s HTTP/1.1" ascii //weight: 100
        $x_100_3 = "\\svchost.exe -k" ascii //weight: 100
        $x_100_4 = "ServiceMain" ascii //weight: 100
        $x_100_5 = "Winlogon" ascii //weight: 100
        $x_10_6 = "SYSTEM\\CurrentControlSet\\Services\\" ascii //weight: 10
        $x_10_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii //weight: 10
        $x_10_8 = "[%04d-%02d-%02d %02d:%02d:%02d]" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_ZF_2147600981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.ZF"
        threat_id = "2147600981"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 [0-8] 44 6f 53 65 72 76 69 63 65 [0-6] 75 70 64 61 74 65 65 76 65 6e 74 00 25 73 3d 00 2e 73 79 73 [0-6] 64 72 69 76 65 72 73 5c [0-6] 2e 70 78 79 [0-6] 2e 64 72 76 [0-6] 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_ZG_2147600984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.ZG"
        threat_id = "2147600984"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 [0-8] 44 6f 53 65 72 76 69 63 65 [0-8] 75 70 64 61 74 65 65 76 65 6e 74 [0-6] 25 73 3d [0-6] 2e 53 59 53 [0-6] 64 72 69 76 65 72 73 5c [0-6] 2e 62 78 79 [0-6] 2e 44 52 56 [0-6] 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_F_2147601001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.gen!F"
        threat_id = "2147601001"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "222.11.12.26" ascii //weight: 5
        $x_5_2 = "http://www.ytwgyxx.com/Images/bg_06.gif" ascii //weight: 5
        $x_5_3 = "Messenger" ascii //weight: 5
        $x_5_4 = "00001823" ascii //weight: 5
        $x_5_5 = "C:\\WINDOWS\\system32\\1.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_ZH_2147601038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.ZH"
        threat_id = "2147601038"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 [0-8] 4c 6f 61 64 50 72 6f 66 69 6c 65 [0-6] 2e 73 79 73 [0-8] 64 72 69 76 65 72 73 5c [0-8] 2e 64 72 76 [0-8] 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_DC_2147601774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.DC"
        threat_id = "2147601774"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "72"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\svchost.exe" ascii //weight: 10
        $x_10_2 = "DoService" ascii //weight: 10
        $x_10_3 = "%s%08x.ini" ascii //weight: 10
        $x_10_4 = "Global\\ps%08x" ascii //weight: 10
        $x_10_5 = "192.168.0." ascii //weight: 10
        $x_10_6 = "douglas520.0033.cn" ascii //weight: 10
        $x_10_7 = "Microsoft .NET Framework TPM" ascii //weight: 10
        $x_1_8 = "eadid" ascii //weight: 1
        $x_1_9 = "drivers\\" ascii //weight: 1
        $x_1_10 = "myguid" ascii //weight: 1
        $x_1_11 = "myparentth" ascii //weight: 1
        $x_1_12 = "yruawfhk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_DE_2147604773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.DE"
        threat_id = "2147604773"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c [0-5] 2e 6c 6f 67}  //weight: 1, accuracy: Low
        $x_1_2 = "OpenSCManagerA" ascii //weight: 1
        $x_1_3 = "\\svchost.exe" ascii //weight: 1
        $x_1_4 = "myguid" ascii //weight: 1
        $x_1_5 = "myparentthreadid" ascii //weight: 1
        $x_1_6 = "drivers\\" ascii //weight: 1
        $x_1_7 = "Global\\ps%08x" ascii //weight: 1
        $x_1_8 = "Global\\ps000" wide //weight: 1
        $x_10_9 = {33 c0 8d bd ?? ?? ff ff f3 ab 66 ab aa 8b 45 08 ff 70 1c 68 ?? ?? 40 00 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? 40 00 83 c4 0c 8d 85 ?? ?? ff ff 50 6a 00 6a 00 ff 15 ?? ?? 40 00}  //weight: 10, accuracy: Low
        $x_10_10 = {50 8b 45 08 05 ?? ?? 00 00 50 ff 15 ?? ?? 40 00 68 ?? ?? 40 00 8b 45 08 05 ?? ?? 00 00 50 ff 15 ?? ?? 40 00 8d 85 ?? ?? ?? ?? 50 8b 45 08 05 ?? ?? 00 00 50 ff 15 ?? ?? 40 00 68 ?? ?? 40 00 8b 45 08 05 ?? ?? 00 00 50 ff 15 ?? ?? 40 00 8d 85 ?? ?? ?? ?? 50 8b 45 08 05 ?? ?? 00 00 50 ff 15 ?? ?? 40 00 68 ?? ?? 40 00 8b 45 08 05 ?? ?? 00 00 50}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_ZI_2147604834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.ZI"
        threat_id = "2147604834"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 e8 2e c6 45 e9 73 c6 45 ea 79 c6 45 eb 73 c6 45 d8 64 c6 45 d9 72 c6 45 da 69 c6 45 db 76 c6 45 dc 65 c6 45 dd 72 c6 45 de 73}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 84 6f c6 45 87 74 c6 45 e8 2e c6 45 e9 74 c6 45 ea 6d c6 45 eb 70}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 84 64 c6 45 87 69 c6 45 e8 2e c6 45 e9 64 c6 45 ea 6c c6 45 eb 6c}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 84 73 c6 45 87 70 c6 45 e8 2e c6 45 e9 74 c6 45 ea 6d c6 45 eb 70}  //weight: 1, accuracy: High
        $x_1_5 = {c6 45 84 7a c6 45 87 61 c6 45 e8 2e c6 45 e9 74 c6 45 ea 6d c6 45 eb 70}  //weight: 1, accuracy: High
        $x_1_6 = {c6 45 e0 25 c6 45 e1 73 c6 45 e2 5c c6 45 e3 25 c6 45 e4 73 c6 45 e5 2e c6 45 e6 65 c6 45 e7 78 c6 45 e8 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_PcClient_DF_2147605026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.DF"
        threat_id = "2147605026"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff ff 00 eb 0d 8b 85 ?? ?? ff ff 40 89 85 ?? ?? ff ff 83 bd ?? ?? ff ff 06 7d 37 ff 15 ?? ?? ?? ?? 99 6a 1a 59 f7 f9 8b 85 ?? ?? ff ff 88 94 ?? ?? fd ff ff 8b 85 ?? ?? ff ff 8a 84 ?? ?? fd ff ff 04 61}  //weight: 2, accuracy: Low
        $x_2_2 = {50 8b 45 08 05 f4 03 00 00 50 68 ?? ?? ?? ?? e8 ?? ?? 00 00 83 c4 0c c6 85 ?? ?? ff ff 08 c6 85 ?? ?? ff ff 08 c6 85 ?? ?? ff ff 04 c6 85 ?? ?? ff ff 02 83 65 fc 00 ff 75 08 8b 45 08 05 06 05 00 00 50}  //weight: 2, accuracy: Low
        $x_2_3 = "Service88" ascii //weight: 2
        $x_1_4 = "www.xuhack.cn/1.txt" ascii //weight: 1
        $x_1_5 = "%s%07x.log" ascii //weight: 1
        $x_1_6 = "Global\\Cs%06x" ascii //weight: 1
        $x_1_7 = "\\SVCHOST.EXE" ascii //weight: 1
        $x_1_8 = "DRIVERS\\" ascii //weight: 1
        $x_1_9 = ".KEY" ascii //weight: 1
        $x_1_10 = ".sco" ascii //weight: 1
        $x_1_11 = ".pro" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_DG_2147605077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.DG"
        threat_id = "2147605077"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://%s" ascii //weight: 1
        $x_1_2 = "Cache-Control: no-cache" ascii //weight: 1
        $x_1_3 = "Connection: Keep-Alive" ascii //weight: 1
        $x_1_4 = "SOFTware\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" ascii //weight: 1
        $x_1_5 = "\\SVCHOST.EXE -k" ascii //weight: 1
        $x_1_6 = "ServiceDll" ascii //weight: 1
        $x_1_7 = "POST /%s HTTP/1.1" ascii //weight: 1
        $x_1_8 = "CurrentControlSet" ascii //weight: 1
        $x_1_9 = "OpenSCManagerA" ascii //weight: 1
        $x_1_10 = "ShellExecuteA" ascii //weight: 1
        $x_1_11 = "MainWork" ascii //weight: 1
        $x_1_12 = "GUANPAI.EXE" ascii //weight: 1
        $x_1_13 = "SUOHA.EXE" ascii //weight: 1
        $x_1_14 = {33 c0 8d 7d 81 f3 ab 66 ab aa c6 45 80 ?? c6 45 81 ?? c6 45 82 ?? c6 45 83 ?? c6 45 84 ?? c6 45 85 ?? c6 45 86 ?? c6 45 87 ?? c6 45 88 ?? c6 45 89 ?? c6 45 8a}  //weight: 1, accuracy: Low
        $x_1_15 = {b9 ff 00 00 00 33 c0 8d bd ?? ?? ff ff f3 ab 66 ab aa 68 00 04 00 00 8d 85 ?? ?? ff ff 50 6a 00 8b 8d ?? ?? ff ff 51 e8 ?? ?? 00 00 89 85 ?? ?? ff ff 8b 95 ?? ?? ff ff 52 ff 15 ?? ?? 00 10 83 bd ?? ?? ff ff 00 76 49 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? 00 10 83 c4 04 68 ?? ?? 00 10 8d 8d ?? ?? ff ff 51 ff 15 ?? ?? 00 10 83 c4 08 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_N_2147608618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.N"
        threat_id = "2147608618"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.1)" ascii //weight: 10
        $x_10_2 = "\\svchost.exe -k" ascii //weight: 10
        $x_10_3 = "ServiceDll" ascii //weight: 10
        $x_10_4 = "SYSTEM\\ControlSet001\\Services\\%s" ascii //weight: 10
        $x_10_5 = {50 33 c0 33 c0 33 c0 33 c0 33 c0 33 c0}  //weight: 10, accuracy: High
        $x_1_6 = "POST http://%s:%d/%s HTTP/1.1" ascii //weight: 1
        $x_1_7 = "Global\\%s-key-Metux" ascii //weight: 1
        $x_1_8 = "myserverport" ascii //weight: 1
        $x_1_9 = "myserveraddr" ascii //weight: 1
        $x_1_10 = "mythreadid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_ZK_2147608830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.ZK"
        threat_id = "2147608830"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {78 c6 44 24 ?? 2e c6 44 24 ?? 61 c6 44 24 ?? 73 c6 44 24 ?? 70 c6 44 24 ?? 3f}  //weight: 3, accuracy: Low
        $x_3_2 = {c6 45 e7 65 c6 45 e8 78 c6 45 e9 2e [0-8] c6 45 ea 61 c6 45 eb 73 [0-8] c6 45 ec 70}  //weight: 3, accuracy: Low
        $x_2_3 = {c6 45 e4 69 89 55 e5 c6 45 e5 6e 89 55 e9 [0-8] c6 45 e7 65 89 55 ?? c6 45 e8 78 [0-4] c6 45 e9 2e}  //weight: 2, accuracy: Low
        $x_1_4 = "PcClient.dll" ascii //weight: 1
        $x_1_5 = {32 30 30 00 25 73 25 73 25 73}  //weight: 1, accuracy: High
        $x_1_6 = "ServiceMain" ascii //weight: 1
        $x_1_7 = "Fuck_Drweb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_AC_2147609089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.AC"
        threat_id = "2147609089"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 73 25 64 25 73 [0-16] 69 6e 64 65 78 2e 61 73 70 3f [0-16] 25 73 25 73 25 73 25 73 25 73 [0-16] 53 65 72 76 69 63 65 44 6c 6c [0-16] 53 59 53 54 45 4d 5c [0-16] 25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c [0-16] 73 65 6e 73 [0-16] 77 62 [0-16] 73 65 6e 73 2e 64 6c 6c [0-16] 53 65 72 76 69 63 65 4d 61 69 6e [0-16] 53 65 6e 73 4e 6f 74 69 66 79 4e 65 74 63 6f 6e 45 76 65 6e 74}  //weight: 5, accuracy: Low
        $x_1_2 = "RegSrcv" ascii //weight: 1
        $x_1_3 = "Norma32.dll" ascii //weight: 1
        $x_1_4 = "(*.exe)|*.exe|" ascii //weight: 1
        $x_1_5 = "ShellExecuteA" ascii //weight: 1
        $x_1_6 = "CreateServiceA" ascii //weight: 1
        $x_3_7 = {52 65 67 53 72 63 76 [0-5] 25 73 5c 54 65 73 74 57 72 69 74 65 50 72 6f 74 65 63 74 2e 74 78 74 [0-5] 25 73 5c 61 75 74 6f 72 75 6e 2e 69 6e 66}  //weight: 3, accuracy: Low
        $x_1_8 = "Recycle" ascii //weight: 1
        $x_4_9 = {89 06 0f 84 d7 00 00 00 8b 45 08 3b c3 0f 84 cc 00 00 00 8b 55 0c 3b d3 0f 84 c1 00 00 00 8d 48 01 89 56 1c 89 4e 18 88 5e 20 8a 08 6a 01 58 88 4e 22 d3 e0 89 5e 30 66 89 46 08 40 66 89 46 0a 8b 45 10 89 46 2c 8d 04 c5 1f 00 00 00 c1 e8 05 c1 e0 02 38 5d 18}  //weight: 4, accuracy: High
        $x_1_10 = {c6 85 a4 fe ff ff 2e c6 85 a5 fe ff ff 64 c6 85 a6 fe ff ff 6c c6 85 a7 fe ff ff 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_DH_2147609757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.DH"
        threat_id = "2147609757"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {e8 00 00 00 00 58 2d ?? ?? ?? ?? 05 [0-96] c7 40 ?? ?? ?? ?? ?? c7 40 20 01 c7 80 ?? 00 00 00 ?? ?? ?? ?? c7 80 ?? 00 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = {2e 64 6c 6c 00 [0-16] 44 6f 4d 61 69 6e [0-16] 53 65 72 76 69 63 65 [0-16] 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 1, accuracy: Low
        $x_1_3 = "%04d%02d%02d/%02d%02d%02d/%d.jsp" ascii //weight: 1
        $x_1_4 = "Global\\%s-key-metux" ascii //weight: 1
        $x_1_5 = "POST http://%s:%d/%s HTTP/1.1" ascii //weight: 1
        $x_1_6 = "qy001id=%d;qy001guid=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_DI_2147609759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.DI"
        threat_id = "2147609759"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c6 85 14 fb ff ff 70 c6 85 15 fb ff ff 61 c6 85 16 fb ff ff 73 c6 85 17 fb ff ff 73}  //weight: 2, accuracy: High
        $x_2_2 = {c6 85 85 fe ff ff 78 c6 85 86 fe ff ff 2e c6 85 87 fe ff ff 69 c6 85 88 fe ff ff 6e c6 85 89 fe ff ff 69}  //weight: 2, accuracy: High
        $x_3_3 = {6d 79 70 61 72 65 6e 74 74 68 72 65 61 64 69 64 3d 25 64 3b ?? ?? ?? ?? 69 64 3d 25 73}  //weight: 3, accuracy: Low
        $x_2_4 = {47 6c 6f 62 61 6c 5c 25 73 2d ?? ?? ?? 2d 6d 65 74 75 78}  //weight: 2, accuracy: Low
        $x_2_5 = {47 6c 6f 62 61 6c 5c 25 73 2d ?? ?? ?? 2d 65 76 65 6e 74}  //weight: 2, accuracy: Low
        $x_1_6 = "mythreadid" ascii //weight: 1
        $x_1_7 = "%d%d.exe" ascii //weight: 1
        $x_1_8 = "\\svchost.exe -k" ascii //weight: 1
        $x_1_9 = "[%02d-%04d-%02d %02d:%02d:%02d]" ascii //weight: 1
        $x_1_10 = "POST /%s HTTP/1.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_T_2147610296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.T"
        threat_id = "2147610296"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f3 ab 66 ab aa c6 85 ?? ?? ?? ?? 5c c6 85 ?? ?? ?? ?? 73 c6 85 ?? ?? ?? ?? 76 c6 85 ?? ?? ?? ?? 63 c6 85 ?? ?? ?? ?? 68 c6 85 ?? ?? ?? ?? 6f c6 85 ?? ?? ?? ?? 73 c6 85 ?? ?? ?? ?? 74 c6 85 ?? ?? ?? ?? 2e c6 85 ?? ?? ?? ?? 65 c6 85 ?? ?? ?? ?? 78 c6 85}  //weight: 10, accuracy: Low
        $x_1_2 = "drivers\\" ascii //weight: 1
        $x_1_3 = "%s%07x.ini" ascii //weight: 1
        $x_1_4 = "Global\\ps%08x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_DK_2147611915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.DK"
        threat_id = "2147611915"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "80"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" ascii //weight: 10
        $x_10_2 = "SYSTEM\\CurrentControlSet\\Services" ascii //weight: 10
        $x_10_3 = "CurrentControlSet" ascii //weight: 10
        $x_10_4 = "PcMain.dll" ascii //weight: 10
        $x_10_5 = "DoService" ascii //weight: 10
        $x_10_6 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322)" ascii //weight: 10
        $x_10_7 = "image/jpeg" wide //weight: 10
        $x_10_8 = {74 16 68 b8 0b 00 00 ff 15 ?? ?? ?? 10 68 ?? ?? ?? 10 ff 15 ?? ?? ?? 10 ff 15 ?? ?? ?? 10 a3 14 ?? ?? 10}  //weight: 10, accuracy: Low
        $x_1_9 = "\\svchost.exe -k " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_DL_2147614129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.DL"
        threat_id = "2147614129"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c6 85 58 ff ff ff 5c c6 85 59 ff ff ff 73 c6 85 5a ff ff ff 76 c6 85 5b ff ff ff 63 c6 85 5c ff ff ff 68 c6 85 5d ff ff ff 6f c6 85 5e ff ff ff 73 c6 85 5f ff ff ff 74 c6 85 60 ff ff ff 2e c6 85 61 ff ff ff 65 c6 85 62 ff ff ff 78 c6 85 63 ff ff ff 65 80 a5 54 fe ff ff 00}  //weight: 10, accuracy: High
        $x_3_2 = {33 c0 33 c0 0f 84 03 00 00 00 2c 2d 2e 58 80 a5 fc fe ff ff 00 6a 3f 59 33 c0 8d bd fd fe ff ff}  //weight: 3, accuracy: High
        $x_1_3 = "myparentthreadid" ascii //weight: 1
        $x_1_4 = "%s%07x.imi" ascii //weight: 1
        $x_1_5 = "Global\\ps%07x" ascii //weight: 1
        $x_1_6 = "jean.520815.com/ms/ip.rar" ascii //weight: 1
        $x_1_7 = "thunder5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_DM_2147616055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.DM"
        threat_id = "2147616055"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "RegisterServiceCtrlHandlerA" ascii //weight: 10
        $x_10_2 = "WSADuplicateSocketA" ascii //weight: 10
        $x_2_3 = "SYSTEM\\CURRENTControlSet\\SERVICES\\" ascii //weight: 2
        $x_2_4 = "ConnecTion: Keep-Alive" ascii //weight: 2
        $x_2_5 = "\\svchost.exe -k " ascii //weight: 2
        $x_1_6 = "%02d%04d%04d/%02d%02d%02d/%d.jsp" ascii //weight: 1
        $x_1_7 = "Global\\%s-ore-metux" ascii //weight: 1
        $x_1_8 = "Global\\%s-ore-EVENT" ascii //weight: 1
        $x_1_9 = "%05x.tnp" ascii //weight: 1
        $x_1_10 = "%s%07x.imi" ascii //weight: 1
        $x_1_11 = "ServeeeDo" ascii //weight: 1
        $x_1_12 = "FindFicked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_ZL_2147617013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.ZL"
        threat_id = "2147617013"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {63 3a 5c 31 2e 65 78 65 ?? ?? ?? ?? 47 65 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 49 6e 66 6f 41 ?? ?? ?? 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 43 61 63 68 65 46 69 6c 65 41}  //weight: 2, accuracy: Low
        $x_2_2 = {2e 50 41 58 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 50 41 44 ?? ?? ?? ?? 52 65 67 53 65 74 56 61 6c 75 65 45 78 28 53 65 72 76 69 63 65 44 6c 6c 29}  //weight: 2, accuracy: Low
        $x_1_3 = {25 64 2e 25 64 2e 25 64 2e 25 64 00 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31}  //weight: 1, accuracy: High
        $x_1_4 = {23 30 25 73 21 08 00 68 74 74 70 3a 2f 2f 00}  //weight: 1, accuracy: Low
        $x_1_5 = "svchost.dll" ascii //weight: 1
        $x_1_6 = "Rundll32 %s,RundllUninstall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_DN_2147618253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.DN"
        threat_id = "2147618253"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.1)" ascii //weight: 10
        $x_2_2 = "SYSTEM\\CurrentCONTROLSET\\SERVICES\\" ascii //weight: 2
        $x_2_3 = "%s%08x.sys" ascii //weight: 2
        $x_2_4 = "%d.exe" ascii //weight: 2
        $x_2_5 = "[%02d-%04d-%02d %02d:%02d:%02d]" ascii //weight: 2
        $x_2_6 = "/svchost.exe -k " ascii //weight: 2
        $x_2_7 = "ServiceDll" ascii //weight: 2
        $x_2_8 = "Global\\%s-key-metux" ascii //weight: 2
        $x_2_9 = "\\\\.\\%s" ascii //weight: 2
        $x_1_10 = "OpenSCManagerA" ascii //weight: 1
        $x_1_11 = "ServiceMain" ascii //weight: 1
        $x_1_12 = "SetWindowsHookExW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 8 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_DO_2147618623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.DO"
        threat_id = "2147618623"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "66"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "system\\currentcontrolset\\services\\" ascii //weight: 10
        $x_10_2 = "user-agent: mozilla/4.0 (compatible; msie 7.0; windows nt 5.2; .net clr 1.1.4322; .net clr 2.0.50727; infopath.1)" ascii //weight: 10
        $x_10_3 = "%d.exe" ascii //weight: 10
        $x_10_4 = "\\svchost.exe -k " ascii //weight: 10
        $x_10_5 = "servicedll" ascii //weight: 10
        $x_10_6 = "servicemain" ascii //weight: 10
        $x_2_7 = "Global\\%s-04d-metux" ascii //weight: 2
        $x_2_8 = "Global\\%s-04d-EVENT" ascii //weight: 2
        $x_2_9 = "mythreadid" ascii //weight: 2
        $x_1_10 = "setwindowshookexw" ascii //weight: 1
        $x_1_11 = "openscmanagera" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_10_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_ZM_2147618750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.ZM"
        threat_id = "2147618750"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 73 3d 00 00 2e 73 79 73 00 00 00 00 64 72 69 76 65 72 73 5c [0-6] 2e 6b 65 79 [0-6] 2e 65 78 65 [0-6] 2e ?? (61|2d|7a) (61|2d|7a) 00 [0-6] 2e ?? (61|2d|7a) (61|2d|7a) 00 [0-6] 2e [0-16] 25 73 25 30 35 78 2e 69 6d 69 [0-6] 47 6c 6f 62 61 6c 5c 70 73 25 30 36 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_ZF_2147619232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.ZF"
        threat_id = "2147619232"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 fa 63 7c f6 6a 63 6a 00 8d 95 04 ff ff ff 52 e8 ?? ?? 00 00 83 c4 0c 0f be 0e 83 f9 31 75 0e 8d 85 04 ff ff ff 50 6a 63 e8 ?? ?? 00 00 0f be 16 83 fa 32 75 0e}  //weight: 1, accuracy: Low
        $x_1_2 = {83 fa 65 0f 94 c1 0f be 50 01 83 e1 01 83 fa 78 0f 94 c0 8b 55 d4 83 e0 01 23 c8 0f be 42 02 83 f8 65 0f 94 c2 83 e2 01 23 ca 74 7d}  //weight: 1, accuracy: High
        $x_1_3 = {72 62 00 63 3a 5c 00 5c 53 65 74 75 70 2e 00 77 62 00 63 3a 5c 00 6f 70 65 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_ZN_2147619235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.ZN"
        threat_id = "2147619235"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {25 73 3d 00 2e 73 79 73 00 00 00 00 64 72 69 76 65 72 73 5c 00 [0-5] 2e 6b 65 79 00 00 00 00 2e 65 78 65 [0-5] 2e 73 63 6f 00 00 00 00 2e 70 72 6f 00 00 00 00 2e 64 6c 6c}  //weight: 4, accuracy: Low
        $x_1_2 = {6d 79 70 61 72 65 6e 74 74 68 72 65 61 64 69 64 00}  //weight: 1, accuracy: High
        $x_1_3 = "Global\\ps" ascii //weight: 1
        $x_1_4 = {6d 79 67 75 69 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_AH_2147622761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.AH"
        threat_id = "2147622761"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Program Files\\Internet Explorer\\%s" ascii //weight: 1
        $x_1_2 = {50 63 43 6c 69 65 6e 74 2e 64 6c 6c 00 44 6f 57 6f 72 6b 45 78 00 44 6f 57 6f 72 6b 57 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {6a 04 68 00 10 00 00 57 56 53 ff 15 ?? ?? ?? ?? 89 45 ?? 3b c6 74 ?? 56 57 ff 75 08 50 53 ff 15 ?? ?? ?? ?? 89 45 ?? 3b c6 74 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 89 45 ?? 3b c6 74 ?? 56 56 ff 75 ?? 50 56 56 53 ff 15 ?? ?? ?? ?? 89 45 ?? 3b c6 74 ?? 6a ff 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_AI_2147622762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.AI"
        threat_id = "2147622762"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 8d 45 ec 50 0f b7 85 ?? ?? ff ff 50 8b 45 08 (83 c0 ??|05 ?? ??) 50 ff b5 ?? ?? ff ff ff 15 ?? ?? 40 00 0f b7 85 ?? ?? ff ff 50 8b 45 08 (83 c0 ??|05 ?? ??) 50 e8 ?? ?? 00 00 59 59 6a 00 8d 45 ec 50}  //weight: 1, accuracy: Low
        $x_1_2 = {99 6a 1a 59 f7 f9 8b 45 08 03 85 ?? ?? ff ff 88 90 78 02 00 00 8b 45 08 03 85 ?? ?? ff ff 8a 80 78 02 00 00 ?? ?? 8b 4d 08 03 8d ?? ?? ff ff 88 81 78 02 00 00 eb ad}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_DS_2147623529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.DS"
        threat_id = "2147623529"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {47 6c 6f 62 c7 05 ?? ?? ?? 10 61 6c 5c 25 c7 05 ?? ?? ?? 10 73 2d 6b 65 c7 05 ?? ?? ?? 10 79 2d 6d 65 c7 05 ?? ?? ?? 10 74 75 78 00}  //weight: 6, accuracy: Low
        $x_2_2 = {6d 79 70 61 72 65 6e 74 74 68 72 65 61 64 69 64 3d 25 64 3b ?? ?? ?? ?? 69 64 3d 25 73}  //weight: 2, accuracy: Low
        $x_2_3 = {47 6c 6f 62 61 6c 5c 25 73 2d ?? ?? ?? 2d 65 76 65 6e 74}  //weight: 2, accuracy: Low
        $x_1_4 = "myserverport" ascii //weight: 1
        $x_1_5 = "mythreadid" ascii //weight: 1
        $x_1_6 = {25 30 38 78 2e 74 6d 70 [0-16] 25 73 5c 2a 2e 2a}  //weight: 1, accuracy: Low
        $x_1_7 = "%02d%04d%02d/%02d%02d%02d/%d.jsp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_AX_2147623563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.AX"
        threat_id = "2147623563"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Connection:Keep-Alive" ascii //weight: 2
        $x_2_2 = "Accept-Language:zh-cn" ascii //weight: 2
        $x_10_3 = "&GameName=%s&Mac=%s" ascii //weight: 10
        $x_3_4 = "Brazil\\pcClient.ini" ascii //weight: 3
        $x_3_5 = "%s%s/%s_%d.zip" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_DT_2147623612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.DT"
        threat_id = "2147623612"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {59 c6 44 24 ?? 41 c6 44 24 ?? 4e c6 44 24 ?? 47 8b 54 24 ?? 8d 8e ?? ?? 00 00 c6 86 ?? ?? 00 00 00 89 86 ?? ?? 00 00 c6 44 24 ?? 5a c6 44 24 ?? 53}  //weight: 2, accuracy: Low
        $x_2_2 = {47 c6 44 24 ?? 68 c6 44 24 ?? 30 c6 44 24 ?? 73 8b 54 24 ?? 8d 8e ?? ?? 00 00 89 86 ?? ?? 00 00 b0 74}  //weight: 2, accuracy: Low
        $x_2_3 = {68 58 02 00 00 50 51 ff 15 ?? ?? 01 10 80 bc 24 ?? ?? 00 00 05 0f 85 ?? ?? 00 00 8a 84 24 ?? ?? 00 00 84 c0 74 0a 3a c3 0f 85 ?? ?? 00 00 eb 08}  //weight: 2, accuracy: Low
        $x_1_4 = {75 70 66 69 6c 65 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = {75 70 66 69 6c 65 65 72 00}  //weight: 1, accuracy: High
        $x_1_6 = {74 72 61 66 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {53 76 63 48 6f 73 74 2e 44 4c 4c 2e 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_8 = {5c 7e 53 65 72 76 65 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_9 = {5c 7e 53 43 6d 64 2e 74 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_DU_2147623613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.DU"
        threat_id = "2147623613"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 00 00 00 c7 45 ?? 01 00 00 00 66 8b 4d ?? 66 89 4d dc 81 7d ?? 49 1f 00 00 75 7f}  //weight: 2, accuracy: Low
        $x_2_2 = {c7 00 57 69 6e 53 c7 40 04 74 61 30 00 61 eb 00}  //weight: 2, accuracy: High
        $x_2_3 = {47 45 54 20 c7 40 04 2f 20 48 54 c7 40 08 54 50 2f 31 c7 40 0c 2e 31 0d 0a}  //weight: 2, accuracy: High
        $x_2_4 = {6d 79 73 65 c7 ?? ?? ?? ?? ?? 72 76 65 72 c7 ?? ?? ?? ?? ?? 70 6f 72 74}  //weight: 2, accuracy: Low
        $x_2_5 = {72 76 65 72 c7 ?? ?? ?? ?? ?? 61 64 64 72}  //weight: 2, accuracy: Low
        $x_2_6 = {3d 25 64 3b ?? ?? ?? ?? 69 64 3d 25 73}  //weight: 2, accuracy: Low
        $x_2_7 = {47 6c 6f 62 61 6c 5c 25 73 2d ?? ?? ?? 2d 65 76 65 6e}  //weight: 2, accuracy: Low
        $x_2_8 = {47 6c 6f 62 61 6c 5c 25 73 2d ?? ?? ?? 2d 6d 65 74 75}  //weight: 2, accuracy: Low
        $x_1_9 = "%02d%04d%02d/%02d%02d%02d/%d.jsp" ascii //weight: 1
        $x_1_10 = "serverport" ascii //weight: 1
        $x_1_11 = "mythreadid" ascii //weight: 1
        $x_1_12 = "myserveraddr" ascii //weight: 1
        $x_1_13 = {25 30 38 78 2e 74 6d 70 [0-21] 25 73 5c 2a 2e 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_BA_2147623641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.BA"
        threat_id = "2147623641"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 cf 01 00 40 6a 00 8d 8c 24 08 01 00 00 6a 01 51 ff 15 4c 20 00 10 85 c0 74 07 50 ff 15 48 20 00 10}  //weight: 1, accuracy: High
        $x_1_2 = {2e 64 6c 6c 00 53 4b 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "OpenWindowStationA" ascii //weight: 1
        $x_1_4 = "CallNextHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_DV_2147624083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.DV"
        threat_id = "2147624083"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 fc fa ff ff 56 ff 15 ?? ?? ?? ?? 8b 7c 24 ?? 8d 4c 24 ?? 6a 00 51 68 04 05 00 00 57 56 c7 44 24 20 00 00 00 00 ff 15}  //weight: 3, accuracy: Low
        $x_2_2 = {76 17 8a 54 24 ?? 8b 4c 24 ?? 53 8a 1c 08 32 da 88 1c 08 40 3b c6 72 f3}  //weight: 2, accuracy: Low
        $x_2_3 = {80 7d 00 53 0f ?? ?? ff ff ff 80 7d 01 53 0f ?? ?? ff ff ff 80 7d 02 48 0f ?? ?? ff ff ff}  //weight: 2, accuracy: Low
        $x_1_4 = {50 63 4d 61 69 6e 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {44 6f 4d 61 69 6e 57 6f 72 6b 00}  //weight: 1, accuracy: High
        $x_1_6 = "%04d%02d%02d/%02d%02d%02d/%d.jsp" ascii //weight: 1
        $x_1_7 = {70 61 73 73 [0-7] 6e 61 6d 65 [0-7] 70 6f 72 74}  //weight: 1, accuracy: Low
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

rule Backdoor_Win32_PcClient_BC_2147624395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.BC"
        threat_id = "2147624395"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 33 c0 e9 4b 0a 00 00 90 53 76 9b 58 68 ff 00 00 00 8b 45 08 05 42 04 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_BE_2147626295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.BE"
        threat_id = "2147626295"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 63 43 6c 69 65 6e 74 2e 64 6c 6c 00 50 63 53 68 61 72 65 50 6c 61 79 57 6f 72 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {51 8d 4e 0c 51 0f b7 0e 51 8d 4e ?? 51 ff b6 ?? ?? 00 00 ff b6 ?? ?? 00 00 ff d0 83 c4 18 68 b8 0b 00 00 ff b6 58 03 00 00 ff 15 ?? ?? ?? ?? 3d 02 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_G_2147627028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.gen!G"
        threat_id = "2147627028"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[%02d-%04d-%02d %02d:%02d:%02d]" ascii //weight: 1
        $x_2_2 = "%02d%04d%02d/%02d%02d%02d/%d.jsp" ascii //weight: 2
        $x_1_3 = "Global\\%s" ascii //weight: 1
        $x_1_4 = "myparentthreadid=%d;rgukid=%s" ascii //weight: 1
        $x_1_5 = "SYSTEM\\ControlSet001\\Services\\" ascii //weight: 1
        $x_1_6 = {50 4f 53 54 [0-16] 68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 73}  //weight: 1, accuracy: Low
        $x_1_7 = {68 74 74 70 3a 2f 2f 25 73 [0-16] 25 64 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_8 = "User-Agent: Mozilla/4.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_DW_2147627647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.DW"
        threat_id = "2147627647"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" ascii //weight: 1
        $x_1_2 = "SYSTEM\\CurrentControlSet\\Services\\" ascii //weight: 1
        $x_1_3 = "ServiceDll" ascii //weight: 1
        $x_1_4 = "%SystemRoot%\\system32\\svchost.exe -k netsvcs" ascii //weight: 1
        $x_1_5 = "SYSTEM\\CurrentControlSet\\Services\\USBDriver" ascii //weight: 1
        $x_1_6 = "Global\\{7EB4B573-1C77-4a33-9CDA-AB3511895AB9}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_BS_2147627925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.BS"
        threat_id = "2147627925"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 00 6d 00 61 00 67 00 65 00 2f 00 67 00 69 00 66 00 00 00 69 00 6d 00 61 00 67 00 65 00 2f 00 6a 00 70 00 65 00 67 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 85 00 fc ff ff 49 c6 85 01 fc ff ff 65 c6 85 02 fc ff ff 78 c6 85 03 fc ff ff 70 c6 85 04 fc ff ff 6c c6 85 05 fc ff ff 6f c6 85 06 fc ff ff 72 c6 85 07 fc ff ff 65 c6 85 08 fc ff ff 2e c6 85 09 fc ff ff 65 c6 85 0a fc ff ff 78 c6 85 0b fc ff ff 65 0f be 8d 00 fe ff ff 83 e9 30 f7 d9 1b c9 83 e1 fb 83 c1 05 51 6a 00 8d 95 01 fe ff ff 52 8d 85 00 fc ff ff 50 6a 00 6a 00 ff 15 ?? ?? ?? ?? 5f 5e 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_DX_2147628148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.DX"
        threat_id = "2147628148"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3d 25 64 3b ?? ?? ?? ?? 69 64 3d 25 73}  //weight: 2, accuracy: Low
        $x_2_2 = {47 6c 6f 62 61 6c 5c 25 73 2d ?? ?? ?? 2d}  //weight: 2, accuracy: Low
        $x_2_3 = {70 61 73 73 [0-7] 6e 61 6d 65 [0-7] 70 6f 72 74}  //weight: 2, accuracy: Low
        $x_1_4 = "serverport" ascii //weight: 1
        $x_1_5 = "mythreadid" ascii //weight: 1
        $x_1_6 = "myserveraddr" ascii //weight: 1
        $x_1_7 = "POST http://%s/" ascii //weight: 1
        $x_1_8 = {64 2f 25 64 2e 6a 73 70 00}  //weight: 1, accuracy: High
        $x_1_9 = "system\\currentcontrolset\\services\\" ascii //weight: 1
        $x_1_10 = "%02d:%02d:%02d]" ascii //weight: 1
        $x_1_11 = {25 30 35 78 2e 74 6e 70 00}  //weight: 1, accuracy: High
        $x_4_12 = {25 73 2d 6b c7 40 04 65 79 2d 65}  //weight: 4, accuracy: High
        $x_3_13 = {c7 00 57 69 6e 53 c7 40 04 74 61 30 00 61 eb 00}  //weight: 3, accuracy: High
        $x_3_14 = {4d 61 69 6e c7 40 04 57 6f 72 6b}  //weight: 3, accuracy: High
        $x_2_15 = {c7 00 56 45 4e 54 61}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_BX_2147628762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.BX"
        threat_id = "2147628762"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c1 70 e8 ?? ?? ?? ?? 6a 00 6a 00 68 b6 05 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {32 75 00 00 77 ?? 81 7d ?? 32 75 00 00 0f 84 ?? ?? ?? ?? 8b 4d ?? 81 e9 41 1f 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_DY_2147629137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.DY"
        threat_id = "2147629137"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 ab aa c6 85 ?? ?? ?? ?? 5c c6 85 ?? ?? ?? ?? 73 c6 85 ?? ?? ?? ?? 76 c6 85 ?? ?? ?? ?? 63 c6 85 ?? ?? ?? ?? 68 c6 85 ?? ?? ?? ?? 6f c6 85 ?? ?? ?? ?? 73 c6 85 ?? ?? ?? ?? 74 c6 85 ?? ?? ?? ?? 2e c6 85 ?? ?? ?? ?? 65}  //weight: 1, accuracy: Low
        $x_1_2 = {66 ab aa c6 85 ?? ?? ?? ?? 25 c6 85 ?? ?? ?? ?? 73 c6 85 ?? ?? ?? ?? 25 c6 85 ?? ?? ?? ?? 30 c6 85 ?? ?? ?? ?? ?? c6 85 ?? ?? ?? ?? 78 c6 85 ?? ?? ?? ?? 2e c6 85 ?? ?? ?? ?? 73}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 1a 59 f7 f9 8b 45 08 03 85 ?? ?? ?? ?? 88 90 78 02 00 00 8b 45 08 03 85 ?? ?? ?? ?? 8a 80 78 02 00 00 ?? ?? 8b 4d 08 03 8d ?? ?? ?? ?? 88 81 78 02 00 00 eb ad}  //weight: 1, accuracy: Low
        $x_1_4 = {53 65 72 76 65 65 65 44 6f [0-32] 25 73 3d [0-5] 2e 73 79 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_PcClient_ZP_2147631500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.ZP"
        threat_id = "2147631500"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b2 25 b1 30 b0 64 b3 32 c6 ?? 24 1c 5b 88 ?? 24 1d 88 ?? 24 1e c6 ?? 24 1f 34 88 ?? 24 20 c6 ?? 24 21 2d 88 ?? 24 22 88 ?? 24 23 88 ?? 24 24 88 ?? 24 25 c6 ?? 24 26 2d 88 ?? 24 27 88 ?? 24 28 88 ?? 24 29 88 ?? 24 2a c6 ?? 24 2b 20 88 ?? 24 2c 88 ?? 24 2d 88 ?? 24 2e 88 ?? 24 2f c6 ?? 24 30 3a 88 ?? 24 31 88 ?? 24 32 88 ?? 24 33 88 ?? 24 34 c6 ?? 24 35 3a 88 ?? 24 36 88 ?? 24 37 88 ?? 24 38 88 ?? 24 39 c6 ?? 24 3a 5d ff d6}  //weight: 10, accuracy: Low
        $x_1_2 = "GetKeyboardState" ascii //weight: 1
        $x_1_3 = "CallNextHookEx" ascii //weight: 1
        $x_1_4 = "SetProcessWindowStation" ascii //weight: 1
        $x_1_5 = "GetWindowTextA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_EB_2147633557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.EB"
        threat_id = "2147633557"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 ab 66 ab aa c6 85 ?? ?? ?? ?? 2e c6 85 ?? ?? ?? ?? 73 c6 85 ?? ?? ?? ?? 79 c6 85 ?? ?? ?? ?? 73 80 a5 ?? ?? ?? ?? 00 68 c8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {f3 ab 66 ab aa c6 85 ?? ?? ?? ?? 7a c6 85 ?? ?? ?? ?? 2e c6 85 ?? ?? ?? ?? 64 c6 85 ?? ?? ?? ?? 6c c6 85 ?? ?? ?? ?? 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_DZ_2147637764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.DZ"
        threat_id = "2147637764"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AinSta0\\Default" ascii //weight: 1
        $x_1_2 = "Fuck_avp" ascii //weight: 1
        $x_1_3 = {00 33 36 30 73 64 61 00}  //weight: 1, accuracy: High
        $x_1_4 = {54 65 72 6d 69 6e 61 6c 20 53 65 72 76 65 72 5c 52 44 50 54 63 70 00 50 6f 72 74 4e 75 6d 62 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_EC_2147637953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.EC!dll"
        threat_id = "2147637953"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {99 b9 ff 00 00 00 f7 f9 80 fa 20}  //weight: 2, accuracy: High
        $x_1_2 = "PcClient.dll" ascii //weight: 1
        $x_1_3 = "http://%s:%d/%d%s" ascii //weight: 1
        $x_1_4 = "%s?mac=%s&i=1&t=%6d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_CM_2147640286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.CM"
        threat_id = "2147640286"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "10198=polmxhat" ascii //weight: 10
        $x_10_2 = "10262=rundll32.exe \"%s\",%s ServerAddr=%s;ServerPort=%d;Hwnd=%d;Cmd=%d;DdnsUrl=%s;" ascii //weight: 10
        $x_5_3 = "jiebiao.3322.org" ascii //weight: 5
        $x_1_4 = "10281=\\%ssck.ini" ascii //weight: 1
        $x_1_5 = "10311=\\%sctr.dll" ascii //weight: 1
        $x_1_6 = "10282=\\%skey.dll" ascii //weight: 1
        $x_1_7 = "10283=\\%skey.txt" ascii //weight: 1
        $x_1_8 = "10312=\\%stmp.exe" ascii //weight: 1
        $x_1_9 = "10240=%sreg.dll" ascii //weight: 1
        $x_1_10 = "10239=%sreg.reg" ascii //weight: 1
        $x_1_11 = "10202=%scom.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_CM_2147640286_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.CM"
        threat_id = "2147640286"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b d3 76 2e bf ?? ?? ?? ?? 81 3c 01 ?? ?? ?? ?? 75 06 39 7c 01 04 74 07 41 3b ca 72 ec eb 13}  //weight: 1, accuracy: Low
        $x_1_2 = {2b f0 8a 14 06 8a 18 3a d3 75 11 41 40 3b cf 7c f1}  //weight: 1, accuracy: High
        $x_1_3 = {76 12 80 3c 38 0d 74 13 47 8b cb 2b cf 83 e9 ?? 3b f9 72 ee 47 3b fb 72 ac eb 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_PcClient_ZR_2147642065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.ZR"
        threat_id = "2147642065"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3d 00 00 20 03 73 ?? 6a 02 6a 00 6a 00 ?? ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 14 01 80 f2 ?? 88 10 40 4d 75 f4}  //weight: 2, accuracy: Low
        $x_2_3 = {6a 00 6a 00 6a 00 6a 00 6a ?? (eb|ff)}  //weight: 2, accuracy: Low
        $x_1_4 = "syslog.dat" ascii //weight: 1
        $x_1_5 = "%d.bak" ascii //weight: 1
        $x_1_6 = "%2d%2d%2d%2d%2d%2d" ascii //weight: 1
        $x_1_7 = "rasphone.pbk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_ZT_2147642274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.ZT!dll"
        threat_id = "2147642274"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 c2 2c 35 00 00 40 3b c1 89 15 ?? ?? ?? ?? 7c dc}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 50 3c 81 c5 ?? 3e 00 00 89 0d ?? ?? ?? ?? 89 2d ?? ?? ?? ?? 8b 54 02 50 83 c2 f8}  //weight: 1, accuracy: Low
        $x_1_3 = {81 3c 01 12 65 12 76 75 06 39 5c 01 04 74 07 41 3b ca 72 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_ZU_2147642275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.ZU"
        threat_id = "2147642275"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 e3 f7 80 f9 a0 72 13 80 f9 a3 77 0e}  //weight: 1, accuracy: High
        $x_1_2 = {83 ee 05 c6 00 e9 89 70 01}  //weight: 1, accuracy: High
        $x_2_3 = {60 8b 85 98 ef ff ff 83 f8 00 74 17}  //weight: 2, accuracy: High
        $x_1_4 = "C:\\mxdos.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_CN_2147645113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.CN"
        threat_id = "2147645113"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 75 74 64 6f 77 6e 68 61 6e 67 65 6c 2e 64 6c 6c [0-4] 6c 75 6d 65 49 6e 66 6f 72 6c [0-4] 44 7a 53 65 72 76 69 63 65 [0-4] 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_CP_2147678467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient.CP"
        threat_id = "2147678467"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 02 00 00 68 60 01 00 00 8d [0-5] 51 6a 00 8d [0-3] 52 ff d0 33 c0 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "\\cmd.exe /c " ascii //weight: 1
        $x_1_3 = {25 34 64 2d 25 30 32 64 2d 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 00 00 00 00 4b 69 6c 6c 20 59 6f 75 00 00 00 00 25 34 2e 32 66 20 47 42 00}  //weight: 1, accuracy: High
        $x_1_4 = {52 69 53 69 6e 67 00 00 49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {57 69 6e 53 74 61 30 5c 44 65 66 61 75 6c 74 00 63 3a 5c 00 63 6d 64 2e 65 78 65 20 2f 63 20 22 25 73 22 00 6f 70 65 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_PcClient_2147789786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient"
        threat_id = "2147789786"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 00 00 00 00 44 6f 53 65 72 76 69 63 65 00 00 00 75 70 64 61 74 65 65 76 65 6e 74 00 25 73 3d 00 2e 73 79 73 00 00 00 00 64 72 69 76 65 72 73 5c 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 3e 46 a0 1f 26 5a 95 1e 7a 4e 02 64 10 64 fa 1f 36 ba 0a 90 cf 8d d1 61 1a 72 9a a2 6f 98 1f 7c a4 a3 31 79 63 ab ca a0 49 1a 93 06 a1 07 c8 20 08 0e 62 3b ea 15 27 74 e2 52 d9 84 7c 4b c4 6e 1f ba 01 9e fa 20 80 46 63 41 ba 50 99 35 9e 05 19 41 9b 9a 01 4e 37 2f e8 e0 04 9a ba ab d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_2147789786_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient"
        threat_id = "2147789786"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 00 00 00 00 44 6f 53 65 72 76 69 63 65 00 00 00 75 70 64 61 74 65 65 76 65 6e 74 00 25 73 3d 00 2e 73 79 73 00 00 00 00 64 72 69 76 65 72 73 5c 00}  //weight: 1, accuracy: High
        $x_1_2 = {ea 8f 57 79 4f 17 af 21 c4 da d9 24 f0 13 06 b7 df 18 66 14 23 e0 6b 58 29 91 5e a4 d8 7e ed 19 96 2c c8 a7 06 e8 80 33 e2 d9 18 e7 1d 1b e0 7e 91 21 99 67 66 b0 44 01 93 0c d6 f0 32 87 90 56 7c f9 05 20 a2 7e e9 c7 6a f8 16 f3 5a 33 c8 57 e0 75 4e 91 cf 77 b8 97 14 ca 12 c8 fe d9 48 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_2147789786_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient"
        threat_id = "2147789786"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 00 44 6f 53 65 72 76 69 63 65 00 00 00 6d 79 67 75 69 64 00 00 6d 79 70 61 72 65 6e 74 74 68 72 65 61 64 69 64 00 00 00 00 25 73 3d 00 2e 73 79 73 00 00 00 00 64 72 69 76 65 72 73 5c 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 31 2a e2 cf 3f 0c e2 0a e8 70 00 3e e9 b5 10 0a 94 88 3a e0 a8 8c 25 31 89 10 09 1e 2d 25 9c 74 26 24 6a d4 20 00 4c 61 11 34 e1 40 4c a8 f6 49 db c4 64 11 e9 b8 c2 4a aa 09 80 5b 81 60 6f 69 c1 c0 0e b0 21 3c 9e 8c 0f 18 e1 1c 49 49 ec 40 a1 1e 30 41 a4 45 20 c0 5a 28 10 05 66 b9 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_2147789786_3
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient"
        threat_id = "2147789786"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 00 00 44 6f 53 65 72 76 69 63 65 00 00 00 6d 79 67 75 69 64 00 00 6d 79 70 61 72 65 6e 74 74 68 72 65 61 64 69 64 00 00 00 00 25 73 3d 00 2e 73 79 73 00 00 00 00 64 72 69 76 65 72 73 5c 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 a3 2b 0d 5f f1 50 ef 1a 3a a2 57 00 3b 40 85 99 03 32 88 18 85 1e be c4 57 d1 86 1d d4 80 c9 d0 41 0c 98 8d 95 30 58 90 90 08 0d b8 ef 67 ad 40 02 6d c5 03 61 55 24 58 83 01 61 c0 12 3d 42 5f 8f 8c 81 ac b9 d5 b8 00 8b a4 d9 12 dd c1 b1 c7 0f 62 bc 44 0d f4 d0 6e 58 c3 52 58 43 17 a8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_2147789786_4
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient"
        threat_id = "2147789786"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 00 00 00 44 6f 53 65 72 76 69 63 65 00 00 00 6d 79 67 75 69 64 00 00 6d 79 70 61 72 65 6e 74 74 68 72 65 61 64 69 64 00 00 00 00 25 73 3d 00 2e 73 79 73 00 00 00 00 64 72 69 76 65 72 73 5c 00}  //weight: 1, accuracy: High
        $x_1_2 = {3e 89 81 03 84 41 b5 54 7d 4e c0 a0 d0 16 21 1b f6 ce 83 f6 35 21 28 e0 4b c0 67 ba 16 65 09 56 4f 54 27 66 19 10 68 ac 16 61 0f 18 20 17 30 61 78 08 82 01 8e 61 08 10 e0 ea a7 cb 72 d0 9e 14 06 3c e1 aa 9d 76 ec 5e 1e ed 6a 4e f6 62 44 27 3a a6 0f a8 19 3e 1b 24 44 13 a3 8c 09 01 ea 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_PcClient_2147789786_5
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient"
        threat_id = "2147789786"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 00 00 53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 53 65 72 76 69 63 65 73 5c 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 61 73 73 00 00 00 00 6e 61 6d 65 00 00 00 00 70 6f 72 74}  //weight: 1, accuracy: High
        $x_1_3 = "mythreadid=%d;myserveraddr=%s;myserverport=%d" ascii //weight: 1
        $x_1_4 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.1)" ascii //weight: 1
        $x_1_5 = "%04d%02d%02d/%02d%02d%02d/%d.jsp" ascii //weight: 1
        $x_10_6 = {50 72 6f 78 79 53 65 72 76 65 72 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 00 50 72 6f 78 79 45 6e 61 62 6c 65 00 2e 65 78 65 00 00 00 00 53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 48 54 54 50 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00 00 00 00 25 73 3d 00 53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 00 00 00 00 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_PcClient_2147789786_6
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/PcClient"
        threat_id = "2147789786"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "111"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\svchost.exe" ascii //weight: 1
        $x_1_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c [0-32] 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 64 72 69 76 65 72 73 5c [0-32] 2e 73 79 73}  //weight: 1, accuracy: Low
        $x_1_4 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c [0-32] 2e 64 72 76}  //weight: 1, accuracy: Low
        $x_1_5 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c [0-32] 2e 70 78 79}  //weight: 1, accuracy: Low
        $x_1_6 = "cmd.exe" ascii //weight: 1
        $x_1_7 = "StrStrA" ascii //weight: 1
        $x_1_8 = "OpenServiceA" ascii //weight: 1
        $x_1_9 = "CloseServiceHandle" ascii //weight: 1
        $x_1_10 = "DeleteService" ascii //weight: 1
        $x_1_11 = "OpenSCManagerA" ascii //weight: 1
        $x_100_12 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 00 00 00 00 44 6f 53 65 72 76 69 63 65 00 00 00 75 70 64 61 74 65 65 76 65 6e 74 00 25 73 3d 00 2e 73 79 73 00 00 00 00 64 72 69 76 65 72 73 5c 00 00 00 00 2e 70 78 79 00 00 00 00 2e 64 72 76 00 00 00 00 2e 64 6c 6c 00}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

