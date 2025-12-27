rule Trojan_Win32_RedLineStealer_RT_2147780240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.RT!MTB"
        threat_id = "2147780240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "44"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Password \\ Pass phrase to be tested" ascii //weight: 10
        $x_10_2 = "Generated Password \\ Passphrase" ascii //weight: 10
        $x_10_3 = "Zombie_GetTypeInfo" ascii //weight: 10
        $x_10_4 = "F*\\AD:\\Junk Programs\\Test_Passw20243252017\\TestPwd\\TestPwd.vbp" ascii //weight: 10
        $x_10_5 = "Kenneth Ives kenaso@tx.rr.com" ascii //weight: 10
        $x_1_6 = "ShellExecuteA" ascii //weight: 1
        $x_1_7 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_8 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_9 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 4 of ($x_1_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_RedLineStealer_RT_2147780240_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.RT!MTB"
        threat_id = "2147780240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36" ascii //weight: 1
        $x_1_2 = "http\\shell\\open\\command" ascii //weight: 1
        $x_1_3 = "channelinfo.pw/" ascii //weight: 1
        $x_1_4 = "\\Google\\Chrome\\User Data\\Default\\Cookies" ascii //weight: 1
        $x_1_5 = "\\Google\\Chrome\\User Data\\Profile 1\\Login Data" ascii //weight: 1
        $x_1_6 = "LoginName" ascii //weight: 1
        $x_1_7 = "AccountStatus" ascii //weight: 1
        $x_1_8 = "tpyyf.com" ascii //weight: 1
        $x_1_9 = "CreditCard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win32_RedLineStealer_MA_2147794372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MA!MTB"
        threat_id = "2147794372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 00 6d 00 69 00 6a 00 65 00 78 00 5c 00 [0-15] 6b 00 75 00 78 00 65 00 79 00 6f 00 72 00 5c 00 36 00 5c 00 [0-15] 2e 00 70 00 64 00 62 00}  //weight: 10, accuracy: Low
        $x_10_2 = {5c 6d 69 6a 65 78 5c [0-15] 6b 75 78 65 79 6f 72 5c 36 5c [0-15] 2e 70 64 62}  //weight: 10, accuracy: Low
        $x_1_3 = {8b 01 ba ff ?? ?? ?? 03 d0 83 f0 ?? 33 c2 83 c1 ?? a9 ?? ?? ?? ?? 74 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_RedLineStealer_MA_2147794372_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MA!MTB"
        threat_id = "2147794372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 4d fc b8 3b 2d 0b 00 01 45 fc 8b 55 fc 8a 04 32 8b 0d ?? ?? ?? ?? 88 04 0e 83 3d ?? ?? ?? ?? 44 75 ?? 8d 55 f4 52 68 ?? ?? ?? ?? ff ?? 6a ?? 6a ?? ff ?? 46 3b 35 ?? ?? ?? ?? 72}  //weight: 5, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_4 = "RaiseException" ascii //weight: 1
        $x_1_5 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MC_2147795096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MC!MTB"
        threat_id = "2147795096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 95 9c fd ff ff 83 c2 01 89 95 9c fd ff ff 83 bd 9c fd ff ff 0c 73 ?? 8b 85 9c fd ff ff 0f b6 4c 05 d0 81 c1 b5 00 00 00 8b 95 9c fd ff ff 88 4c 15 d0 eb ?? c6 45 cd 00 0f b6 45 d1 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_2 = "UnlockFileEx" ascii //weight: 1
        $x_1_3 = "GetCPInfoExW" ascii //weight: 1
        $x_1_4 = "GetDiskFreeSpaceA" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MC_2147795096_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MC!MTB"
        threat_id = "2147795096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 1d 44 f1 47 00 8b 4d f4 8b c6 d3 e8 8b 4d e4 c7 05 4c 23 48 00 2e ce 50 91 89 45 f0 8d 45 f0 e8 96 fe ff ff 8b 45 fc 03 c6 50 8b 45 f8 e8 7a fe ff ff 8b 4d f0 33 c8 89 45 f8 2b f9 25 bb 52 c0 5d 8b c7 8d 4d f8 e8 58 fe ff ff 8b 4d d8 8b c7 c1 e8 05 89 45 f0 8d 45 f0 e8 5c fe ff ff 8b 45 fc 8b 4d dc 03 c7 50 8b 45 f8 03 c1 e8 3b fe ff ff 8b 4d f0 89 45 f8 8d 45 f8 e8 2a fe ff ff 2b 75 f8 89 1d 28 e3 47 00 8b 45 e8 29 45 fc ff 4d ec 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {89 55 fc b8 ?? ?? ?? ?? 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_DA_2147795332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.DA!MTB"
        threat_id = "2147795332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c start clr_soft.exe & start redline_.exe" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_3 = "wextract.pdb" ascii //weight: 1
        $x_1_4 = "DecryptFileA" ascii //weight: 1
        $x_1_5 = "GetTempPathA" ascii //weight: 1
        $x_1_6 = "DefaultInstall" ascii //weight: 1
        $x_1_7 = "Reboot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_DE_2147796546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.DE!MTB"
        threat_id = "2147796546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 5d 0c 57 8b 7d 14 8b c1 8b 75 08 33 d2 f7 f7 8a 04 32 30 04 19 41 3b 4d 10 72}  //weight: 1, accuracy: High
        $x_1_2 = "hVAxtyfwyfswtydfw" ascii //weight: 1
        $x_1_3 = "gvcgfxrdrtwdwteysdgfyufw4673efdsgytu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_ME_2147796708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.ME!MTB"
        threat_id = "2147796708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 8b c6 f7 75 08 8a 04 0a 30 04 3e 46 3b 75 0c 72}  //weight: 1, accuracy: High
        $x_1_2 = {83 65 9c 00 8b 45 9c 89 45 98 ff 75 98 ff 55}  //weight: 1, accuracy: High
        $x_1_3 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_4 = "FindFirstFileExW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_ME_2147796708_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.ME!MTB"
        threat_id = "2147796708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f4 8b d7 d3 ea 89 45 f0 03 55 e4 33 d0 89 55 ec 8b 45 ec 29 45 f8 25 ?? ?? ?? ?? 8b 55 f8 8b c2 8d 4d f0 e8 ?? ?? ?? ?? 8b 4d d8 8b c2 c1 e8 ?? ?? ?? ?? 8d 45 ec e8 ?? ?? ?? ?? 8b 45 fc 03 c2 50 8b 45 f0 03 45 dc e8 ?? ?? ?? ?? ff 75 ec 8d 75 f0 89 45 f0 e8 ?? ?? ?? ?? 2b 7d f0 89 1d ?? ?? ?? ?? 8b 45 e0 29 45 fc ff 4d e8 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e0 04 89 01 c3}  //weight: 1, accuracy: High
        $x_1_3 = {89 55 fc b8 ?? ?? ?? ?? 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MG_2147796712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MG!MTB"
        threat_id = "2147796712"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 89 85 ?? ?? ?? ?? c7 85 e4 3b f2 ff ?? ?? ?? ?? 8b 8d e4 3b f2 ff 83 c1 01 89 8d 60 3a f2 ff 8b 95 e4 3b f2 ff 8a 02 88 85 f7 3b f2 ff 83 85 e4 3b f2 ff 01 80 bd f7 3b f2 ff 00 75 ?? 8b 8d e4 3b f2 ff 2b 8d 60 3a f2 ff 89 8d fc 39 f2 ff 8b 95 a8 3b f2 ff 3b 95 fc 39 f2 ff 73 ?? 8b 85 a8 3b f2 ff 0f be 88}  //weight: 1, accuracy: Low
        $x_1_2 = {85 c0 74 34 b9 4d 5a 00 00 66 39 08 75 2a 8b 48 3c 03 c8 81 39 ?? ?? ?? ?? 75 ?? b8 ?? ?? ?? ?? 66 39 41 18 75 ?? 83 79 74 0e 76 0c 83 b9 ?? ?? ?? ?? 00 74 ?? b0 01 c3 32 c0 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MH_2147796713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MH!MTB"
        threat_id = "2147796713"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 8b 4d f0 03 c7 8b f7 d3 ee 50 ff 75 f4 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 75 e4 e8 ?? ?? ?? ?? 33 f0 89 45 f4 89 75 ec 8b 45 ec 29 45 f8 25 ?? ?? ?? ?? 8b 55 f8 8b c2 8d 4d f4 e8 ?? ?? ?? ?? 8b 75 fc 8b 4d d8 03 f2 c1 ea 05 8d 45 ec 89 55 ec e8}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e0 04 89 01 c3}  //weight: 1, accuracy: High
        $x_1_3 = {89 55 fc b8 ?? ?? ?? ?? 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MJ_2147797054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MJ!MTB"
        threat_id = "2147797054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d ec 8b 45 f8 8b d6 d3 ea 03 c6 50 ff 75 f0 03 55 d8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 55 f4 e8 ?? ?? ?? ?? 31 45 f4 2b 7d f4 89 45 f0 25 ?? ?? ?? ?? 8b c7 8d 4d f0 e8 ?? ?? ?? ?? 8b 4d f8 8b c7 c1 e8 05 03 cf 89 45 f4 8b 45 e4 01 45 f4 8b 45 f0 03 45 dc 51 50 e8 ?? ?? ?? ?? 8b 4d f4 89 45 f0 8d 45 f0 e8 ?? ?? ?? ?? 2b 75 f0 89 1d ?? ?? ?? ?? 8b 45 d4 29 45 f8 ff 4d e8 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e0 04 89 01 c3}  //weight: 1, accuracy: High
        $x_1_3 = {89 55 fc b8 ?? ?? ?? ?? 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MN_2147797744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MN!MTB"
        threat_id = "2147797744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 06 89 1d ?? ?? ?? ?? 8b 4d ?? 8b 45 ?? 8b d6 d3 ea 03 c6 50 ff 75 ?? 03 55 ?? c7 05 ?? ?? ?? ?? 2e ce 50 91 89 55 ?? e8 ?? ?? ?? ?? 31 45 ?? 2b 7d ?? 89 45 ?? 25 ?? ?? ?? ?? 8b c7 8d 4d ?? e8 ?? ?? ?? ?? 8b 4d ?? 8b c7 c1 e8 05 03 cf 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 03 45 ?? 51 50 e8 ?? ?? ?? ?? 8b 4d ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 2b 75 ?? 89 1d ?? ?? ?? ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e0 04 89 01 c3}  //weight: 1, accuracy: High
        $x_1_3 = {89 55 fc b8 ?? ?? ?? ?? 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MQ_2147797747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MQ!MTB"
        threat_id = "2147797747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 b9 05 ?? ?? ?? f7 f1 0f be 82 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f b6 8a ?? ?? ?? ?? 03 c1 33 d2 b9 00 01 00 00 f7 f1 89 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f b6 82 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f b6 91 ?? ?? ?? ?? 33 d0 a1 ?? ?? ?? ?? 88 ?? ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f b6 91 ?? ?? ?? ?? 89 55 ?? a1 ?? ?? ?? ?? 0f b6 88 ?? ?? ?? ?? 33 4d ?? 8b 15 ?? ?? ?? ?? 88 8a ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f b6 88 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f b6 82 ?? ?? ?? ?? 33 c1 8b 0d ?? ?? ?? ?? 88 81 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c1 01 89 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 33 d2 b9 00 01 00 00 f7 f1 89 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f b6 82 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 33 d2 b9 00 01 00 00 f7 f1 89 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8a 82 ?? ?? ?? ?? a2 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8a 82 ?? ?? ?? ?? 88 81 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 88 91 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f b6 88 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f b6 82 ?? ?? ?? ?? 03 c8 81 e1 ?? ?? ?? ?? 79 ?? 49 81 c9 ?? ?? ?? ?? 41 8a 89 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 ?? 0f be 02 0f b6 0d ?? ?? ?? ?? 33 c1 8b 15 ?? ?? ?? ?? 03 55 ?? 88 02 e9}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c0 88 84 05 ?? ?? ?? ?? 40 3b c6 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_2147797750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MT!MTB"
        threat_id = "2147797750"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f0 a1 ?? ?? ?? ?? 03 4d ?? 3d ?? ?? ?? ?? 75 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 3d ?? ?? ?? ?? 75 ?? 83 25 ?? ?? ?? ?? ?? 8b 45 ?? 03 c6 50 8b c1 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d ?? d3 ee 89 45 ?? 03 75 ?? 33 f0 2b fe 25 ?? ?? ?? ?? 8b c7 8d 4d ?? e8 ?? ?? ?? ?? 8b 4d ?? 8b c7 c1 e8 05 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 03 c7 50 8b 45 ?? 03 c3 e8 ?? ?? ?? ?? ff 75 ?? 8d 75 ?? 89 45 ?? e8 ?? ?? ?? ?? 8b 4d ?? 83 25 ?? ?? ?? ?? ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e0 04 89 01 c3}  //weight: 1, accuracy: High
        $x_1_3 = {89 55 fc b8 ?? ?? ?? ?? 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MU_2147797972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MU!MTB"
        threat_id = "2147797972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f0 a1 ?? ?? ?? ?? 03 4d ?? 3d a9 0f 00 00 75 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 3d eb 03 00 00 75 ?? 83 25 ?? ?? ?? ?? ?? 8b 45 f8 03 c6 50 8b c1 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d f4 d3 ee 89 45 ?? 03 75 ?? 33 f0 2b fe 25 ?? ?? ?? ?? 8b c7 8d 4d f0 e8 ?? ?? ?? ?? 8b 4d ?? 8b c7 c1 e8 05 89 45 e8 8d 45 e8 e8 ?? ?? ?? ?? 8b 45 ?? 03 c7 50 8b 45 ?? 03 c3 e8 ?? ?? ?? ?? 50 89 45 ?? 8d 45 ?? 50 8b 45 ?? e8 ?? ?? ?? ?? 8b 4d ?? 83 25 ?? ?? ?? ?? ?? 8d 45 ec e8 ?? ?? ?? ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e0 04 89 01 c3}  //weight: 1, accuracy: High
        $x_1_3 = {89 55 fc b8 ?? ?? ?? ?? 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_CG_2147798712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.CG!MTB"
        threat_id = "2147798712"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 06 46 88 07 47 bb 02 00 00 00 00 d2 75 05 8a 16 46 10 d2 73 ea}  //weight: 1, accuracy: High
        $x_1_2 = {89 c0 29 c7 8a 07 5f 88 07 47 bb 02 00 00 00 eb 99}  //weight: 1, accuracy: High
        $x_1_3 = "Stored password is corrupt" ascii //weight: 1
        $x_1_4 = "Select virus scanner" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_DF_2147798736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.DF!MTB"
        threat_id = "2147798736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d8 8b 45 d8 89 18 8b 45 c8 03 45 a0 8b 55 d8 31 02 6a 66 e8 ?? ?? ?? ?? bb 04 00 00 00 2b d8 6a 66 e8 ?? ?? ?? ?? 03 d8 01 5d ec 83 45 d8 04 8b 45 ec 3b 45 d4 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_DF_2147798736_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.DF!MTB"
        threat_id = "2147798736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "wedsycdssdfaesf" ascii //weight: 3
        $x_3_2 = "Vumendskimes" ascii //weight: 3
        $x_3_3 = "wanumesfrscsasfv2" ascii //weight: 3
        $x_3_4 = "modReplace" ascii //weight: 3
        $x_3_5 = "Codejock.FlowGraph" ascii //weight: 3
        $x_3_6 = "txtPassword" ascii //weight: 3
        $x_3_7 = "chkLoadTipsAtStartup" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MAO_2147805565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MAO!MTB"
        threat_id = "2147805565"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dipileyufukenijanitikar" wide //weight: 1
        $x_1_2 = "rogakozg" wide //weight: 1
        $x_1_3 = "weyenokonezefi" wide //weight: 1
        $x_1_4 = "Fakale" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_6 = {8b 4c 24 18 8b 54 24 14 51 c1 ea 05 03 54 24 2c 8d 4c 24 14 c7 05 ?? ?? ?? ?? b4 02 d7 cb c7 05 ?? ?? ?? ?? ff ff ff ff e8 ?? ?? ?? ?? 52 8d 4c 24 14 e8 ?? ?? ?? ?? 2b 7c 24 10 8d 44 24 20 89 7c 24 1c e8 ?? ?? ?? ?? 4d 0f 85}  //weight: 1, accuracy: Low
        $x_1_7 = {c7 84 24 e4 00 00 00 57 78 d1 51 c7 84 24 e0 00 00 00 0b 4c 1b 7e c7 44 24 18 dd 0b fa 64 c7 44 24 68 cf 72 b2 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MAQ_2147806283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MAQ!MTB"
        threat_id = "2147806283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b fe 25 bb 52 c0 5d 8b 45 fc 83 25 ?? ?? ?? ?? 00 03 c7 50 8b c7 c1 e0 04 03 45 f0 e8 ?? ?? ?? ?? 8b cf c1 e9 05 03 4d e4 33 c1 2b d8 8b 45 ec 29 45 fc ff 4d f4 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MAU_2147807761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MAU!MTB"
        threat_id = "2147807761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Xegixaze" wide //weight: 1
        $x_1_2 = "lidirahowefi" wide //weight: 1
        $x_1_3 = "pamocibotobipo" wide //weight: 1
        $x_1_4 = "Valepeba" wide //weight: 1
        $x_1_5 = "misufitixezeha" ascii //weight: 1
        $x_1_6 = "FindFirstFile" ascii //weight: 1
        $x_1_7 = "BackupWrite" ascii //weight: 1
        $x_1_8 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MI_2147808460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MI!MTB"
        threat_id = "2147808460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 83 c0 01 89 45 fc 83 7d fc 20 0f 83 06 03 00 00 c7 85 70 ff ff ff 04 00 00 00 8b 55 d0 8b 8d 70 ff ff ff d3 e2 89 55 e4 8b 45 e4 03 45 dc 89 45 e4 8b 45 d0 8b 5d e8 03 c3 89 45 f0 c7 45 a8 05 00 00 00 8b 55 d0 8b 4d a8 d3 ea 89 55 ec 8b 45 ec 03 45 e0 89 45 ec c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 83 3d ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d e4 33 4d f0 89 4d e4 8b 55 ec 33 55 e4 89 55 ec 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 f4 8b 4d a8 d3 e8 89 45 ec 8b 4d ec 03 4d d4 89 4d ec 8b 55 e4 33 55 f0 89 55 e4 8b 45 ec 31 45 e4 8b 45 e4 29 45 d0 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? eb ?? 8b 45 e8 2b 45 d8 89 45 e8 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MFA_2147811263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MFA!MTB"
        threat_id = "2147811263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OuAmmwmjp" ascii //weight: 1
        $x_1_2 = "JhWqfqA|f" ascii //weight: 1
        $x_1_3 = "Passwords" ascii //weight: 1
        $x_1_4 = "Encryption constants" ascii //weight: 1
        $x_1_5 = "encryption section(s) might not be properly decrypted" ascii //weight: 1
        $x_1_6 = "Sleep" ascii //weight: 1
        $x_1_7 = "GetDiskFreeSpaceA" ascii //weight: 1
        $x_1_8 = "WSAIsBlocking" ascii //weight: 1
        $x_1_9 = "rqbwjqbwj345n3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MBA_2147811457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MBA!MTB"
        threat_id = "2147811457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 00 8c 10 40 00 b0 10 40 00 00 cb}  //weight: 1, accuracy: High
        $x_1_2 = "@user123311a_crypted.exe" ascii //weight: 1
        $x_1_3 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_4 = "Fortnite cheat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_RPD_2147811600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.RPD!MTB"
        threat_id = "2147811600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 01 2b e8 00 00 00 00 5a 8b 42 ?? 90 90 90}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_RPE_2147811601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.RPE!MTB"
        threat_id = "2147811601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b f1 8b ce c1 e1 04 03 4d ec 8b c6 c1 e8 05 03 45 e8 03 de 33 cb 33 c8 8d 45 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_RPE_2147811601_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.RPE!MTB"
        threat_id = "2147811601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 05 21 bb ?? ?? ?? 50 e8 17 00 00 00 33 c0 eb 02 00 a9 71 64 eb 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MKA_2147811905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MKA!MTB"
        threat_id = "2147811905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc b8 3b 2d 0b 00 01 45 fc 12 00 a1 ?? ?? ?? ?? 89 45 [0-10] 8b 45 fc 8a 04 38 8b 0d ?? ?? ?? ?? 88 04 39 83 3d ?? ?? ?? ?? 44 75 ?? 56 8d 85 b4 f6 ff ff 50 ff 15 ?? ?? ?? ?? 47 3b 3d 48 16 43 00 72}  //weight: 1, accuracy: Low
        $x_1_2 = "runexobozez" ascii //weight: 1
        $x_1_3 = "zopiv.txt" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MNA_2147812288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MNA!MTB"
        threat_id = "2147812288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bZGtARYPF\\AeWG5" ascii //weight: 1
        $x_1_2 = {14 3c f6 69 5a 45 79 6d 7e 42 43 46 8a 97 64 70 fb 72 4d 62 76 69 73 74 33 55 34 71 4e 33 61 66 72 31 78 6e 37 4a 46 4e 49 56 31 75 6f 55 30 6a 6f 4b 59 59 39 44 65 42 6a 55 67 56 f2 67 79 4b}  //weight: 1, accuracy: High
        $x_1_3 = "FindNextFileW" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "LockResource" ascii //weight: 1
        $x_1_6 = ".5bi1k2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MOA_2147812291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MOA!MTB"
        threat_id = "2147812291"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "osjdnfisbdfisdofsdiof" ascii //weight: 1
        $x_1_2 = "zelayuhefehew" wide //weight: 1
        $x_1_3 = "capasufidolid" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MPA_2147812730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MPA!MTB"
        threat_id = "2147812730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".FYykpDc" ascii //weight: 1
        $x_1_2 = "blacklisted key" ascii //weight: 1
        $x_1_3 = "Encryption constants" ascii //weight: 1
        $x_1_4 = "encryption section(s) might not be properly decrypted" ascii //weight: 1
        $x_1_5 = "GetKeyboardType" ascii //weight: 1
        $x_1_6 = "aspr_keys.ini" ascii //weight: 1
        $x_1_7 = "Enter Mode Password" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MSA_2147813452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MSA!MTB"
        threat_id = "2147813452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".QhE6kte" ascii //weight: 1
        $x_1_2 = "blacklisted key" ascii //weight: 1
        $x_1_3 = "Encryption constants" ascii //weight: 1
        $x_1_4 = "encryption section(s) might not be properly decrypted" ascii //weight: 1
        $x_1_5 = "Passwords" ascii //weight: 1
        $x_1_6 = "GetKeyboardType" ascii //weight: 1
        $x_1_7 = "GetAsyncKeyState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_2147813459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MTA!MTB"
        threat_id = "2147813459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTA: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 04 39 83 3d ?? ?? ?? ?? 44 75 1f 00 a1 ?? ?? ?? ?? 8a 84 38 3b 2d 0b 00 8b 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c7 50 89 45 f8 8b c7 c1 e0 04 03 85 ?? ?? ?? ?? 50 e8 6a fe ff ff 50 89 85 ?? ?? ?? ?? 8b c7 c1 e8 05 03 85 ?? ?? ?? ?? 50 8d 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MVA_2147814543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MVA!MTB"
        threat_id = "2147814543"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".u0mc0Dc" ascii //weight: 1
        $x_1_2 = "blacklisted key" ascii //weight: 1
        $x_1_3 = "Encryption constants" ascii //weight: 1
        $x_1_4 = "encryption section(s) might not be properly decrypted" ascii //weight: 1
        $x_1_5 = "Enter Mode Password" wide //weight: 1
        $x_1_6 = "\\TEMP\\aspr_keys.ini" wide //weight: 1
        $x_1_7 = "GetKeyboardType" ascii //weight: 1
        $x_1_8 = "GetAsyncKeyState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_RPQ_2147815541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.RPQ!MTB"
        threat_id = "2147815541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 28 45 d0 0f 29 85 50 fe ff ff 8b 95 78 ff ff ff 0f 10 02 0f 29 85 60 fe ff ff 0f 28 85 60 fe ff ff 66 0f ef 85 50 fe ff ff 0f 29 85 40 fe ff ff 0f 28 85 40 fe ff ff 8b 85 78 ff ff ff 0f 11 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_RPY_2147815867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.RPY!MTB"
        threat_id = "2147815867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c7 c1 e0 04 03 45 e8 03 cf 33 c1 89 45 fc 8d 45 fc 50 e8}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 08 89 78 04 5f 89 30 5e 5b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_RPY_2147815867_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.RPY!MTB"
        threat_id = "2147815867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f6 17 33 f3 33 c0 33 db 33 c6 8b f3 33 c6 8b f3 8b f0 8b d8 80 07 75 33 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_RPZ_2147815868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.RPZ!MTB"
        threat_id = "2147815868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 02 f6 bf 50 eb 02 8d 43 e8 1a 00 00 00 eb 04 be da 68 17 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_RPZ_2147815868_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.RPZ!MTB"
        threat_id = "2147815868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 6a 04 8d 4d dc 51 8b 8b a4 00 00 00 83 c1 08 51 ff 75 cc ff d0 6a 40 68 00 30 00 00 ff b7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_RPZ_2147815868_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.RPZ!MTB"
        threat_id = "2147815868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 db b8 11 00 00 00 83 c0 1f 64 8b 3c 03 8b 7f 0c 8b 77 14 8b 36 8b 36 8b 46 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_RPZ_2147815868_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.RPZ!MTB"
        threat_id = "2147815868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 68 00 10 00 00 8b 45 08 8b 40 04 ff 70 09 6a 00 8b 45 08 ff 50 24 89 45 f8 83 65 f4 00 6a 00 8d 45 f4 50 ff 75 f8 8b 45 08 8b 40 04 ff 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_RPA_2147815869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.RPA!MTB"
        threat_id = "2147815869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 02 69 f6 50 eb 02 0f 1c e8 1a 00 00 00 eb 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_QP_2147815941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.QP!MTB"
        threat_id = "2147815941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 85 1c fd ff ff 01 45 fc 8b 85 ?? ?? ?? ?? 03 c7 33 f0 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 1b}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 85 2c fd ff ff 03 cb 33 c1 31 45 fc 81 3d ?? ?? ?? ?? a3 01 00 00 75 08}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MYA_2147816212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MYA!MTB"
        threat_id = "2147816212"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f0 8b 4d f4 83 c0 ?? 89 45 f0 83 d1 ?? 89 4d f4 8b 45 08 89 45 f0 8b 45 0c 89 45 f4 8b 4d f0 8b 45 f4 0b c8 74}  //weight: 1, accuracy: Low
        $x_1_2 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_3 = "Sleep" ascii //weight: 1
        $x_1_4 = "FindFirstFileExW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_GE_2147816290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.GE!MTB"
        threat_id = "2147816290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 10 85 d2 74 0e 8a 84 15 ?? ?? ?? ?? 30 44 17 ff 4a 75 f2}  //weight: 10, accuracy: Low
        $x_1_2 = "MANTCVSRVXBYGHIBPS@AWDRT.COM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PA_2147816545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PA!MTB"
        threat_id = "2147816545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 75 ec 8b 45 e8 01 45 ec 8b 45 e4 01 45 ec 8b 45 ec 89 45 f4 8b 45 e4 8b 4d f0 d3 e8 89 45 fc 8b 45 cc 01 45 fc 8b 5d e4 c1 e3 ?? 03 5d d8 33 5d f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PA_2147816545_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PA!MTB"
        threat_id = "2147816545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 b9 0a 00 00 00 f7 f1 0f b6 92 ?? ?? ?? ?? 8b 45 ?? 03 45 ?? 0f b6 08 33 ca 8b 55 ?? 03 55 ?? 88 0a ff 15 ?? ?? ?? ?? 89 45 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PB_2147816630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PB!MTB"
        threat_id = "2147816630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 d5 41 1d d4 8b ce f7 e6 8b c6 2b c2 d1 e8 03 c2 c1 e8 05 6b c0 ?? 2b c8 8a 81 ?? ?? ?? ?? 30 04 1e 46 3b f7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PB_2147816630_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PB!MTB"
        threat_id = "2147816630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f1 0f b6 92 ?? ?? ?? ?? 8b 45 ?? 03 45 ?? 0f b6 08 33 ca 8b 55 ?? 03 55 ?? 88 0a 8b 45 ?? 8b 08 83 c1 01 8b 55 ?? 89 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PB_2147816630_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PB!MTB"
        threat_id = "2147816630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 c1 e8 05 89 45 0c 8b 45 ec 01 45 0c 8b 45 e8 83 25 ?? ?? ?? ?? ?? 03 c8 8d 04 3b 33 c8 31 4d 0c 8b 45 0c 01 05 44 7e b4 00 2b 75 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 10 03 44 24 18 89 44 24 1c 8b 44 24 18 c1 e8 ?? 89 44 24 14 8b 44 24 14 33 74 24 1c 03 c3 33 c6 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 14 75 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_RedLineStealer_PC_2147816900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PC!MTB"
        threat_id = "2147816900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 c7 45 fc ?? ?? ?? ?? 8b 45 0c 01 45 fc 83 6d fc ?? 8b 45 08 8b 4d fc 31 08 c9 c2 08 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PC_2147816900_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PC!MTB"
        threat_id = "2147816900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 52 00 65 00 67 00 53 00 76 00 63 00 73 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_3_3 = {b8 d5 41 1d d4 8b ce f7 e6 8b c6 2b c2 d1 e8 03 c2 c1 e8 05 6b c0 ?? 2b c8 8a 81 ?? ?? ?? ?? 30 04 1e 46 3b f7 72}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_AA_2147817044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.AA!MTB"
        threat_id = "2147817044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 ca 89 4c 24 ?? 89 5c 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 54 24 ?? 89 54 24 ?? 89 1d ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 81 44 24 ?? ?? ?? ?? ?? ff 4c 24 ?? 0f 85 ?? ?? ?? ?? 8b 44 24 ?? 8b 4c 24 ?? 89 08 89 78}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_AA_2147817044_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.AA!MTB"
        threat_id = "2147817044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c7 33 45 ?? 33 c1 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 75 40 00 81 ad ?? ?? ?? ?? ?? ?? ?? ?? 81 ad ?? ?? ?? ?? ?? ?? ?? ?? b8 ?? ?? ?? ?? 8b 85}  //weight: 1, accuracy: Low
        $x_1_2 = {2b d8 89 75 ?? 81 6d ?? ?? ?? ?? ?? 81 45 ?? ?? ?? ?? ?? 8b 4d ?? 8b f3 d3 e6 8b 4d ?? 8b c3 d3 e8 03 b5 ?? ?? ?? ?? 89 45 ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8b 85 ?? ?? ?? ?? 03 c3 33 f0 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_FX_2147817554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.FX!MTB"
        threat_id = "2147817554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 45 fc 8b 45 8c 01 45 fc c1 e6 04 03 75 88 33 f2 81 3d ?? ?? ?? ?? 21 01 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {c7 85 50 fe ff ff bb e5 ad 07 c7 85 ?? ?? ?? ?? c5 b1 6b 00 c7 85 ?? ?? ?? ?? 66 dd 60 43 c7 85 ?? ?? ?? ?? 4a d0 8a 2c c7 85 ?? ?? ?? ?? 15 6e 75 0e c7 85 ?? ?? ?? ?? 8e 52 57 39 c7 85 ?? ?? ?? ?? 5b 4a 15 44 c7 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MZA_2147817836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MZA!MTB"
        threat_id = "2147817836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 45 fc b8 d6 38 00 00 01 45 fc 8b 45 08 8b 4d fc 8a 0c 01 8b 15 ?? ?? ?? ?? 88 0c 02 c9 c2}  //weight: 10, accuracy: Low
        $x_1_2 = "LockFile" ascii //weight: 1
        $x_1_3 = "CreateMailslotA" ascii //weight: 1
        $x_1_4 = "DebugActiveProcess" ascii //weight: 1
        $x_1_5 = "GetCompressedFileSizeW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PD_2147817922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PD!MTB"
        threat_id = "2147817922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 0c 8b 45 ec 01 45 0c 8b 45 e8 83 25 ?? ?? ?? ?? ?? 03 c8 8d 04 3b 33 c8 31 4d 0c 8b 45 0c 01 05 ?? ?? ?? ?? 2b 75 0c 83 0d ?? ?? ?? ?? ?? 8b c6 c1 e8 ?? 03 45 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PD_2147817922_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PD!MTB"
        threat_id = "2147817922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c7 33 f0 33 75 ?? 89 75 ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 83 0d ?? ?? ?? ?? ff 2b de 8b c3 c1 e0 04 03 45 ?? 8b d3 89 45 ?? 8d 04 1f 50 8d 45 ?? c1 ea 05 03 55 ?? 50 c7 05 ?? ?? ?? ?? b4 21 e1 c5 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_AN_2147818049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.AN!MTB"
        threat_id = "2147818049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{11111-22222-10009-11112}" wide //weight: 1
        $x_1_2 = "k8yL0DbbKFTgJePlfr.SjRaBmw7XWvJr0UFKe" wide //weight: 1
        $x_1_3 = "{11111-22222-50001-00000}" wide //weight: 1
        $x_1_4 = "AppProxyRunStart" wide //weight: 1
        $x_1_5 = "OnStart ReadInstallReg.GetValue" wide //weight: 1
        $x_1_6 = "RunService" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MB_2147818334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MB!MTB"
        threat_id = "2147818334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 45 fc b8 d6 38 00 00 01 45 fc 8b 45 fc 8a 04 18 8b 0d ?? ?? ?? ?? 88 04 19 c9 c3}  //weight: 10, accuracy: Low
        $x_1_2 = "GetThreadContext" ascii //weight: 1
        $x_1_3 = "GetMailslotInfo" ascii //weight: 1
        $x_1_4 = "DebugBreak" ascii //weight: 1
        $x_1_5 = "Permission denied" ascii //weight: 1
        $x_1_6 = "DebugSetProcessKillOnExit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_VZ_2147819482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.VZ!MTB"
        threat_id = "2147819482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {92 24 83 c4 04 f7 e6 8b c6 2b c2 d1 e8 03 c2 c1 e8 02 8d 0c c5 ?? ?? ?? ?? 2b c8 8b c6 2b c1 8a 80 ?? ?? ?? ?? 30 04 1e 46 ff 07 3b f5 72 c4}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_A_2147820161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.A!MTB"
        threat_id = "2147820161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 55 ff 0f b6 45 ff c1 f8 03 0f b6 4d ff c1 e1 05 0b c1 88 45 ff 8b 55 ec 8a 45 ff 88 44 15 d0 e9 dd fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_AV_2147820214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.AV!MTB"
        threat_id = "2147820214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c8 8b 45 fc 33 d2 f7 f1 52 8d 4d 10 e8 [0-4] 0f be 10 33 f2 b8 ff 00 00 00 2b c6 03 45 f8 89 45 f8 eb b8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_DG_2147820309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.DG!MTB"
        threat_id = "2147820309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce c1 e1 04 03 4d ec 8b c6 c1 e8 05 03 45 e4 8d 14 33 33 ca 33 c8 2b f9 81 3d ?? ?? ?? ?? 17 04 00 00 c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 0c 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 e8 03 d0 89 55 f4 8b 45 f8 c1 e8 05 89 45 fc 8b 45 fc 33 4d f4 03 45 d4 c7 05 ?? ?? ?? ?? ee 3d ea f4 33 c1 81 3d ?? ?? ?? ?? 16 05 00 00 89 45 fc 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_RedLineStealer_DH_2147821600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.DH!MTB"
        threat_id = "2147821600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce f7 e6 c1 ea ?? 6b c2 ?? 2b c8 0f b6 81 ?? ?? ?? ?? 8d 8f ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 03 ce b8 1f 85 eb 51 f7 e1 8b ce c1 ea ?? 6b c2 ?? 2b c8 0f b6 81 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 83 c6 ?? 81 fe 7e 07 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PE_2147821935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PE!MTB"
        threat_id = "2147821935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 44 24 18 8b 4c 24 20 8b c3 d3 e8 89 44 24 14 8b 44 24 38 01 44 24 14 8b cb c1 e1 ?? 03 4c 24 3c 89 15 ?? ?? ?? ?? 33 4c 24 14 33 4c 24 18 2b f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PF_2147821963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PF!MTB"
        threat_id = "2147821963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d f8 3b c2 0f b6 3f c1 e6 ?? c1 e0 ?? 0b f7 ff 45 f8 66 c1 c7 ?? 23 fc 0f b7 3c 0a 0f b7 cf 2b d5 66 0f ba fa a3 8b d0 f8 c1 ea}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 6c 25 fc 66 c1 e6 ?? 66 8b df 66 23 df 89 44 25 00 8b f5 5b 5f f7 c3 ?? ?? ?? ?? 66 0f bc c2 5d 66 c1 e8 ?? 66 25 ?? ?? 8d ad fc ff ff ff 0f b7 c3 66 0f bd c4 8b 44 25 00 33 c3 66 85 f9 8d 80 a2 0a 16 1f 85 ea f9 0f c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_RedLineStealer_MD_2147821997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MD!MTB"
        threat_id = "2147821997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 fc b8 d6 38 00 00 01 45 fc 8b 45 08 8b 4d fc 8a 0c 01 8b 15 ?? ?? ?? ?? 88 0c 02 c9 c2}  //weight: 1, accuracy: Low
        $x_1_2 = "GetMailslotInfo" ascii //weight: 1
        $x_1_3 = "GetDiskFreeSpaceExA" ascii //weight: 1
        $x_1_4 = "UnlockFileEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PG_2147822257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PG!MTB"
        threat_id = "2147822257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 24 89 44 24 18 8b 44 24 10 01 44 24 18 8b 44 24 24 c1 e8 ?? 89 44 24 14 8b 44 24 14 03 44 24 40 c7 05 [0-8] 33 44 24 18 33 c6 81 3d [0-8] 89 44 24 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PH_2147822429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PH!MTB"
        threat_id = "2147822429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 18 8b c7 d3 e8 89 44 24 10 8b 44 24 34 01 44 24 10 ?? ?? ?? ?? ?? ?? ?? ?? 8b cf c1 e1 ?? 03 4c 24 40 89 15 ?? ?? ?? ?? 33 4c 24 10 33 4c 24 14 2b d9 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PI_2147822812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PI!MTB"
        threat_id = "2147822812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 2d 30 99 c7 02 8b 44 24 20 89 44 24 14 8b 44 24 24 01 44 24 14 8b 44 24 20 c1 e8 ?? 89 44 24 10 8b 44 24 10 03 44 24 44 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 44 24 14 33 c6 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PJ_2147822906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PJ!MTB"
        threat_id = "2147822906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 29 45 fc 8b 4d fc c1 e1 ?? 03 4d f0 8b 45 fc 03 45 f8 89 45 0c 8b 55 fc ?? ?? ?? ?? ?? ?? ff 8b c2 c1 e8 ?? 03 45 e4 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 08 33 45 0c 33 c1 2b f0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 20 89 44 24 14 8b 44 24 24 01 44 24 14 8b 44 24 20 c1 e8 ?? 89 44 24 10 8b 44 24 10 03 44 24 44 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 44 24 14 33 c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_RedLineStealer_RPR_2147822924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.RPR!MTB"
        threat_id = "2147822924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e0 17 31 45 fc 8b 45 fc c1 f8 11 31 45 fc 8b 45 f8 31 45 fc 8b 45 f8 c1 f8 1a 31 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_RPS_2147822925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.RPS!MTB"
        threat_id = "2147822925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 0c 69 c7 e8 ae e9 71 30 04 1a 43 eb d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PK_2147823593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PK!MTB"
        threat_id = "2147823593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 45 fc 8b 4d fc c1 e1 ?? 03 4d f0 8b 45 fc 03 45 f8 89 45 0c 8b 55 fc 83 0d ?? ?? ?? ?? ff 8b c2 c1 e8 ?? 03 45 e4 68 ?? ?? ?? ?? 89 45 08 33 45 0c c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 20 89 44 24 14 8b 44 24 24 01 44 24 14 8b 44 24 20 c1 e8 ?? 89 44 24 10 8b 44 24 10 03 44 24 38 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 44 24 14 33 c6 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 10 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 8c 0d c4 5b ff ff 88 8d 8b 5b ff ff 0f b6 85 8b 5b ff ff 8b 0d e8 2b 48 00 03 8d 14 58 ff ff 0f be 11 33 d0 a1 e8 2b 48 00 03 85 14 58 ff ff 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_RedLineStealer_PL_2147823766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PL!MTB"
        threat_id = "2147823766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 20 89 44 24 14 8b 44 24 24 01 44 24 14 8b 44 24 20 c1 e8 ?? 89 44 24 10 8b 44 24 38 03 44 24 10 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 44 24 14 33 c6 81 3d 8c 92 63 00 ?? ?? ?? ?? 89 44 24 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_BA_2147823802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.BA!MTB"
        threat_id = "2147823802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 d2 be 04 00 00 00 f7 f6 a1 [0-4] 0f be 14 10 8b 45 f8 0f b6 0c 01 33 ca 8b 55 fc 8b 42 04 8b 55 f8 88 0c 10 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PM_2147823942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PM!MTB"
        threat_id = "2147823942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 44 24 14 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? c1 e8 05 89 44 24 ?? 8b 44 24 ?? 03 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 44 24 ?? 33 c6 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PO_2147823955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PO!MTB"
        threat_id = "2147823955"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc c1 e1 ?? 03 4d e8 8b 45 fc 03 45 f8 89 45 0c 8b 55 fc 83 0d ?? ?? ?? ?? ff 8b c2 c1 e8 ?? 03 45 e4 68 ?? ?? ?? ?? 33 45 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_NEF_2147824175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.NEF!MTB"
        threat_id = "2147824175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 fc 0f b6 0d ?? ?? ?? ?? 8b 55 fc 03 55 08 0f b6 02 33 c1 8b 4d fc 03 4d 08 88 01 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PP_2147824386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PP!MTB"
        threat_id = "2147824386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c4 89 84 24 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 04 24 f0 43 03 00 75 08 6a 00 ff 15 ?? ?? ?? ?? 56 83 44 24 04 0d a1 ?? ?? ?? ?? 0f af 44 24 04 05 c3 9e 26 00 81 3d ?? ?? ?? ?? 81 13 00 00 a3 ?? ?? ?? ?? 0f b7 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PQ_2147824701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PQ!MTB"
        threat_id = "2147824701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 29 45 fc 8b 4d fc c1 e1 04 03 4d e8 8b 45 fc 03 45 f8 89 45 0c 8b 55 fc 83 0d ?? ?? ?? ?? ff 8b c2 c1 e8 05 03 45 e4 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 45 0c 33 c1 2b f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_UE_2147824951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.UE!MTB"
        threat_id = "2147824951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 fc 03 55 ?? 0f b6 02 33 c1 8b 4d ?? 03 4d ?? 88 01 e9 ?? ?? ?? ?? 8b e5}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PR_2147825215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PR!MTB"
        threat_id = "2147825215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 14 89 44 24 18 8b 44 24 28 01 44 24 18 8b 44 24 14 c1 e8 05 89 44 24 10 8b 44 24 10 33 74 24 18 03 44 24 44 c7 05 ?? ?? ?? ?? ee 3d ea f4 33 c6}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e1 04 03 4d f0 8b 45 fc 03 45 f8 89 45 0c 8b 45 fc 83 0d ?? ?? ?? ?? ff c1 e8 05 c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 08 8b 45 e4 01 45 08 8b 45 08 33 45 0c 33 c1 2b f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_RedLineStealer_MF_2147825246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MF!MTB"
        threat_id = "2147825246"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 fc b8 d6 38 00 00 01 45 fc 8b 45 08 8b 4d fc 8a 0c 01 8b 15 ?? ?? ?? ?? 88 0c 02 c9 c2}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 33 45 0c 81 45 f8 ?? ?? ?? ?? 33 c1 2b f0 ff 4d f0 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = "OpenMutexW" ascii //weight: 1
        $x_1_4 = "VirtualLock" ascii //weight: 1
        $x_1_5 = "CreateMailslotA" ascii //weight: 1
        $x_1_6 = "GetDiskFreeSpaceExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_EK_2147825277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.EK!MTB"
        threat_id = "2147825277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {55 89 e5 83 ec 04 89 4d fc 8b 45 fc 8b 55 08 89 50 04 90 c9 c2 04 00}  //weight: 2, accuracy: High
        $x_2_2 = {8b 45 0c 0f b6 10 8b 45 08 88 10 90}  //weight: 2, accuracy: High
        $x_1_3 = "yomoycl" ascii //weight: 1
        $x_1_4 = "fgkycxduixopics" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PS_2147825401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PS!MTB"
        threat_id = "2147825401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c3 33 45 f4 33 45 f0 89 45 0c 8b 45 0c 01 05 ?? ?? ?? ?? 8b 45 0c 29 45 fc 8b 4d fc c1 e1 04 03 4d dc 8b 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PS_2147825401_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PS!MTB"
        threat_id = "2147825401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 8b 44 24 ?? 03 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 33 02 01 01 c1 c6 81 3d ?? ?? ?? ?? 16 05 00 00 89 4c 24 ?? 89 44 24 ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PT_2147825880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PT!MTB"
        threat_id = "2147825880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 08 8b 45 e4 01 45 08 8b 45 08 33 45 0c 33 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PT_2147825880_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PT!MTB"
        threat_id = "2147825880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 18 89 44 24 1c 8b 44 24 2c 01 44 24 1c 8b 44 24 18 c1 e8 05 89 44 24 14 8b 4c 24 10 33 4c 24 1c 8b 44 24 14 [0-16] 33 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 05 c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 08 8b 45 e4 01 45 08 8b 45 08 33 45 0c 81 45 f8 47 86 c8 61 33 c1 2b f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_RedLineStealer_PU_2147825881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PU!MTB"
        threat_id = "2147825881"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 44 24 ?? 89 74 24 ?? 89 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PU_2147825881_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PU!MTB"
        threat_id = "2147825881"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 40 47 4e c7 84 24 ?? ?? ?? ?? 1a 41 9f 17 c7 84 24 ?? ?? ?? ?? 44 55 93 01 c7 84 24 ?? ?? ?? ?? 79 16 54 13 c7 84 24 ?? ?? ?? ?? 7f 0c 54 3c c7 84 24 ?? ?? ?? ?? f8 dc bd 0f c7 84 24 ?? ?? ?? ?? 37 1e d5 38}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 a4 24 80 00 00 00 8b 84 24 80 00 00 00 81 ac 24 80 00 00 00 d6 8a cd 68 b8 e2 3f 96 6e f7 a4 24 80 00 00 00 8b 84 24 80 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PV_2147827631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PV!MTB"
        threat_id = "2147827631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 81 c9 00 ff ff ff 41 8a 89 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 8d c4 fc ff ff 0f be 11 33 d0 a1 ?? ?? ?? ?? 03 85 c4 fc ff ff 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_LSA_2147827655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.LSA!MTB"
        threat_id = "2147827655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 33 ca 89 4c 24 ?? 89 7c 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 54 24 ?? 89 54 24 ?? 89 3d ?? ?? ?? ?? 8b 44 24}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_LSB_2147827656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.LSB!MTB"
        threat_id = "2147827656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {d3 ea 89 54 24 18 8b 44 24 50 01 44 24 18 8b 44 24 10 33 44 24 1c 89 74 24 34 89 44 24 10 89 44 24 58 8b 44 24 58 89 44 24 34 8b 44 24 18 31 44 24 34 8b 44 24 34}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PW_2147827812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PW!MTB"
        threat_id = "2147827812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ca 89 4c 24 ?? 89 5c 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 54 24 ?? 89 54 24 ?? 89 1d ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 8b 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PX_2147828047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PX!MTB"
        threat_id = "2147828047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {23 cf 8d bc 0c ?? ?? ?? ?? 8a 17 89 4c 24 ?? 8a 08 88 0f 8b 4c 24 30 88 10 a1 ?? ?? ?? ?? 8d 2c 08 0f b6 07 0f b6 ca 03 c1 99 b9 00 01 00 00 f7 f9 8a 84 14 ?? ?? ?? ?? 30 45 00 ff 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_LSE_2147828455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.LSE!MTB"
        threat_id = "2147828455"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 81 e1 ?? ?? ?? ?? 79 ?? 49 81 c9 ?? ?? ?? ?? 41 8a 89 ?? ?? ?? ?? 88 4d fb 0f b6 45 fb 8b 0d ?? ?? ?? ?? 03 4d e0 0f be 11 33 d0 a1 ?? ?? ?? ?? 03 45 e0 88 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_F_2147830375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.F!MTB"
        threat_id = "2147830375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AUbxxbqtq" ascii //weight: 1
        $x_1_2 = "\\Downloads\\NewPublish\\" ascii //weight: 1
        $x_1_3 = "evjousf" wide //weight: 1
        $x_1_4 = "ncossya" wide //weight: 1
        $x_1_5 = "AppPolicyGetProcessTerminationMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_EM_2147834183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.EM!MTB"
        threat_id = "2147834183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {69 c9 98 09 00 00 81 e1 ff 00 00 00 8b 55 0c 03 55 dc 0f b6 02 33 c1 8b 4d 0c 03 4d dc 88 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_EM_2147834183_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.EM!MTB"
        threat_id = "2147834183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {0f be 04 10 6b c0 44 99 b9 12 00 00 00 f7 f9 8b 55 0c 03 55 fc 0f b6 0a 33 c8 8b 55 0c 03 55 fc 88 0a}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_EM_2147834183_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.EM!MTB"
        threat_id = "2147834183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {b9 41 00 00 00 f7 f9 8b 45 08 0f be 0c 10 81 e1 ff 00 00 00 8b 55 0c 03 55 dc 0f b6 02 33 c1 8b 4d 0c 03 4d dc 88 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_EM_2147834183_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.EM!MTB"
        threat_id = "2147834183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {96 4b 27 81 db 93 00 00 00 2b f7 87 d2 f7 ea 27 83 e7 62 0b ff 87 da}  //weight: 7, accuracy: High
        $x_7_2 = {97 f7 d8 f8 25 89 00 00 00 8b ff 93 40 2f 83 ea 45 8b c7 87 d3}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_RedLineStealer_EM_2147834183_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.EM!MTB"
        threat_id = "2147834183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {29 c3 89 d8 c0 c0 02 83 f0 62 83 e8 0e f7 d0 d0 c8 88 44 15 c1}  //weight: 4, accuracy: High
        $x_2_2 = "nurtoycktoqoXRJWQORJVoqwjrixnqwirokvJEOWTNMxowetkonwvo" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_EM_2147834183_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.EM!MTB"
        threat_id = "2147834183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uaqbhzupfmzq" ascii //weight: 1
        $x_1_2 = "msxntxjvinmvqsdityiqnjveoketqzevrlibvrtihbskqsdxsgoqrkoaifkiqb" ascii //weight: 1
        $x_1_3 = "ksryytvdmkkaxxozluwqswaujmlktkpfpjplwfonrjbxpifdmfplmintz" ascii //weight: 1
        $x_1_4 = "hulifsfsqnlqfgxuwqkhtkyguosi" ascii //weight: 1
        $x_1_5 = "CreateFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_SA_2147834529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.SA!MTB"
        threat_id = "2147834529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 10 40 00 46 3b 35 ?? ?? ?? ?? 72 cd 26 00 a1 ?? ?? ?? ?? 8a 84 30 3b 2d 0b 00 8b 0d ?? ?? ?? ?? 88 04 31 81 3d ?? ?? ?? ?? 92 02 00 00 75 ?? 57 57 57 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_EB_2147835749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.EB!MTB"
        threat_id = "2147835749"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {0f be 00 0f be 8d 5b ff ff ff 09 c8 88 c1 8b 85 60 ff ff ff 88 08 0f b7 85 f6 fe ff ff}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_B_2147839193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.B!MTB"
        threat_id = "2147839193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe %sadvpack.dll,DelNodeRunDLL32" ascii //weight: 1
        $x_1_2 = "rundll32.exe %s,InstallHinfSection %s" ascii //weight: 1
        $x_2_3 = "cmd /c cmd < Desk.xlsx & ping -n 5 localhost" ascii //weight: 2
        $x_2_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_C_2147839638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.C!MTB"
        threat_id = "2147839638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cmd /c cmd < Aging.adt & ping -n 5 localhost" ascii //weight: 2
        $x_1_2 = "nslookup /" ascii //weight: 1
        $x_1_3 = "SeShutdownPrivilege" ascii //weight: 1
        $x_2_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_DI_2147840536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.DI!MTB"
        threat_id = "2147840536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 03 45 f8 8a 08 88 4d fe 0f b6 4d fe 8b 45 f8 33 d2 f7 75 10 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ff 8b 45 08 03 45 f8 8a 08 88 4d fd}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 03 55 f8 88 0a 8a 45 fd 88 45 fc 0f b6 4d fc 8b 55 08 03 55 f8 0f b6 02 2b c1 8b 4d 08 03 4d f8 88 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_E_2147843117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.E!MTB"
        threat_id = "2147843117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 44 24 08 83 2c 24 ?? ?? 01 04 24 8b 04 24 31 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_D_2147847951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.D!MTB"
        threat_id = "2147847951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 c2 0f b6 c0 0f b6 84 05 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 89 8d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_G_2147848428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.G!MTB"
        threat_id = "2147848428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 c2 0f b6 c0 0f b6 84 05 ?? ?? ?? ?? 30 83 ?? ?? ?? ?? 43 81 fb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_I_2147848975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.I!MTB"
        threat_id = "2147848975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 84 04 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 89 4c 24 ?? 81 f9 ?? ?? ?? ?? 72 ?? 05 00 03 c2 0f b6 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_EN_2147849112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.EN!MTB"
        threat_id = "2147849112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 7d 08 f6 17 80 2f 8f 47 e2 f8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_EN_2147849112_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.EN!MTB"
        threat_id = "2147849112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 7d 08 f6 17 80 2f 9d 80 2f 35 47 e2 f5}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_J_2147849237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.J!MTB"
        threat_id = "2147849237"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 e1 c1 ea ?? 6b c2 ?? 2b c8 8a 81 ?? ?? ?? ?? 8b 4c 24 ?? 88 44 0c ?? 41 89 4c 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_K_2147849252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.K!MTB"
        threat_id = "2147849252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 e2 c1 ea ?? 8b ca c1 e1 ?? 03 ca 8b 54 24 ?? 8b c2 2b c1 8a 80}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_L_2147850227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.L!MTB"
        threat_id = "2147850227"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fe 07 47 e2 f6 05 00 f6 17 80}  //weight: 2, accuracy: Low
        $x_2_2 = {33 c2 83 c1 ?? a9 ?? ?? ?? ?? 74 0c 00 8b 01 ba ?? ?? ?? ?? 03 d0 83 f0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_M_2147852410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.M!MTB"
        threat_id = "2147852410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f6 17 80 37 ?? 47 e2 f8 5f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_N_2147887404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.N!MTB"
        threat_id = "2147887404"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c0 33 db f6 17 80 37 ?? 47 e2 ?? 5f 5e 5b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_O_2147892166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.O!MTB"
        threat_id = "2147892166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 2f 88 33 ?? ?? ?? ?? ?? 80 07 49 ?? ?? ?? ?? ?? ?? f6 2f 47 e2}  //weight: 2, accuracy: Low
        $x_2_2 = {80 2f 88 8b ?? 33 ?? ?? ?? 80 07 49 ?? ?? 8b ?? ?? ?? f6 2f 47 e2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_RedLineStealer_P_2147899126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.P!MTB"
        threat_id = "2147899126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 07 48 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 2f 97 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f6 2f 47 e2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_MEA_2147900568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.MEA!MTB"
        threat_id = "2147900568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://api.ip.sb/ip" wide //weight: 1
        $x_1_2 = "BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO" ascii //weight: 1
        $x_1_3 = "AntiFileSystemSpy" wide //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "EncryptedData" ascii //weight: 1
        $x_1_6 = "DecryptBlob" ascii //weight: 1
        $x_1_7 = "Discord" ascii //weight: 1
        $x_1_8 = "Replace" ascii //weight: 1
        $x_1_9 = "Reverse" ascii //weight: 1
        $x_1_10 = "get_os_crypt" ascii //weight: 1
        $x_1_11 = "FromBase64CharArray" ascii //weight: 1
        $x_1_12 = "bGhjY25pbWlnfFN" wide //weight: 1
        $x_1_13 = "asdl94jlajsd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_PN_2147902097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.PN!MTB"
        threat_id = "2147902097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 44 24 ?? 8b 44 24 ?? 03 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 44 24 ?? 33 c6 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_RP_2147903621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.RP!MTB"
        threat_id = "2147903621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\First.pdb" ascii //weight: 1
        $x_1_2 = "SetThreadContext" ascii //weight: 1
        $x_1_3 = "ResumeThread" ascii //weight: 1
        $x_1_4 = "\\RegAsm.exe" ascii //weight: 1
        $x_1_5 = "sIasnnfbnxhbsAUie" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_SPBB_2147908219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.SPBB!MTB"
        threat_id = "2147908219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 70 0c 31 c0 29 c8 31 c9 29 f1 01 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RedLineStealer_BAA_2147947009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RedLineStealer.BAA!MTB"
        threat_id = "2147947009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 0c 16 8b c2 42 83 e0 ?? 8a 04 38 8b 7d ?? 32 04 39 88 01 3b 95 ?? ?? ?? ?? 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

