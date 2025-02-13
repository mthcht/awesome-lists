rule Trojan_Win32_PSWStealer_ACS_2147793150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.ACS!MTB"
        threat_id = "2147793150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "samp.dll" ascii //weight: 3
        $x_3_2 = "WinExec" ascii //weight: 3
        $x_3_3 = "/passwd" ascii //weight: 3
        $x_3_4 = "AriMailStr:" ascii //weight: 3
        $x_3_5 = "hackmode" ascii //weight: 3
        $x_3_6 = "Ashot Samp" ascii //weight: 3
        $x_3_7 = "SOFTWARE\\SAMP" ascii //weight: 3
        $x_3_8 = "ashot_st" ascii //weight: 3
        $x_3_9 = "data\\acces" ascii //weight: 3
        $x_3_10 = "AntiStealerByDarkP1xel" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_SDS_2147797976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.SDS!MTB"
        threat_id = "2147797976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 d0 4c 8d 64 24 04 c0 c8 4e d2 e2 8b 45 08 0f 9a c2 8b 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_MP_2147797981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.MP!MTB"
        threat_id = "2147797981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 45 93 33 85 40 fc ff ff 88 45 93 8b 8d fc fd ff ff 8b 11 8b 8d f0 fd ff ff d3 e2 89 95 e4 fd ff ff 8b 45 e4 8b 8d 68 fc ff ff 8b 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_GTS_2147809829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.GTS!MTB"
        threat_id = "2147809829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 8a 01 01 00 00 8d 92 05 01 00 00 33 c0 83 e1 01 33 04 ca 33 44 ca 04 c3}  //weight: 10, accuracy: High
        $x_10_2 = {0f b6 75 5d 0f b6 45 5e 0f b6 55 5f 0f b6 4d 60 c1 e6 18 c1 e0 10 c7 45 1c ff ff ff ff 0b f0 c1 e2 08 0b f2 0b f1 89 75 20 33 ff 89 7d 4c 89 7d 58 8b 44 24 38 3b 45 24 77 47 83 7d 48 00 75 1c}  //weight: 10, accuracy: High
        $x_1_3 = "http://lady.webnice.ru" ascii //weight: 1
        $x_1_4 = "http://www.rabota.ricor.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_GRM_2147810547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.GRM!MTB"
        threat_id = "2147810547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 45 fc 8b c6 83 e8 65 33 05 e8 0e 48 00 83 e8 38 81 c0 bb c8 63 62 2b c7 81 f0 2a a4 3a bf 68 09 54 46 00 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_GTQ_2147814051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.GTQ!MTB"
        threat_id = "2147814051"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c6 40 04 01 cc e9 00 00 00 00 33 c0 33 c0 0f 84 00 00 00 00 85 ff 83 e9 20 85 c9 c1 e0 10 0f 85 41 02 00 00 c2 08 00}  //weight: 10, accuracy: High
        $x_1_2 = ".loathli" ascii //weight: 1
        $x_1_3 = ".ligamen" ascii //weight: 1
        $x_1_4 = "GetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_GZT_2147814055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.GZT!MTB"
        threat_id = "2147814055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4c 24 10 8b 44 24 0c 33 d2 f7 f1 8b d8 8b 44 24 ?? f7 f1 8b f0 8b c3 f7 64 24 ?? 8b c8 8b c6 f7 64 24 ?? 03 d1 eb 47 8b c8 8b 5c 24 ?? 8b 54 24 ?? 8b 44 24 ?? d1 e9 d1 db d1 ea d1 d8 0b c9 75 ?? f7 f3 8b f0 f7 64 24 ?? 8b c8 8b 44 24 ?? f7 e6 03 d1 72}  //weight: 10, accuracy: Low
        $x_1_2 = "goo.gl/vT7idg" ascii //weight: 1
        $x_1_3 = "URLDownloadToFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_GNT_2147814247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.GNT!MTB"
        threat_id = "2147814247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 45 e8 8b 45 e8 0f b6 84 05 e8 fe ff ff 8b 4d 08 03 4d ec 0f b6 09 33 c8 8b 45 08 03 45 ec 88 08 e9 3f ff ff ff}  //weight: 10, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "SystemFunction036" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_GJ_2147816606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.GJ!MTB"
        threat_id = "2147816606"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d9 8a 44 0a ff 30 44 0f ff 49 75 f5 03 fb 29 5d 10 0f 84}  //weight: 5, accuracy: High
        $x_5_2 = {0f b6 13 32 d0 c1 e8 ?? 33 04 96 43 49 75 f1}  //weight: 5, accuracy: Low
        $x_1_3 = "SHChangeNotifyRegister" ascii //weight: 1
        $x_1_4 = "RegisterEventSource" ascii //weight: 1
        $x_1_5 = "srand" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_FQ_2147818355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.FQ!MTB"
        threat_id = "2147818355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 08 83 c2 5b 89 95 ?? ?? ?? ?? 8b 45 08 05 a0 00 00 00 89 85 ?? ?? ?? ?? 8b 4d 08 83 c1 48 89 8d ?? ?? ?? ?? 8b 55 08 83 c2 0b 89 95 ?? ?? ?? ?? 8b 45 08 83 c0 0d 89 85 64 fe ff ff 8b 4d 08}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 8d e4 fe ff ff 03 4d c0 89 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 0f af 95 ?? ?? ?? ?? 89 55 ac 8b 45 ac 0f af 85 ?? ?? ?? ?? 89 45 c4 8b 4d e8 3b 8d}  //weight: 10, accuracy: Low
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_WM_2147818609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.WM!MTB"
        threat_id = "2147818609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 34 10 68 12 96 67 05 68 19 42 09 00 e8 ?? ?? ?? ?? 83 c4 08 0f af f0 8b 4d 0c 03 4d fc 0f be 11 33 d6 8b 45 0c 03 45 fc 88 10 eb b6}  //weight: 10, accuracy: Low
        $x_10_2 = {30 ff ff ff 03 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 0f af 4d f4 89 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 0f af 95 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8b 85 28 ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_FV_2147818669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.FV!MTB"
        threat_id = "2147818669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 95 4c ff ff ff 03 55 f4 89 95 ?? ?? ?? ?? 8b 45 f0 0f af 45 fc 89 45 a8 8b 4d 80 0f af 4d fc 89 8d ?? ?? ?? ?? 8b 55 f8 0f af 95 ?? ?? ?? ?? 89 55 c4 8b 45 f8 0f af 85 ?? ?? ?? ?? 89 85 e4 fe ff ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_VM_2147819231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.VM!MTB"
        threat_id = "2147819231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Copyright (C) 2022, pozkarte" ascii //weight: 1
        $x_1_2 = ".pdb" ascii //weight: 1
        $x_1_3 = "29.47.75.23" ascii //weight: 1
        $x_1_4 = "22.82.74.73" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
        $x_1_6 = "Yuhovoyuyamovupe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_VU_2147819667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.VU!MTB"
        threat_id = "2147819667"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {66 89 4d e8 c6 45 e6 01 0f bf 55 c8 81 f2 7f 46 00 00 66 89 55 c8 c6 45 bf 01 c6 45 ef 01 0f bf 45 e0}  //weight: 10, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_VX_2147820031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.VX!MTB"
        threat_id = "2147820031"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 32 21 c0 48 29 fb 81 e6 ?? ?? ?? ?? 81 e8 ?? ?? ?? ?? 40 31 31 f7 d0 bf ?? ?? ?? ?? bf ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 4b 81 e8 ?? ?? ?? ?? 29 d8 42 89 f8 48 81 ef}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_XZ_2147820210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.XZ!MTB"
        threat_id = "2147820210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 d8 31 d2 8d 4d ?? f7 75 ?? 8b 45 ?? 0f be 34 10 e8 ?? ?? ?? ?? 8d 4d ?? e8 ?? ?? ?? ?? 69 c6 ?? ?? ?? ?? 30 04 1f 43 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_XB_2147820297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.XB!MTB"
        threat_id = "2147820297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {29 cb b8 d8 85 40 00 29 d9 e8 ?? ?? ?? ?? 31 06 81 c6 ?? ?? ?? ?? 39 d6 75 e8 01 cb c3 81 eb ?? ?? ?? ?? 01 d9 8d 04 38 01 cb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_XC_2147820390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.XC!MTB"
        threat_id = "2147820390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 31 81 ea ?? ?? ?? ?? 29 d0 81 e6 ?? ?? ?? ?? 81 eb ?? ?? ?? ?? 4b 21 c2 31 37 01 c2 29 da 81 ea ?? ?? ?? ?? 47 f7 d3 89 c3 81 c1 ?? ?? ?? ?? 29 d3 01 d0 81 ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_XF_2147820842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.XF!MTB"
        threat_id = "2147820842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 18 29 ca f7 d7 81 e3 ?? ?? ?? ?? 4a f7 d2 29 d7 31 1e 21 cf 47 46 4f bf ?? ?? ?? ?? 40 29 ca 81 c7 ?? ?? ?? ?? 81 fe}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_XH_2147821578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.XH!MTB"
        threat_id = "2147821578"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 1f 21 c0 81 c6 ?? ?? ?? ?? 48 81 e3 ?? ?? ?? ?? 21 c0 09 f0 31 19 be ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 41 4e 89 f0 47 81 c2 ?? ?? ?? ?? 89 d0 42 81 f9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_XP_2147823119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.XP!MTB"
        threat_id = "2147823119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 d4 69 d2 ?? ?? ?? ?? 89 55 d4 c6 45 ?? 01 c6 45 ?? ?? c6 45 ?? 01 0f bf 45 9c 35 ?? ?? ?? ?? 66 89 45 9c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_DA_2147828794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.DA!MTB"
        threat_id = "2147828794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "d1rectory_3322_t" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_PAAA_2147888533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.PAAA!MTB"
        threat_id = "2147888533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "w_MousePressEvent" ascii //weight: 1
        $x_1_2 = "w_MouseMoveEvent" ascii //weight: 1
        $x_1_3 = "w_KeyPressEvent" ascii //weight: 1
        $x_1_4 = "w_SetDisableKeyboard" ascii //weight: 1
        $x_1_5 = "w_SetDisableMouse" ascii //weight: 1
        $x_1_6 = "w_SetDisableMonitor" ascii //weight: 1
        $x_1_7 = "user UserDefender /delete" ascii //weight: 1
        $x_1_8 = "add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList\" /v UserDefender /t REG_DWORD /d 0 /reg:64 /f" ascii //weight: 1
        $x_1_9 = "\\Coinomi\\Coinomi\\wallets" ascii //weight: 1
        $x_1_10 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" ascii //weight: 1
        $x_1_11 = "SELECT rowid , name_on_card , expiration_month , expiration_year , card_number_encrypted FROM credit_cards" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PSWStealer_RP_2147924104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWStealer.RP!MTB"
        threat_id = "2147924104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "123"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\vbame.dll" wide //weight: 1
        $x_1_2 = "Can't run file!" wide //weight: 1
        $x_10_3 = "winmgmts:\\\\.\\root\\cimv2" wide //weight: 10
        $x_10_4 = "Select * from Win32_ComputerSystem" wide //weight: 10
        $x_1_5 = "Model" wide //weight: 1
        $x_100_6 = "wecaws7eafrgsf2mfcvnr" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

