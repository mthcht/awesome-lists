rule Trojan_Win32_Vidar_PA_2147745435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PA!MTB"
        threat_id = "2147745435"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {8b 45 88 8d 0c 06 33 d2 8b c6 f7 75 84 8a 04 3a 8b 55 80 32 04 0a 46 88 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PA_2147745435_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PA!MTB"
        threat_id = "2147745435"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\pool.exe" ascii //weight: 1
        $x_1_2 = "\\paster.exe" ascii //weight: 1
        $x_1_3 = "\\uc.exe" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_5 = "suspiria" wide //weight: 1
        $x_1_6 = "iplogger.org" ascii //weight: 1
        $x_1_7 = "pix-fix.net" ascii //weight: 1
        $x_1_8 = "wo.php?stub=" ascii //weight: 1
        $x_1_9 = "gate1.php?a={" ascii //weight: 1
        $x_1_10 = "qemu-ga.exe" ascii //weight: 1
        $x_1_11 = "SOFTWARE\\VMware, Inc.\\VMware Tools" ascii //weight: 1
        $x_1_12 = "HARDWARE\\ACPI\\RSDT\\VBOX__" ascii //weight: 1
        $x_1_13 = "cmd.exe /c start /B powershell -windowstyle hidden -command" ascii //weight: 1
        $x_1_14 = {26 7b 24 74 3d 27 [0-16] 69 [0-16] 65 78 [0-32] 40 28 6e [0-16] 65 77 [0-16] 2d [0-16] 6f 62 [0-16] 6a 65 63 [0-16] 74 20 4e [0-16] 65 74 [0-16] 2e 57 [0-16] 65 62 [0-16] 43 6c [0-16] 69 65 [0-16] 6e 74 [0-16] 29 2e [0-16] 55 70 [0-16] 6c 6f 61 [0-16] 64 [0-16] 53 74 [0-16] 72 69 [0-16] 6e 67 28 [0-16] 27 27 68 [0-16] 74 [0-16] 74 70 [0-16] 3a [0-16] 2f 2f}  //weight: 1, accuracy: Low
        $x_1_15 = {27 48 23 6f 72 [0-10] 73 65 48 6f [0-10] 75 72 73 27 27 [0-10] 29 [0-10] 7c [0-10] 69 [0-10] 65 [0-10] 78 27 2e 72 65 70 6c 61 63 65 28 27 ?? 27 2c 27 27 29 2e 73 70 6c 69 74 28 27 40 27 2c 35 29 3b}  //weight: 1, accuracy: Low
        $x_1_16 = "C:\\INTERNAL\\REMOTE.EXE" wide //weight: 1
        $x_2_17 = "Software\\fuck\\" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((14 of ($x_1_*))) or
            ((1 of ($x_2_*) and 12 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vidar_PB_2147745748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PB!MTB"
        threat_id = "2147745748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d0 c1 ea 05 03 54 24 24 8b f8 c1 e7 04 03 7c 24 20 03 c1 33 d7 33 d0 2b f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PB_2147745748_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PB!MTB"
        threat_id = "2147745748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 88 8d 0c 06 33 d2 8b c6 f7 75 84 8a 04 3a 8b 55 80 32 04 0a 46 88 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PB_2147745748_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PB!MTB"
        threat_id = "2147745748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\pool.exe" ascii //weight: 1
        $x_1_2 = "\\paster.exe" ascii //weight: 1
        $x_1_3 = "\\uc.exe" ascii //weight: 1
        $x_1_4 = "iplogger.org" ascii //weight: 1
        $x_1_5 = "pix-fix.net" ascii //weight: 1
        $x_1_6 = "gate1.php?a={bbed3e55656ghf02-0b41-11e3-8249}id=2" ascii //weight: 1
        $x_1_7 = "cmd.exe /c start /B powershell -windowstyle hidden -command" ascii //weight: 1
        $x_1_8 = {27 48 23 6f 72 [0-10] 73 65 48 6f [0-10] 75 72 73 27 27 [0-10] 29 [0-10] 7c [0-10] 69 [0-10] 65 [0-10] 78 27 2e 72 65 70 6c 61 63 65 28 27 ?? 27 2c 27 27 29 2e 73 70 6c 69 74 28 27 40 27 2c 35 29 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_V_2147745808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.V!MTB"
        threat_id = "2147745808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 74 fb ff ff 8b 8d 60 fb ff ff 03 8d 80 fb ff ff 8d 58 04 0f af d8 8b 85 68 fb ff ff 0f af de 8b 15 4c 3f 42 00 0f af de 89 8d 50 fb ff ff 8b 8d 88 fb ff ff 8a 04 01 83 c3 ?? 32 c3 88 85 78 fb ff ff 89 95}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PC_2147746135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PC!MTB"
        threat_id = "2147746135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c start /B powershell -windowstyle hidden -command" ascii //weight: 1
        $x_1_2 = "Software\\fuck\\" ascii //weight: 1
        $x_1_3 = "gate1.php?a={bbed3e55656ghf02-0b41-11e3-8249}id=2" ascii //weight: 1
        $x_1_4 = "wo.php?stub=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PC_2147746135_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PC!MTB"
        threat_id = "2147746135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 88 8d 0c 07 33 d2 8b c7 f7 f3 8b 85 ?? ?? ?? ?? 56 8a 04 02 8b 55 84 32 04 0a 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {2b c1 89 45 ?? 8b 45 ?? 8d 0c ?? 33 d2 8b c3 f7 75 ?? 8b 85 ?? ?? ?? ?? 57 8a 04 02 8b 55 84 32 04 0a 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Vidar_AA_2147748091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AA!MTB"
        threat_id = "2147748091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "80"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Mozilla\\icecat\\Profiles\\" ascii //weight: 10
        $x_10_2 = "\\NETGATE Technologies\\BlackHawk\\Profiles\\" ascii //weight: 10
        $x_10_3 = "\\TorBro\\Profile" ascii //weight: 10
        $x_10_4 = "\\Comodo\\Dragon\\User Data" ascii //weight: 10
        $x_10_5 = "\\Chromium\\User Data" ascii //weight: 10
        $x_10_6 = "passwords.txt" ascii //weight: 10
        $x_10_7 = "encryptedUsername" ascii //weight: 10
        $x_10_8 = "encryptedPassword" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PD_2147753133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PD!MTB"
        threat_id = "2147753133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "U0VMRUNUIG5hbWVfb25fY2FyZCwgZXhwaXJhdGlvbl9tb250aCwgZXhwaXJhdGlvbl95ZWFyLCBjYXJkX251bWJlcl9lbmNyeXB0ZWQgRlJPTSBjcmVkaXRfY2FyZHM" ascii //weight: 1
        $x_1_2 = "U0VMRUNUIGFjdGlvbl91cmwsIHVzZXJuYW1lX3ZhbHVlLCBwYXNzd29yZF92YWx1ZSBGUk9NIGxvZ2lucw" ascii //weight: 1
        $x_1_3 = "XFxPcGVyYSBTb2Z0d2FyZVxcT3BlcmEgU3RhYmxlXFxVc2VyIERhdGFcXA" ascii //weight: 1
        $x_1_4 = "XFxNb3ppbGxhXFxGaXJlZm94XFxQcm9maWxlc1xc" ascii //weight: 1
        $x_1_5 = "\\Exodus\\exodus.wallet\\" ascii //weight: 1
        $x_1_6 = "\\Electrum-LTC\\wallets\\" ascii //weight: 1
        $x_1_7 = "files\\passwords.txt" ascii //weight: 1
        $x_1_8 = "cookies.sqlite" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GA_2147774353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GA!MTB"
        threat_id = "2147774353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 8b c3 f7 75 08 8b 45 0c 8d 0c 33 8a 04 02 8b 55 fc 32 04 0a 43 88 01 3b df 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GA_2147774353_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GA!MTB"
        threat_id = "2147774353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e0 04 89 45 fc 8b 45 dc 01 45 fc 8b 45 f8 8b 4d f0 8d 14 01 8b 4d f4 31 55 fc 8b f0 d3 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GA_2147774353_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GA!MTB"
        threat_id = "2147774353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b c8 8b 45 f8 33 d2 f7 f1 8b 45 0c 8a 0c 02 8b 45 f0 8b 55 08 32 0c 02 88 08}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GA_2147774353_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GA!MTB"
        threat_id = "2147774353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8a 94 01 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88 14 01 83 c4 ?? c3}  //weight: 10, accuracy: Low
        $x_10_2 = {8b d3 c1 ea ?? 8d 0c 18 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b f3 c1 e6 04 03 74 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 f1 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 31 74 24 ?? 81 3d}  //weight: 10, accuracy: Low
        $x_10_3 = {89 44 24 10 8b 44 24 ?? 01 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8b 4c 24 10 33 cf 33 ce 2b d9 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 83 6c 24 ?? 01}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Vidar_OMJ_2147794198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.OMJ!MTB"
        threat_id = "2147794198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_11_1 = {8b 55 08 03 95 f4 fb ff ff 0f b6 02 8b 8d e4 f7 ff ff 33 84 8d f8 fb ff ff 8b 95 f0 fb ff ff 03 95 f4 fb ff ff 88 02}  //weight: 11, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PAB_2147816739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PAB!MTB"
        threat_id = "2147816739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 cd cc cc cc f7 e1 8b c1 c1 ea 03 8d 14 92 03 d2 2b c2 8d 96 10 76 4b 00 03 d1 0f b6 80 00 30 41 00 30 81 10 76 4b 00 b8 cd cc cc cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PAM_2147817310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PAM!MTB"
        threat_id = "2147817310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c1 8b d8 33 d2 8b c6 f7 f3 8b 45 0c 8d 0c 3e 8a 04 02 8b 95 ?? ?? ?? ?? 32 04 0a 46 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PAM_2147817310_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PAM!MTB"
        threat_id = "2147817310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 03 f9 d9 ca 66 03 d6 75 04 74 02 37 8c 66 2b d6 ac 0f ba e1 75 34 fe aa 8d 76 01 8d 76 ff 49 76 05 77 03 d5 7e 06 0b c9 75 d3}  //weight: 1, accuracy: High
        $x_1_2 = {66 0f ba e5 2d ac 77 04 76 02 32 ef 8d 40 fd 7c 05 7d 03 45 cc a1 8d 40 03 34 fe 71 03 70 01 1a aa c1 c9 06 c1 c1 06 49 75 03 74 01 a6 0b c9 75 cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Vidar_PAN_2147818651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PAN!MTB"
        threat_id = "2147818651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c6 89 45 f0 8b c6 d3 e8 03 45 d0 89 45 f8 8b 45 f0 31 45 fc 8b 45 f8 31 45 fc 89 1d ?? ?? ?? ?? 8b 45 fc 29 45 f4 8d 45 e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PAN_2147818651_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PAN!MTB"
        threat_id = "2147818651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b f9 8b c7 c1 e0 04 03 45 e8 8b d7 89 45 fc 8b 45 f8 03 c7 c1 ea 05 03 55 ec 50 8d 4d fc c7 05}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 51 c7 45 fc 02 00 00 00 8b 45 08 01 45 fc 83 6d fc 02 8b 45 fc 31 01 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_DA_2147819199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.DA!MTB"
        threat_id = "2147819199"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 d8 8b 1a 03 5d ec 2b d8 6a 66 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 89 18 8b 45 c8 03 45 a0 8b 55 d8 31 02 83 45 ec 04 83 45 d8 04 8b 45 ec 3b 45 d4 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AK_2147819223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AK!MTB"
        threat_id = "2147819223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {3e e3 b4 f3 0d 96 e4 e0 cf 4d a9 3d bf 41 07 df 86 b9 43 4a 52 d7 32 1e 63 95 fe 86 50 05 98 8c fa 7f de bd b1 56 43 de 99 23 30 fe 70 68 dc 21 45 f0 c9 b5 f9 4e 87 f4 87 02 00 01 00 00 0b 51 d1}  //weight: 3, accuracy: High
        $x_1_2 = "license.key" wide //weight: 1
        $x_1_3 = "FILEFUNC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vidar_RPT_2147819639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RPT!MTB"
        threat_id = "2147819639"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b1 6d b0 6c 68 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 73 c6 05 ?? ?? ?? ?? 33 a2 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 64 88 0d ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 67 a2 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 00 ff 15 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_DB_2147820030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.DB!MTB"
        threat_id = "2147820030"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d8 8b 45 d8 89 18 6a ?? e8 ?? ?? ?? ?? 8b 5d c8 03 5d a0 2b d8 6a ?? e8 ?? ?? ?? ?? 03 d8 8b 45 d8 31 18 6a ?? e8 ?? ?? ?? ?? bb 04 00 00 00 2b d8 6a ?? e8 ?? ?? ?? ?? 03 d8 01 5d ec 83 45 d8 04 8b 45 ec 3b 45 d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_DC_2147820129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.DC!MTB"
        threat_id = "2147820129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 a4 33 c0 89 45 a4 8b 45 c8 03 45 a0 03 45 ec 03 45 a4 8b 55 d8 31 02 83 45 ec 04 83 45 d8 04 8b 45 ec 3b 45 d4 0f 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MA_2147822274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MA!MTB"
        threat_id = "2147822274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 06 89 45 fc 33 d2 8b c3 6a ?? 59 f7 f1 8b 4d fc 8a 04 0a 8b 4d 0c 30 04 1f 43 8b 41 04 8b 39 2b c7 3b d8 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MA_2147822274_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MA!MTB"
        threat_id = "2147822274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 0c 69 d2 fd 43 03 00 81 c2 c3 9e 26 00 89 15 14 ?? 45 00 8a 0d 16 ?? 45 00 30 0c 30 83 ff 0f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MA_2147822274_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MA!MTB"
        threat_id = "2147822274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 28 89 44 24 20 8b 44 24 24 01 44 24 20 8b 44 24 28 c1 e8 05 89 44 24 14 8b 4c 24 2c 8d 44 24 14 c7 05 24 0f 4d 00 ee 3d ea f4 e8 ?? ff ff ff 8b 44 24 20 31 44 24 10 8b 54 24 10 31 54 24 14 81 3d 2c 0f 4d 00 13 02 00 00 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MA_2147822274_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MA!MTB"
        threat_id = "2147822274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {8b 45 0c 8d 48 01 8a 10 40 84 d2 75 ?? 2b c1 8b d8 33 d2 8b c6 f7 f3 8b 45 0c 8d 0c 3e 8a 04 02 8b 55 08 32 04 0a 46 88 01 3b 75 10 72}  //weight: 10, accuracy: Low
        $x_2_3 = "\\Wallets\\" ascii //weight: 2
        $x_2_4 = "\\Telegram\\" ascii //weight: 2
        $x_2_5 = " /f & timeout /t 6 & del /f /q" ascii //weight: 2
        $x_2_6 = "/c taskkill /im" ascii //weight: 2
        $x_2_7 = "\\screenshot.jpg" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MA_2147822274_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MA!MTB"
        threat_id = "2147822274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {26 77 9d 6e 61 8f cb b8 15 dc fc d3 47 0f 2e 62 1b 7d 6a bf 25 8d 84 f0 a9 f3 cb 82 15 70 13 2b}  //weight: 2, accuracy: High
        $x_2_2 = {16 a5 10 90 12 f3 c8 7d f6 0c 92 67 ff ff ff ff d9 bb d0 4d db da 77 45 e4 e9 e2 d4 b5 b6 c7 19}  //weight: 2, accuracy: High
        $x_2_3 = {85 5c 6a 56 1c 88 8e b0 1e 6d e2 7c af 7f e5 5a 74 2a 70 7d 95 9b f0 7a 70 14 4c 8f 28 3e a3 60 ea 61 55 bb 9f f0 cf 5b 73 a5 95 e2 54 e5 5c 0f a4 fa a3 5a ea 21 b9 12 a5 50 04 13 cb 98}  //weight: 2, accuracy: High
        $x_2_4 = {e0 00 02 01 0b 01 0a 00 00 d4 03 00 00 30 19 00 00 00 00 00 4f 06 25}  //weight: 2, accuracy: High
        $x_1_5 = ".vmp0" ascii //weight: 1
        $x_1_6 = ".vmp2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_A_2147825078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.A!MTB"
        threat_id = "2147825078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CCOYS///hdr" wide //weight: 1
        $x_1_2 = "wallet.dat" wide //weight: 1
        $x_1_3 = "mozzzzzzzzzzz" wide //weight: 1
        $x_1_4 = {40 8a 0c 85 ?? ?? ?? ?? 8b 45 08 32 0c 03 a1 ?? ?? ?? ?? 88 0c 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_A_2147825078_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.A!MTB"
        threat_id = "2147825078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 57 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? 89 c7 89 f1 ?? ?? ?? ?? ?? e0 4e b7 8b 35 dc b5 41 00 50 ?? ?? 01 0e 04 eb ?? ?? ff b3 84 00 00 00 50 ?? ?? ?? ?? ?? e0 4e b7 83 c4 08 89 c7 50 ?? ?? 85 c0}  //weight: 2, accuracy: Low
        $x_1_2 = "\"id\":1,\"method\":\"Storage.getCookies\"" ascii //weight: 1
        $x_2_3 = "\\Monero\\wallet.keys" ascii //weight: 2
        $x_2_4 = "\\BraveWallet\\Preferences" ascii //weight: 2
        $x_1_5 = "/c timeout /t 10 & rd /s /q \"C:\\ProgramData\\" ascii //weight: 1
        $x_1_6 = "wallet_path" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\monero-project\\monero-core" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_B_2147825079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.B!MTB"
        threat_id = "2147825079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 14 80 34 38 5e 5f 5e 5b 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {2b c8 be 98 6c 14 00 8d 49 00 8a 14 01 88 10 40 4e 75 f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_B_2147825079_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.B!MTB"
        threat_id = "2147825079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 19 30 c3 0f b6 f3 c1 e8 08 33 04 b5 c0 95 41 00 8a 59 01 30 c3 0f b6 f3 c1 e8 08 33 04 b5 c0 95 41 00 8a 59 02 30 c3 0f b6 f3 c1 e8 08 33 04 b5 c0 95 41 00 8a 59 03 30 c3 0f b6 f3 c1 e8 08 33 04 b5 c0 95 41 00}  //weight: 2, accuracy: High
        $x_1_2 = "\"id\":1,\"method\":\"Storage.getCookies\"" ascii //weight: 1
        $x_1_3 = "\\Monero\\wallet.keys" ascii //weight: 1
        $x_1_4 = "\\BraveWallet\\Preferences" ascii //weight: 1
        $x_1_5 = "/c timeout /t 10 & rd /s /q \"C:\\ProgramData\\" ascii //weight: 1
        $x_1_6 = "Software\\Martin Prikryl\\WinSCP 2\\Sessions" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\monero-project\\monero-core" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_DD_2147827629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.DD!MTB"
        threat_id = "2147827629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 10 6a 00 e8 ?? ?? ?? ?? 8b 5d c8 03 5d a0 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 31 18 83 45 ec 04 83 45 d8 04 8b 45 ec 3b 45 d4 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_DD_2147827629_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.DD!MTB"
        threat_id = "2147827629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 c8 88 45 ?? 0f b6 45 ?? 0f b6 84 05 ?? ?? ?? ?? 88 45 ?? 8b 55 ?? 8b 45 ?? 01 d0 0f b6 00 32 45 ?? 88 45 ?? 8b 55 ?? 8b 45 ?? 01 c2 0f b6 45 ?? 88 02 83 45 ?? ?? 8b 45 ?? 3b 45 ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_NH_2147827654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.NH!MTB"
        threat_id = "2147827654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "climatejustice.social/@ffoleg94" ascii //weight: 1
        $x_1_2 = "t.me/korstonsales" ascii //weight: 1
        $x_1_3 = "%s\\%s\\*wallet*.dat" ascii //weight: 1
        $x_1_4 = "indexeddb.leveldb" ascii //weight: 1
        $x_1_5 = "\\Bitcoin\\wallets" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_NQ_2147827706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.NQ!MTB"
        threat_id = "2147827706"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {87 d5 7c 3a 81 44 24 ?? 8c eb 73 22 8b 4c 24 10 8b d7 8b 5c 24 ?? 8b c7 d3 e2 03 54 24 1c c1 e8 ?? 03 44 24 34 33 d0 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8d 04 2f 33 d0 2b da 8b 15 ?? ?? ?? ?? 89 5c 24 14 81 fa}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_NR_2147827824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.NR!MTB"
        threat_id = "2147827824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 8c 8d 0c 03 33 d2 8b c3 f7 75 88 8b 85 ?? ?? ?? ?? 57 8a 04 02 8b 55 80 32 04 0a 88 01 8d 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_NX_2147828212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.NX!MTB"
        threat_id = "2147828212"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 2c 89 44 24 1c 8b 44 24 10 01 44 24 1c 8b 44 24 2c c1 e8 ?? 89 44 24 14 8b 44 24 14 33 74 24 1c 03 44 24 38 c7 05 ?? ?? ?? ?? ee 3d ea f4 33 c6 83 3d}  //weight: 10, accuracy: Low
        $x_10_2 = {6a 00 c7 05 ?? ?? ?? ?? 64 00 6c 00 c7 05 ?? ?? ?? ?? 65 00 6c 00 c7 05 ?? ?? ?? ?? 65 00 72 00 66 89 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PAX_2147832630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PAX!MTB"
        threat_id = "2147832630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 55 94 8d 94 95 ?? ?? ?? ?? 8b 1a 89 18 89 0a 8b 00 03 c1 25 ?? ?? ?? ?? 79 ?? 48 [0-10] 0f b6 d1 8d 84 85 98 03 00 00 39 10 75 08 8b 45 8c 88 0c 30 eb 0a 8a 00 32 c1 8b 4d 8c 88 04 31 ff 75 88 ff 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PF_2147832966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PF!MTB"
        threat_id = "2147832966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e8 89 45 f8 8b 45 d4 01 45 f8 8b 4d f8 33 4d e0 89 3d ?? ?? ?? ?? 31 4d f4 8b 45 f4 29 45 f0 81 45 dc ?? ?? ?? ?? 83 eb 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PG_2147833014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PG!MTB"
        threat_id = "2147833014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e8 05 03 45 ?? c7 05 ?? ?? ?? ?? 19 36 6b ff 33 45 0c 33 f8 89 7d f4 8b 45 f4 29 45 fc 89 75 f8 8b 45 d8 01 45 f8 2b 5d f8 ff 4d ec 89 5d e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c6 d3 e8 89 45 f8 8b 45 d4 01 45 f8 8b 4d f8 33 4d e8 8b 45 f4 81 45 e0 ?? ?? ?? ?? 33 c1 2b f8 83 6d d8 01 89 45 f4 89 1d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Vidar_PH_2147833519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PH!MTB"
        threat_id = "2147833519"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c7 8b d7 d3 e2 8b 4d ?? 89 45 ?? 8b c7 03 55 d4 d3 e8 89 45 f8 8b 45 d0 01 45 f8 33 55 ec 8d 4d e0 52 ff 75 f8 89 55 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_BA_2147833998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.BA!MTB"
        threat_id = "2147833998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b c8 8b 45 fc 33 d2 f7 f1 8b 45 0c 8b 4d 08 8a 04 02 32 04 31 ff 45 fc 88 06 39 5d fc 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MP_2147835303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MP!MTB"
        threat_id = "2147835303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 8b 40 04 ff 70 09 6a 00 8b 45 08 ff 50 24 89 45 f8 83 65 f4 00 6a 00 8d 45 f4 50 ff 75 f8 8b 45 08 8b 40 04 ff 30 ff 75 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MC_2147835410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MC!MTB"
        threat_id = "2147835410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc c1 e0 04 8b 4d 08 0f be 09 03 c1 89 45 fc 8b 45 fc 25 00 00 00 f0 89 45 f4 74 11 8b 45 f4 c1 e8 18 33 45 fc 25 ff ff ff 0f 89 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MC_2147835410_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MC!MTB"
        threat_id = "2147835410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {55 8b ec 6a 0c b9 3c 08 45 00 e8 d1 1e 00 00 b9 3c 08 45 00 e8 57 13 00 00 68 30 4a 40 00 e8 94}  //weight: 3, accuracy: High
        $x_3_2 = {2d 00 00 83 c4 04 5d c3 cc cc cc cc cc cc cc cc 53 8b dc 83 ec 08 83 e4 f8 83 c4 04 55 8b 6b 04}  //weight: 3, accuracy: High
        $x_3_3 = {ab 2c 01 00 45 4e 4a 45 59}  //weight: 3, accuracy: High
        $x_1_4 = {b9 48 08 45 00 e8 ?? ?? ?? ?? 8d 4d ff e8 ?? ?? ?? ?? 89 45 f8 c6 45 dc 21 c6 45 dd 32 c6 45 de 26 c6 45 df 6f c6 45 e0 54}  //weight: 1, accuracy: Low
        $x_1_5 = "ResumeThread" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_1_7 = "CalcMova.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MC_2147835410_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MC!MTB"
        threat_id = "2147835410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "://135.181.26.183" ascii //weight: 4
        $x_1_2 = "\\screenshot.jpg" ascii //weight: 1
        $x_1_3 = {47 65 63 6b 6f 20 2f 20 [0-37] 20 46 69 72 65 66 6f 78}  //weight: 1, accuracy: Low
        $x_1_4 = "SOFTWARE\\Microsoft\\Cryptography" ascii //weight: 1
        $x_1_5 = "Enkrypt" ascii //weight: 1
        $x_1_6 = "Opera Wallet" ascii //weight: 1
        $x_1_7 = "Exodus\\exodus.wallet" ascii //weight: 1
        $x_1_8 = "Select * From Win32_OperatingSystem" wide //weight: 1
        $x_1_9 = "ROOT\\CIMV2" wide //weight: 1
        $x_1_10 = "Select * From AntiVirusProduct" wide //weight: 1
        $x_1_11 = "root\\SecurityCenter2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MB_2147835411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MB!MTB"
        threat_id = "2147835411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f0 8d 50 01 8b 45 ec 01 d0 0f b6 84 05 1e 8f ff ff 88 85 2f bb ff ff 8b 45 f0 8d 50 01 8b 45 ec 01 c2 8b 45 f4 83 e8 01 2b 45 ec 0f b6 84 05 1e 8f ff ff 88 84 15 1e 8f ff ff 8b 45 f4 83 e8 01 2b 45 ec 0f b6 95 2f bb ff ff 88 94 05 1e 8f ff ff 83 45 ec 01 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MB_2147835411_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MB!MTB"
        threat_id = "2147835411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {73 2e e0 65 9c cc 87 bf a4 fa 10 10 61 6c a1 01 a3 3d a3 ab 23 f9 15 47 10 e5 90 4e 08 24 c2 cc 20 75 3a 4d d9 c7 8c f9 68 50 40 f6 bb fd 25 46}  //weight: 5, accuracy: High
        $x_5_2 = {6b 71 4a d1 2b db 23 90 30 d5 65 cb f0 2a b6 ad 70 4b 27 c2 60 36 13 10 8d 35 a1 8b 20 4c be 7e e8 32 b7 9c 1b fc 29 4f 9a 28 85 0f 28 01 1e bd}  //weight: 5, accuracy: High
        $x_5_3 = {e0 00 02 01 0b 01 0a 00 00 ee 03 00 00 e8}  //weight: 5, accuracy: High
        $x_1_4 = ".themida" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MB_2147835411_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MB!MTB"
        threat_id = "2147835411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {8b c8 8b 85 10 fc ff ff 33 d2 f7 f1 8b 85 0c fc ff ff 8a 0c 02 8b 85 10 fc ff ff 8b 95 08 fc ff ff 03 c3 32 0c 02 88 08 8d 85 14 fc ff ff 50}  //weight: 20, accuracy: High
        $x_5_2 = "sdfkjnsdfkjlnk jhsdbfjshd" ascii //weight: 5
        $x_20_3 = {8b c8 8b 85 28 f8 ff ff 33 d2 f7 f1 8b 85 20 f8 ff ff 8a 0c 02 8b 85 18 f8 ff ff 8b 95 1c f8 ff ff 32 0c 02 88 08 8d 85 2c f8 ff ff 50 8d 85 14 fc ff ff 50}  //weight: 20, accuracy: High
        $x_5_4 = "skjd38726287346wuyg23764t2gf76fgytr" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_5_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vidar_MPI_2147835460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MPI!MTB"
        threat_id = "2147835460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d f0 03 fa d3 ea 89 55 f8 8b 45 c8 01 45 f8 8b 45 f8 33 c7 31 45 fc 89 35 0c fa 42 00 8b 45 f4 89 45 e4 8b 45 fc 29 45 e4 8b 45 e4 89 45 f4 8d 45 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PJ_2147835493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PJ!MTB"
        threat_id = "2147835493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 08 8b 45 e4 01 45 08 03 f3 33 75 08 8d 45 f4 33 75 0c 56 50}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PK_2147835591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PK!MTB"
        threat_id = "2147835591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 d3 e8 89 7d e8 89 35 ?? ?? ?? ?? 03 45 ?? 33 c7 31 45 ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? ff 4d d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PL_2147835594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PL!MTB"
        threat_id = "2147835594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 8b 85 ?? ?? ?? ?? 33 d2 f7 f1 8b 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 8a 04 02 32 04 31 88 06}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 01 ba ff fe fe 7e 03 d0 83 f0 ?? 33 c2 83 c1 04 a9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PAI_2147836002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PAI!MTB"
        threat_id = "2147836002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c8 33 d2 8b c3 f7 f1 8b 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 8a 04 02 32 04 31 88 06 8d 85 ?? ?? ?? ?? 50 8d 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PAJ_2147836098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PAJ!MTB"
        threat_id = "2147836098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 8b 45 d8 03 45 ac 03 d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ec 31 18 6a 00 e8 ?? ?? ?? ?? 8b 55 e8 83 c2 04 03 c2 89 45 e8 8b 45 ec 83 c0 04 89 45 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PAK_2147836202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PAK!MTB"
        threat_id = "2147836202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d7 d3 ea 03 45 ?? 89 45 ?? 8b 45 e4 03 55 cc 03 c7 89 45 f0 8b 45 f0 31 45 fc 31 55 fc 89 35 ?? ?? ?? ?? 8b 45 f8 89 45 e8 8b 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_NEA_2147836370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.NEA!MTB"
        threat_id = "2147836370"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Tangram4.exe" ascii //weight: 10
        $x_5_2 = "Winapi.Qos" ascii //weight: 5
        $x_5_3 = "1.Pack$231$ActRec" ascii //weight: 5
        $x_5_4 = "D$HPkD$TdPV" ascii //weight: 5
        $x_1_5 = "ExtFloodFill" ascii //weight: 1
        $x_1_6 = "System.Win.TaskbarCore" ascii //weight: 1
        $x_1_7 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RB_2147836573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RB!MTB"
        threat_id = "2147836573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {39 10 75 08 8b 45 88 88 0c 38 eb 0a 8a 00 32 c1 8b 4d 88 88 04 39 ff 75 90 ff 45 94}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RB_2147836573_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RB!MTB"
        threat_id = "2147836573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {8b 55 f4 8a 0a 0f b6 d9 8d 84 85 ?? ?? ff ff 39 18 75 08 8b 45 fc 88 0c 10 eb 0a 8a 00 32 c1 8b 4d fc 88 04 11 ff 45 f8}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RB_2147836573_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RB!MTB"
        threat_id = "2147836573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 04 68 00 30 00 00 68 c0 41 c8 17 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {0f a2 89 06 89 5e 04 89 4e 08 89 56 0c 6a 01 ff d7 6a 01 ff d7 6a 01 ff d7 6a 01 ff d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MD_2147836827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MD!MTB"
        threat_id = "2147836827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 7d f0 8b 45 f4 8b 4d f8 03 c7 d3 ef 89 45 e4 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 7d d8 8b 45 e4 31 45 fc 33 7d fc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MD_2147836827_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MD!MTB"
        threat_id = "2147836827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2b c6 8b f8 33 d2 8b c1 f7 f7 8b 45 0c 8d 34 19 41 8a 14 02 8b 85 ec fd ff ff 32 14 30 88 16 3b 8d f0 fd ff ff 72}  //weight: 10, accuracy: High
        $x_1_2 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_3 = "GetLocaleInfoW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MD_2147836827_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MD!MTB"
        threat_id = "2147836827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 c8 76 d4 96 80 e2 15 69 87 ac da 47 b3 03 c6 54 69 11 ef 63 69 b9 ea 6c fb ce a6 fb dd 92 af 55 47 33 c6 26 e2 58 fc 5b bb ad d1 48 f0 98 e3}  //weight: 5, accuracy: High
        $x_5_2 = {d0 21 fe a6 5d ea f4 64 16 eb ba 9b 19 0d ba c2 73 e1 c5 99 2e 4c c2 9c 13 39 93 b7 29 21 05 a4 36 ea 28 a3 2b eb d4 b1 19 f3 10 c1 1e 05 cd 64}  //weight: 5, accuracy: High
        $x_2_3 = {e0 00 02 01 0b 01 50 00 00 b6 0f 00 00 54 03 00 00 00 00 00 e0 92 4e 00 00 20}  //weight: 2, accuracy: High
        $x_2_4 = {e0 00 02 01 0b 01 50 00 00 32 10 00 00 20 01 00 00 00 00 00 b8 4d 4b 00 00 20}  //weight: 2, accuracy: High
        $x_1_5 = ".themida" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vidar_PAL_2147837535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PAL!MTB"
        threat_id = "2147837535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 34 3b e8 ?? ?? ?? ?? 8b c8 33 d2 8b c3 f7 f1 8b 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 8a 04 02 32 04 31 88 06 8d 85 f4 fd ff ff 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GCO_2147838386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GCO!MTB"
        threat_id = "2147838386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 84 0d ?? ?? ?? ?? 88 84 15 ?? ?? ?? ?? 88 9c 0d ?? ?? ?? ?? 0f b6 94 15 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 0f b6 c3 03 d0 0f b6 c2 0f b6 84 05 ?? ?? ?? ?? 30 04 0e 46 8a 85 ?? ?? ?? ?? 3b f7 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PAY_2147839981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PAY!MTB"
        threat_id = "2147839981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 ff d6 8b c8 33 d2 8b c7 f7 f1 8b 85 ?? ?? ?? ?? 8a 0c 02 8b 95 ?? ?? ?? ?? 8d 04 17 8b 95 ?? ?? ?? ?? 32 0c 02 88 08 8d 85 ?? ?? ?? ?? 50 ff d6 8d 8d ?? ?? ?? ?? 51 ff d6 47 3b fb 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RA_2147840278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RA!MTB"
        threat_id = "2147840278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 fe 8b 45 ?? 0f be 0c 11 83 e1 ?? 81 e1 ?? ?? ?? ?? 31 c8 88 45 ?? 0f be 45 ?? 0f be 4d ?? 01 c8 88 c2 8b 45 ?? 8b 4d ?? 88 14 08 0f be 75 ?? 8b 45 ?? 8b 4d ?? 0f be 14 08 29 f2 88 14 08 8b 45 ?? 83 c0 01 89 45 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_CLS_2147840462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.CLS!MTB"
        threat_id = "2147840462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 d8 23 da c1 e8 ?? 33 04 ?? ?? ?? ?? ?? 83 c1 ?? 83 ef ?? 4e}  //weight: 5, accuracy: Low
        $x_5_2 = {0f b6 31 33 f0 23 f2 c1 e8 ?? 33 04 ?? ?? ?? ?? ?? 41 4f 75}  //weight: 5, accuracy: Low
        $x_1_3 = "GeroWallet" ascii //weight: 1
        $x_1_4 = "Pontem Wallet" ascii //weight: 1
        $x_1_5 = "Petra Wallet" ascii //weight: 1
        $x_1_6 = "Martian Wallet" ascii //weight: 1
        $x_1_7 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" ascii //weight: 1
        $x_1_8 = "Select * From Win32_OperatingSystem" ascii //weight: 1
        $x_1_9 = "Select * From AntiVirusProduct" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RF_2147840927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RF!MTB"
        threat_id = "2147840927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f8 8b 4d f4 8d 14 07 31 55 fc}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 10 89 45 fc 8b 45 0c 31 45 fc 8b 45 fc 8b 4d 08 89 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RF_2147840927_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RF!MTB"
        threat_id = "2147840927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 14 31 bf ?? ?? ?? ?? 2b de 2b f9 eb 03 8d 49 00 8a 04 13 8d 52 01 34 ?? 88 42 ff 4f 75 f2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RF_2147840927_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RF!MTB"
        threat_id = "2147840927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 01 88 06 88 11 0f b6 0e 0f b6 c2 03 c8 0f b6 c1 8b 8d ?? ?? ff ff 0f b6 84 05 ?? ?? ff ff 30 04 0f 47 3b bd 3c f0 ff ff 72 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_LK_2147841077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.LK!MTB"
        threat_id = "2147841077"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {81 ea 4e 44 27 29 0f be 45 fe 2b c2 88 45 fe 8b 4d dc 83 c1 01 89 4d dc 81 7d dc 94 14 00 00 7c d8}  //weight: 4, accuracy: High
        $x_1_2 = "HttpAnalyzerStdV7.exe" ascii //weight: 1
        $x_1_3 = "HTTPDebuggerUI.exe" ascii //weight: 1
        $x_1_4 = "Wireshark.exe" ascii //weight: 1
        $x_1_5 = "PROCEXP64.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vidar_GEV_2147841190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GEV!MTB"
        threat_id = "2147841190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "t.me/noktasina" ascii //weight: 1
        $x_1_2 = "95.217.152.87" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Cryptography" ascii //weight: 1
        $x_1_4 = "Select * From AntiVirusProduct" ascii //weight: 1
        $x_1_5 = "Select * From Win32_OperatingSystem" ascii //weight: 1
        $x_1_6 = "Exodus\\exodus.wallet" ascii //weight: 1
        $x_1_7 = "\\Downloads\\%s_%s.txt" ascii //weight: 1
        $x_1_8 = "\\screenshot.jpg" ascii //weight: 1
        $x_1_9 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_BD_2147841270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.BD!MTB"
        threat_id = "2147841270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {0f b6 d1 8d 04 32 0f b6 f0 8a 84 35 fc fe ff ff 88 84 3d fc fe ff ff 8b 45 fc 88 8c 35 fc fe ff ff 0f b6 8c 3d fc fe ff ff 03 ca 0f b6 c9 8a 8c 0d fc fe ff ff 30 0b 43 85 c0 75}  //weight: 4, accuracy: High
        $x_1_2 = "ShellExecuteW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_NEAC_2147841519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.NEAC!MTB"
        threat_id = "2147841519"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c6 f7 f1 8b 85 f0 fd ff ff 8a 0c 02 8b 95 ec fd ff ff 32 0c 3a 8d 85 f4 fd ff ff 50 88 0f}  //weight: 10, accuracy: High
        $x_2_2 = "Exodus Web3 Wallet" ascii //weight: 2
        $x_2_3 = "Select * From AntiVirusProduct" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RE_2147841523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RE!MTB"
        threat_id = "2147841523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 8b 15 ?? ?? ?? ?? 80 34 11 ?? 8d 04 11 8d 45 fc 50 ff 15 ?? ?? ?? ?? 8b 4d fc 3b 0d ?? ?? ?? ?? 72 db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GFE_2147841637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GFE!MTB"
        threat_id = "2147841637"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c1 99 8b 4d d0 8b 75 d4 33 c8 33 f2 88 0d ?? ?? ?? ?? 0f b7 85 6c ff ff ff 99 8b 4d ?? 8b 75 94 23 c8 23 f2 88 4d e7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PBB_2147841647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PBB!MTB"
        threat_id = "2147841647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? 83 0d ?? ?? ?? ?? ?? 8b c6 c1 e8 05 03 c3 03 ce 33 c8 31 4d 08 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 0c 8b 45 08 29 45 f8 8b 45 e4 29 45 fc ff 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GFF_2147841671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GFF!MTB"
        threat_id = "2147841671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c1 0f af c3 99 89 44 24 18 8b 44 24 68 89 54 24 1c 28 44 24 13 0f b6 44 24 15 0f af 44 24 3c 0f af 44 24 3c 89 44 24 3c 8b 44 24 18 a3 ?? ?? ?? ?? 8b 44 24 1c a3 ?? ?? ?? ?? a0 ?? ?? ?? ?? 04 ?? 30 44 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GFA_2147841812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GFA!MTB"
        threat_id = "2147841812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 f6 8d 64 24 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff d7 a1 ?? ?? ?? ?? 80 34 30 ?? 46 3b 35 ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GFB_2147841814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GFB!MTB"
        threat_id = "2147841814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 89 55 c8 8b 45 ?? 35 28 74 0d e0 8b 4d 94 83 f1 00 66 a3 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 33 c0 8b 4d 8c 03 55 88 13 c1 8b 0d ?? ?? ?? ?? 33 f6 03 ca 13 f0 89 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GFG_2147841823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GFG!MTB"
        threat_id = "2147841823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 55 f4 8b 45 08 01 d0 0f b6 18 8b 55 f4 8b 45 f0 01 d0 0f b6 08 8b 55 f4 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 f4 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GFK_2147841957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GFK!MTB"
        threat_id = "2147841957"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 00 0f b6 d0 8b 45 ec 0f b6 44 85 cb 0f b6 c0 89 54 24 04 89 04 24 e8 ?? ?? ?? ?? 89 c3 8b 45 ec 8d 14 85 00 00 00 00 8b 45 08 8d 0c 02 89 f2 31 da 8b 45 e8 01 c8 88 10}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_NEAD_2147842028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.NEAD!MTB"
        threat_id = "2147842028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 c1 41 81 f9 ff 00 00 00 7c f5 32 c2 34 0f 88 04 1e 46 3b 75 0c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_CAR_2147842145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.CAR!MTB"
        threat_id = "2147842145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 f1 f0 ad 0a ff 75 f0 e8 ?? ?? ?? ?? 59 59 a3 78 c0 40 00 e8 ?? ?? ?? ?? 68 64 18 2d 07 ff 75 f0 e8 ?? ?? ?? ?? 59 59 a3 7c c0 40 00 e8 ?? ?? ?? ?? 68 b5 3d 2c 06 ff 75 f0 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_CAS_2147842148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.CAS!MTB"
        threat_id = "2147842148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f3 a4 81 f1 ?? ?? ?? ?? c1 c7 ?? 43 29 ?? ?? ?? ?? ?? 29 ?? ?? ?? ?? ?? 4f 87 d1 f7 d8}  //weight: 5, accuracy: Low
        $x_5_2 = {f7 d8 87 d1 47 89 ?? ?? ?? ?? ?? 4b c1 cf 1d 81 ?? ?? ?? ?? ?? ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GFL_2147842192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GFL!MTB"
        threat_id = "2147842192"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 89 85 ?? ?? ?? ?? 8a 8d ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 84 c9 66 8b 8d ?? ?? ?? ?? 0f 94 c2 f7 d0 33 d0 0f bf c1 03 d0 f7 da 1b d2 42 89 95}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RDD_2147842202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RDD!MTB"
        threat_id = "2147842202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b f8 33 f6 c6 04 1f 00 85 db 74 36 8b 45 08 2b c7 89 45 08 8b 45 0c 8d 48 01 8a 10 40 84 d2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GFO_2147842224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GFO!MTB"
        threat_id = "2147842224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 e8 40 89 45 e8 83 7d ?? ?? 73 ?? 0f be 85 ?? ?? ?? ?? 8b 4d e4 03 4d e8 0f be 09 33 c8 8b 45 e4 03 45 e8 88 08 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GFP_2147842439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GFP!MTB"
        threat_id = "2147842439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c8 33 d2 8b c7 f7 f1 8b 85 ?? ?? ?? ?? 83 c4 04 8a 0c 02 8b 95 ?? ?? ?? ?? 8d 04 17 8b 95 ?? ?? ?? ?? 32 0c 02 88 08}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PBC_2147842924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PBC!MTB"
        threat_id = "2147842924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 14 33 44 24 10 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 2b f0 89 44 24 14 8b c6 c1 e0 04 89 44 24 10 8b 44 24 24 01 44 24 10 8b ce c1 e9 05 03 4c 24 28 8d 04 33 31 44 24 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PBD_2147842998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PBD!MTB"
        threat_id = "2147842998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? 03 c5 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 10 33 4c 24 18 8d 44 24 28 89 4c 24 10 e8 ?? ?? ?? ?? 8b 44 24 38 29 44 24 14 83 ef 01 8b 4c 24 28 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RL_2147843118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RL!MTB"
        threat_id = "2147843118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 c7 04 24 04 00 00 00 8b 44 24 08 83 2c 24 04 90 01 04 24 8b 04 24 31 01 59 c2 04 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GHC_2147843868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GHC!MTB"
        threat_id = "2147843868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c8 33 d2 8b c7 f7 f1 8b 85 ?? ?? ?? ?? 8a 0c 02 8b 95 ?? ?? ?? ?? 32 0c 1a 8d 85 ?? ?? ?? ?? 50 88 0b ff d6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MKV_2147844281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MKV!MTB"
        threat_id = "2147844281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 c8 88 45 ?? 0f b6 45 ?? 0f b6 84 05 ?? ?? ?? ?? 88 45 ?? 8b 55 ?? 8b 45 ?? 01 d0 0f b6 00 32 45 ?? 88 45 ?? 8b 55 ?? 8b 45 ?? 01 c2 0f b6 45 ?? 88 02 83 45 ?? ?? 8b 45 ?? 3b 45 ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GHL_2147844530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GHL!MTB"
        threat_id = "2147844530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 d3 e8 03 45 ?? 89 45 ?? 33 45 ?? 31 45 ?? 8b 45 ?? 29 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MKZ_2147844693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MKZ!MTB"
        threat_id = "2147844693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 52 89 54 24 ?? ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 00 8d 54 24 ?? 52 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 31 7c 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 15 ?? ?? ?? ?? 81 fa ?? ?? ?? ?? 74 ?? 81 c3 ?? ?? ?? ?? ff 4c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MKB_2147844795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MKB!MTB"
        threat_id = "2147844795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c8 c1 e8 08 81 e1 ff 00 00 00 33 04 8d 08 82 44 00 81 e2 fd ff 00 00 89 46 38 8b 4e 3c 83 ca 02 8b c2 83 f0 01 0f af c2 c1 e8 08 32 45 08 43 88 44 0b ff 3b 5d 0c 72 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PBG_2147845241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PBG!MTB"
        threat_id = "2147845241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 04 80 8b 15 ?? ?? ?? ?? 8b 44 c2 10 a3 30 ec 45 00 a1 2c ec 45 00 3b 05 30 ec 45 00 73 ?? a1 30 ec 45 00 31 05 2c ec 45 00 a1 2c ec 45 00 31 05 30 ec 45 00 a1 30 ec 45 00 31 05 2c ec 45 00 6a 04 68 00 10 00 00 a1 2c ec 45 00 50 8b 07 8d 04 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MNN_2147845291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MNN!MTB"
        threat_id = "2147845291"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d0 69 c9 05 84 08 08 41 89 4e 34 c1 e9 18 33 c8 c1 e8 08 81 e1 ff 00 00 00 33 04 8d 50 82 44 00 81 e2 fd ff 00 00 89 46 38 8b 4e 3c 83 ca 02 8b c2 83 f0 01 0f af c2 c1 e8 08 32 45 08 43 88 44 0b ff 3b 5d 0c 72 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RPY_2147845328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RPY!MTB"
        threat_id = "2147845328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 30 06 02 00 59 8d 85 30 f7 ff ff 50 e8 23 06 02 00 59 8d 85 30 f7 ff ff 50 e8 16 06 02 00 59 8d 85 30 f7 ff ff 50 e8 09 06 02 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RPY_2147845328_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RPY!MTB"
        threat_id = "2147845328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 99 f7 7d 0c 03 55 0c 8b c2 99 f7 7d 0c 8b c2 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 d8 61 c6 45 d9 67 c6 45 da 6a c6 45 db 76 c6 45 dc 33 c6 45 dd 76 c6 45 de 33 c6 45 df 6a c6 45 e0 76}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_BTC_2147845574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.BTC!MTB"
        threat_id = "2147845574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? 03 c3 03 ce 31 4c 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 4f 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_VID_2147845723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.VID!MTB"
        threat_id = "2147845723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c8 c1 e8 08 81 e1 ff 00 00 00 33 04 8d b8 83 44 00 81 e2 fd ff 00 00 89 46 38 8b 4e 3c 83 ca 02 8b c2 83 f0 01 0f af c2 c1 e8 08 32 45 08 43 88 44 0b ff 3b 5d 0c 72 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GHW_2147845749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GHW!MTB"
        threat_id = "2147845749"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6b e9 5c 3d 0f be 45 99 0f be 4d 9a 2b c1 88 45 99 0f be 45 e7 99 35 ?? ?? ?? ?? 81 f2 ?? ?? ?? ?? 66 a3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GHW_2147845749_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GHW!MTB"
        threat_id = "2147845749"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 84 3c ?? ?? ?? ?? 88 84 34 ?? ?? ?? ?? 88 8c 3c ?? ?? ?? ?? 0f b6 84 34 ?? ?? ?? ?? 03 c2 0f b6 c0 0f b6 84 04 ?? ?? ?? ?? 30 83 ?? ?? ?? ?? 43 81 fb 00 56 05 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GHZ_2147845833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GHZ!MTB"
        threat_id = "2147845833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 8a a5 08 00 c7 45 ?? 8d 00 00 00 c7 45 ?? f0 d0 05 00 c7 45 ?? 01 14 00 00 c7 45 ?? 79 00 00 00 c7 45 ?? 15 00 00 00 b8 ?? ?? ?? ?? 89 45 c0 6a 40 68 00 10 00 00 8b 45 f8 8b 10 ff 12}  //weight: 10, accuracy: Low
        $x_1_2 = "y435uy2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GIA_2147845857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GIA!MTB"
        threat_id = "2147845857"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4d 08 8b c6 83 e0 03 46 83 c4 0c 8a 04 08 30 07 8b 45 f8 3b 75 fc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_REW_2147846109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.REW!MTB"
        threat_id = "2147846109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c8 c1 e8 08 81 e1 ff 00 00 00 33 04 8d 18 5b 44 00 81 e2 fd ff 00 00 89 46 38 8b 4e 3c 83 ca 02 8b c2 83 f0 01 0f af c2 c1 e8 08 32 45 08 43 88 44 0b ff 3b 5d 0c 72 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GID_2147846153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GID!MTB"
        threat_id = "2147846153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4d e8 8b 55 ec 8b 45 f0 8b 75 f4 33 c8 33 d6 8b 45 e8 8b 75 ec 03 c1 13 f2 89 45 e8 89 75 ec}  //weight: 10, accuracy: High
        $x_10_2 = {f7 d6 33 ce 03 d1 03 c2 a2 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? 8b 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GIE_2147846169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GIE!MTB"
        threat_id = "2147846169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 44 3d 10 88 44 35 10 88 4c 3d 10 0f b6 44 35 10 03 c2 0f b6 c0 8a 44 05 10 30 83 ?? ?? ?? ?? 43 81 fb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_CLR_2147846247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.CLR!MTB"
        threat_id = "2147846247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://95.216.164.28:80" ascii //weight: 1
        $x_1_2 = "softokn3.dll" ascii //weight: 1
        $x_1_3 = "nss3.dll" ascii //weight: 1
        $x_1_4 = "mozglue.dll" ascii //weight: 1
        $x_1_5 = "freebl3.dll" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ascii //weight: 1
        $x_1_7 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" ascii //weight: 1
        $x_1_8 = "Select * From Win32_OperatingSystem" ascii //weight: 1
        $x_1_9 = "Select * From AntiVirusProduct" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_EH_2147846343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.EH!MTB"
        threat_id = "2147846343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AEPNrIoFXmz" ascii //weight: 1
        $x_1_2 = "LTFfLbCPouV" ascii //weight: 1
        $x_1_3 = "LHhDBBjijNOth" ascii //weight: 1
        $x_1_4 = "rPEuPuigXnSgrvMqHn" ascii //weight: 1
        $x_1_5 = "EHFpPVJcEyhjxhUVEKnhclGFDQALNHHItOz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_CAF_2147846522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.CAF!MTB"
        threat_id = "2147846522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IPHPQG41NB1UF3U" ascii //weight: 1
        $x_1_2 = "WDKFOBU9G62YDMC2U9LUDZNP5" ascii //weight: 1
        $x_1_3 = "NKOWSBTKI5JNJCINQA6IV" ascii //weight: 1
        $x_1_4 = "V650X8AZJI3K" ascii //weight: 1
        $x_1_5 = "EW4TZJKN96EU0M" ascii //weight: 1
        $x_1_6 = "checkpointed" ascii //weight: 1
        $x_1_7 = "wal_autocheckpoint" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_NBT_2147846907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.NBT!MTB"
        threat_id = "2147846907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d0 69 c9 05 84 08 08 41 89 4e 34 c1 e9 18 33 c8 c1 e8 08 81 e1 ff 00 00 00 33 04 8d 90 5c 44 00 81 e2 fd ff 00 00 89 46 38 8b 4e 3c 83 ca 02 8b c2 83 f0 01 0f af c2 c1 e8 08 32 45 08 43 88 44 0b ff 3b 5d 0c 72 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GJE_2147846939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GJE!MTB"
        threat_id = "2147846939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 f8 33 d2 f7 75 fc 52 8b 4d 10 e8 ?? ?? ?? ?? 0f be 10 8b 45 08 03 45 f8 0f b6 08 33 ca 8b 55 08 03 55 f8 88 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MVU_2147846972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MVU!MTB"
        threat_id = "2147846972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 89 46 04 89 85 5c fb ff ff c1 e8 18 33 c7 25 ff 00 00 00 c1 ef 08 89 0e 33 3c 85 b0 5c 44 00 8b c7 8b bd 60 fb ff ff 8b df 83 f3 01 0f af df c1 eb 08 32 9d 68 fb ff ff 89 46 08 88 5c 15 db 89 95 60 fb ff ff 83 fa 0c 0f 8c dd fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_JMS_2147847818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.JMS!MTB"
        threat_id = "2147847818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 69 c9 ?? ?? ?? ?? 41 89 4e 34 c1 e9 18 33 c8 c1 e8 08 81 e1 ff 00 00 00 33 04 8d 88 6d 44 00 81 e2 fd ff 00 00 89 46 38 8b 4e 3c 83 ca 02 8b c2 83 f0 01 0f af c2 c1 e8 08 32 45 08 43 88 44 0b ff 3b 5d 0c 72 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GJM_2147848363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GJM!MTB"
        threat_id = "2147848363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 10 8b 85 ?? ?? ?? ?? 32 d1 88 14 18 8b 8d ?? ?? ?? ?? ff 85 ?? ?? ?? ?? 51 43 e8 ?? ?? ?? ?? 83 c4 ?? 39 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GJN_2147848366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GJN!MTB"
        threat_id = "2147848366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2b c6 8b f8 33 d2 8b c1 f7 f7 8b 44 24 18 8d 34 19 41 8a 14 02 8b 44 24 1c 32 14 30 88 16 3b cd}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_BK_2147848403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.BK!MTB"
        threat_id = "2147848403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {33 d2 8b c7 f7 f1 8b 85 [0-4] 8a 0c 02 8b 95 [0-4] 32 0c 1a 8d 85 [0-4] 50 88 0b e8 [0-4] 83 c4 04 8d 8d [0-4] 51 ff d6 8b 9d [0-3] ff 47 3b bd [0-4] 72}  //weight: 3, accuracy: Low
        $x_2_2 = {53 56 6a 04 68 00 30 00 00 68 c0 41 c8 17 6a 00 ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PAA_2147848527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PAA!MTB"
        threat_id = "2147848527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "fuck u" wide //weight: 1
        $x_1_2 = "pix-fix.net" ascii //weight: 1
        $x_1_3 = "wo.php?stub=" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_5 = "gate1.php?a={bbed3e55656ghf02-0b41-11e3-8249}id=" ascii //weight: 1
        $x_1_6 = "cmd.exe /c start /B powershell -windowstyle hidden -command" ascii //weight: 1
        $x_1_7 = {26 7b 24 74 3d 27 [0-16] 69 [0-16] 65 78 [0-32] 40 28 6e [0-16] 65 77 [0-16] 2d [0-16] 6f 62 [0-16] 6a 65 63 [0-16] 74 20 4e [0-16] 65 74 [0-16] 2e 57 [0-16] 65 62 [0-16] 43 6c [0-16] 69 65 [0-16] 6e 74 [0-16] 29 2e [0-16] 55 70 [0-16] 6c 6f 61 [0-16] 64 [0-16] 53 74 [0-16] 72 69 [0-16] 6e 67 28 [0-16] 27 27 68 [0-16] 74 [0-16] 74 70 [0-16] 3a [0-16] 2f 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GHO_2147848534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GHO!MTB"
        threat_id = "2147848534"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b7 1b 89 e8 05 04 00 00 00 33 18 81 c3 a6 88 2d 68 89 e8 05 04 00 00 00 31 18 81 e3 ff ff 00 00 c1 e3 02 01 d9 8b 31 89 ef 81 c7 dc 00 00 00 8b 3f 81 c7 09 00 00 00 8b 0f 89 ef 81 c7 dc 00 00 00 01 0f ff e6}  //weight: 10, accuracy: High
        $x_1_2 = ".winlice" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PBH_2147848549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PBH!MTB"
        threat_id = "2147848549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 c7 04 24 ?? ?? ?? ?? 8b 44 24 08 83 2c 24 04 01 04 24 8b 04 24 31 01 59}  //weight: 1, accuracy: Low
        $x_2_2 = {57 8d 4c 24 ?? 89 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 44 24 18 33 44 24 14 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 2b f0 89 44 24 18 8b c6 c1 e0 04 89 44 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PBI_2147848679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PBI!MTB"
        threat_id = "2147848679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 00 00 00 00 33 d2 51 b9 08 00 00 00 d1 c0 8a fc 8a e6 d1 cb 49 75 ?? 8b c3 59}  //weight: 1, accuracy: Low
        $x_1_2 = {8b cf 83 e1 03 75 ?? 46 0f b6 5e 04 ba 11 00 00 00 d3 c2 23 d3 ac 0a c2 aa ff 4d 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_FKI_2147849248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.FKI!MTB"
        threat_id = "2147849248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f9 83 bd 04 fc ff ff ?? 0f 43 b5 ?? ?? ?? ?? f7 e1 d1 ea 8d 04 52 2b c8 8a 84 0d ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 32 07 88 04 0e 41 89 8d ?? ?? ?? ?? 3b 8d ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_BHN_2147849414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.BHN!MTB"
        threat_id = "2147849414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 89 44 24 14 8b 44 24 34 01 44 24 14 8b 44 24 24 31 44 24 10 8b 4c 24 10 8b 54 24 14 51 52 8d 44 24 ?? 50 e8 ?? ?? ?? ?? 8b 4c 24 10 8d 44 24 2c ?? ?? ?? ?? ff 8d 44 24 28 e8 ?? ?? ?? ?? 83 6c 24 ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_JNB_2147849479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.JNB!MTB"
        threat_id = "2147849479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d0 69 c9 05 84 08 08 41 89 4e 34 c1 e9 18 33 c8 c1 e8 08 81 e1 ff 00 00 00 33 04 8d d0 6d 44 00 81 e2 fd ff 00 00 89 46 38 8b 4e 3c 83 ca 02 8b c2 83 f0 01 0f af c2 c1 e8 08 32 45 08 43 88 44 0b ff 3b 5d 0c 72 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GKH_2147849585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GKH!MTB"
        threat_id = "2147849585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 8c 3d ?? ?? ?? ?? 03 ca 0f b6 c9 8a 8c 0d ?? ?? ?? ?? 30 08 40 89 45 fc 83 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_NNV_2147849602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.NNV!MTB"
        threat_id = "2147849602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 f1 66 f5 8d ad ?? ?? ?? ?? 32 d3 80 c2 ?? f6 d2 66 0f be cc 1b ce 0f b7 cf 80 c2 e8 66 c1 d9 ?? d0 c2 80 c2 ?? f6 d2 32 da 89 04 14}  //weight: 5, accuracy: Low
        $x_1_2 = "FTiNvS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_NVD_2147849605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.NVD!MTB"
        threat_id = "2147849605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 65 44 43 00 47 ?? 49 33 32 2e 64 6c 6c 00 00 00 47 ?? 74 44 65 76 69 63 65 ?? 61 70 73 00 6f ?? 65 33 32 2e 64 6c 6c 00 00 00 43 ?? 43}  //weight: 5, accuracy: Low
        $x_1_2 = "pwpxx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_NVD_2147849605_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.NVD!MTB"
        threat_id = "2147849605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 08 05 36 2d 40 00 89 45 f8 b9 ?? ?? ?? ?? 6b d1 00 8b 45 f8 8b 0c 10 89 4d f4 8b 55 f4 c1 e2 02 52 b8 ?? ?? ?? ?? d1 e0 03 45 f8 50 8b 4d 0c 51 e8 ?? ?? ?? ?? 83 c4 0c ba ?? ?? ?? ?? c1 e2 00 8b 45 f8 8b 0c 10 89 4d f0}  //weight: 5, accuracy: Low
        $x_1_2 = "AHf94Au" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MBEV_2147849645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MBEV!MTB"
        threat_id = "2147849645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 fc 83 c2 01 89 55 fc 8b 45 fc 3b 45 0c 73 36 8b 4d f4 03 4d fc 8b 55 08 03 55 f8 8a 02 88 01 8b 4d f8 83 c1 01 89 4d f8 8b 45 fc 33 d2 f7 35 ?? ?? ?? ?? 85 d2}  //weight: 1, accuracy: Low
        $x_1_2 = {40 8b 55 10 03 95 ?? ?? ?? ?? 0f b6 0a 33 8c 85 ?? ?? ?? ?? 8b 55 10 03 95 ?? ?? ?? ?? 88 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RTG_2147849808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RTG!MTB"
        threat_id = "2147849808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 8b 85 dc fe ff ff 33 d2 f7 f1 52 8d 8d ec fe ff ff e8 57 eb ff ff 0f b6 10 33 f2 8b 85 dc fe ff ff 0f b6 88 ?? ?? ?? ?? 33 ce 8b 95 dc fe ff ff 88 8a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RDH_2147849902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RDH!MTB"
        threat_id = "2147849902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 44 24 14 8b 44 24 24 31 44 24 10 8b 4c 24 10 33 4c 24 14 8d 44 24 2c 89 4c 24 10}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PBK_2147850023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PBK!MTB"
        threat_id = "2147850023"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 c1 ce 08 2b ce 33 c6 f7 d3 c1 c2 11 33 c1 81 ef ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 33 c1 c1 ca 11 f7 d3 33 c6 03 ce c1 c6 08 49 33 c7 2b cc 81 f7 ?? ?? ?? ?? 46 f7 d1 c1 c7 13 4a 4a 87 c6 c1 c7 11 33 d9 49}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PBJ_2147850024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PBJ!MTB"
        threat_id = "2147850024"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d8 81 e3 ?? ?? ?? ?? 8b 94 9d ?? ?? ?? ?? 89 94 bd ?? ?? ?? ?? 89 84 9d ?? ?? ?? ?? 8b 8c bd ?? ?? ?? ?? 03 c1 25 ff 00 00 80 8b 95 ?? ?? ?? ?? 8a 0a 0f b6 d1 39 94 85 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 8d 84 85 ?? ?? ?? ?? 8a 00 32 c1 8b 8d ?? ?? ?? ?? 88 04 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RJ_2147850107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RJ!MTB"
        threat_id = "2147850107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 08 03 55 f8 89 55 f0 8b 45 f0 89 45 f4 8b 4d f4 8b 11 33 55 10 8b 45 f4 89 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_CRI_2147850775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.CRI!MTB"
        threat_id = "2147850775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 f7 7d 94 8b 85 78 ff ff ff 0f be 0c 10 8b 55 90 03 55 98 0f be 02 33 c1 8b 4d 90 03 4d 98 88 01 eb c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GNI_2147851086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GNI!MTB"
        threat_id = "2147851086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4d 08 03 8d ?? ?? ?? ?? 8a 09 88 08 ?? ?? 8b 45 08 03 85 ?? ?? ?? ?? 0f b6 00 8b 8d ?? ?? ?? ?? 33 84 8d ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 88 01}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_DAR_2147851116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.DAR!MTB"
        threat_id = "2147851116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {88 0c 10 0f b6 55 fd 8b 45 f8 8a 4d ff 88 0c 10 0f b6 55 fe 8b 45 f8 0f b6 0c 10 0f b6 55 fd 8b 45 f8 0f b6 14 10 03 ca 81 e1 ff 00 00 00 8b 45 f8 0f b6 0c 08 8b 55 08 03 55 f4 0f b6 02 33 c1 8b 4d 08 03 4d f4 88 01 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_DAS_2147851127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.DAS!MTB"
        threat_id = "2147851127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 02 8b 45 c4 03 45 94 03 45 ec 03 45 9c 89 45 a4 6a 00 e8 [0-4] 8b 55 a4 2b d0 8b 45 d4 31 10 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AMS_2147851296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AMS!MTB"
        threat_id = "2147851296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 44 24 [0-40] 30 04 29 45 3b 6b 04 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AMS_2147851296_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AMS!MTB"
        threat_id = "2147851296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 a4 2b d0 8b 45 d4 31 10 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GNL_2147851323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GNL!MTB"
        threat_id = "2147851323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c8 33 d2 8b c6 f7 f1 8b 85 ?? ?? ?? ?? 8a 0c 02 8b 95 ?? ?? ?? ?? 32 0c 1a 8d 85 ?? ?? ?? ?? 50 88 0b}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RAN_2147851697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RAN!MTB"
        threat_id = "2147851697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 ca 0f b6 c9 89 4d f8 8b 4c 88 08 89 4c b8 08 02 ca 89 7d ?? 8b 7d f8 0f b6 c9 89 54 b8 08 89 55 fc 0f b6 54 88 08 30 56 04 83 c6 06 ff 4d f0 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GNR_2147851944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GNR!MTB"
        threat_id = "2147851944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 08 03 85 ?? ?? ?? ?? 0f be 18 ff 75 0c e8 ?? ?? ?? ?? 59 8b c8 8b 85 ?? ?? ?? ?? 33 d2 f7 f1 8b 45 0c 0f be 04 10 33 d8 8b 85 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 88 18 8d 85 ?? ?? ?? ?? 50}  //weight: 10, accuracy: Low
        $x_1_2 = "K4PCHOXE2JJBAJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GNS_2147852045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GNS!MTB"
        threat_id = "2147852045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c2 8b d8 8b 85 ?? ?? ?? ?? 8d 0c 07 33 d2 8b c7 f7 f3 8b 5d 0c 8b 85 ?? ?? ?? ?? 8a 14 1a 32 14 08 88 11 8d 8d ?? ?? ?? ?? 51 ff d6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_NIV_2147852426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.NIV!MTB"
        threat_id = "2147852426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 cf 8d 4d ?? 89 f2 e8 14 14 00 00 39 df 74 ?? 0f b7 07 8d 4f ?? 89 c2 0f b7 f0 81 e2}  //weight: 5, accuracy: Low
        $x_1_2 = "cmd/Cicacls/setintegritylevelhigh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MEE_2147852508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MEE!MTB"
        threat_id = "2147852508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b c2 8b f8 8b 85 7c ec ff ff 8d 0c 06 33 d2 8b c6 f7 f7 8b 45 0c 8a 14 02 8b 85 78 ec ff ff 32 14 08 88 11 8d 8d 80 ec ff ff 51 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_BKL_2147852564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.BKL!MTB"
        threat_id = "2147852564"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 4c 24 1c 8b c6 c1 e8 05 03 44 24 24 c7 05 40 1b 2d 02 00 00 00 00 33 c1 8d 0c 33 33 c1 2b f8 8b d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_HT_2147852947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.HT!MTB"
        threat_id = "2147852947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 4c 24 20 8b d0 c1 ea 05 03 54 24 24 03 c5 33 d1 33 d0 2b fa 8b cf c1 e1 04 81 3d 34 28 35 02 8c 07 00 00 c7 05 e0 87 34 02 00 00 00 00 89 4c 24 10}  //weight: 1, accuracy: High
        $x_1_2 = {33 f3 31 74 24 10 8b 44 24 10 29 44 24 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RD_2147853120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RD!MTB"
        threat_id = "2147853120"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 95 7c ec ff ff 2b c6 8d 34 11 8b f8 33 d2 8b c1 f7 f7 8b 45 0c 41 8a 14 02 8b 85 ?? ?? ?? ?? 32 14 30 88 16 3b cb 72 ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_IND_2147853367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.IND!MTB"
        threat_id = "2147853367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 89 4e 34 c1 e9 18 33 c8 c1 e8 08 81 e1 ff 00 00 00 33 04 8d c0 ca 44 00 81 e2 fd ff 00 00 89 46 38 8b 4e 3c 83 ca 02 8b c2 83 f0 01 0f af c2 c1 e8 08 32 45 08 43 88 44 0b ff 3b 5d 0c 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RZ_2147888284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RZ!MTB"
        threat_id = "2147888284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 37 83 c4 0c 34 74 8b cb 04 59 88 04 37 6a 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RZ_2147888284_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RZ!MTB"
        threat_id = "2147888284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 4c 24 28 8b d0 c1 ea 05 03 54 24 20 03 c5 33 d1 33 d0 2b fa}  //weight: 1, accuracy: High
        $x_1_2 = {33 f3 31 74 24 10 8b 44 24 10 29 44 24 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_HR_2147888628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.HR!MTB"
        threat_id = "2147888628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d0 c1 ea 05 03 54 24 24 03 cd 33 d1 03 c6 33 d0 2b fa}  //weight: 1, accuracy: High
        $x_1_2 = {33 f3 31 74 24 14 8b 44 24 14 29 44 24 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AB_2147888877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AB!MTB"
        threat_id = "2147888877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7d f4 8b 4d f8 8d 04 3b d3 ef 89 45 e0 c7 05 ec bc 49 02 ee 3d ea f4 03 7d e4 8b 45 e0 31 45 fc 33 7d fc}  //weight: 1, accuracy: High
        $x_1_2 = "robubizeki_jo.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AB_2147888877_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AB!MTB"
        threat_id = "2147888877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 c1 e9 05 03 4c 24 2c 8b d0 c1 e2 04 03 54 24 28 03 c7 33 ca 33 c8 2b f1 8b ce c1 e1 04 c7 05 ?? ?? ?? ?? 00 00 00 00 89 4c 24 14 8b 44 24 30 01 44 24 14 81 3d ?? ?? ?? ?? be 01 00 00 8d 1c 37 75 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_ASAF_2147888919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.ASAF!MTB"
        threat_id = "2147888919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 03 85 ?? ?? ff ff 8a 08 88 0a eb ?? 8b 55 08 03 95 ?? ?? ff ff 0f b6 02 8b 8d ?? ?? ff ff 33 84 8d ?? ?? ff ff 8b 95 ?? ?? ff ff 03 95 ?? ?? ff ff 88 02 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PR_2147888933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PR!MTB"
        threat_id = "2147888933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 4c 24 20 8b f0 c1 ee 05 03 74 24 2c 03 c5 33 f1 33 f0 2b fe}  //weight: 1, accuracy: High
        $x_1_2 = {33 f3 31 74 24 14 8b 44 24 14 29 44 24 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GMH_2147889364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GMH!MTB"
        threat_id = "2147889364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".themida" ascii //weight: 1
        $x_1_2 = "ejkIinpzqvx" ascii //weight: 1
        $x_1_3 = "chmosdik" ascii //weight: 1
        $x_1_4 = "Vouwhdhj" ascii //weight: 1
        $x_1_5 = ".boot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_ASAG_2147889508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.ASAG!MTB"
        threat_id = "2147889508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Select * From AntiVirusProduct" wide //weight: 1
        $x_1_2 = "68E2GVZRRSQVXXIXWUQWPCC3G1HC3WWY" ascii //weight: 1
        $x_1_3 = "G5X09EUH00Z9K4T7Q5K69LXL9UMVX" ascii //weight: 1
        $x_1_4 = "t.me/odyssey_tg" ascii //weight: 1
        $x_1_5 = "CC\\%s_%s.txt" ascii //weight: 1
        $x_1_6 = "kmhcihpebfmpgmihbkipmjlmmioameka" ascii //weight: 1
        $x_1_7 = "2HKCJPU7WHTAC95AFFW0QL" ascii //weight: 1
        $x_1_8 = "Wallets\\Chia Wallet\\%s\\%s" ascii //weight: 1
        $x_1_9 = "les\\9375CFF0413111d3" ascii //weight: 1
        $x_1_10 = "LWUM172YEOPOVUS2K0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MBIP_2147890025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MBIP!MTB"
        threat_id = "2147890025"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pivegukidopapetodenufirovanuko" ascii //weight: 1
        $x_1_2 = "luyucucihizaworumokulidofiki pevexipiwapivoreduwikozojemodat vukociku" ascii //weight: 1
        $x_1_3 = "leyimuzubucedab yadijawupadeseliherofuvinutobizi vunetekimirepogexic" ascii //weight: 1
        $x_1_4 = "yonaxumoy gakeyuwujosepafusogigawehe fenitedinugarehi wavedujudezunanimuze" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_CCAQ_2147890130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.CCAQ!MTB"
        threat_id = "2147890130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c7 d3 ef 89 45 e0 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 7d e4 8b 45 e0 31 45 fc 33 7d fc 81 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_ME_2147890281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.ME!MTB"
        threat_id = "2147890281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 85 0c ff ff ff 89 85 0c ff ff ff 8b 85 10 ff ff ff 33 85 08 ff ff ff 89 85 08 ff ff ff c6 85 b9 fd ff ff 00 8b 85 d4 fd ff ff 8b 40 54 89 85 14 ff ff ff 8b 85 14 ff ff ff 03 85 f0 fe ff ff 89 85 18 ff ff ff 8b 85 18 ff ff ff 8b 00 8b 95 08 ff ff ff 3b c2 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MBJA_2147891384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MBJA!MTB"
        threat_id = "2147891384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ouqepbqgrrlwgrtvtworwlrzjyovleksdliqhhpitsakcsytwgqxgurftvbwcaeafxgruaoavsgcbtcjfzsvtkirjwainfne" ascii //weight: 1
        $x_1_2 = "nwqbzjzpclbzkrckecmdcnuioxblrsmdyvyftosn" ascii //weight: 1
        $x_1_3 = {67 62 63 69 79 6e 78 61 6e 70 72 72 6d 69 73 75 72 65 6a 72 69 73 6e 75 67 66 6c 76 70 70 73 61 64 77 79 6c 61 63 66 74 74 6e 6e 6b 65 69 63 74 67 79 7a 6a 61 7a 00 00 67 79 70 64 63 79 68 6d 72 6a 68 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_NDR_2147891422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.NDR!MTB"
        threat_id = "2147891422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e8 f5 08 ff ff 0f b6 45 ?? 8b 4d f4 8a 55 ?? 84 54 01 1d 75 1e 83 7d 10 ?? 74 12 8b 4d f0 8b 89 ?? ?? ?? ?? 0f b7 04 41 23 45 ?? eb 02 33 c0 85 c0 74 03 33 c0 40}  //weight: 5, accuracy: Low
        $x_1_2 = "odyssey_tg" ascii //weight: 1
        $x_1_3 = "chia\\mainnet\\wallet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_C_2147891490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.C!MTB"
        threat_id = "2147891490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {88 54 24 12 0f b6 51 ?? 88 54 24 13 8a 51 ?? 89 5c 24 14 83 44 24 14 ?? 89 5c 24 18 83 44 24 18 ?? 8b 4c 24 14 8a da d2 e3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_C_2147891490_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.C!MTB"
        threat_id = "2147891490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 19 30 c3 0f b6 f3 c1 e8 08 33 04 b5 74 e6 41 00 0f b6 59 01 30 c3 0f b6 f3 c1 e8 08 33 04 b5 74 e6 41 00 0f b6 59 02 30 c3 0f b6 f3 c1 e8 08 33 04 b5 74 e6 41 00 0f b6 59 03 30 c3 0f b6 f3 c1 e8 08 33 04 b5 74 e6 41 00}  //weight: 2, accuracy: High
        $x_1_2 = {8b 4c 24 04 68 d4 f7 41 00 e8 e8 85 00 00 8d 73 6c 8d 7b 04 8d 4b 30 e8 5a 86 00 00 8d 4b 1c e8 52 86 00 00 8d 4b 10 e8 4a 86 00 00 89 f9 e8 43 86 00 00 89 f1 e8 3c 86 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "\"id\":1,\"method\":\"Storage.getCookies\"" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\monero-project\\monero-core" ascii //weight: 1
        $x_1_5 = "wallet_path" ascii //weight: 1
        $x_1_6 = "Software\\Martin Prikryl\\WinSCP 2\\Sessions" ascii //weight: 1
        $x_1_7 = "https://t.me/l793oy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_CCBQ_2147891860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.CCBQ!MTB"
        threat_id = "2147891860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 55 d8 8b 45 f0 31 45 fc 33 55 fc 81 3d}  //weight: 1, accuracy: High
        $x_1_2 = {d3 e8 03 45 d4 8b c8 8b 45 f0 31 45 fc 31 4d fc 2b 5d fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_CCBR_2147891865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.CCBR!MTB"
        threat_id = "2147891865"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b c6 f7 f1 8b 45 ?? 8a 0c 02 8b 55 ?? 8d 04 1e 32 0c 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_NVV_2147892393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.NVV!MTB"
        threat_id = "2147892393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 f6 81 3d a0 2c 45 00 ?? ?? ?? ?? 57 75 43 56 e8 fc 03 00 00 59 56 e8 de 05 00 00 59 56 56 e8 f6 08 00 00 8b c4 89 30 89 70 04 e8 ff f9 ff ff}  //weight: 5, accuracy: Low
        $x_1_2 = "placement delete[] closure" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_LL_2147892566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.LL!MTB"
        threat_id = "2147892566"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d0 8b f8 c1 ea 05 c1 e7 04 03 fb 03 d5 33 d7 8b 7c 24 10 03 f8 33 d7 2b f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_VA_2147892751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.VA!MTB"
        threat_id = "2147892751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d0 c1 ea 05 03 54 24 1c 8b f8 c1 e7 04 03 7c 24 20 03 c1 33 d7 33 d0 2b f2 8b d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GMR_2147893036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GMR!MTB"
        threat_id = "2147893036"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c8 8b 45 10 33 d2 f7 f1 8b 45 0c 8b 4d 08 8a 04 02 32 04 39 88 07}  //weight: 10, accuracy: High
        $x_1_2 = "Exodus\\exodus.wallet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_ML_2147893393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.ML!MTB"
        threat_id = "2147893393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 8b d0 c1 e9 05 03 4c 24 34 c1 e2 04 03 d5 33 ca 8b 54 24 14 03 d0 33 ca 2b f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GN_2147893468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GN!MTB"
        threat_id = "2147893468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f4 c1 e0 04 89 45 fc 8b 45 dc 01 45 fc 8b 55 f4 8b 4d f8 8b f2 d3 ee 8d 04 13 31 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_VD_2147893918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.VD!MTB"
        threat_id = "2147893918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 8b 45 10 33 d2 f7 f1 8b 45 0c 8a 0c 02 8b 45 10 8b 55 08 03 c3 32 0c 02 88 08 ff 75 fc ff d7 ff 75 fc ff d7 ff 75 fc ff d7 ff 75 fc ff d7 ff 45 10 39 75 10 72 ab}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_VE_2147894053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.VE!MTB"
        threat_id = "2147894053"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 33 d2 8b c3 f7 f1 8b 45 0c 56 8a 0c 02 8b 55 fc 8d 04 13 8b 55 08 32 0c 02 88 08 ff d7 56 ff d7 56 ff d7 56 ff d7 56 ff d7 56 ff d7 43 3b 5d 10 72 a7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_VF_2147894061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.VF!MTB"
        threat_id = "2147894061"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 b4 3b 45 b8 73 28 8b 55 dc 03 55 b4 8b 45 d4 03 45 b0 8b 4d c0 e8 ?? ?? ?? ?? 8b 45 c0 01 45 b0 8b 45 c0 01 45 b4 8b 45 bc 01 45 b4 eb d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_IP_2147894262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.IP!MTB"
        threat_id = "2147894262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c7 c1 e8 05 03 44 24 28 8b cf c1 e1 04 03 4c 24 2c 8d 14 2f 33 c1 33 c2 2b d8 8b c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AC_2147895020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AC!MTB"
        threat_id = "2147895020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 14 33 f5 33 c6 2b f8 81 c3 47 86 c8 61 ff 4c 24 24 89 44 24 14}  //weight: 1, accuracy: High
        $x_1_2 = {8b 74 24 20 8b 4c 24 18 89 3e 89 4e 04 83 3d 20 61 7b 00 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_VG_2147895232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.VG!MTB"
        threat_id = "2147895232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 00 32 c1 8b 8d 80 e4 ff ff 88 04 11 ff 85 84 e4 ff ff ff b5 7c e4 ff ff 42 89 95 78 e4 ff ff e8 ?? ?? ?? ?? 59 39 85 84 e4 ff ff 0f 8c 56 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_VK_2147895238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.VK!MTB"
        threat_id = "2147895238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 00 32 c1 8b 8d 80 e4 ff ff 88 04 31 ff b5 74 e4 ff ff ff 85 84 e4 ff ff 46 e8 ?? ?? ?? ?? 59 39 85 84 e4 ff ff 0f 8c 62 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AV_2147896118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AV!MTB"
        threat_id = "2147896118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 39 45 10 76 ?? 8b 55 fc 8b 45 f4 01 d0 8b 4d fc 8b 55 f8 01 ca 0f b6 00 88 02 83 45 fc 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GNA_2147896243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GNA!MTB"
        threat_id = "2147896243"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {33 ed 31 54 ef 10 31 54 ef 14 45}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_VX_2147896553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.VX!MTB"
        threat_id = "2147896553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 14 2a 32 14 18 88 13 ff d7 8b 5c 24 10 46 3b 74 24 20 72 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_ASF_2147896694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.ASF!MTB"
        threat_id = "2147896694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 d2 f7 f1 8b 45 0c 8a 0c 02 8b 45 10 8b 55 08 03 c3 32 0c 02 88 08 ff 75 fc ff d7 ff 75 fc ff d7}  //weight: 2, accuracy: High
        $x_1_2 = "t.me/solonichat" ascii //weight: 1
        $x_1_3 = "Autofill\\%s_%s.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_BC_2147898787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.BC!MTB"
        threat_id = "2147898787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 4d 0c 51 03 de ff d7 8b c8 33 d2 8b c6 f7 f1 8b 45 0c 68 ?? ?? ?? 00 8a 0c 02 8b 55 f8 32 0c 1a 88 0b ff d7 68 ?? ?? ?? 00 ff d7 68 ?? ?? ?? 00 ff d7 8b 5d fc 46 3b 75 10 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RH_2147899754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RH!MTB"
        threat_id = "2147899754"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 6a 40 68 00 30 00 00 ff 70 50 56 ff 15 ?? ?? ?? ?? 8b f0 85 f6 75 26 85 db 0f 84 9c 02 00 00 8b 45 fc 6a 40 68 00 30 00 00 ff 70 50 56 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_SB_2147899916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.SB!MTB"
        threat_id = "2147899916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d e8 03 cf 89 4d f0 8b 4d f4 8b f7 d3 ee c7 05 ?? ?? ?? ?? ee 3d ea f4 03 75 d0 8b 45 f0 31 45 fc 81 3d ?? ?? ?? ?? e6 09 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_YAA_2147900277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.YAA!MTB"
        threat_id = "2147900277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e0 8b cf c1 e9 05 03 8c 24 ?? ?? ?? ?? 03 84 24 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 33 c1 8b 4c 24 14 03 cf 33 c1 2b e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_SG_2147900351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.SG!MTB"
        threat_id = "2147900351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 f7 f1 8b 45 fc 68 ?? ?? ?? ?? 8a 0c 02 8b 55 08 03 d6 8a 04 13 32 c1 88 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_SG_2147900351_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.SG!MTB"
        threat_id = "2147900351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 02 32 04 39 88 07 ff d6 68 ?? ?? ?? ?? ff d6 68 ?? ?? ?? ?? ff d6 8b 7d ?? 43 3b 5d ?? 72 a2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_EM_2147900372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.EM!MTB"
        threat_id = "2147900372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 55 f8 2b c1 8b c8 8b 45 fc 03 d0 89 55 f4 33 d2 f7 f1 8b 45 0c 57 8a 0c 02 8b 45 f4 8b 55 08 32 0c 02 88 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_CCGR_2147900774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.CCGR!MTB"
        threat_id = "2147900774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b c7 f7 f1 8b 45 ?? 8b 4d ?? 03 c7 47 8a 92 ?? ?? ?? ?? 32 14 08 88 10 83 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AAQ_2147900985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AAQ!MTB"
        threat_id = "2147900985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 33 d2 8b c7 f7 f1 8b 45 ?? 8b 4d fc 8a 04 02 32 04 31 47 88 06 3b 7d 10 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_DF_2147901018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.DF!MTB"
        threat_id = "2147901018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 8d 34 0f 8a 0e 88 4d ff 8a 4d fe d2 45 ff 8a 4d 10 2a cb 32 4d ff fe c3 88 0e 3a d8 75 ?? 32 db fe c2 88 55 fe 3a 55 fd 75 ?? 32 d2 88 55 fe 47 3b 7d 0c 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PMV_2147901382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PMV!MTB"
        threat_id = "2147901382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 08 88 0a eb 27 8b 55 08 03 95 f4 fb ff ff 0f b6 02 8b 8d 14 f0 ff ff 33 84 8d f8 fb ff ff 8b 95 f0 fb ff ff 03 95 f4 fb ff ff 88 02 e9 d5 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PE_2147902098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PE!MTB"
        threat_id = "2147902098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 db 09 f3 89 da 8b 5d ?? 6a 08 8f 45 ?? d1 c0 8a fc 8a e6 d1 cb ff 4d fc 75 ?? 56 83 e6 00 31 de 83 e0 00 31 f0 5e aa 49 75 c5}  //weight: 1, accuracy: Low
        $x_1_2 = {46 89 75 e4 2b 75 ?? 33 75 ?? 83 e0 00 09 f0 8b 75 ?? 0f b6 1c 30 89 7d ?? 31 ff 33 7d f8 89 fa 8b 7d e4 d3 c2 23 d3 ac 0a c2 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Vidar_PBE_2147902102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PBE!MTB"
        threat_id = "2147902102"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f4 8a 0a 0f b6 d9 8d 84 85 ?? ?? ?? ?? 39 18 75 08 8b 45 fc 88 0c 10 eb 0a ?? ?? 32 c1 8b 4d fc 88 04 11 ff 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_D_2147902361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.D!MTB"
        threat_id = "2147902361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 04 02 32 04 39 88 07}  //weight: 2, accuracy: High
        $x_2_2 = {8b c8 33 d2 8b c3 f7 f1 8b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_SPFD_2147902941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.SPFD!MTB"
        threat_id = "2147902941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 4d dc 30 04 31 83 ff 0f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_SPFD_2147902941_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.SPFD!MTB"
        threat_id = "2147902941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 04 8d 80 f0 42 00 8b f0 81 e6 ff 00 00 00 c1 e8 08 33 04 b5 80 f4 42 00 41 89 04 8d 7c f4 42 00 3b ca}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_OPT_2147903373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.OPT!MTB"
        threat_id = "2147903373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c6 89 45 e4 8b 45 ec c1 e8 05 89 45 f8 8b 45 d4 01 45 f8 8b 45 fc c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 e8 89 5d ec 8b 45 ?? 01 45 ec 8b 45 ec 31 45 e8 8b 45 e8 31 45 f8 2b 7d f8 83 3d ?? ?? ?? ?? 0c 89 45 fc 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_BAS_2147903718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.BAS!MTB"
        threat_id = "2147903718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 d3 e8 03 45 ?? 89 45 f8 8b 45 e4 31 45 fc 8b 45 fc 89 45 e8 89 75 f0 8b 45 e8 89 45 f0 8b 45 f8 31 45 f0 8b 45 f0 81 45 ec ?? ?? ?? ?? 2b f8 ff 4d dc 89 45 fc 89 7d e8 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_BS_2147903898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.BS!MTB"
        threat_id = "2147903898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 8b 45 ?? 33 d2 f7 f1 8b 45 ?? 8b 4d ?? c7 04 24 ?? ?? ?? ?? 8a 04 02 32 04 19 88 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AMMB_2147903935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AMMB!MTB"
        threat_id = "2147903935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 ec 08 08 00 00 a1 ?? ?? ?? ?? 33 c4 89 84 24 04 08 00 00 81 3d ?? ?? ?? ?? c7 0f 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {30 04 33 83 ff ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_SPXX_2147904260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.SPXX!MTB"
        threat_id = "2147904260"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 e4 31 45 ec 8b 45 ec 31 45 f8 2b 75 f8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_SPGS_2147904270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.SPGS!MTB"
        threat_id = "2147904270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 b4 f7 d8 33 45 b4 83 e0 01 75 0e 8b 4d b4 81 c1 1e 22 00 00 89 4d b4 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AVI_2147904650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AVI!MTB"
        threat_id = "2147904650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 6a 00 53 ff 15 ?? ?? ?? ?? 56 89 45 fc ff 15}  //weight: 2, accuracy: Low
        $x_1_2 = "Malolo is a volcanic island in the Pacific Ocean" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\monero-project\\monero-core" ascii //weight: 1
        $x_1_4 = "\\Monero\\wallet.keys" ascii //weight: 1
        $x_1_5 = "\\AppData\\Roaming\\FileZilla\\recentservers.xml" ascii //weight: 1
        $x_1_6 = "Indonesia spying scandal developed from allegations" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_ASDN_2147905334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.ASDN!MTB"
        threat_id = "2147905334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 04 02 32 04 19 88 03 ff}  //weight: 10, accuracy: High
        $x_10_2 = {8a 04 02 32 04 39 88 07 ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Vidar_BQ_2147905717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.BQ!MTB"
        threat_id = "2147905717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 f7 f1 8b 45 0c 8b 4d f4 53 6a 00 8a 04 02 32 04 31 88 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_NDD_2147905791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.NDD!MTB"
        threat_id = "2147905791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 03 55 dc 8b 4d d8 89 55 f8 33 d0 8b 45 fc 33 c2 8b 55 ?? 2b f8 89 45 fc ff 4d ?? 89 7d f4 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GPA_2147905962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GPA!MTB"
        threat_id = "2147905962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 02 32 04 31 88 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_SPDH_2147906090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.SPDH!MTB"
        threat_id = "2147906090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 00 6e 00 c7 05 ?? ?? ?? ?? 65 00 6c 00 c7 05 ?? ?? ?? ?? 33 00 32 00 c7 05 ?? ?? ?? ?? 2e 00 64 00 c7 05 ?? ?? ?? ?? 6c 00 6c 00 66 89 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_SPDB_2147906346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.SPDB!MTB"
        threat_id = "2147906346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {69 c0 fd 43 03 00 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 30 0c 33 83 ff 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_SPDB_2147906346_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.SPDB!MTB"
        threat_id = "2147906346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 44 24 0c 69 c9 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 30 14 30 83 ff 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_GZY_2147906609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.GZY!MTB"
        threat_id = "2147906609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {51 03 df ff d6 8b c8 33 d2 8b c7 f7 f1 8b 45 ?? 68 ?? ?? ?? ?? 8a 0c 02 8b 55 ?? 32 0c 1a 88 0b ff d6 68 ?? ?? ?? ?? ff d6 8b 5d ?? 47 3b 7d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RPX_2147907006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RPX!MTB"
        threat_id = "2147907006"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "76561199658817715" ascii //weight: 1
        $x_1_2 = "sa9ok" ascii //weight: 1
        $x_1_3 = "passwords.txt" ascii //weight: 1
        $x_1_4 = "BraveWallet" ascii //weight: 1
        $x_1_5 = "FileZilla" ascii //weight: 1
        $x_1_6 = "recentservers.xml" ascii //weight: 1
        $x_1_7 = "@wallet_path" ascii //weight: 1
        $x_1_8 = "Monero" ascii //weight: 1
        $x_1_9 = "wallet.keys" ascii //weight: 1
        $x_1_10 = "avghookx.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_TWZ_2147907012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.TWZ!MTB"
        threat_id = "2147907012"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 89 0d 38 ?? ?? ?? 8a 15 ?? ?? ?? ?? 8b 4c 24 14 30 14 0e 83 f8 0f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_SRH_2147907175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.SRH!MTB"
        threat_id = "2147907175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 ca 81 ea fb 07 82 d2 83 ea 01 81 c2 fb 07 82 d2 0f af ca 83 e1 01 83 f9 00 0f 94 c1 80 e1 01 88 4d e6 83 f8 0a 0f 9c c0 24 01 88 45 e7 c7 45 e0 ?? ?? ?? ?? 8b 45 e0 89 45 d4 2d 0d 0d 8c 9d 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_KHZ_2147907723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.KHZ!MTB"
        threat_id = "2147907723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 6c 24 2c 8b 5c 24 30 8b 7c 24 28 8b 4c 24 38 8a 44 2c 3c 88 44 1c 3c 8a 44 24 ?? 88 44 2c 3c 0f b6 44 1c 3c 03 44 24 34 0f b6 c0 8a 44 04 3c 30 04 39 8b 44 24 ?? 85 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_UMP_2147908225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.UMP!MTB"
        threat_id = "2147908225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c6 0f b6 c0 8a 44 04 2c 30 04 3b 85 ed 74 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_ZCP_2147908404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.ZCP!MTB"
        threat_id = "2147908404"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c6 0f b6 c0 0f b6 44 04 ?? 30 04 3a 8b 54 24 18 85 d2 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_ZAJ_2147908484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.ZAJ!MTB"
        threat_id = "2147908484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d a4 24 00 00 00 00 8b 0d f4 b8 45 00 69 c9 ?? ?? ?? ?? 81 c1 c3 9e 26 00 89 0d f4 b8 45 00 8a 15 f6 b8 45 00 30 14 1e 83 ff 0f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_KGA_2147908998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.KGA!MTB"
        threat_id = "2147908998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 c0 8a 44 04 40 30 04 29 45 3b ac 24 4c 02 00 00 7c a0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_SPRD_2147909044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.SPRD!MTB"
        threat_id = "2147909044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 6c 24 0c 64 8a 4c 24 0c 30 0c 33 83 ff 0f 75 ?? 8b 54 24 08 8b 4c 24 08 55 55 52 8d 44 24 38 50 51 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_SPGH_2147909511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.SPGH!MTB"
        threat_id = "2147909511"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 64 89 44 24 10 83 6c 24 10 64 8a 54 24 10 8b 44 24 14 30 14 30 83 bc 24 ?? ?? ?? ?? 0f 75 ?? 6a 00 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_DE_2147909797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.DE!MTB"
        threat_id = "2147909797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 3c ?? 03 c6 0f b6 c0 59 8a 44 04 ?? 30 85 00 ?? ?? ?? 45 81 fd 00 ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_SPGG_2147910278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.SPGG!MTB"
        threat_id = "2147910278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c4 04 8b 44 24 0c 83 c0 64 89 44 24 08 83 6c 24 08 64 8a 4c 24 08 30 0c 3e 46 3b f3 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_SV_2147910841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.SV!MTB"
        threat_id = "2147910841"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c0 64 89 85 ?? ?? ff ff 83 ad ?? ?? ff ff 64 8a 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 30 14 30 83 ff 0f 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_KLS_2147910910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.KLS!MTB"
        threat_id = "2147910910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 8b 85 f4 f7 ff ff 83 c0 ?? 89 85 f8 f7 ff ff 83 ad f8 f7 ff ff 64 8a 8d f8 f7 ff ff 30 0c 33 83 ff 0f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AMMF_2147911309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AMMF!MTB"
        threat_id = "2147911309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 8b 45 ?? 31 18 83 45 ?? ?? 6a 00 e8 ?? ?? ?? ?? 83 c0 ?? 01 45 ?? 8b 45 ?? 3b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_ASGD_2147911419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.ASGD!MTB"
        threat_id = "2147911419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b d0 8b 45 ?? 31 10 83 45 ?? 04 6a 00 e8 ?? ?? ?? ff 83 c0 04 01 45 ?? 8b 45 ?? 3b 45 ?? 72}  //weight: 2, accuracy: Low
        $x_2_2 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 89 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_ASGE_2147911549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.ASGE!MTB"
        threat_id = "2147911549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d4 31 18 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 83 c0 04 01 45 d4 8b 45 ec 3b 45 d0 72}  //weight: 2, accuracy: Low
        $x_2_2 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 89 45 ?? c7 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_ASGF_2147911669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.ASGF!MTB"
        threat_id = "2147911669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 89 45 ?? c7 45 ?? ?? ?? 00 00 6a 00 e8 ?? ?? ?? ff 8b 55 ?? 81 c2 ?? ?? ?? 00 2b 55 ?? 2b d0 8b 45 ?? 31 10 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_SPXK_2147911751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.SPXK!MTB"
        threat_id = "2147911751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 44 24 18 33 4c 24 14 03 44 24 2c 33 c1 c7 05}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_VOT_2147911812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.VOT!MTB"
        threat_id = "2147911812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c2 9e 09 00 00 2b 55 a0 2b d0 8b 45 d8 31 10 83 45 ec ?? 83 45 d8 04 8b 45 ec 3b 45 d4 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AMMH_2147912051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AMMH!MTB"
        threat_id = "2147912051"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d0 8b 45 ?? 31 10 [0-10] 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AVR_2147912053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AVR!MTB"
        threat_id = "2147912053"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 00 7c 63 40 00 40 37 40 00 34 37 40 00 8c 63 40 00 90 34 40 00 cc 34 40 00 12 54 4f 58 44}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AVR_2147912053_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AVR!MTB"
        threat_id = "2147912053"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {69 0c 24 00 03 00 00 01 c8 8d 0d 84 46 42 00 6b 14 24 0c 01 d1 89 01 8d 05 00 30 42 00 69 0c 24 00 03 00 00 01 c8 05 00 01 00 00 8d 0d 84 46 42 00 6b 14 24 0c 01 d1 89 41 04 8d 05 00 30 42 00 69 0c 24 00 03 00 00 01 c8 05 00 02 00 00 8d 0d 84 46 42 00 6b 14 24 0c 01 d1}  //weight: 2, accuracy: High
        $x_1_2 = {a3 e4 4f 63 00 68 54 0c 42 00 ff 35 c4 51 63 00 e8 2a c7 fe ff a3 e8 4f 63 00 68 bd 0a 42 00 ff 35 c4 51 63 00 e8 15 c7 fe ff a3 ec 4f 63 00 68 13 09 42 00 ff 35 c4 51 63 00 e8 00 c7 fe ff a3 f0 4f 63 00 68 51 03 42 00 ff 35 c4 51 63 00 e8 eb c6 fe ff a3 98 4f 63 00 68 dc 09 42 00 ff 35 c4 51 63 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_ASGG_2147912189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.ASGG!MTB"
        threat_id = "2147912189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff 6a 00 e8 ?? ?? ?? ff 8b 5d ?? 81 c3 ?? ?? ?? 00 2b 5d ?? 2b d8 6a 00 e8 ?? ?? ?? ff 2b d8 8b 45 ?? 31 18 6a 00 e8 ?? ?? ?? ff 83 45 ec 04 83 45 ?? 04 8b 45 ec 3b 45 ?? 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_SVD_2147912290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.SVD!MTB"
        threat_id = "2147912290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 8b 45 a8 05 ?? ?? ?? ?? 2b 45 a0 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d8 31 18 6a 00 e8 ?? ?? ?? ?? 83 45 ec 04 83 45 d8 04 8b 45 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AMMJ_2147912392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AMMJ!MTB"
        threat_id = "2147912392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 8b 45 ?? 31 18 6a 00 e8 ?? ?? ?? ?? 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {83 45 ec 04 83 45 ?? 04 8b 45 ec 3b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_NTJ_2147912495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.NTJ!MTB"
        threat_id = "2147912495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 5c 0c 3c 0f b6 44 2c 3c 8b 4c 24 ?? 03 c7 8b 5c 24 14 0f b6 c0 8a 44 04 3c 30 04 19 8b 44 24 ?? 2b c6 83 e0 f8 50 56 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AMAA_2147912625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AMAA!MTB"
        threat_id = "2147912625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 8b 45 ?? 31 18 6a 00 e8 ?? ?? ?? ?? 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_IIV_2147912702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.IIV!MTB"
        threat_id = "2147912702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 37 34 74 04 4e 34 70 2c 65 34 22 2c 73 68 ?? ?? ?? ?? 88 04 37 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_KT_2147912811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.KT!MTB"
        threat_id = "2147912811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 8b 45 a8 05 ?? ?? ?? ?? 2b 45 a0 03 d8}  //weight: 1, accuracy: Low
        $x_1_2 = {2b d8 8b 45 d8 31 18}  //weight: 1, accuracy: High
        $x_1_3 = {83 45 d8 04 8b 45 ec 3b 45 d4 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_ASGH_2147912928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.ASGH!MTB"
        threat_id = "2147912928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {2b d0 8b 45 ?? 31 10 6a 00 e8 ?? ?? ?? ff 6a 00 e8 ?? ?? ?? ff 83 45 ec 04 6a 00 e8 ?? ?? ?? ff 83 45 ?? 04 8b 45 ec 3b 45 d4 72}  //weight: 4, accuracy: Low
        $x_1_2 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AMAD_2147913027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AMAD!MTB"
        threat_id = "2147913027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d0 8b 45 ?? 31 10 6a 00 e8 ?? ?? ?? ?? 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 45 ec 04 6a 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_ASGI_2147913162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.ASGI!MTB"
        threat_id = "2147913162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {2b d8 6a 00 e8 ?? ?? ?? ff 2b d8 8b 45 ?? 31 18 6a 00 e8}  //weight: 4, accuracy: Low
        $x_1_2 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_LML_2147913205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.LML!MTB"
        threat_id = "2147913205"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb e8 fc 3e 00 00 8b 54 24 1c 8b 4c 24 24 8b 7c 24 28 0f b6 44 14 ?? 03 44 24 20 0f b6 c0 8a 44 04 34 30 04 0e 46 3b f5 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_ASGJ_2147913314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.ASGJ!MTB"
        threat_id = "2147913314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {2b d0 8b 45 ?? 31 10 6a 00 e8 ?? ?? ?? ff 6a 00 e8 ?? ?? ?? ff 6a 00 e8 ?? ?? ?? ff 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 d4 72}  //weight: 4, accuracy: Low
        $x_1_2 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_QW_2147913323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.QW!MTB"
        threat_id = "2147913323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 a8 81 c2 ?? ?? ?? ?? 2b 55 a0 2b d0 8b 45 d8 31 10 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 45 d8 04 8b 45 ec 3b 45 d4 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AMAG_2147913509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AMAG!MTB"
        threat_id = "2147913509"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d0 8b 45 ?? 31 10 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {83 45 ec 04 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AMAE_2147914169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AMAE!MTB"
        threat_id = "2147914169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 00 32 c1 8b 4d ?? 88 04 31 ff 75 ?? ff 45 ?? 46}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AMAI_2147914225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AMAI!MTB"
        threat_id = "2147914225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d8 8b 45 ?? 31 18 6a 00 e8 ?? ?? ?? ?? 83 45 ec 04 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_NV_2147914401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.NV!MTB"
        threat_id = "2147914401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f6 c1 20 0f 45 f7 0f 45 f8 89 bc cc 5c 0b 00 00 31 d6 89 b4 cc 58 0b 00 00 f6 c1 0f 75 c5}  //weight: 2, accuracy: High
        $x_1_2 = {c1 e6 05 8b bc 24 58 01 00 00 0f b7 9c 4c 58 09 00 00 01 fb 01 f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_NV_2147914401_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.NV!MTB"
        threat_id = "2147914401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {55 8b ec 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 ff 05 dc af 45 00 33 c0 5a 59 59 64 89 10 68 98 7a 45}  //weight: 3, accuracy: Low
        $x_3_2 = {83 c4 f0 b8 cc 7a 45 00 e8 ?? ?? ?? ?? a1 b4 9d 45 00 8b 00 e8 ?? ?? ?? ?? 8b 0d 48 9a 45 00 a1 b4 9d 45 00 8b 00 8b 15 14 75 45 00 e8 ?? ?? ?? ?? a1 b4 9d 45}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_ASGK_2147914412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.ASGK!MTB"
        threat_id = "2147914412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 83 45 ?? 04 6a 00 e8 ?? ?? ?? ?? 8b 45 ec 3b 45 d4 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_YB_2147914702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.YB!MTB"
        threat_id = "2147914702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 31 18 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 83 45 d8 04 6a 00 e8 ?? ?? ?? ?? 8b 45 ec 3b 45 d4 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AMAJ_2147914864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AMAJ!MTB"
        threat_id = "2147914864"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d8 8b 45 d8 31 18 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 83 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AMAJ_2147914864_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AMAJ!MTB"
        threat_id = "2147914864"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {59 8b c8 8b 45 ?? 33 d2 f7 f1 8b 45 ?? 0f be 04 10 33 d8 8b 45 ?? 03 45 ?? 88 18}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 14 ff 15 ?? ?? ?? ?? 6a 14 ff 15 ?? ?? ?? ?? 6a 14 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_ASGL_2147915151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.ASGL!MTB"
        threat_id = "2147915151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {31 02 83 45 ec 04 6a 00 e8}  //weight: 4, accuracy: High
        $x_1_2 = {8b 45 ec 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_TOQ_2147916281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.TOQ!MTB"
        threat_id = "2147916281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b c1 89 45 f4 8b 45 fc 8d 0c 03 33 d2 8b c3 f7 75 f4 8b 45 0c 57 8a 04 02 8b 55 f0 32 04 0a 88 01 ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_ADG_2147917890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.ADG!MTB"
        threat_id = "2147917890"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 08 0f c6 1c 00 00 00 00 00 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PAFH_2147918296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PAFH!MTB"
        threat_id = "2147918296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 33 d2 8b c7 f7 f1 8b 45 0c 68 ?? ?? ?? ?? 8a 0c 02 8b 55 f8 32 0c 1a 88 0b}  //weight: 1, accuracy: Low
        $x_1_2 = "\\Monero\\wallet.keys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_KAE_2147918871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.KAE!MTB"
        threat_id = "2147918871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d7 8b 44 24 ?? c1 e8 05 89 44 24 ?? 8b 44 24 ?? 03 c5 33 c2 33 c1 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_PAFQ_2147920663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.PAFQ!MTB"
        threat_id = "2147920663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 75 fc ff 75 0c 03 f7 ff 15 ?? ?? ?? ?? 8b c8 8b 45 fc 33 d2 f7 f1 8b 45 0c 8b 4d f8 8a 04 02 32 04 31 ff 45 fc 88 06 39 5d fc 72 d3}  //weight: 2, accuracy: Low
        $x_2_2 = "Select * From AntiVirusProduct" wide //weight: 2
        $x_1_3 = "\\Discord\\tokens.txt" ascii //weight: 1
        $x_2_4 = "loginusers.vdf" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MBXX_2147921642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MBXX!MTB"
        threat_id = "2147921642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "tuwimevetikazibowabucoku" ascii //weight: 2
        $x_1_2 = "Judumibohin yewupu fefe dawe casadiciwih" wide //weight: 1
        $x_1_3 = "Riyozeluha murumijax yuco micolecas xotuhutu kocunexoh rofujanimumije" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_ND_2147922733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.ND!MTB"
        threat_id = "2147922733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "juhijit" ascii //weight: 2
        $x_1_2 = "wonubajicicegodoniput" ascii //weight: 1
        $x_1_3 = "dihuvosusoxuyevohigoralewifozuh" ascii //weight: 1
        $x_1_4 = "nakahusudoxi" ascii //weight: 1
        $x_1_5 = "bizareduli" ascii //weight: 1
        $x_1_6 = "cavuwoxegufiyipavizes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_ASJ_2147922815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.ASJ!MTB"
        threat_id = "2147922815"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {03 c6 59 8b 4c 24 24 0f b6 c0 8a 44 04 30 30 04 0a 41 89 4c 24 24 3b 0f 7c}  //weight: 4, accuracy: High
        $x_1_2 = {23 c9 66 f7 e2 33 f2 46 42}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AMK_2147922947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AMK!MTB"
        threat_id = "2147922947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 3c ?? 03 c6 59 8b 4c 24 ?? 0f b6 c0 8a 44 04 ?? 30 04 29 45 3b 2b 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_SPOB_2147923185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.SPOB!MTB"
        threat_id = "2147923185"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 54 24 30 8a 44 34 34 59 8b 4c 24 24 30 04 0a 41 89 4c 24 24 3b 0f 7c 8e}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_EC_2147923304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.EC!MTB"
        threat_id = "2147923304"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Soft\\Steam\\steam_tokens.txt" ascii //weight: 1
        $x_1_2 = "information.txt" ascii //weight: 1
        $x_1_3 = "wallet_path" ascii //weight: 1
        $x_1_4 = "t.me/iyigunl" ascii //weight: 1
        $x_1_5 = "Monero\\wallet.keys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AIN_2147923717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AIN!MTB"
        threat_id = "2147923717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c4 08 c7 45 d4 00 00 00 00 c7 45 d8 00 00 00 00 c7 45 dc 00 00 00 00 8b 7d bc 8b 45 c0 0f b6 84 05 ?? ?? ?? ?? 8b 4d 08 30 04 39 47 8b 45 c8 3b 38 8b 55 b8 0f 8d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_MOZ_2147923830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.MOZ!MTB"
        threat_id = "2147923830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {57 50 e8 17 ?? ?? ?? 33 c0 59 59 89 44 24 10 89 44 24 ?? 89 44 24 18 8b 7c 24 1c 8b 4c 24 20 8a 44 0c 3c 8b 4c 24 38 30 04 29 45 3b 6b 04 0f 8c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_IKV_2147924768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.IKV!MTB"
        threat_id = "2147924768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 64 24 00 8d 4c 24 08 c7 44 24 04 ?? ?? ?? ?? c7 44 24 08 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 44 24 08 83 c0 46 89 44 24 04 83 6c 24 04 46 8a 4c 24 ?? 30 0c 33 83 ff 0f 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AXBA_2147924781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AXBA!MTB"
        threat_id = "2147924781"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff 8b 44 24 ?? 83 c4 08 8a 4c 2c ?? 30 0c 03 8b ce e8 ?? ?? ?? ?? 8b 6c 24 ?? 43 3b 5f ?? 0f 8c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_CZ_2147925013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.CZ!MTB"
        threat_id = "2147925013"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c8 8b 45 ?? 33 d2 f7 f1 8b 45 ?? 8b 4d ?? 8a 04 02 32 04 31 ff 45 ?? 88 06 39 5d ?? 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_NF_2147926461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.NF!MTB"
        threat_id = "2147926461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 89 e5 57 56 83 ec 2c a1 ?? ?? ?? ?? 8b 7d 0c 8d 75 dc 31 e8 89 45 f4 b8 be 78 b2 ed 3d e3 0b 35 19 7e 13 eb 5a 84 c9 0f 45 c2}  //weight: 2, accuracy: Low
        $x_1_2 = {83 e1 1f 8b 7e 04 33 d8 8b 76 08 33 f8 33 f0 d3 cf d3 ce d3 cb 3b fe 75 7b 2b f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_ASU_2147926856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.ASU!MTB"
        threat_id = "2147926856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 45 f8 ff 75 0c 8d 34 3b 8a 04 30 88 45 ff ff 15 ?? ?? ?? ?? 8b c8 33 d2 8b c3 f7 f1 8b 45 0c 8a 04 02 32 45 ff 43 88 06 3b 5d 10 72}  //weight: 3, accuracy: Low
        $x_1_2 = "65 79 41 69 64 48 6C 77 49 6A 6F 67 49 6B 70 58 56 43 49 73 49 43 4A 68 62 47 63 69 4F 69 41 69 52 57 52 45 55 30 45 69 49 48 30" ascii //weight: 1
        $x_1_3 = "malware" ascii //weight: 1
        $x_1_4 = "virus" ascii //weight: 1
        $x_1_5 = "_key.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AVD_2147927185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AVD!MTB"
        threat_id = "2147927185"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 14 1e 29 c2 0f b6 42 15 32 44 1e 29 88 44 1f 15 41 43}  //weight: 2, accuracy: High
        $x_3_2 = {6b 48 33 1b a1 ?? ?? ?? ?? ff 75 ec ff ?? 6b 48 33 1b a1 ?? ?? ?? ?? ff 75 c8 ff ?? 6b 48 33 1b a1 ?? ?? ?? ?? ff 75 f0 ff}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AVDR_2147928150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AVDR!MTB"
        threat_id = "2147928150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 34 3b 8a 04 30 88 45 ff ff 15 ?? ?? ?? ?? 8b c8 33 d2 8b c3 f7 f1 8b 45 0c 8a 04 02 32 45 ff 43 88 06}  //weight: 2, accuracy: Low
        $x_1_2 = {8b c8 83 e1 03 8a 8c 0d ?? ?? ?? ?? 30 0c 06 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_EA_2147928344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.EA!MTB"
        threat_id = "2147928344"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 f7 29 75 f8 8b 45 e8 29 45 fc 83 6d f0 01 0f 85 ?? ?? ?? ?? 8b 45 08 8b 4d f8 8b 55 f4 5f 5e 89 08 89 50 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_ZFZ_2147928833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.ZFZ!MTB"
        threat_id = "2147928833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 c2 03 47 34 69 c0 05 84 08 08 40 89 47 34 c1 e8 18 0f b6 d1 31 c2 c1 e9 08 33 0c 95 ?? ?? ?? ?? 89 4f 38 32 7c 24 03 88 7c 35 00 8b 6c 24 20 46 39 f5 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_POV_2147929461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.POV!MTB"
        threat_id = "2147929461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 f8 47 c1 e8 02 f7 e5 6b c2 e4 8d 14 19 0f b6 44 10 1f 32 44 19 ?? 88 44 1e 1f 43 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_LLV_2147931108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.LLV!MTB"
        threat_id = "2147931108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 ff 89 f0 89 fa 83 e2 03 8a 54 14 ?? 30 14 38 47 8b 44 24 04 8b 54 24 08 89 d6 29 c6 39 f7 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_VKZ_2147932213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.VKZ!MTB"
        threat_id = "2147932213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 00 85 c0 75 4a 8b b4 24 30 0c 00 00 89 f1 68 09 ae 41 00 8d 5c 24 14 53 e8 6c f5 ff ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_APD_2147932535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.APD!MTB"
        threat_id = "2147932535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 d9 83 e1 03 8a 8c 0c b8 00 00 00 32 0c 18 0f be c1 89 f1 50 6a 01 e8 5e 78 00 00 43 39 dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RRR_2147932632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RRR!MTB"
        threat_id = "2147932632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 08 0f d0 2d 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_TEH_2147933437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.TEH!MTB"
        threat_id = "2147933437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 fa 83 e2 03 8a 54 14 38 30 14 38 47 8b 44 24 04 8b 54 24 08 89 d6 29 c6 39 f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_YAC_2147933571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.YAC!MTB"
        threat_id = "2147933571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {f7 d6 33 f7 f7 de 81 c1 f9 5b 85 78 c1 c1 05 f7 de 81 f1 61 da 69 b4 81 c7 fb 85 94 ef 81 31 ?? ?? ?? ?? 33 dc 87 d3 49}  //weight: 11, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AAD_2147933797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AAD!MTB"
        threat_id = "2147933797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "54"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/c timeout /t 10 & rd /s /q \"C:\\ProgramData\\" ascii //weight: 10
        $x_10_2 = "Release\\vdr1.pdb" ascii //weight: 10
        $x_10_3 = "vdr1.exe" ascii //weight: 10
        $x_5_4 = "\\Monero\\wallet.keys" ascii //weight: 5
        $x_5_5 = "SOFTWARE\\monero-project\\monero-cor" ascii //weight: 5
        $x_2_6 = "_cookies.db" ascii //weight: 2
        $x_2_7 = "_passwords.db" ascii //weight: 2
        $x_2_8 = "_key4.db" ascii //weight: 2
        $x_2_9 = "_logins.json" ascii //weight: 2
        $x_2_10 = "passwords.txt" ascii //weight: 2
        $x_1_11 = "UseMasterPassword" ascii //weight: 1
        $x_1_12 = "Crash Detected" ascii //weight: 1
        $x_1_13 = "https://steamcommunity.com" ascii //weight: 1
        $x_1_14 = "https://t.me/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_EAA_2147937251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.EAA!MTB"
        threat_id = "2147937251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 4c 24 07 00 c8 00 44 24 07 0f b6 44 24 08 0f b6 c0 89 c1 c1 e1 04 01 c1 f7 d9 00 4c 24 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_SEY_2147937262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.SEY!MTB"
        threat_id = "2147937262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 05 00 20 42 00 69 0c 24 00 03 00 00 01 c8 8d 0d 9c 36 42 00 6b 14 24 0c 01 d1 89 01}  //weight: 2, accuracy: High
        $x_1_2 = "\\\\Monero\\\\wallet0123456789" ascii //weight: 1
        $x_1_3 = "\\\\BraveWallet\\\\P" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_EAAA_2147937337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.EAAA!MTB"
        threat_id = "2147937337"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b b4 24 18 01 00 00 32 0c 16 30 d9 88 0c 16 42 39 94 24 1c 01 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_EB_2147938908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.EB!MTB"
        threat_id = "2147938908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "39"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*wallet*.*" ascii //weight: 1
        $x_1_2 = "*seed*.*" ascii //weight: 1
        $x_1_3 = "*btc*.*" ascii //weight: 1
        $x_1_4 = "*key*.*" ascii //weight: 1
        $x_1_5 = "*2fa*.*" ascii //weight: 1
        $x_1_6 = "*crypto*.*" ascii //weight: 1
        $x_1_7 = "*coin*.*" ascii //weight: 1
        $x_1_8 = "*private*.*" ascii //weight: 1
        $x_1_9 = "*auth*.*" ascii //weight: 1
        $x_1_10 = "*ledger*.*" ascii //weight: 1
        $x_1_11 = "*trezor*.*" ascii //weight: 1
        $x_1_12 = "*pass*.*" ascii //weight: 1
        $x_1_13 = "*wal*.*" ascii //weight: 1
        $x_1_14 = "*upbit*.*" ascii //weight: 1
        $x_1_15 = "*bcex*.*" ascii //weight: 1
        $x_1_16 = "*bithimb*.*" ascii //weight: 1
        $x_1_17 = "*hitbtc*.*" ascii //weight: 1
        $x_1_18 = "*bitflyer*.*" ascii //weight: 1
        $x_1_19 = "*kucoin*.*" ascii //weight: 1
        $x_1_20 = "*huobi*.*" ascii //weight: 1
        $x_1_21 = "*poloniex*.*" ascii //weight: 1
        $x_1_22 = "*kraken*.*" ascii //weight: 1
        $x_1_23 = "*okex*.*" ascii //weight: 1
        $x_1_24 = "*binance*.*" ascii //weight: 1
        $x_1_25 = "*bitfinex*.*" ascii //weight: 1
        $x_1_26 = "*gdax*.*" ascii //weight: 1
        $x_1_27 = "*ethereum*.*" ascii //weight: 1
        $x_1_28 = "*exodus*.*" ascii //weight: 1
        $x_1_29 = "*metamask*.*" ascii //weight: 1
        $x_1_30 = "*myetherwallet*.*" ascii //weight: 1
        $x_1_31 = "*electrum*.*" ascii //weight: 1
        $x_1_32 = "*bitcoin*.*" ascii //weight: 1
        $x_1_33 = "*blockchain*.*" ascii //weight: 1
        $x_1_34 = "*coinomi*.*" ascii //weight: 1
        $x_1_35 = "*words*.*" ascii //weight: 1
        $x_1_36 = "*meta*.*" ascii //weight: 1
        $x_1_37 = "*mask*.*" ascii //weight: 1
        $x_1_38 = "*eth*.*" ascii //weight: 1
        $x_1_39 = "*recovery*.*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AD_2147939487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AD!MTB"
        threat_id = "2147939487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 80 f2 ff 41 20 f2 41 88 fb 41 80 f3 ff 40 88 de 44 20 de 80 f3 ff 40 20 df 40 08 fe 45 88 d3 41 20 f3 41 30 f2 45 08 d3 41 f6 c3 01 b8 37 89 da 81}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_EAAQ_2147942200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.EAAQ!MTB"
        threat_id = "2147942200"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6b 14 24 0c 01 d1 89 41 08 8b 04 24 83 c0 01 89 04 24}  //weight: 2, accuracy: High
        $x_2_2 = {83 c4 0c 01 ef 89 bc 9e 44 1e 00 00 0f b6 0c 9d ?? ?? ?? ?? bd 01 00 00 00 d3 e5 8b 04 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AEL_2147942320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AEL!MTB"
        threat_id = "2147942320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 cb 0f b6 c1 88 8d ?? ?? ff ff 8d 8d cc fe ff ff 03 c8 0f b6 01 88 02 88 19 0f b6 02 8b 8d bc fe ff ff 02 c3 0f b6 c0 0f b6 84 05 cc fe ff ff 30 04 0e 46 8a 8d cb fe ff ff 3b f7 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_YAT_2147944517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.YAT!MTB"
        threat_id = "2147944517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 fd 81 f2 ?? ?? ?? ?? 03 f0 2b d5 87 c7 f7 d6 87 f0 33 fe c1 c8}  //weight: 1, accuracy: Low
        $x_10_2 = {2b f9 31 05 ?? ?? ?? ?? 33 d0 c1 c7 0a 8b fe}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AR_2147944733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AR!MTB"
        threat_id = "2147944733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {32 0e 32 c8 8b 45 a0 40 88 0e 89 45 a0 3b 45}  //weight: 3, accuracy: High
        $x_2_2 = {f7 e1 8b d8 8b 44 24 08 f7 64 24 14 03 d8 8b 44 24 08 f7 e1 03 d3 5b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_AE_2147944990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.AE!MTB"
        threat_id = "2147944990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 d1 da 59 47 89 46 04 c7 a0 8c 6b 73 94 1b 53 1b 1c 7c 7d d4 52 94}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_RJZ_2147951788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.RJZ!MTB"
        threat_id = "2147951788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 04 37 2c 05 34 53 88 04 37 46 57 e8 ?? ?? ?? ?? 59 3b f0 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vidar_A_2147959615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidar.A!AMTB"
        threat_id = "2147959615"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "nslookup.exe /?najshu308fags83" ascii //weight: 2
        $x_1_2 = "slut biodiversity perth" ascii //weight: 1
        $x_2_3 = "cmd /v /c Set UkOMu=cmd" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

