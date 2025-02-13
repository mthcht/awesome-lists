rule TrojanDownloader_Win32_Phorpiex_2147749586_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Phorpiex!MSR"
        threat_id = "2147749586"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c start _ & _\\DeviceManager.exe & exit" wide //weight: 1
        $x_1_2 = "%ls\\_\\DeviceManager.exe" wide //weight: 1
        $x_1_3 = "c rmdir /q /s \"%ls\"" wide //weight: 1
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" wide //weight: 1
        $x_1_5 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" wide //weight: 1
        $x_1_6 = "DisableAntiSpyware" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Phorpiex_MK_2147759312_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Phorpiex.MK!MTB"
        threat_id = "2147759312"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://217.8.117.63/spm" ascii //weight: 10
        $x_10_2 = "http://tldrnet.top/spm" ascii //weight: 10
        $x_1_3 = "DisableScanOnRealtimeEnable" ascii //weight: 1
        $x_1_4 = "DisableOnAccessProtection" ascii //weight: 1
        $x_1_5 = "DisableBehaviorMonitoring" ascii //weight: 1
        $x_1_6 = "AntiVirusOverride" ascii //weight: 1
        $x_1_7 = "UpdatesOverride" ascii //weight: 1
        $x_1_8 = "FirewallOverride" ascii //weight: 1
        $x_1_9 = "AntiVirusDisableNotify" ascii //weight: 1
        $x_1_10 = "UpdatesDisableNotify" ascii //weight: 1
        $x_1_11 = "AutoUpdateDisableNotify" ascii //weight: 1
        $x_1_12 = "FirewallDisableNotify" ascii //weight: 1
        $x_1_13 = "DisableAntiSpyware" ascii //weight: 1
        $x_2_14 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" ascii //weight: 2
        $x_2_15 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Phorpiex_GS_2147762174_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Phorpiex.GS!MTB"
        threat_id = "2147762174"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://tldrnet.top/" ascii //weight: 1
        $x_1_2 = "%temp%" wide //weight: 1
        $x_1_3 = "AntiVirusDisableNotify" wide //weight: 1
        $x_1_4 = "FirewallDisableNotify" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Phorpiex_MK_2147773801_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Phorpiex.MK!MTC"
        threat_id = "2147773801"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTC: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%ls:Zone.Identifier" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" ascii //weight: 1
        $x_1_3 = "/c start __ & __\\DriveMgr.exe & exit" ascii //weight: 1
        $x_1_4 = "%s\\%s\\DriveMgr.exe" ascii //weight: 1
        $x_1_5 = "http://worm.ws" ascii //weight: 1
        $x_1_6 = "http://tsrv1.ws" ascii //weight: 1
        $x_1_7 = "svchost.exe" ascii //weight: 1
        $x_1_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_Win32_Phorpiex_C_2147776551_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Phorpiex.C"
        threat_id = "2147776551"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "102"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {52 6a 63 8d 45 ?? 50 8b 4d ?? 51 ff 15 ?? ?? ?? ?? 6a 3e 8d 55 ?? 52 e8 ?? ?? ?? ?? 83 c4 08 89 ?? 88 83 7d ?? 00 74 ?? 8b 45 ?? 83 c0 01 89 ?? 88 68 ?? ?? ?? ?? 8b 4d ?? 51 e8}  //weight: 100, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f 61 65 61 61 67 65 67 61 65 67 65 61 68 72 68 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_3 = {68 74 74 70 3a 2f 2f 61 65 66 69 61 65 66 69 64 6a 69 64 67 68 68 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_4 = {68 74 74 70 3a 2f 2f 61 65 67 75 61 68 65 6f 75 66 75 68 66 68 75 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_5 = {68 74 74 70 3a 2f 2f 61 6f 65 6b 66 6f 61 65 66 6f 61 68 66 6f 68 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_6 = {68 74 74 70 3a 2f 2f 61 76 64 62 61 77 75 64 68 61 66 69 65 68 66 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_7 = {68 74 74 70 3a 2f 2f 61 77 77 61 72 61 72 75 68 75 65 64 68 68 66 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_8 = {68 74 74 70 3a 2f 2f 62 72 6f 77 6e 62 6f 78 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_9 = {68 74 74 70 3a 2f 2f 65 61 66 75 65 62 64 62 65 64 62 65 64 67 67 01 00 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_10 = {68 74 74 70 3a 2f 2f 65 61 66 75 65 75 64 7a 65 66 76 65 72 72 67 01 00 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_11 = {68 74 74 70 3a 2f 2f 65 62 75 66 61 65 68 66 61 68 65 66 68 65 68 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_12 = {68 74 74 70 3a 2f 2f 65 66 61 65 6a 66 6f 6a 65 67 6f 68 67 75 74 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_13 = {68 74 74 70 3a 2f 2f 65 66 65 75 61 66 75 62 65 75 62 61 65 66 75 72 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_14 = {68 74 74 70 3a 2f 2f 65 66 6e 69 61 65 6e 66 69 6e 65 66 69 6e 67 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_15 = {68 74 74 70 3a 2f 2f 66 65 61 75 68 75 65 75 64 75 67 68 75 75 72 6b 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_16 = {68 74 74 70 3a 2f 2f 67 61 65 68 61 65 6a 65 68 67 61 65 66 67 7a 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_17 = {68 74 74 70 3a 2f 2f 67 61 75 65 75 64 62 75 77 64 62 75 67 75 75 72 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_18 = {68 74 74 70 3a 2f 2f 67 65 61 66 6e 65 69 65 66 69 65 66 6e 69 6e 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_19 = {68 74 74 70 3a 2f 2f 67 65 61 6f 68 67 6f 65 68 61 67 75 67 65 68 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_20 = {68 74 74 70 3a 2f 2f 6b 6f 65 6b 66 6f 61 65 6a 66 6f 65 66 6f 6b 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_21 = {68 74 74 70 3a 2f 2f 6c 6f 65 6f 66 61 69 68 65 66 69 68 66 68 67 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_22 = {68 74 74 70 3a 2f 2f 6c 70 69 61 75 65 66 68 75 68 65 75 66 68 67 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_23 = {68 74 74 70 3a 2f 2f 6d 6e 65 6e 6e 65 61 69 68 66 69 68 65 67 69 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_24 = {68 74 74 70 3a 2f 2f 6d 6f 6b 61 65 64 75 65 67 66 75 61 65 68 68 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_25 = {68 74 74 70 3a 2f 2f 6f 6b 64 6f 65 6b 65 6f 65 68 67 68 61 6f 65 72 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_26 = {68 74 74 70 3a 2f 2f 6f 73 68 65 6f 75 66 68 75 73 68 65 6f 67 68 75 65 73 64 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_27 = {68 74 74 70 3a 2f 2f 6f 75 68 66 75 6f 73 75 6f 6f 73 72 68 66 7a 72 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_28 = {68 74 74 70 3a 2f 2f 70 6c 6f 65 75 61 68 66 75 65 75 67 65 75 67 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_29 = {68 74 74 70 3a 2f 2f 72 6f 68 67 6f 72 75 68 67 73 6f 72 68 75 67 69 68 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_30 = {68 74 74 70 3a 2f 2f 72 75 62 62 66 69 62 69 64 69 64 68 69 65 69 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_31 = {68 74 74 70 3a 2f 2f 73 65 75 75 66 68 65 68 66 75 65 75 67 68 65 01 00 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_32 = {68 74 74 70 3a 2f 2f 74 68 61 75 73 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_33 = {68 74 74 70 3a 2f 2f 74 6c 64 72 62 6f 78 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_34 = {68 74 74 70 3a 2f 2f 74 6c 64 72 68 61 75 73 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_35 = {68 74 74 70 3a 2f 2f 74 6c 64 72 7a 6f 6e 65 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_36 = {68 74 74 70 3a 2f 2f 74 72 75 65 62 6f 78 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_37 = {68 74 74 70 3a 2f 2f 74 73 72 76 01 00 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_38 = {68 74 74 70 3a 2f 2f 75 6e 6f 6b 61 6f 65 6f 6a 6f 65 6a 66 67 68 72 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_39 = {68 74 74 70 3a 2f 2f 77 6f 72 6d 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_40 = {68 74 74 70 3a 2f 2f 7a 72 7a 69 71 65 7a 72 69 7a 72 69 7a 7a 66 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_41 = {68 74 74 70 3a 2f 2f 7a 7a 72 75 75 6f 6f 6f 73 68 66 72 6f 68 75 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
        $x_1_42 = {68 74 74 70 3a 2f 2f 63 72 65 65 67 62 6f 78 2e 04 02 02 02 03 72 75 77 73 73 75 74 6f 70 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Phorpiex_PAAE_2147850036_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Phorpiex.PAAE!MTB"
        threat_id = "2147850036"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 3a 00 00 00 66 89 ?? ?? ?? ?? ?? b9 2f 00 00 00 66 89 ?? ?? ?? ?? ?? ba 2f 00 00 00 66 89 ?? ?? ?? ?? ?? b8 31 00 00 00 66 89 ?? ?? ?? ?? ?? b9 38 00 00 00 66 89 ?? ?? ?? ?? ?? ba 35 00 00 00 66 89 ?? ?? ?? ?? ?? b8 2e 00 00 00 66 89 ?? ?? ?? ?? ?? b9 32 00 00 00 66 89 ?? ?? ?? ?? ?? ba 31 00 00 00 66 89 ?? ?? ?? ?? ?? b8 35 00 00 00 66 89 ?? ?? ?? ?? ?? b9 2e 00 00 00 66 89 ?? ?? ?? ?? ?? ba 31 00 00 00 66 89 ?? ?? ?? ?? ?? b8 31 00 00 00 66 89 ?? ?? ?? ?? ?? b9 33 00 00 00 66 89 ?? ?? ?? ?? ?? ba 2e 00 00 00 66 89 ?? ?? ?? ?? ?? b8 36 00 00 00 66 89 ?? ?? ?? ?? ?? b9 36 00 00 00 66 89 ?? ?? ?? ?? ?? ba 2f 00 00 00 66 89 ?? ?? ?? ?? ?? b8 6e 00 00 00 66 89 ?? ?? ?? ?? ?? b9 70 00 00 00 66 89 ?? ?? ?? ?? ?? ba 70 00 00 00 66 89 ?? ?? ?? ?? ?? b8 2e 00 00 00 66 89 ?? ?? ?? ?? ?? b9 65 00 00 00 66 89 ?? ?? ?? ?? ?? ba 78 00 00 00 66 89 ?? ?? ?? ?? ?? b8 65 00 00 00 66 89}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Phorpiex_A_2147923738_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Phorpiex.A!MTB"
        threat_id = "2147923738"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 1c 28 8b ff 32 5c 34 ?? 8d 4c 24 ?? 46 8d 79 ?? 8d 64 24 ?? 8a 11 41 84 d2}  //weight: 4, accuracy: Low
        $x_2_2 = {88 1c 28 8a 14 28 f6 d2 8b c8 88 14 28 45 8d 71 ?? 8b ff 8a 11 41 84 d2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Phorpiex_B_2147924026_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Phorpiex.B!MTB"
        threat_id = "2147924026"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 08 03 45 ?? 0f be 08 f7 d1 8b 55 ?? 03 55 ?? 88 0a}  //weight: 2, accuracy: Low
        $x_4_2 = {8b 4d f0 0f be 54 0d ?? 8b 45 ?? 03 45 ?? 0f be 08 33 ca 8b 55 ?? 03 55 ?? 88 0a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Phorpiex_APX_2147929290_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Phorpiex.APX!MTB"
        threat_id = "2147929290"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 55 fc 8b 45 cc 2b 42 14 8b 4d fc 03 41 0c 2b 45 f8 8b 55 d4 89 42 28 8b 45 d4 c7 40 08 ad de 00 00 6a 00 8b 4d f8 51 ff 15 ?? ?? ?? ?? 8b 55 f8 52 ff 15 ?? ?? ?? ?? 8b 45 f4 50}  //weight: 3, accuracy: Low
        $x_2_2 = "%appdata%\\windrx.txt" wide //weight: 2
        $x_1_3 = "MeNot_.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

