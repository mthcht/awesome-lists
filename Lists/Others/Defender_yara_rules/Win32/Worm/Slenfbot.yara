rule Worm_Win32_Slenfbot_B_115853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Slenfbot.gen!B"
        threat_id = "115853"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Slenfbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ipconfig /flushdns" ascii //weight: 1
        $x_1_2 = "tSkMainForm.UnicodeClass" ascii //weight: 1
        $x_1_3 = "PuTTY" ascii //weight: 1
        $x_1_4 = "TFrmMain" ascii //weight: 1
        $x_1_5 = "YahooBuddyMain" ascii //weight: 1
        $x_1_6 = "MSBLWindowClass" ascii //weight: 1
        $x_1_7 = "_Oscar_StatusNotify" ascii //weight: 1
        $x_1_8 = "__oxFrame.class__" ascii //weight: 1
        $x_1_9 = "imAppSystemTrayHandler" ascii //weight: 1
        $x_1_10 = "irc.reconnect" ascii //weight: 1
        $x_1_11 = "%s\\temp%i%i%i%i.bat" ascii //weight: 1
        $x_1_12 = {6a 09 5b 99 8b cb f7 f9 52 e8}  //weight: 1, accuracy: High
        $x_10_13 = {6a 04 50 6a 07 68 00 08 00 00 1b 00 [0-4] 6a 24 (99|33 d2) 59 f7 (f9|f1) 46 83 fe 0a 8a (44 15 ??|84 15 ?? ??) 88 44 35 ?? 72 ?? 8d 45}  //weight: 10, accuracy: Low
        $x_6_14 = {33 f6 5a 8b 44 24 ?? bf 00 01 00 00 8a 84 30 ?? ?? ?? ?? 32 c2 88 04 0e 8d 42 01 99 f7 ff 46 83 fe ?? 7c df}  //weight: 6, accuracy: Low
        $x_6_15 = {88 01 8b 45 fc 40 89 45 fc 8b 45 fc 99 b9 00 01 00 00 f7 f9 89 55 fc eb}  //weight: 6, accuracy: High
        $x_6_16 = {8b 45 f8 83 c0 01 89 45 f8 83 7d f8 ?? 7d ?? 8b 4d 08 03 4d f8 0f be 91 ?? ?? ?? ?? 33 55 fc 8b 45 f4 03 45 f8 88 10}  //weight: 6, accuracy: Low
        $x_10_17 = {6a 24 59 f7 f1 8b 45 ?? 8a 4c 15 ?? 88 4c 05 ?? eb ?? 6a 04 8d 45 ?? 50 6a 07 68 00 08 00 00 ff}  //weight: 10, accuracy: Low
        $x_10_18 = {b9 24 00 00 00 f7 f1 46 83 fe 0a 8a 54 14 ?? 88 54 34 ?? 72 ?? 8d 44 24 ?? 6a 04 50 6a 07 68 00 08 00 00 ff 15}  //weight: 10, accuracy: Low
        $x_10_19 = {f7 f1 46 83 fe 0a 8a 04 1a 88 44 35 ?? 72 ?? 8d 45 ?? 6a 04 50 6a 07 68 00 08 00 00 ff 15}  //weight: 10, accuracy: Low
        $x_6_20 = {6a 00 6a 01 6a 00 6a 11 ff (15 ?? ?? ?? ??|d6) 6a 00 6a 00 6a 00 6a 56 ff (15 ?? ?? ?? ??|d3) 50 ff (15 ?? ?? ?? ??|d6) 6a 00 6a 03 6a 2d 6a 11 ff (15 ?? ?? ?? ??|d6) 6a 00 6a 00 6a 00 6a 0d ff (15|d6)}  //weight: 6, accuracy: Low
        $x_6_21 = {56 6a 01 56 6a 11 ff d3 56 56 56 6a 56 ff 15 ?? ?? ?? ?? 50 ff d3 56 6a 03 6a 2d 6a 11 ff d3 56 56 56 6a 0d ff d3}  //weight: 6, accuracy: Low
        $x_10_22 = {3d b7 00 00 00 75 (07 56|08) ff 15 ?? ?? ?? ?? 8d 45 ?? 50 8d 45 ?? 50 8d 45 ?? 50 e8 ?? ?? ?? ?? 83 c4 0c 83 7d ?? 05 75 25 83 7d ?? 01 75 1f 8d 4d ?? e8 ?? ?? ?? ?? ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 7 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_1_*))) or
            ((3 of ($x_6_*))) or
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Slenfbot_AIC_144437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Slenfbot.AIC"
        threat_id = "144437"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Slenfbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetLogicalDriveStringsA" ascii //weight: 1
        $x_1_2 = "#botv5.exe|D|Memory Execute|%thisexe%#FileInfo.who|T|Extract File Only|None Inject" ascii //weight: 1
        $x_1_3 = {00 74 65 61 6c 74 68 53 65 74 74 69 6e 67 73 00 55 73 62 00 70 32 70 53 70 4d 61 73 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\eMule\\Incoming\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Slenfbot_D_146363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Slenfbot.gen!D"
        threat_id = "146363"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Slenfbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 6a 6f 68 ?? ?? ?? ?? ff 75 fc ff d6 83 f8 ff 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = {99 b9 e8 03 00 00 f7 f9 99 b9 3c 00 00 00 f7 f9 99 b9 3c 00 00 00 f7 f9 99 b9 18 00 00 00 f7 f9 99 b9 07 00 00 00 f7 f9}  //weight: 1, accuracy: High
        $x_1_3 = {6a 04 68 00 10 00 00 68 6c 05 00 00 6a 00 8b ?? f4 ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Slenfbot_F_167347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Slenfbot.gen!F"
        threat_id = "167347"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Slenfbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 6d 73 70 72 65 61 64 65 76 65 6e 74 00 [0-16] 68 00 74 00 74 00 70 00 [0-47] 5c 49 43 51 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 f8 83 c0 01 89 45 f8 83 7d f8 ?? 7d ?? 8b 4d 08 03 4d f8 0f be 91 ?? ?? ?? ?? 33 55 fc 8b 45 f4 03 45 f8 88 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Slenfbot_ALD_172698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Slenfbot.ALD"
        threat_id = "172698"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Slenfbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 83 c0 01 89 45 f8 83 7d f8 ?? 7d ?? 8b 4d 08 03 4d f8 0f be 91 ?? ?? ?? ?? 33 55 fc 8b 45 f4 03 45 f8 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = {70 69 64 67 69 6e 00 00 73 6b 79 70 65 00 00 00 6d 73 6e 6d 73 67 72 00 61 69 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = "gdkWindowToplevel" ascii //weight: 1
        $x_1_4 = {4d 53 42 4c 57 69 6e 64 6f 77 43 6c 61 73 73 00 49 4d 57 69 6e 64 6f 77 43 6c 61 73 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Slenfbot_ALJ_175362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Slenfbot.ALJ"
        threat_id = "175362"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Slenfbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 f8 83 c0 01 89 45 f8 83 7d f8 ?? 7d ?? 8b 4d 08 03 4d f8 0f be 91 95 38 20 03 33 55 fc 8b 45 f4 03 45 f8 88 10 8b 4d fc 83 c1 01 89 4d fc 8b 55 fc 81 e2 ff 00 00 80 79 ?? 4a 81 ca 00 ff ff ff}  //weight: 5, accuracy: Low
        $x_1_2 = {6e 65 74 73 6b 25 64 25 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = ":\\Autorun.inf" ascii //weight: 1
        $x_1_4 = {64 6f 77 6e 5f 65 78 65 63 00 00 00 21}  //weight: 1, accuracy: High
        $x_1_5 = "##4ucku" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Slenfbot_G_178575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Slenfbot.gen!G"
        threat_id = "178575"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Slenfbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 83 c0 01 89 45 f8 83 7d f8 ?? 7d ?? 8b 4d 08 03 4d f8 0f be 91 ?? ?? ?? ?? 33 55 fc 8b 45 f4 03 45 f8 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = {99 b9 1c 00 00 00 f7 f9 83 f8 06 75 0c c7 85 ?? ?? ?? ?? 01 00 00 00 eb 0a c7 85 ?? ?? ?? ?? 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {64 6f 77 6e 5f 65 78 65 63 00 00 00 21 00 00 00 2d 76 00 00 64 6f 77 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {75 70 64 61 74 65 00 00 21 00 00 00 73 74 61 72 74 2d 73 63 61 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = {73 75 31 63 31 64 33 00}  //weight: 1, accuracy: High
        $x_1_6 = {61 73 64 33 72 34 74 72 77 65 72 00}  //weight: 1, accuracy: High
        $x_1_7 = {73 74 6f 70 70 69 6e 67 20 74 68 72 65 61 64 73 00}  //weight: 1, accuracy: High
        $x_1_8 = {83 f8 02 74 0f 8d 45 fc 50 ff 15 ?? ?? ?? ?? 83 f8 04 75 04 b0 01 eb 08 32 c0}  //weight: 1, accuracy: Low
        $x_1_9 = {99 b9 e8 03 00 00 f7 f9 99 b9 3c 00 00 00 f7 f9 99 b9 3c 00 00 00 f7 f9 99 b9 18 00 00 00 f7 f9 99 b9 07 00 00 00 f7 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

