rule Backdoor_Win32_Popwin_A_2147581715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Popwin.A"
        threat_id = "2147581715"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Popwin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "EnumProcessModules" ascii //weight: 1
        $x_1_2 = "GetProcAddress" ascii //weight: 1
        $x_1_3 = "KillMe.bat" ascii //weight: 1
        $x_1_4 = "Product_Notification" ascii //weight: 1
        $x_1_5 = "SYSTEM\\CurrentControlSet\\Services" ascii //weight: 1
        $x_1_6 = "explorer.exe" ascii //weight: 1
        $x_1_7 = "goto selfkill" ascii //weight: 1
        $x_1_8 = "ping -n 45 localhost" ascii //weight: 1
        $x_5_9 = {be 00 10 40 00 b9 04 00 00 00 8b f9 81 fe ?? ?? ?? ?? 7f 10 ac 47 04 18 2c 02 73 f0 29 3e 03 f1 03 f9 eb e8 ba 00 00 40 00 8d b2 ?? ?? 00 00 8b 46 0c 85 c0 [0-6] 03 c2 8b 7e 10 8b 1e 85 db 75 02 8b df 03 da 03 fa 52 57 50 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Popwin_C_2147583270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Popwin.gen!C"
        threat_id = "2147583270"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Popwin"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 65 6c 20 25 30 0d 0a 00 00 00 00 22 20 67 6f 74 6f 20 73 65 6c 66 6b 69 6c 6c 0d 0a 00 00 00 69 66 20 65 78 69 73 74 20 22 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {64 65 6c 20 2f 46 20 2f 51 20 22 00 3a 73 65 6c 66 6b 69 6c 6c 0d 0a 00 40 65 63 68 6f 20 6f 66 66 0d 0a 00 64 65 6c 6d 65 2e 62 61}  //weight: 1, accuracy: High
        $x_1_3 = {2d 73 65 72 76 69 63 65 00 00 00 00 2e 44 4c 4c 00 00 00 00 54 00 00 00 2e 45 58 45 00 00 00 00 63 3a 5c 00 25 78 00 00 54 79 70 65 00 00 00 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_4 = "5.2.3790.1830" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Popwin_D_2147595113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Popwin.gen!D"
        threat_id = "2147595113"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Popwin"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 65 6c 20 25 30 0d 0a 00 00 00 00 22 20 67 6f 74 6f 20 73 65 6c 66 6b 69 6c 6c 0d 0a 00 00 00 69 66 20 65 78 69 73 74 20 22 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6a 01 68 b8 0b 00 00 8d 85 ?? ?? ff ff 68 ?? ?? ?? ?? 50 be ?? ?? ?? ?? 53 56 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Popwin_E_2147595114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Popwin.gen!E"
        threat_id = "2147595114"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Popwin"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_2 = "DeleteUrlCacheEntry" ascii //weight: 10
        $x_1_3 = {3d 2b 05 00 00 73 07 b8 e6 73 3e 02 c9 c3 83 f8 f0 76 0b 33 d2 b9 00 e1 f5 05 f7 f1 8b c2 c9 c3}  //weight: 1, accuracy: High
        $x_5_4 = {8a 55 10 8d 84 0d fc fe ff ff 2a d1 8a 1c 06 32 da 41 3b 4d 10 88 18 7c e7}  //weight: 5, accuracy: High
        $n_100_5 = "www.360.cn" ascii //weight: -100
        $n_100_6 = "360safeupload_mutex" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Popwin_F_2147601601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Popwin.gen!F"
        threat_id = "2147601601"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Popwin"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 fc 3d 2b 05 00 00 73 07 b8 e6 73 3e 02}  //weight: 5, accuracy: High
        $x_5_2 = {83 f8 f0 76 0b 33 d2 b9 00 e1 f5 05 f7 f1 8b c2}  //weight: 5, accuracy: High
        $x_1_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_4 = {77 69 6e 6c 6f 67 6f 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Popwin_H_2147601660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Popwin.gen!H"
        threat_id = "2147601660"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Popwin"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {3d 2b 05 00 00 73 07 b8 e6 73 3e 02 04 00 8b 45 fc}  //weight: 5, accuracy: Low
        $x_5_2 = {83 f8 f0 76 0b 33 d2 b9 00 e1 f5 05 f7 f1 8b c2}  //weight: 5, accuracy: High
        $x_1_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Popwin_G_2147603661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Popwin.gen!G"
        threat_id = "2147603661"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Popwin"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 ee 49 c6 45 ef 45 c6 45 f0 2e c6 45 f1 77 c6 45 f2 6f c6 45 f3 72 c6 45 f4 6d c6 45 f5 69 c6 45 f6 65 8d 45 e8 8d 55 ee b9 09 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {7e 4e bb 01 00 00 00 8b 45 fc 8a 44 18 ff 24 0f 8b 55 e8 8a 54 32 ff 80 e2 0f 32 c2 88 45 f7 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 1a ff 80 e2 f0 8a 4d f7 02 d1 88 54 18 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {70 6f 70 77 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Popwin_C_2147603662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Popwin.C"
        threat_id = "2147603662"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Popwin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 56 f5 ff ff 8b ?? ?? 30 40 00 8b ?? ?? 30 40 00 8b ?? ?? 30 40 00 83 c4 0c 85 c0 74 19 50 6a 00 68 01 04 10 00 ff d7 8b e8 6a 01 55 ff d6 6a 00 55 ff d6 55 ff d3 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Popwin_G_2147630242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Popwin.G"
        threat_id = "2147630242"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Popwin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 25 64 2e 6f 6c 64 69 6d 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {57 69 6e 64 6f 77 73 2e 69 6d 65 00 50 61 72 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {4b 65 79 62 6f 61 72 64 20 4c 61 79 6f 75 74 5c 50 72 65 6c 6f 61 64 5c 00}  //weight: 1, accuracy: High
        $x_1_4 = {26 70 63 3d 00 00 00 00 26 6d 64 35 3d 00 00 00 26 75 73 65 72 3d 00 00 26 76 65 72 3d 00 00 00 3f 6d 61 63 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {6c 6c 6b 25 64 31 2e 6d 70 33 00}  //weight: 1, accuracy: High
        $x_1_6 = {73 6c 65 65 70 74 69 6d 65 00 00 00 6e 6f 68 69 64 65 00 00 75 6b 65 79 00 00 00 00 70 6f 70 77 69 6e 00 00 61 64 73 63 6c 69 63 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Popwin_I_2147640010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Popwin.gen!I"
        threat_id = "2147640010"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Popwin"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ntsd -c q -p " ascii //weight: 2
        $x_3_2 = "trojdie" ascii //weight: 3
        $x_1_3 = "SYSTEM\\ControlSet001\\Control\\Session Manager\\" ascii //weight: 1
        $x_2_4 = "RAVTIMER" ascii //weight: 2
        $x_1_5 = "SYSTEM\\CurrentControlSet\\Services\\" ascii //weight: 1
        $x_2_6 = "rtvscan" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

