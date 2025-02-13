rule TrojanDropper_Win32_Koobface_J_2147804007_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Koobface.J"
        threat_id = "2147804007"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 0c 38 46 40 81 fe 00 02 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8a 14 29 32 54 24 1c 88 11 49 48 75 f3}  //weight: 1, accuracy: High
        $x_1_3 = {68 95 1f 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Koobface_K_2147804014_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Koobface.K"
        threat_id = "2147804014"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 14 29 40 45 3d 00 02 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8a 14 01 32 54 24 24 88 10 48 ff 4c 24 10 75 f0}  //weight: 1, accuracy: High
        $x_1_3 = {68 95 1f 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Koobface_M_2147804016_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Koobface.M"
        threat_id = "2147804016"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b3 01 6a 02 56 e8 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8a c3}  //weight: 1, accuracy: Low
        $x_1_2 = {68 95 1f 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Koobface_F_2147804038_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Koobface.F"
        threat_id = "2147804038"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 6e 73 62 6c 6f 63 6b 65 72 5c 64 72 69 76 65 72 5c 6f 62 6a 66 72 65 5f 77 78 70 5f 78 38 36 5c 69 33 38 36 5c 46 69 6c 74 65 72 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = "\\DosDevices\\Ctrl" wide //weight: 1
        $x_1_3 = "s%s%s\\dri%s%sTE%ss" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Koobface_E_2147804181_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Koobface.E"
        threat_id = "2147804181"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s /%s copy \"%s\" \"%s.exe\"" ascii //weight: 1
        $x_1_2 = "reg add \"HKLM\\%s\" /v tp /t REG_SZ /d %s /f" ascii //weight: 1
        $x_1_3 = "rE%sad%sh%sm%ssT%s\\C%sre%so%so%sT%se%scES%ssFi%sr" ascii //weight: 1
        $x_1_4 = "%%p%sRA%slES%%%sDDn%sl%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Koobface_L_2147804197_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Koobface.L"
        threat_id = "2147804197"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 4d fc ff e8 24 00 00 00 83 7d e0 00 75 13 ff 75 08 6a 00 ff 35 ?? ?? 44 00 ff 15 64 ?? 41 00 8b f0 8b c6}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 75 1c ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff 15 ?? ?? ?? ?? 8b f0}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 1c 8d 45 d8 50 56 ff 15 1c ?? 41 00 85 c0 74 77 8b 5d dc 8d 45 b4 50 ff 15 5c ?? 41 00 8b 4d b8 a1}  //weight: 1, accuracy: Low
        $x_1_4 = {41 00 ff 25 68 ?? 41 00 ff 25 6c ?? 41 00 ff 25 70 ?? 41 00 ff 25 74 ?? 41 00 ff 25 78 ?? 41 00 ff 25 7c ?? 41 00 ff 25 80 ?? 41 00 ff 25 84 ?? 41 00 cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

