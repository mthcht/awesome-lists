rule Worm_Win32_Rimecud_B_2147622942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rimecud.B"
        threat_id = "2147622942"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rimecud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 3d e8 00 00 00 00 5e 83 c6 ?? b9 ?? ?? ?? ?? 2b e1 83 ec ?? 8a 43 01 8a ?? 02 f6 d0 02 ?? d0 f8 8a ?? 0e 02 ?? 32 ?? ?? ?? 88 ?? 0c ff e2 f1}  //weight: 2, accuracy: Low
        $x_2_2 = {64 8b 0d 30 00 00 00 8b 59 68 89 9d ?? ?? ff ff 8b ?? ?? ?? ff ff 83 ?? 70 74 07}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 45 f8 83 c0 01 89 45 f8 81 7d f8 fa ff ff 0f 74 02 eb ec}  //weight: 2, accuracy: High
        $x_2_4 = {c6 01 2e 8b 55 10 03 55 f8 c6 42 01 65 8b 45 10 03 45 f8 c6 40 02 78 8b 4d 10 03 4d f8 c6 41 03 65}  //weight: 2, accuracy: High
        $x_1_5 = "[AuToRuN]" ascii //weight: 1
        $x_1_6 = "P2P Copy to:" ascii //weight: 1
        $x_1_7 = "MSN spreader running" ascii //weight: 1
        $x_1_8 = "USB spreader running" ascii //weight: 1
        $x_1_9 = "Flood running" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Rimecud_F_2147626076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rimecud.F"
        threat_id = "2147626076"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rimecud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Send an Instant Message" ascii //weight: 1
        $x_1_2 = "YIMInputWindow" ascii //weight: 1
        $x_1_3 = "App Paths\\ICQ.exe" ascii //weight: 1
        $x_1_4 = "icon=%systemroot%\\SYSTEM32\\SHELL32.Dll" ascii //weight: 1
        $x_1_5 = "ShellExecute=vshost.exe" ascii //weight: 1
        $x_1_6 = "autorun.inf" ascii //weight: 1
        $x_1_7 = {5b 49 43 51 20 4d 65 73 73 61 67 65 20 55 73 65 72 5d ?? 55 49 4e 3d 25 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Rimecud_G_2147626077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rimecud.G"
        threat_id = "2147626077"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rimecud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 00 00 ?? 00 00 00 01 03 ?? ?? 00 00 00 00 [0-4] 00 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 74 64 6c 6c 2e 64 6c 6c 00 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63}  //weight: 1, accuracy: High
        $x_1_3 = {e8 00 00 00 00 5e 83 c6 49 b9 4b c0 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Rimecud_Q_2147629142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rimecud.Q"
        threat_id = "2147629142"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rimecud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b e1 83 e9 01 8a 53 01 8a 73 02 f6 d2 02 d6 c0 fa ?? 8a 1c 0f 02 da 32 de f6 d2 88 5c 0c ff e2 f1}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d0 8b 45 ?? 03 45 ?? 88 10 0f be 4d ?? 8b 55 ?? 03 55 ?? 0f be 02 2b c1 8b 4d ?? 03 4d ?? 88 01 0f be 55 ?? f7 d2 88 55 10 eb b8}  //weight: 1, accuracy: Low
        $x_1_3 = {e8 c0 e9 af ed b5 f3 79 f3 ab f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Worm_Win32_Rimecud_HM_2147641375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rimecud.HM"
        threat_id = "2147641375"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rimecud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 6d 2f 73 65 74 75 70 5f 62 2e 61 73 70 3f 70 72 6a 3d [0-3] 26 70 69 64 3d [0-3] 26 6d 61 63 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f [0-5] 2e 77 69 6e 73 6f 66 74 31 2e 63 6f 6d 2f}  //weight: 1, accuracy: Low
        $x_1_3 = "/receive/r_autoidcnt.asp?mer_seq=%s&realid=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

