rule TrojanDownloader_Win32_Unruy_H_2147801021_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Unruy.H"
        threat_id = "2147801021"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Unruy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 25 73 2f ?? ?? ?? 2f 69 6e 64 ?? 78 2e 70 68 70 3f 55 3d 25 64 40 25 64 40 25 64 40 25 64 40 25 64 40 25 73}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c1 99 f7 7d ?? 8a 84 15 ?? ?? ?? ?? 30 44 0d ?? 41 83 f9 20 7c e9}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 00 20 40 c6 00 2e 40 c6 00 65 40 c6 00 78 40 c6 00 65 80 60 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Unruy_C_2147801346_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Unruy.C"
        threat_id = "2147801346"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Unruy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 00 83 f8 58 0f 85 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 0f b6 40 ff 83 f8 50 75 78 a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 0f b6 40 fe 83 f8 55 75 64}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 48 50 51 8b 55 ?? 8b 42 34}  //weight: 1, accuracy: Low
        $x_2_3 = {eb 0d 8b 85 fc fb ff ff 40 89 85 fc fb ff ff 8b 85 fc fb ff ff 3b 85 f0 fb ff ff 73 3b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 32 9c 0d 00 fc ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Unruy_C_2147801346_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Unruy.C"
        threat_id = "2147801346"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Unruy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--CLICK_CYCLES" ascii //weight: 1
        $x_1_2 = "%s.delme%u" ascii //weight: 1
        $x_1_3 = "faker_v" ascii //weight: 1
        $x_1_4 = "%s/search.php?q=%d.%d." ascii //weight: 1
        $x_1_5 = ".megawebfind" ascii //weight: 1
        $x_1_6 = "122.141.86.12" ascii //weight: 1
        $x_1_7 = "ad-watch" ascii //weight: 1
        $x_1_8 = "pavfnsv" ascii //weight: 1
        $x_1_9 = "Adobe_Reader" ascii //weight: 1
        $x_1_10 = "RE WE GO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule TrojanDownloader_Win32_Unruy_R_2147801561_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Unruy.R"
        threat_id = "2147801561"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Unruy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 01 00 00 e8 ?? ?? 00 00 3b ?? 8d}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 00 28 00 00 72}  //weight: 1, accuracy: High
        $x_1_3 = {3d ff 7f 00 00 89 [0-4] 75 ?? c7 [0-3] fe 7f 00 00 db}  //weight: 1, accuracy: Low
        $x_1_4 = {83 f8 03 74 ?? (83|3b c5) 8d [0-5] 75 ?? e8 ?? ?? 00 00 85 c0 75 ?? 8d [0-5] e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Unruy_F_2147803147_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Unruy.F"
        threat_id = "2147803147"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Unruy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 00 83 f8 44 0f 85 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 0f b6 40 ff 83 f8 43 0f 85 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 0f b6 40 fe 83 f8 46}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 70 50 8b 45 ?? ff 70 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Unruy_E_2147803898_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Unruy.E"
        threat_id = "2147803898"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Unruy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "RE WE GO" ascii //weight: 1
        $x_1_2 = "122.141.86.12" ascii //weight: 1
        $x_1_3 = {25 73 69 65 78 70 6c 6f 72 65 2e 65 78 65 [0-4] 52 55 4e 41 53 [0-4] 2e 62 61 74}  //weight: 1, accuracy: Low
        $x_10_4 = {8b 45 fc 8b 00 8b 4d fc 8b 49 04 03 48 28 89 4d f4 a1 ?? ?? ?? ?? 83 c0 07 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 6b c9 05 2b c1 a3 ?? ?? ?? ?? 6a 00 6a 00 8b 45 fc ff 70 04 ff 55 f4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Unruy_A_2147803984_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Unruy.A"
        threat_id = "2147803984"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Unruy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 7d 00 58 75 6a 80 7d ff 50 75 64 80 7d fe 55 75 5e a1}  //weight: 2, accuracy: High
        $x_2_2 = {59 85 c0 74 3d 68 ?? ?? 40 00 50 e8 ?? ?? 00 00 ff 35}  //weight: 2, accuracy: Low
        $x_4_3 = {80 38 3d 75 03 c6 00 00 ff 45 ?? 8d 45 ?? 50 ff d6 39 45 ?? 72 e3 68 ?? ?? ?? ?? 8d 45 ?? 50 c6 85}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Unruy_B_2147803987_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Unruy.B"
        threat_id = "2147803987"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Unruy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3b 58 75 36 80 7b ff 50 75 30 80 7b fe 55 75 2a 56}  //weight: 1, accuracy: High
        $x_1_2 = {80 78 ff 50 75 ?? 80 78 fe 55 75 ?? 56 56 56}  //weight: 1, accuracy: Low
        $x_1_3 = {80 38 58 89 45 10 0f 85 ?? ?? ?? ?? 80 78 ff 50 75 7c 80 78 fe 55 75 76}  //weight: 1, accuracy: Low
        $x_1_4 = {73 70 6f 6f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Unruy_Q_2147804019_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Unruy.Q"
        threat_id = "2147804019"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Unruy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 c7 45 e0 42 4d c7 45 ea 36 00 00 00 ff 50 50}  //weight: 1, accuracy: High
        $x_1_2 = {ff 90 8c 00 00 00 50 ff 16}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Unruy_D_2147804162_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Unruy.D"
        threat_id = "2147804162"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Unruy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://%s/dupe.php?q=%d.%d.%d.%d.%d.%s.1.%d" ascii //weight: 1
        $x_1_2 = "faker_version is %d" ascii //weight: 1
        $x_1_3 = {64 74 64 5f 64 6c 6c 2e 64 6c 6c 00 61 00 61 64 64 4e 75 6d 62 65 72 00}  //weight: 1, accuracy: High
        $x_1_4 = "{FA531BC1-0497-11d3-A180-3339052286C3E}" ascii //weight: 1
        $x_1_5 = "\\acrotray .exe" ascii //weight: 1
        $x_1_6 = "NetScheduleJobAdd" ascii //weight: 1
        $x_1_7 = "QueryPerformanceCounter" ascii //weight: 1
        $x_2_8 = {8a 04 02 88 01 eb 98 a1 ?? ?? 40 00 83 e8 04 a3 ?? ?? 40 00 ff 35 ?? ?? 41 00 68 ?? ?? 40 00 ff 35 ?? ?? 40 00 e8 a2 0c 00 00 83 c4 0c 89 85 ?? ?? ?? ?? a1 ?? ?? 40 00 0f af 05 ?? ?? 40 00 83 e8 03 a3 ?? ?? 40 00}  //weight: 2, accuracy: Low
        $x_1_9 = "%s.delme%u" ascii //weight: 1
        $x_1_10 = ".megawebfind" ascii //weight: 1
        $x_1_11 = "http://%s/banner3.php?q=%d.%d.%d.%d.%d.%s.1.%d.%d" ascii //weight: 1
        $x_1_12 = "Global\\acrobat201" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Unruy_S_2147804178_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Unruy.S"
        threat_id = "2147804178"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Unruy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 14 6a 00 56 68 02 04 00 00 8b 48 04 89 4e 08 8b 00 ff 70 04 a1 ?? ?? ?? ?? ff 90 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 14 00 00 c8 57 66 c7 45 dc 02 00 66 89 75 de 66 c7 45 ec 02 00 66 89 75 ee 89 75 f0 89 75 fc ff 90 ?? ?? 00 00 a1 ?? ?? ?? ?? 57 ff 90 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Unruy_I_2147804203_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Unruy.I"
        threat_id = "2147804203"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Unruy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 44 6a 46 6a 30 6a 34 [0-47] 81 c4 a0 00 00 00 8d [0-9] 68 03 00 1f 00 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Unruy_G_2147804204_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Unruy.G"
        threat_id = "2147804204"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Unruy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 88 88 19 00 00 0f af c1}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 fc 81 a4 f4 01}  //weight: 1, accuracy: High
        $x_2_3 = {81 7d 9c 55 54 45 52 75 ?? 81 7d a0 4e 41 4d 45}  //weight: 2, accuracy: Low
        $x_2_4 = {70 7a 62 70 75 ?? 83 ?? 06 74}  //weight: 2, accuracy: Low
        $x_2_5 = {48 41 4c 39 75 ?? 83 ?? 07 0f 84}  //weight: 2, accuracy: Low
        $x_2_6 = {49 4f 41 56 75 ?? 83 ?? 05 0f 84}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Unruy_T_2147804224_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Unruy.T"
        threat_id = "2147804224"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Unruy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 81 48 64 01 00 8d 91 48 64 01 00 56 8d 70 01 8b c6 69 c0 30 01 00 00 8b 04 08 89 32 5e c3}  //weight: 1, accuracy: High
        $x_1_2 = {3d 00 28 00 00 73 05}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 fc 2e c6 45 fd 2e c6 45 fe 2e ff 90 2c 01 00 00 f7 d8 1b c0 40 c9 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Unruy_AUR_2147913972_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Unruy.AUR!MTB"
        threat_id = "2147913972"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Unruy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 85 f6 7e 16 57 8a 11 6b c0 1f 0f be fa 03 c7 84 d2 75 01 4e 41 85 f6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

