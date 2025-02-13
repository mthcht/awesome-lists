rule Worm_Win32_Kasidet_A_2147687758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kasidet.A"
        threat_id = "2147687758"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kasidet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&os=%s&av=%s&nat=%s&" ascii //weight: 1
        $x_1_2 = "?taskexec=1&task_id=%s" ascii //weight: 1
        $x_1_3 = "?getcmd=1&uid=%s&cn=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Kasidet_B_2147689258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kasidet.B"
        threat_id = "2147689258"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kasidet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "taskexec=1&task_id=%s" ascii //weight: 2
        $x_2_2 = "&host=%s&form=%s&browser=%s" ascii //weight: 2
        $x_2_3 = "&os=%s&av=%s&nat=%s&" ascii //weight: 2
        $x_1_4 = "NeutrinoDesk" ascii //weight: 1
        $x_1_5 = "InjectProcedure - HookChrome" ascii //weight: 1
        $x_1_6 = "track_type=%s&track_data=%s&process_name=%s" ascii //weight: 1
        $x_1_7 = "SELECT * FROM AntiVirusProduct" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Kasidet_D_2147706012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kasidet.D"
        threat_id = "2147706012"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kasidet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\N3NNetwork\\" ascii //weight: 1
        $x_1_2 = "delself.bat" wide //weight: 1
        $x_1_3 = "logs.rar" wide //weight: 1
        $x_1_4 = "\\PhotoExplorer.exe" wide //weight: 1
        $x_1_5 = "\\autorun.inf" wide //weight: 1
        $x_1_6 = "SharedDocs" wide //weight: 1
        $x_1_7 = "aHR0cDovL3JvbGVpbi5pbi9TZXJ2ZXJTaWRlL3Rhc2tzLnBocA==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Kasidet_F_2147709019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kasidet.F"
        threat_id = "2147709019"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kasidet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 a4 61 8b 55 fc 33 c9 8d 04 4a 66 83 30 07 41 81 f9 b4 00 00 00 76 f0}  //weight: 1, accuracy: High
        $x_1_2 = {75 04 c6 45 fb 01 83 c7 28 ff 4d fc 75 db 80 7d fb 00 75 18}  //weight: 1, accuracy: High
        $x_1_3 = {0f 84 96 00 00 00 33 c0 57 66 89 84 24 34 06 00 00 8d 84 24 36 06 00 00 53 50 e8 ?? ?? ?? ?? 83 c4 0c 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b f8 59 8d 44 24 18 50 8d 84 24 34 06 00 00 57 50 ff d6}  //weight: 1, accuracy: Low
        $x_1_4 = "PNICNU" wide //weight: 1
        $x_1_5 = "tqdohts" wide //weight: 1
        $x_1_6 = "Thaspfub[Jnduhthas[Pnichpt[DruubisQbutnhi[Uri" wide //weight: 1
        $x_1_7 = "\\VFFiWwxx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_Win32_Kasidet_G_2147724871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kasidet.G!bit"
        threat_id = "2147724871"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kasidet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 58 00 6c 00 35 00 6a 00 56 00 56 00 78 00 63 00 56 00 57 00 49 00 78 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 c9 c1 c0 07 33 c1 83 c2 02 0f b7 0a 66 85 c9 75 ed}  //weight: 1, accuracy: High
        $x_1_3 = {66 83 34 48 ?? 41 3b 4d 0c 76 f5}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 9d 66 1c c7 45 ?? 18 6a f5 c2 c7 45 ?? dd d9 57 74 c7 45 ?? 7b e1 06 c1 c7 45 ?? c4 bc 08 56 c7 45 ?? d0 f9 12 65 c7 45 ?? 2a d5 04 c6 c7 45 ?? a5 51 06 4d c7 45 ?? fb b9 12 ac c7 45 ?? 61 75 74 5b c7 45 ?? 85 9c 30 53 c7 45 ?? 22 d5 3e e5}  //weight: 1, accuracy: Low
        $x_1_5 = {68 c3 f6 e6 a3 e8 ?? ?? ?? ?? 8b f8 59 85 ff 74 68 8b 47 3c 53 56 8b 74 38 78 03 f7 8b 46 20 8b 4e 24 8b 5e 1c 03 c7 03 cf 03 df}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Worm_Win32_Kasidet_H_2147725533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kasidet.H!bit"
        threat_id = "2147725533"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kasidet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b 40 0c 53 8b 58 0c 56 57 8b 7d 08 8b f3 81 f7 ?? ?? ?? ?? 8b 56 30 e8 ?? ?? ?? ff 8b c8 e8 ?? ?? ?? ff 3b c7 74 17 8b 36 3b de 74 0a 85 f6 74 06 83 7e 30 00 75 dd}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 04 68 00 30 00 00 8d 47 01 50 6a 00 ff 15 ?? ?? ?? 00 8b f0 85 f6 74 1f 57 53 56 e8 ?? ?? ?? ff 83 c4 0c 33 c0 85 ff 74 0a 66 83 34 46 02 40 3b c7 72 f6}  //weight: 1, accuracy: Low
        $x_1_3 = {42 80 3c 0a 00 75 f9 3b f2 73 0f 0f be 14 0e 33 c2 69 c0 ?? ?? ?? ?? 46 eb dc 5e c3 56 be ?? ?? ?? ?? 33 d2 e8 ?? ?? ?? ff 85 c0 74 16 0f b7 04 51 33 f0 69 f6 ?? ?? ?? ?? 42 e8 ?? ?? ?? ff 3b d0 72 ea 8b c6 5e c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Kasidet_I_2147726173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kasidet.I!bit"
        threat_id = "2147726173"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kasidet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {64 a1 30 00 00 00 8b 40 0c 53 8b 58 0c 56 57 8b 7d 08 8b f3 81 f7 ?? ?? ?? ?? 8b 56 30 e8 ?? ?? ?? ff 8b c8 e8 ?? ?? ?? ff 3b c7 74 17 8b 36 3b de 74 0a 85 f6 74 06 83 7e 30 00 75 dd 33 c0 5f 5e 5b 5d c3 8b 46 18 eb f6}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 42 58 6a 59 66 89 45 ?? 58 6a 2a 66 89 45 ?? 58 6a 52 66 89 45 ?? 58 6a 55 66 89 45 ?? 58 6a 2a 66 89 45 ?? 58 6a 4b 66 89 45 ?? 58 66 89 45 ?? 6a 5a 58 66 89 45 ?? 33 c0 66 89 45}  //weight: 2, accuracy: Low
        $x_1_3 = {68 4c 5e 28 03 6a 01 e8 ?? ?? ?? ff 59 59 6a 04 68 00 30 00 00 ff 75 08 6a 00 ff d0 5d c3}  //weight: 1, accuracy: Low
        $x_1_4 = {66 83 34 46 ?? 40 3b c7 72 f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

