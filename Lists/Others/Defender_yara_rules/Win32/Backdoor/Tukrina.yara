rule Backdoor_Win32_Tukrina_A_2147724967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tukrina.A!dha"
        threat_id = "2147724967"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tukrina"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "norwaynews.mooo.com" ascii //weight: 2
        $x_2_2 = "ebay-global.publicvm.com" ascii //weight: 2
        $x_2_3 = "psychology-blog.ezua.com" ascii //weight: 2
        $x_3_4 = "/scripts/m/query.php?id=" ascii //weight: 3
        $x_1_5 = "Microsoft Update" ascii //weight: 1
        $x_1_6 = "cmd.exe /c" ascii //weight: 1
        $x_1_7 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36" ascii //weight: 1
        $x_1_8 = "StartRoutine" ascii //weight: 1
        $x_1_9 = "InstallRoutineW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Tukrina_C_2147744092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tukrina.C!dha"
        threat_id = "2147744092"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tukrina"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 59 a9 33 76}  //weight: 1, accuracy: High
        $x_1_2 = {68 b7 97 16 9c}  //weight: 1, accuracy: High
        $x_1_3 = {68 8d 00 d2 17}  //weight: 1, accuracy: High
        $x_1_4 = {68 5f 95 90 f4}  //weight: 1, accuracy: High
        $x_1_5 = {68 62 62 db 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Tukrina_D_2147744093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tukrina.D!dha"
        threat_id = "2147744093"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tukrina"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {58 66 89 45 ?? 6a 73 58 66 89 45 ?? 6a 33 58 66 89 45 ?? 6a 32 58 66 89 45 ?? 6a 6c 58 66 89 45 ?? 6a 6f 58 66 89 45 ?? 6a 63 58}  //weight: 6, accuracy: Low
        $x_6_2 = {6a 4d 66 89 [0-5] 58 6a 69 66 89 [0-5] 58 6a 63 66 89 [0-5] 58 6a 72 66 89 [0-5] 58 6a 6f}  //weight: 6, accuracy: Low
        $x_6_3 = {6a 4d 58 66 89 [0-5] 6a 69 58 66 89 [0-5] 6a 63 58 66 89 [0-5] 6a 72 58 66 89 [0-5] 6a 6f 58}  //weight: 6, accuracy: Low
        $x_6_4 = {b8 4f 00 00 00 66 89 84 24 ?? ?? ?? ?? b8 6e 00 00 00 66 89 84 24 ?? ?? ?? ?? b8 65 00 00 00 66 89 84 24 ?? ?? ?? ?? b8 44 00 00 00 66 89 84 24 ?? ?? ?? ?? b8 72 00 00 00 66 89 84 24 ?? ?? ?? ?? b8 69 00 00 00}  //weight: 6, accuracy: Low
        $x_6_5 = {b8 30 55 00 00 66 89 84 24 ?? ?? ?? ?? b8 2d 55 00 00 66 89 84 24 ?? ?? ?? ?? b8 25 55 00 00 66 89 84 24 ?? ?? ?? ?? b8 39 55 00 00 66 89 84 24 ?? ?? ?? ?? b8 3a 55 00 00 66 89 84 24 ?? ?? ?? ?? b8 27 55 00 00 66 89 84 24 ?? ?? ?? ?? b8 30 55 00 00}  //weight: 6, accuracy: Low
        $x_2_6 = {1a 25 30 3b c7 [0-5] 05 27 3a 36 c7 [0-5] 30 26 26 55}  //weight: 2, accuracy: Low
        $x_2_7 = {16 27 30 34 c7 [0-5] 21 30 05 27 c7 [0-5] 3a 36 30 26}  //weight: 2, accuracy: Low
        $x_2_8 = {03 3c 27 21 c7 [0-5] 20 34 39 14 c7 [0-5] 39 39 3a 36}  //weight: 2, accuracy: Low
        $x_2_9 = {16 39 3a 26 c7 [0-5] 30 1d 34 3b c7 [0-5] 31 39 30 55}  //weight: 2, accuracy: Low
        $x_2_10 = {06 55 30 55 11 55 30 55 37 55 20 55 32 55 05 55 27 55 3c 55 23 55 3c 55 39 55 30 55 32 55 30 55}  //weight: 2, accuracy: High
        $x_2_11 = "[activator]::CreateInstance([Type]::GetTypeFromCLSID('9BA05972-F6A8-11CF-A442-00A0C90A8F39'));" wide //weight: 2
        $x_4_12 = {25 00 32 00 31 00 00 00 25 00 32 00 33 00 00 00 25 00 32 00 34 00 00 00 25 00 32 00 36 00 00 00 25 00 32 00 37 00 00 00 25 00 32 00 38 00 00 00}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*))) or
            ((2 of ($x_6_*))) or
            (all of ($x*))
        )
}

