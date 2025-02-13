rule Backdoor_Win32_Kshell_A_2147636879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kshell.A"
        threat_id = "2147636879"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kshell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {3d a1 55 40 77 7f 56 74 2d 3d ?? ?? ?? ?? 74 14 3d 64 79 43 58 0f 85 ?? ?? 00 00}  //weight: 4, accuracy: Low
        $x_3_2 = {b8 04 00 00 00 b1 a7 30 88 ?? ?? ?? ?? 40 3d 00 01 00 00 72 f2}  //weight: 3, accuracy: Low
        $x_1_3 = {3d 22 00 00 c0 75 ?? 8d ?? 24 ?? ?? 68 00 00 06 00}  //weight: 1, accuracy: Low
        $x_1_4 = {68 00 10 00 00 81 ?? 00 f0 ff ff ?? 6a 00 6a 04 ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_5 = {0f b6 03 83 f8 0c 77 0c ff 24 85 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_6 = "%s\\dllcache\\sethc.exe" ascii //weight: 1
        $x_1_7 = "MyShell v" ascii //weight: 1
        $x_1_8 = "-infect" ascii //weight: 1
        $x_2_9 = "mnjcc.vicp.net" ascii //weight: 2
        $x_1_10 = "Software\\ntshell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

