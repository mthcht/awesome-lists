rule Backdoor_Win32_Slingshot_A_2147726433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Slingshot.A!dha"
        threat_id = "2147726433"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Slingshot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 63 68 6d 68 6c 70 72 2e 64 6c 6c 00 49 6e 69 74 00 64 6c 6c 5f 75 00}  //weight: 2, accuracy: High
        $x_1_2 = "LineRecs" ascii //weight: 1
        $x_1_3 = "%hc%hc%hc" ascii //weight: 1
        $x_1_4 = {00 25 68 73 50 72 6f 78 79 2d 41 75 74 68 6f 72 69 7a 61 74 69 6f 6e 3a 20 42 61 73 69 63 20 25 68 73 0d 0a}  //weight: 1, accuracy: High
        $x_1_5 = {0d f0 ad de 75 ?? 68 90 00 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {68 02 02 00 00 89 74 24 20 89 7c 24 1c c7 44 24 24 b2 7f 23 43 ff 15}  //weight: 1, accuracy: High
        $x_2_7 = {74 0b ff 15 ?? ?? ?? ?? e9 ?? ?? ff ff ff 74 24 ?? c7 44 24 ?? 32 30 30 00 56 c7 44 24 ?? 34 30 37 00}  //weight: 2, accuracy: Low
        $x_2_8 = {74 06 8b 11 51 ff 52 08 53 53 53 8d 44 24 1c 50 89 5c 24 20 ff d6}  //weight: 2, accuracy: High
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

