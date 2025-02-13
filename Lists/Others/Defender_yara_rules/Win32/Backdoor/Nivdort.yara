rule Backdoor_Win32_Nivdort_A_2147707845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nivdort.A!dll"
        threat_id = "2147707845"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nivdort"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c9 b3 7b 30 99 ?? ?? ?? ?? 41 81 f9 b4 01 00 00 72 f1 33 c9 30 99 ?? ?? ?? ?? 41 83 f9 54 72 f4}  //weight: 2, accuracy: Low
        $x_1_2 = {8b f0 2b f2 89 34 8d ?? ?? ?? ?? 41 40 8b d0 40 3d b4 01 00 00 7c cd}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 44 24 10 e9 c6 44 24 12 e8 c6 44 24 11 60 c6 44 24 13 61 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {50 68 80 00 00 00 6a 05 53 ff 15 ?? ?? ?? ?? 8d 4c 24 ?? 8d 54 24 ?? 51 6a 14 52 53 57 ff 15 ?? ?? ?? ?? 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_5 = {31 37 32 2e 31 36 2e 33 32 2e 31 34 36 00 00 00 00 73 74 75 62 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

