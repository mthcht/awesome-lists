rule Worm_Win32_Yeltminky_A_2147626007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Yeltminky.A"
        threat_id = "2147626007"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Yeltminky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 db 8a 1c 10 66 81 f3 ?? ?? 88 1c 11 42 4e 75 ef}  //weight: 1, accuracy: Low
        $x_1_2 = {74 11 6a 00 6a 03 6a 00 a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 80 3d ?? ?? ?? ?? 00 74 11 6a 00 6a 02 6a 00 a1 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Yeltminky_A_2147626090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Yeltminky.A!dll"
        threat_id = "2147626090"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Yeltminky"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 10 66 ?? ?? ?? ?? 88 1c 11 42 4e 75 ef}  //weight: 1, accuracy: Low
        $x_1_2 = "DrvKiller" ascii //weight: 1
        $x_1_3 = {66 ba 30 08 66 b8 22 00 e8}  //weight: 1, accuracy: High
        $x_1_4 = {68 48 20 22 00 53 ff d6 53 ff d7 68 d0 07 00 00 ff 55 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

