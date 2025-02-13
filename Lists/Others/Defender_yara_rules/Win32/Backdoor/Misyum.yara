rule Backdoor_Win32_Misyum_A_2147726407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Misyum.A!bit"
        threat_id = "2147726407"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Misyum"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e2 ff 00 00 80 79 08 4a 81 ca 00 ff ff ff 42 8a 54 ?? ?? 8a 1c 38 32 da 88 1c 38 40 3b c5 7c 8e}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 04 51 c7 44 ?? ?? 78 56 34 12 e8 ?? ?? ?? 00 6a 1e 68 ?? ?? ?? 00 8d 54 ?? ?? 6a 04 52 e8 ?? ?? ?? 00 8b 3d ?? ?? ?? 00 6a 00 83 ef 0a 89 3d ?? ?? ?? 00 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = {00 61 6b 73 70 62 75 2e 74 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

