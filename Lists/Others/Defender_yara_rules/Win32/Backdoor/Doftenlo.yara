rule Backdoor_Win32_Doftenlo_A_2147624919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Doftenlo.gen!A"
        threat_id = "2147624919"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Doftenlo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8a 88 ?? ?? ?? ?? 30 0c 37 40 83 f8 09 72 f1 83 3d ?? ?? ?? ?? 00 74 03 f6 14 37 56 47 e8 ?? ?? ?? ?? 3b f8 59 72 d7}  //weight: 1, accuracy: Low
        $x_1_2 = {68 0c 17 00 00 57 8d 04 40 ff 34 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 0c 85 c0 74 af}  //weight: 1, accuracy: Low
        $x_1_3 = {66 81 78 0e 28 0a 75 29 0f b7 40 0c 3d 84 08 00 00 74 19 3d 4c 0b 00 00 74 0d}  //weight: 1, accuracy: High
        $x_1_4 = {25 73 20 28 55 70 74 69 6d 65 3a 20 25 64 64 29 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

