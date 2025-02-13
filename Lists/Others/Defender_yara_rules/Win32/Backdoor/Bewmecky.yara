rule Backdoor_Win32_Bewmecky_A_2147626858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bewmecky.A"
        threat_id = "2147626858"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bewmecky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 48 0f 85 ?? ?? 00 00 80 be ?? ?? ?? ?? 54 0f 85 ?? ?? 00 00 80 be ?? ?? ?? ?? 54 0f 85 ?? ?? 00 00 80 be ?? ?? ?? ?? 50 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {76 29 8b df 2b de 8a 06 3c 23 74 06 3c 40 74 02 fe c0 3c 40 88 04 33 74 12}  //weight: 1, accuracy: High
        $x_1_3 = {66 3d 0d 00 74 06 66 3d 01 00 75 05 be 90 0e 00 00 66 3d 0e 00 74 06 66 3d 02 00 75 03 6a 51 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

