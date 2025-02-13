rule Backdoor_Win32_Argech_A_2147611498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Argech.A"
        threat_id = "2147611498"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Argech"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 89 88 88 88 f7 25 ?? ?? ?? ?? c1 ea 05 b8 d3 4d 62 10 f7 e2}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 68 55 51 ff 15}  //weight: 1, accuracy: High
        $x_2_3 = {e9 7f 02 00 00 3c 01 0f 85 72 02 00 00 6a 5c 8d 44 24 24}  //weight: 2, accuracy: High
        $x_2_4 = {79 08 4a 81 ca 00 ff ff ff 42 83 c0 ?? 3d ?? ?? ?? ?? 0f 82 ?? ?? ff ff 6a 00 8d 44 24 14 50 68}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

