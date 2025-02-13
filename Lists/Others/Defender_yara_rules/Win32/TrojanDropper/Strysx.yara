rule TrojanDropper_Win32_Strysx_A_2147599287_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Strysx.A"
        threat_id = "2147599287"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Strysx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {75 2d 8d 44 24 10 50 e8 ?? ff ff ff 59 ff 70 04 ff 15 ?? ?? 15 13 8d 4c 24 10 8b f0 e8 ?? 01 00 00 68 ?? ?? 15 13 56 ff 15 ?? ?? 15 13 ff d0 5e}  //weight: 3, accuracy: Low
        $x_1_2 = {62 6f 74 00 6d 6f 64 5f 65 6d 61 69 6c 73 00 00 63 72 79 70 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 79 73 00 77 69 6e 33 32 00 00 00 6d 73 78 6d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

