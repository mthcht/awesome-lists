rule Worm_Win32_Filunork_A_2147655274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Filunork.A"
        threat_id = "2147655274"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Filunork"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 21 56 89 7e 04 ff 75 08 e8 ?? ?? ?? ?? 59 85 c0 59 74 08 83 7e 1c 07 75 02 b3 01}  //weight: 1, accuracy: Low
        $x_1_2 = {75 2b 8d 9e d4 00 00 00 33 c0 53 50 50 68 2b 80 00 00 50 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {83 f8 02 74 14 83 f8 03 74 0f 83 f8 04 74 0a 83 f8 05 74 05 83 f8 06 46 83 fe 1a 7c a0}  //weight: 1, accuracy: Low
        $x_1_4 = "S-1-5-21-%0.2d%0.2d%0.2d%0.2d%0.2d-" wide //weight: 1
        $x_1_5 = "-s -copyto -bncc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

