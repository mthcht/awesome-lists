rule Worm_Win32_Pondfull_B_2147687861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pondfull.B"
        threat_id = "2147687861"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pondfull"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 31 04 0b 05 ?? ?? ?? ?? 83 c1 04 81 f9 ?? ?? ?? 00 75 ed eb 05 e8 de ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {5e ff d6 00 00 80 7c 00 00 dd 77 00 00 ab 71 00 00 41 7e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 7c ?? ?? ?? 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {5a 03 d0 c7 02 2e 65 78 65 c6 42 04 00 8d 94 24 00 01 00 00 6a 03 6a 01 68 00 00 00 10 52 e8 ?? ?? ?? ?? 83 c4 ?? 83 f8 00 74 ?? 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

