rule Worm_Win32_Dumpy_B_2147681135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dumpy.B"
        threat_id = "2147681135"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dumpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 04 07 00 00 00 c7 04 24 74 41 40 00 e8 ?? ?? ?? ?? 83 ec 08 c7 44 24 08 00 00 00 00 c7 44 24 04 80 41 40 00 8b 45 0c 8b 00 89 04 24}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 04 24 62 42 40 00 e8 ?? ?? ?? ?? 8d 85 e8 fe ff ff 89 04 24 e8}  //weight: 1, accuracy: Low
        $x_1_3 = "C:\\WinShell\\WinSeven.exe" ascii //weight: 1
        $x_1_4 = {c4 a7 2d 56 69 52 75 53 2d a7 c4}  //weight: 1, accuracy: High
        $x_1_5 = "-BiBiNS-" ascii //weight: 1
        $x_1_6 = {a7 50 f4 4c f4 41 f4 59 a7 42 f4 59 a7 42 f4 34 f4 55 a7 47 f4 41 f4 4d f4 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

