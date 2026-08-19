rule VirTool_Win32_Frepesz_A_2147976421_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Frepesz.A"
        threat_id = "2147976421"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Frepesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 04 ff b5 e0 fd ff ff ff b5 c4 fd ff ff ff ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 8b 4d 08 8b bd e8 fd ff ff 8b 9d ec fd ff ff 03 fe 8b 85 f8 fd ff ff 89 41 10 81 fb 00 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {56 57 68 04 01 00 00 ?? ?? ?? ?? ?? ?? 50 6a 00 ff [0-17] 6a 5c 50 ff ?? ?? ?? ?? ?? c6 00 00 ?? ?? ?? ?? ?? ?? 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

