rule VirTool_Win32_Naretesz_A_2147959639_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Naretesz.A"
        threat_id = "2147959639"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Naretesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f8 57 6a 00 6a 02 ff ?? ?? ?? ?? ?? 8b f0 85 f6 ?? ?? ff ?? ?? ?? ?? ?? 50 57 68 a4 31 00 10 e8 ?? ?? ?? ?? 83 c4 0c ?? ?? 56 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 0f 47 85 d0 fd ff ff 68 a8 32 00 10 50 6a 00 ff ?? ?? ?? ?? ?? 68 20 4e 00 00 ff ?? ?? ?? ?? ?? 8b 8d e4 fd ff ff 83 f9 07 ?? ?? ?? ?? ?? ?? 8b 95 d0 fd ff ff ?? ?? ?? ?? ?? ?? ?? 8b c2 81 f9 00 10 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

