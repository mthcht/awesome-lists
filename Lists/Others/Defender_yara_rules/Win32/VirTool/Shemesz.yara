rule VirTool_Win32_Shemesz_A_2147970841_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Shemesz.A"
        threat_id = "2147970841"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Shemesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 ff 75 9c 56 ff ?? ?? ?? ?? ?? 8b 0d 70 40 40 00 ba 38 44 40 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b c8 ff ?? ?? ?? ?? ?? ff 75 9c ff}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 40 56 8b 75 94 56 ff 75 98 ff ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 85 c0 ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

