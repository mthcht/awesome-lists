rule VirTool_Win32_Iresz_A_2147975263_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Iresz.A"
        threat_id = "2147975263"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Iresz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 02 6a 02 57 68 00 00 00 02 ff 75 f8 ff ?? ?? ?? ?? ?? 85 c0 ?? ?? ff 75 fc ff ?? ?? ?? ?? ?? 85 c0 ?? ?? 56 8b 35}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 47 08 6a 04 68 00 30 00 00 ff 70 04 6a 00 ff 77 04 ff ?? ?? ?? ?? ?? 8b c8 89 4d 10 85 c9 ?? ?? 85 f6 ?? ?? ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_3 = {52 ff 70 04 ff 30 51 ff 77 04 ff ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 8b 47 08 8b 40 04 39 45 fc ?? ?? ?? ?? ?? ?? ?? ?? ?? 51 6a 40 50 ff 75 10 ff 77 04 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

