rule VirTool_Win32_Silentload_A_2147928575_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Silentload.A"
        threat_id = "2147928575"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Silentload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 68 40 31 40 00 6a 00 ff ?? ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? 8d ?? ?? ?? 50 6a 28 ff ?? ?? ?? ?? ?? 50 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4c 24 34 6a 00 6a 00 6a 10 89 44 24 50 ?? ?? ?? ?? 50 6a 00 ff 74 24 40 0f 29 44 24 28 c7 44 24 58 01 00 00 00 89 4c 24 60 c7 44 24 64 02 00 00 00 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 3c 01 00 00 00 50 6a 04 6a 00 68 ?? ?? ?? ?? ff 74 24 40 ff ?? 85 c0 ?? ?? ?? ?? ?? ?? 6a 04 8d 44 24 40 c7 44 24 40 03 00 00 00 50 6a 04 6a 00 68 ?? ?? ?? ?? ff 74 24 40 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

