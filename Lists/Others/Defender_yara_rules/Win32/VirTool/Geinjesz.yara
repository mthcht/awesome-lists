rule VirTool_Win32_Geinjesz_A_2147962534_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Geinjesz.A"
        threat_id = "2147962534"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Geinjesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 02 03 c6 3b c8 ?? ?? 8b 02 85 c0 ?? ?? 33 f6 85 c0 ?? ?? 8a 43 10 ?? ?? ?? 03 4a fc 46 30 01 3b 32}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 44 56 08 8b c8 81 e1 00 f0 00 00 81 f9 00 a0 00 00 ?? ?? 8b 4d fc 25 ff 0f 00 00 03 06 01 0c 18 42 3b d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

