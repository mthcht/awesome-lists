rule VirTool_Win32_Gelesz_A_2147967499_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Gelesz.A"
        threat_id = "2147967499"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Gelesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 ff 77 10 89 af 84 00 00 00 e8 [0-16] 50 55 e8 ?? ?? ?? ?? 83 c4 10 ?? ?? ?? ?? 50 6a 20 68 00 10 00 00 55 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {89 6c 24 18 ?? ?? 66 39 0c 73 ?? ?? ?? ?? ?? ?? 46 3b 30 ?? ?? 81 fe a0 03 00 00 ?? ?? ?? ?? ?? ?? 39 8f 84 00 00 00 ?? ?? 6a 04 68 00 30 00 00 68 00 10 00 00 51 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {50 53 ff 77 0c e8 ?? ?? ?? ?? 8b 8f 8c 00 00 00 8b d8 2b ce 89 9f 88 00 00 00 03 c9 51 ?? ?? ?? 6a 00 51 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

