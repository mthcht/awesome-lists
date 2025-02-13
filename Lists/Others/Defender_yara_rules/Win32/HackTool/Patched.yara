rule HackTool_Win32_Patched_Y_2147647747_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Patched.Y"
        threat_id = "2147647747"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Patched"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 18 81 38 ?? ?? ?? 00 74 0c 89 1d ?? ?? ?? 00 c7 00 ?? ?? ?? 00 68 ?? ?? ?? 00 c3 60 b9 20 00 00 00 8d 3d ?? ?? ?? 00 8b 74 24 28 f3 a6 74 07 61 ff 25 ?? ?? ?? 00 61 b8 ?? ?? ?? 00 c2 08 00}  //weight: 1, accuracy: Low
        $x_1_2 = "radll_HasTheProductBeenPurchased" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

