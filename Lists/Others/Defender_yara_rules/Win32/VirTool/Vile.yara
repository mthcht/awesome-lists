rule VirTool_Win32_Vile_A_2147758619_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vile.A"
        threat_id = "2147758619"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vile"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "to/target/exe" ascii //weight: 1
        $x_1_2 = "dll_inj" ascii //weight: 1
        $x_1_3 = "InjectProc" ascii //weight: 1
        $x_1_4 = {41 b9 00 30 00 00 c7 44 24 20 04 00 00 00 48 8b c8 4c 8b c3 33 d2 48 8b f0 ff 15 ?? ?? ?? ?? 4c 8b cb 48 c7 44 24 20 00 00 00 00 48 8b d0 4c 8d 84 24 80 02 00 00 48 8b ce 48 8b e8 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

